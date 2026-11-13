//! TCP relay entrance.

mod socket;
mod middle;
mod plain;

#[cfg(feature = "hook")]
mod hook;

#[cfg(feature = "proxy")]
mod proxy;

#[cfg(feature = "transport")]
mod transport;

use std::io::{ErrorKind, Result};

use crate::sni;
use crate::trick::Ref;
use crate::endpoint::Endpoint;

use middle::{connect_and_relay, connect_and_relay_with_prefix};

/// Launch a tcp relay.
pub async fn run_tcp(endpoint: Endpoint) -> Result<()> {
    let Endpoint {
        laddr,
        raddr,
        bind_opts,
        conn_opts,
        extra_raddrs,
        sni,
    } = endpoint;

    let raddr = Ref::new(&raddr);
    let conn_opts = Ref::new(&conn_opts);
    let extra_raddrs = Ref::new(&extra_raddrs);
    let sni = Ref::new(&sni);

    let lis = socket::bind(&laddr, bind_opts).unwrap_or_else(|e| panic!("[tcp]failed to bind {}: {}", laddr, e));
    let keepalive = socket::keepalive::build(&conn_opts);

    loop {
        let (local, addr) = match lis.accept().await {
            Ok(x) => x,
            Err(e) if e.kind() == ErrorKind::ConnectionAborted => {
                log::warn!("[tcp]failed to accept: {}", e);
                continue;
            }
            Err(e) => {
                log::error!("[tcp]failed to accept: {}", e);
                break;
            }
        };

        // ignore error
        let _ = local.set_nodelay(true);
        // set tcp_keepalive
        if let Some(kpa) = &keepalive {
            use socket::keepalive::SockRef;
            SockRef::from(&local).set_tcp_keepalive(kpa)?;
        }

        tokio::spawn(async move {
            let Some(routes) = sni.as_ref() else {
                return match connect_and_relay(local, raddr, conn_opts, extra_raddrs).await {
                    Ok(..) => log::debug!("[tcp]{} => {}, finish", addr, raddr.as_ref()),
                    Err(e) => log::error!("[tcp]{} => {}, error: {}", addr, raddr.as_ref(), e),
                };
            };

            // sniff tls client hello, then select the route by server name
            let mut local = local;
            let sniffed = match sni::sniff(&mut local, routes.timeout).await {
                Ok(x) => x,
                Err(e) => return log::warn!("[tcp]{} failed to sniff client hello: {}", addr, e),
            };

            let route = sniffed.server_name.as_deref().and_then(|name| routes.find(name));
            let target = match route {
                Some(route) => {
                    log::debug!("[tcp]{} sni {:?} => {}", addr, sniffed.server_name, route.raddr);
                    &route.raddr
                }
                None => {
                    log::debug!(
                        "[tcp]{} sni {:?} => default {}",
                        addr,
                        sniffed.server_name,
                        raddr.as_ref()
                    );
                    raddr.as_ref()
                }
            };

            // route-specific connection options (dns resolver / interface / source address)
            let opts = route.filter(|route| route.has_conn_overrides()).map(|route| {
                let mut opts = conn_opts.as_ref().clone();
                route.apply_conn_opts(&mut opts);
                opts
            });
            let opts = opts.as_ref().map(Ref::new).unwrap_or(conn_opts);

            match connect_and_relay_with_prefix(local, Ref::new(target), opts, extra_raddrs, Some(sniffed.prefix)).await
            {
                Ok(..) => log::debug!("[tcp]{} => {}, finish", addr, target),
                Err(e) => log::error!("[tcp]{} => {}, error: {}", addr, target, e),
            }
        });
    }

    Ok(())
}
