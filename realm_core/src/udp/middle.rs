use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::SockMap;
use super::{socket, batched};

use crate::trick::Ref;
use crate::time::timeoutfut;
use crate::dns::resolve_addr_with;
use crate::endpoint::{RemoteAddr, ConnectOpts};
use crate::sni::SniRoutes;

#[cfg(feature = "quic-sni")]
use std::collections::HashMap;
#[cfg(feature = "quic-sni")]
use std::io::{Error, ErrorKind};
#[cfg(feature = "quic-sni")]
use std::time::Duration;
#[cfg(feature = "quic-sni")]
use tokio::time::Instant;

#[cfg(feature = "quic-sni")]
use crate::dns::Resolver;
#[cfg(feature = "quic-sni")]
use crate::quic;

use batched::{Packet, SockAddrStore};
use registry::Registry;
mod registry {
    use super::*;
    type Range = std::ops::Range<u16>;

    pub struct Registry {
        pkts: Box<[Packet]>,
        groups: Vec<Range>,
        cursor: u16,
    }

    impl Registry {
        pub fn new(npkts: usize) -> Self {
            debug_assert!(npkts <= batched::MAX_PACKETS);
            Self {
                pkts: vec![Packet::new(); npkts].into_boxed_slice(),
                groups: Vec::with_capacity(npkts),
                cursor: 0u16,
            }
        }

        pub async fn batched_recv_on(&mut self, sock: &UdpSocket) -> Result<()> {
            let n = batched::recv_some(sock, &mut self.pkts).await?;
            self.cursor = n as u16;
            Ok(())
        }

        pub fn group_by_addr(&mut self) {
            let n = self.cursor as usize;
            self.groups.clear();
            group_by_inner(&mut self.pkts[..n], &mut self.groups, |a, b| a.addr == b.addr);
        }

        pub fn group_iter(&self) -> GroupIter<'_> {
            GroupIter {
                pkts: &self.pkts,
                ranges: self.groups.iter(),
            }
        }

        pub fn iter(&self) -> std::slice::Iter<'_, Packet> {
            self.pkts[..self.cursor as usize].iter()
        }

        pub const fn count(&self) -> usize {
            self.cursor as usize
        }
    }

    use std::slice::Iter;
    use std::iter::Iterator;
    pub struct GroupIter<'a> {
        pkts: &'a [Packet],
        ranges: Iter<'a, Range>,
    }

    impl<'a> Iterator for GroupIter<'a> {
        type Item = &'a [Packet];

        fn next(&mut self) -> Option<Self::Item> {
            self.ranges
                .next()
                .map(|Range { start, end }| &self.pkts[*start as usize..*end as usize])
        }
    }

    fn group_by_inner<T, F>(data: &mut [T], groups: &mut Vec<Range>, eq: F)
    where
        F: Fn(&T, &T) -> bool,
    {
        let maxn = data.len();
        let (mut beg, mut end) = (0, 1);
        while end < maxn {
            // go ahead if addr is same
            if eq(&data[end], &data[beg]) {
                end += 1;
                continue;
            }
            // pick packets afterwards
            let mut probe = end + 1;
            while probe < maxn {
                if eq(&data[probe], &data[beg]) {
                    data.swap(probe, end);
                    end += 1;
                }
                probe += 1;
            }
            groups.push(beg as _..end as _);
            (beg, end) = (end, end + 1);
        }
        groups.push(beg as _..end as _);
    }
}

pub async fn associate_and_relay(
    lis: Ref<UdpSocket>,
    rname: Ref<RemoteAddr>,
    conn_opts: Ref<ConnectOpts>,
    routes: Option<&SniRoutes>,
    sockmap: Ref<SockMap>,
) -> Result<()> {
    let mut registry = Registry::new(batched::MAX_PACKETS);

    let local_addr = lis.local_addr()?;

    #[cfg(feature = "quic-sni")]
    let mut pending: HashMap<SocketAddr, PendingFlow> = HashMap::new();

    #[cfg(not(feature = "quic-sni"))]
    let routes = {
        let _ = routes;
        None::<&SniRoutes>
    };

    loop {
        // wait for datagrams, or flush pending flows on timeout
        #[cfg(feature = "quic-sni")]
        let deadline = pending.values().filter_map(|flow| flow.deadline).min();

        #[cfg(feature = "quic-sni")]
        match deadline {
            Some(deadline) => tokio::select! {
                res = registry.batched_recv_on(&lis) => res?,
                _ = tokio::time::sleep_until(deadline) => {
                    flush_pending(&mut pending, lis, rname, conn_opts, sockmap, local_addr).await?;
                    continue;
                }
            },
            None => registry.batched_recv_on(&lis).await?,
        }

        #[cfg(not(feature = "quic-sni"))]
        registry.batched_recv_on(&lis).await?;

        log::debug!("[udp]entry batched recvfrom[{}]", registry.count());

        // default route, only resolved when the endpoint is not sni-routed
        let default_addr = match routes {
            Some(_) => None,
            None => Some(
                resolve_addr_with(&rname, conn_opts.resolver.as_ref())
                    .await?
                    .iter()
                    .next()
                    .unwrap(),
            ),
        };

        if let Some(addr) = default_addr {
            log::debug!("[udp]{} resolved as {}", *rname, addr);
        }

        registry.group_by_addr();
        for pkts in registry.group_iter() {
            let laddr: SocketAddr = pkts[0].addr.clone().into();

            // existing association
            if let Some((rsock, target)) = sockmap.find(&laddr) {
                send_packets(&rsock, pkts, target, conn_opts.as_ref(), laddr, local_addr).await?;
                continue;
            }

            // new flow, routed by quic sni
            #[cfg(feature = "quic-sni")]
            if let Some(routes) = routes {
                let decision = {
                    let flow = pending.entry(laddr).or_insert_with(|| PendingFlow::new(routes.timeout));

                    for pkt in pkts.iter() {
                        flow.push(pkt.data());
                    }

                    flow.decision(routes, rname.as_ref())
                };

                if let Some(choice) = decision {
                    if let Some(flow) = pending.remove(&laddr) {
                        relay_pending(flow, laddr, choice, lis, conn_opts, sockmap, local_addr).await?;
                    }
                }

                continue;
            }

            // plain route
            let raddr = default_addr.unwrap();
            let (rsock, _) = sockmap.find_or_insert(&laddr, || {
                let s = Arc::new(socket::associate(&raddr, &conn_opts)?);
                tokio::spawn(send_back(lis, laddr, s.clone(), conn_opts, sockmap));
                log::info!("[udp]new association {} => {} as {}", laddr, *rname, raddr);
                Result::Ok((s, raddr))
            })?;

            send_packets(&rsock, pkts, raddr, conn_opts.as_ref(), laddr, local_addr).await?;
        }
    }
}

#[cfg_attr(not(feature = "proxy"), allow(unused_variables))]
async fn send_packets(
    rsock: &UdpSocket,
    pkts: &[Packet],
    target: SocketAddr,
    conn_opts: &ConnectOpts,
    laddr: SocketAddr,
    local_addr: SocketAddr,
) -> Result<()> {
    let target: SockAddrStore = target.into();

    #[cfg(feature = "proxy")]
    if conn_opts.proxy_opts.send_proxy {
        let dst = if local_addr.ip().is_unspecified() {
            laddr
        } else {
            local_addr
        };
        let (h, n) = super::proxy::build_udp_v2_header(laddr, dst);
        return batched::send_all_with_header(rsock, pkts.iter().map(|x| x.ref_with_addr(&target)), &h[..n]).await;
    }

    batched::send_all(rsock, pkts.iter().map(|x| x.ref_with_addr(&target))).await
}

#[cfg(feature = "quic-sni")]
const MAX_PENDING_DATAGRAMS: usize = 8;
#[cfg(feature = "quic-sni")]
const MAX_PENDING_BYTES: usize = 16 * 1024;

#[cfg(feature = "quic-sni")]
struct PendingFlow {
    deadline: Option<Instant>,
    datagrams: Vec<Vec<u8>>,
    bytes: usize,
    overflowed: bool,
    sniffer: quic::Sniffer,
    state: quic::Sniff,
}

#[cfg(feature = "quic-sni")]
impl PendingFlow {
    fn new(timeout: usize) -> Self {
        Self {
            deadline: match timeout {
                0 => None,
                x => Some(Instant::now() + Duration::from_secs(x as u64)),
            },
            datagrams: Vec::new(),
            bytes: 0,
            overflowed: false,
            sniffer: quic::Sniffer::new(),
            state: quic::Sniff::Pending,
        }
    }

    fn push(&mut self, datagram: &[u8]) {
        if self.overflowed && self.datagrams.len() > MAX_PENDING_DATAGRAMS {
            return;
        }

        if self.datagrams.len() >= MAX_PENDING_DATAGRAMS || self.bytes + datagram.len() > MAX_PENDING_BYTES {
            self.overflowed = true;
        }

        self.datagrams.push(datagram.to_vec());
        self.bytes += datagram.len();

        if self.state == quic::Sniff::Pending {
            self.state = self.sniffer.feed(datagram);
        }
    }

    fn decision(&self, routes: &SniRoutes, default: &RemoteAddr) -> Option<(RemoteAddr, Option<Resolver>)> {
        match &self.state {
            quic::Sniff::Complete(server_name) => Some(select_route(routes, server_name.as_deref(), default)),
            quic::Sniff::NotQuic => Some((default.clone(), None)),
            quic::Sniff::Pending if self.overflowed => Some((default.clone(), None)),
            quic::Sniff::Pending => None,
        }
    }
}

#[cfg(feature = "quic-sni")]
fn select_route(routes: &SniRoutes, server_name: Option<&str>, default: &RemoteAddr) -> (RemoteAddr, Option<Resolver>) {
    match server_name.and_then(|name| routes.find(name)) {
        Some(route) => (route.raddr.clone(), route.resolver.clone()),
        None => (default.clone(), None),
    }
}

#[cfg(feature = "quic-sni")]
async fn flush_pending(
    pending: &mut HashMap<SocketAddr, PendingFlow>,
    lis: Ref<UdpSocket>,
    rname: Ref<RemoteAddr>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
    local_addr: SocketAddr,
) -> Result<()> {
    let now = Instant::now();

    let expired: Vec<SocketAddr> = pending
        .iter()
        .filter(|(_, flow)| flow.deadline.is_some_and(|deadline| deadline <= now))
        .map(|(laddr, _)| *laddr)
        .collect();

    for laddr in expired {
        if let Some(flow) = pending.remove(&laddr) {
            log::debug!("[udp]quic sniff timeout for {}", laddr);
            relay_pending(
                flow,
                laddr,
                (rname.as_ref().clone(), None),
                lis,
                conn_opts,
                sockmap,
                local_addr,
            )
            .await?;
        }
    }

    Ok(())
}

#[cfg(feature = "quic-sni")]
#[allow(clippy::too_many_arguments)]
async fn relay_pending(
    flow: PendingFlow,
    laddr: SocketAddr,
    (raddr, resolver): (RemoteAddr, Option<Resolver>),
    lis: Ref<UdpSocket>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
    local_addr: SocketAddr,
) -> Result<()> {
    let resolver = resolver.or_else(|| conn_opts.resolver.clone());

    let (rsock, target) = open_association(lis, laddr, &raddr, resolver.as_ref(), conn_opts, sockmap).await?;

    log::debug!(
        "[udp]quic route {} => {} as {}, buffered {} datagrams",
        laddr,
        raddr,
        target,
        flow.datagrams.len()
    );

    send_buffered(&rsock, target, &flow.datagrams, conn_opts.as_ref(), laddr, local_addr).await
}

#[cfg(feature = "quic-sni")]
async fn open_association(
    lis: Ref<UdpSocket>,
    laddr: SocketAddr,
    raddr: &RemoteAddr,
    resolver: Option<&Resolver>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    let addr = resolve_addr_with(raddr, resolver)
        .await?
        .iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::AddrNotAvailable, "could not resolve remote address"))?;

    let s = Arc::new(socket::associate(&addr, &conn_opts)?);
    tokio::spawn(send_back(lis, laddr, s.clone(), conn_opts, sockmap));
    sockmap.insert(laddr, s.clone(), addr);
    log::info!("[udp]new association {} => {} as {}", laddr, raddr, addr);

    Ok((s, addr))
}

#[cfg(feature = "quic-sni")]
#[cfg_attr(not(feature = "proxy"), allow(unused_variables))]
async fn send_buffered(
    rsock: &UdpSocket,
    target: SocketAddr,
    datagrams: &[Vec<u8>],
    conn_opts: &ConnectOpts,
    laddr: SocketAddr,
    local_addr: SocketAddr,
) -> Result<()> {
    #[cfg(feature = "proxy")]
    let header = if conn_opts.proxy_opts.send_proxy {
        let dst = if local_addr.ip().is_unspecified() {
            laddr
        } else {
            local_addr
        };
        let (h, n) = super::proxy::build_udp_v2_header(laddr, dst);
        Some(h[..n].to_vec())
    } else {
        None
    };

    for datagram in datagrams {
        #[cfg(feature = "proxy")]
        if let Some(header) = &header {
            let mut buf = Vec::with_capacity(header.len() + datagram.len());
            buf.extend_from_slice(header);
            buf.extend_from_slice(datagram);
            rsock.send_to(&buf, target).await?;
            continue;
        }

        rsock.send_to(datagram, target).await?;
    }

    Ok(())
}

async fn send_back(
    lsock: Ref<UdpSocket>,
    laddr: SocketAddr,
    rsock: Arc<UdpSocket>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
) {
    let mut registry = Registry::new(batched::MAX_PACKETS);
    let timeout = conn_opts.associate_timeout;
    let laddr_s: SockAddrStore = laddr.into();

    loop {
        match timeoutfut(registry.batched_recv_on(&rsock), timeout).await {
            Err(_) => {
                log::debug!("[udp]rear recvfrom timeout");
                break;
            }
            Ok(Err(e)) => {
                log::error!("[udp]rear recvfrom failed: {}", e);
                break;
            }
            Ok(Ok(())) => {
                log::debug!("[udp]rear batched recvfrom[{}]", registry.count())
            }
        };

        let pkts = registry.iter().map(|pkt| pkt.ref_with_addr(&laddr_s));
        if let Err(e) = batched::send_all(&lsock, pkts).await {
            log::error!("[udp]failed to sendto client{}: {}", laddr, e);
            break;
        }
    }

    sockmap.remove(&laddr);
    log::debug!("[udp]remove association for {}", laddr);
}
