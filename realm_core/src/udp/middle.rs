use std::io::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::SockMap;
use super::sockmap::now_millis;
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
use crate::sni::SniRoute;

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

    #[cfg(feature = "quic-sni")]
    let mut cache = RouteCache::new();

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

            // mark client activity, used by the association idle timeout
            sockmap.touch(&laddr);

            #[cfg(feature = "quic-sni")]
            if routes.is_some() {
                // keep the sticky route fresh while the association is alive
                cache.touch(&laddr);
            }

            // existing association
            if let Some((rsock, target)) = sockmap.find(&laddr) {
                send_packets(&rsock, pkts, target, conn_opts.as_ref(), laddr, local_addr).await?;
                continue;
            }

            // new flow, routed by quic sni
            #[cfg(feature = "quic-sni")]
            if let Some(routes) = routes {
                let cached = cache.get(&laddr);

                let decision = {
                    let flow = pending.entry(laddr).or_insert_with(|| PendingFlow::new(routes.timeout));

                    for pkt in pkts.iter() {
                        flow.push(pkt.data());
                    }

                    flow.decision(routes, rname.as_ref(), cached.as_ref())
                };

                if let Some((choice, cacheable)) = decision {
                    if cacheable {
                        cache.put(&laddr, choice.clone());
                    }

                    if let Some(flow) = pending.remove(&laddr) {
                        relay_pending(flow, laddr, choice, lis, conn_opts, sockmap, local_addr).await?;
                    }
                }

                continue;
            }

            // plain route
            let raddr = default_addr.unwrap();

            // PROXY-header UDP flows (send_proxy) hide realm's transport change
            // from quic-go inside the node's reverse map. Tearing the
            // association down on a one-directional (node->client) idle window
            // churns the source port, which leaves the node sending to a dead
            // socket and stalls the flow. Keep such associations alive based on
            // client activity instead, so the source port stays stable across
            // idle pauses. Plain UDP keeps the existing node->client timeout.
            #[cfg(feature = "proxy")]
            let client_based = conn_opts.proxy_opts.send_proxy;
            #[cfg(not(feature = "proxy"))]
            let client_based = false;

            let rsock = if let Some((rsock, _)) = sockmap.find(&laddr) {
                rsock
            } else {
                let s = Arc::new(socket::associate(&raddr, &conn_opts)?);
                let activity = if client_based {
                    Some(sockmap.insert(laddr, s.clone(), raddr))
                } else {
                    sockmap.insert(laddr, s.clone(), raddr);
                    None
                };
                tokio::spawn(send_back(lis, laddr, s.clone(), conn_opts, sockmap, activity));
                log::info!("[udp]new association {} => {} as {}", laddr, *rname, raddr);
                s
            };

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

    fn decision(
        &self,
        routes: &SniRoutes,
        default: &RemoteAddr,
        cached: Option<&RouteChoice>,
    ) -> Option<(RouteChoice, bool)> {
        let fallback = || {
            cached.cloned().unwrap_or_else(|| RouteChoice {
                raddr: default.clone(),
                route: None,
                server_name: None,
            })
        };

        match &self.state {
            quic::Sniff::Complete(server_name) => {
                let route = server_name.as_deref().and_then(|name| routes.find(name));

                let choice = match route {
                    Some(route) => RouteChoice {
                        raddr: route.raddr.clone(),
                        route: Some(route.clone()),
                        server_name: server_name.clone(),
                    },
                    None => RouteChoice {
                        raddr: default.clone(),
                        route: None,
                        server_name: server_name.clone(),
                    },
                };

                Some((choice, true))
            }

            // short header packet, cannot sniff: keep the previously selected route
            quic::Sniff::NotQuic => Some((fallback(), false)),
            quic::Sniff::Pending if self.overflowed => Some((fallback(), false)),
            quic::Sniff::Pending => None,
        }
    }
}

#[cfg(feature = "quic-sni")]
const SNI_CACHE_TTL: u64 = 600;
#[cfg(feature = "quic-sni")]
const SNI_CACHE_CAP: usize = 65536;

/// Route selected by sni sniffing, kept sticky per client address.
#[cfg(feature = "quic-sni")]
#[derive(Clone)]
struct RouteChoice {
    raddr: RemoteAddr,
    route: Option<SniRoute>,
    server_name: Option<String>,
}

#[cfg(feature = "quic-sni")]
struct CachedRoute {
    choice: RouteChoice,
    last_seen: std::time::Instant,
}

#[cfg(feature = "quic-sni")]
struct RouteCache {
    map: HashMap<SocketAddr, CachedRoute>,
}

#[cfg(feature = "quic-sni")]
impl RouteCache {
    fn new() -> Self {
        Self { map: HashMap::new() }
    }

    fn get(&mut self, addr: &SocketAddr) -> Option<RouteChoice> {
        let now = std::time::Instant::now();

        match self.map.get_mut(addr) {
            Some(entry) if now.duration_since(entry.last_seen).as_secs() < SNI_CACHE_TTL => {
                entry.last_seen = now;
                Some(entry.choice.clone())
            }
            Some(_) => {
                self.map.remove(addr);
                None
            }
            None => None,
        }
    }

    fn touch(&mut self, addr: &SocketAddr) {
        if let Some(entry) = self.map.get_mut(addr) {
            entry.last_seen = std::time::Instant::now();
        }
    }

    fn put(&mut self, addr: &SocketAddr, choice: RouteChoice) {
        let now = std::time::Instant::now();

        if self.map.len() >= SNI_CACHE_CAP && !self.map.contains_key(addr) {
            self.map
                .retain(|_, entry| now.duration_since(entry.last_seen).as_secs() < SNI_CACHE_TTL);

            while self.map.len() >= SNI_CACHE_CAP {
                let Some(victim) = self.map.keys().next().copied() else {
                    break;
                };
                self.map.remove(&victim);
            }
        }

        self.map.insert(*addr, CachedRoute { choice, last_seen: now });
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
                RouteChoice {
                    raddr: rname.as_ref().clone(),
                    route: None,
                    server_name: None,
                },
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
    choice: RouteChoice,
    lis: Ref<UdpSocket>,
    conn_opts: Ref<ConnectOpts>,
    sockmap: Ref<SockMap>,
    local_addr: SocketAddr,
) -> Result<()> {
    // route-specific connection options (dns resolver / interface / source address)
    let mut opts = conn_opts.as_ref().clone();
    if let Some(route) = &choice.route {
        route.apply_conn_opts(&mut opts);
    }

    let (rsock, target) = open_association(
        lis,
        laddr,
        &choice.raddr,
        opts.resolver.as_ref(),
        conn_opts,
        &opts,
        sockmap,
    )
    .await?;

    let server_name = choice.server_name.as_deref().unwrap_or("none");
    let default = if choice.route.is_none() { ", default" } else { "" };

    log::info!(
        "[udp]new association {} => {} (sni: {}{}) as {}, buffered {} datagrams",
        laddr,
        choice.raddr,
        server_name,
        default,
        target,
        flow.datagrams.len()
    );

    send_buffered(&rsock, target, &flow.datagrams, &opts, laddr, local_addr).await
}

#[cfg(feature = "quic-sni")]
#[allow(clippy::too_many_arguments)]
async fn open_association(
    lis: Ref<UdpSocket>,
    laddr: SocketAddr,
    raddr: &RemoteAddr,
    resolver: Option<&Resolver>,
    send_back_opts: Ref<ConnectOpts>,
    associate_opts: &ConnectOpts,
    sockmap: Ref<SockMap>,
) -> Result<(Arc<UdpSocket>, SocketAddr)> {
    let addr = resolve_addr_with(raddr, resolver)
        .await?
        .iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::AddrNotAvailable, "could not resolve remote address"))?;

    let s = Arc::new(socket::associate(&addr, associate_opts)?);
    let activity = sockmap.insert(laddr, s.clone(), addr);
    tokio::spawn(send_back(
        lis,
        laddr,
        s.clone(),
        send_back_opts,
        sockmap,
        Some(activity),
    ));

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
    activity: Option<Arc<AtomicU64>>,
) {
    let mut registry = Registry::new(batched::MAX_PACKETS);
    let timeout = conn_opts.associate_timeout;
    let idle_timeout = conn_opts.udp_idle_timeout;
    let laddr_s: SockAddrStore = laddr.into();

    'recv: loop {
        let recv = registry.batched_recv_on(&rsock);

        match &activity {
            // client-activity based lifetime, sni routed associations
            Some(activity) => {
                if idle_timeout == 0 {
                    match recv.await {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("[udp]rear recvfrom failed: {}", e);
                            break;
                        }
                    }
                } else {
                    let idle_ms = idle_timeout as u64 * 1000;
                    let elapsed = now_millis().saturating_sub(activity.load(Ordering::Relaxed));

                    if elapsed >= idle_ms {
                        log::info!(
                            "[udp]remove association for {} (idle {}s, no client traffic)",
                            laddr,
                            idle_timeout
                        );
                        break 'recv;
                    }

                    let wait = (idle_ms - elapsed).div_ceil(1000);

                    match timeoutfut(recv, wait as usize).await {
                        // re-check activity on the next round
                        Err(_) => continue 'recv,
                        Ok(Err(e)) => {
                            log::error!("[udp]rear recvfrom failed: {}", e);
                            break;
                        }
                        Ok(Ok(())) => {}
                    }
                }
            }

            // backend-activity based lifetime, plain udp associations
            None => match timeoutfut(recv, timeout).await {
                Err(_) => {
                    log::debug!("[udp]rear recvfrom timeout");
                    break;
                }
                Ok(Err(e)) => {
                    log::error!("[udp]rear recvfrom failed: {}", e);
                    break;
                }
                Ok(Ok(())) => {}
            },
        }

        log::debug!("[udp]rear batched recvfrom[{}]", registry.count());

        let pkts = registry.iter().map(|pkt| pkt.ref_with_addr(&laddr_s));
        if let Err(e) = batched::send_all(&lsock, pkts).await {
            log::error!("[udp]failed to sendto client{}: {}", laddr, e);
            break;
        }
    }

    sockmap.remove(&laddr);
    log::debug!("[udp]remove association for {}", laddr);
}
