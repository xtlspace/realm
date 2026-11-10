#![allow(static_mut_refs)]

//! Global dns resolver.

use std::io::{Result, Error};
use std::net::SocketAddr;

use hickory_resolver as resolver;
use resolver::net::runtime::TokioRuntimeProvider as Tokio;
use resolver::TokioResolver;
use resolver::system_conf::read_system_conf;
use resolver::lookup_ip::{LookupIp, LookupIpIter};
use resolver::config::{ResolverOpts, ResolverConfig};

#[cfg(not(feature = "multi-thread"))]
use once_cell::unsync::{OnceCell, Lazy};

#[cfg(feature = "multi-thread")]
use once_cell::{unsync::OnceCell, sync::Lazy};

use crate::endpoint::RemoteAddr;

pub mod config {
    use super::resolver;
    pub use resolver::config::*;
}

/// Dns resolver.
pub type Resolver = TokioResolver;

/// Dns config.
#[derive(Debug, Clone)]
pub struct DnsConf {
    pub conf: ResolverConfig,
    pub opts: ResolverOpts,
}

/// Use system config on unix(except android) or windows,
/// otherwise use google's public dns servers.
impl Default for DnsConf {
    fn default() -> Self {
        #[cfg(any(all(unix, not(target_os = "android")), windows))]
        let (conf, opts) = read_system_conf().unwrap_or_default();

        #[cfg(not(any(all(unix, not(target_os = "android")), windows)))]
        let (conf, opts) = (ResolverConfig::udp_and_tcp(&config::GOOGLE), Default::default());

        Self { conf, opts }
    }
}

static mut DNS_CONF: OnceCell<DnsConf> = OnceCell::new();

fn build_resolver_with(conf: ResolverConfig, opts: ResolverOpts) -> Result<Resolver> {
    TokioResolver::builder_with_config(conf, Tokio::default())
        .with_options(opts)
        .build()
        .map_err(Error::other)
}

static mut DNS: Lazy<Resolver> = Lazy::new(|| {
    let DnsConf { conf, opts } = global_conf();
    build_resolver_with(conf, opts).expect("failed to build global dns resolver")
});

/// Get a copy of the global dns config.
pub fn global_conf() -> DnsConf {
    unsafe { DNS_CONF.get().cloned() }.unwrap_or_default()
}

/// Build a dns resolver from the global config, with optional overrides.
pub fn build_resolver(conf: Option<ResolverConfig>, opts: Option<ResolverOpts>) -> Result<Resolver> {
    let DnsConf {
        conf: mut base_conf,
        opts: mut base_opts,
    } = global_conf();

    if let Some(conf) = conf {
        base_conf = conf;
    }

    if let Some(opts) = opts {
        base_opts = opts;
    }

    build_resolver_with(base_conf, base_opts)
}

/// Force initialization.
pub fn force_init() {
    use std::ptr;
    unsafe {
        Lazy::force(&*ptr::addr_of!(DNS));
    }
}

/// Setup global dns resolver. This is not thread-safe!
pub fn build(conf: Option<ResolverConfig>, opts: Option<ResolverOpts>) {
    build_lazy(conf, opts);
    force_init();
}

/// Setup config of global dns resolver, without initialization.
/// This is not thread-safe!
pub fn build_lazy(conf: Option<ResolverConfig>, opts: Option<ResolverOpts>) {
    let mut dns_conf = DnsConf::default();

    if let Some(conf) = conf {
        dns_conf.conf = conf;
    }

    if let Some(opts) = opts {
        dns_conf.opts = opts;
    }

    unsafe {
        DNS_CONF.set(dns_conf).unwrap();
    }
}

/// Lookup ip with global dns resolver.
pub async fn resolve_ip(ip: &str) -> Result<LookupIp> {
    resolve_ip_with(ip, None).await
}

/// Lookup ip with the given dns resolver, or the global one.
pub async fn resolve_ip_with(ip: &str, dns: Option<&Resolver>) -> Result<LookupIp> {
    let lookup = match dns {
        Some(dns) => dns.lookup_ip(ip).await,
        None => unsafe { DNS.lookup_ip(ip).await },
    };
    lookup.map_err(Error::other)
}

/// Lookup socketaddr with global dns resolver.
pub async fn resolve_addr(addr: &RemoteAddr) -> Result<LookupRemoteAddr<'_>> {
    resolve_addr_with(addr, None).await
}

/// Lookup socketaddr with the given dns resolver, or the global one.
pub async fn resolve_addr_with<'a>(addr: &'a RemoteAddr, dns: Option<&Resolver>) -> Result<LookupRemoteAddr<'a>> {
    use RemoteAddr::*;
    use LookupRemoteAddr::*;
    match addr {
        SocketAddr(addr) => Ok(NoLookup(addr)),
        DomainName(ip, port) => resolve_ip_with(ip, dns).await.map(|ip| Dolookup(ip, *port)),
    }
}

/// Resolved result.
pub enum LookupRemoteAddr<'a> {
    NoLookup(&'a SocketAddr),
    Dolookup(LookupIp, u16),
}

impl LookupRemoteAddr<'_> {
    /// Get view of resolved result.
    pub fn iter(&self) -> LookupRemoteAddrIter<'_> {
        use LookupRemoteAddr::*;
        match self {
            NoLookup(addr) => LookupRemoteAddrIter::NoLookup(std::iter::once(addr)),
            Dolookup(ip, port) => LookupRemoteAddrIter::DoLookup(ip.iter(), *port),
        }
    }
}

/// View of resolved result.
pub enum LookupRemoteAddrIter<'a> {
    NoLookup(std::iter::Once<&'a SocketAddr>),
    DoLookup(LookupIpIter<'a>, u16),
}

impl Iterator for LookupRemoteAddrIter<'_> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        use LookupRemoteAddrIter::*;
        match self {
            NoLookup(addr) => addr.next().copied(),
            DoLookup(ip, port) => ip.next().map(|ip| SocketAddr::new(ip, *port)),
        }
    }
}
