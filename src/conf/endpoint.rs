use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use serde::de::{self, IgnoredAny, MapAccess, Visitor};

use realm_core::endpoint::{Endpoint, RemoteAddr};
use realm_core::sni::{SniRoute, SniRoutes, DEFAULT_TIMEOUT};

#[cfg(feature = "balance")]
use realm_core::balance::Balancer;

#[cfg(feature = "transport")]
use realm_core::kaminari::mix::{MixAccept, MixConnect};

use super::{Config, NetConf, NetInfo, DnsConf};

/// Sni route target, either a plain `remote` or a table with per-route options.
#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum SniTargetConf {
    Addr(String),
    Detail {
        remote: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        dns: Option<DnsConf>,

        #[serde(skip_serializing_if = "Option::is_none")]
        interface: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        through: Option<String>,

        /// Unknown options of the table, reported but not fatal.
        #[serde(skip)]
        unknown: Vec<String>,
    },
}

impl<'de> Deserialize<'de> for SniTargetConf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SniTargetVisitor;

        impl<'de> Visitor<'de> for SniTargetVisitor {
            type Value = SniTargetConf;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a remote address string or a table with `remote`")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SniTargetConf::Addr(v.to_string()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SniTargetConf::Addr(v))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut remote = None;
                let mut dns = None;
                let mut interface = None;
                let mut through = None;
                let mut unknown = Vec::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "remote" => remote = Some(map.next_value::<String>()?),
                        "dns" => dns = Some(map.next_value::<DnsConf>()?),
                        "interface" => interface = Some(map.next_value::<String>()?),
                        "through" => through = Some(map.next_value::<String>()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                            unknown.push(key);
                        }
                    }
                }

                let Some(remote) = remote else {
                    return Err(de::Error::missing_field("remote"));
                };

                Ok(SniTargetConf::Detail {
                    remote,
                    dns,
                    interface,
                    through,
                    unknown,
                })
            }
        }

        deserializer.deserialize_any(SniTargetVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EndpointConf {
    pub listen: String,

    pub remote: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_remotes: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub through: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_interface: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_transport: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_transport: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<BTreeMap<String, SniTargetConf>>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni_timeout: Option<usize>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Config::is_empty")]
    pub network: NetConf,

    #[serde(default)]
    #[serde(skip_serializing_if = "Config::is_empty")]
    pub dns: DnsConf,
}

impl EndpointConf {
    fn build_local(&self) -> SocketAddr {
        self.listen
            .to_socket_addrs()
            .expect("invalid local address")
            .next()
            .unwrap()
    }

    fn build_remote(&self) -> RemoteAddr {
        Self::build_remote_x(&self.remote)
    }

    fn build_remote_x(remote: &str) -> RemoteAddr {
        if let Ok(sockaddr) = remote.parse::<SocketAddr>() {
            RemoteAddr::SocketAddr(sockaddr)
        } else {
            let mut iter = remote.rsplitn(2, ':');
            let port = iter.next().unwrap().parse::<u16>().unwrap();
            let addr = iter.next().unwrap().to_string();
            RemoteAddr::DomainName(addr, port)
        }
    }

    fn build_sni(&self) -> Option<SniRoutes> {
        let sni = self.sni.as_ref()?;

        let routes = sni
            .iter()
            .map(|(name, target)| {
                let (remote, dns, interface, through, unknown) = match target {
                    SniTargetConf::Addr(remote) => (remote, None, None, None, &[][..]),
                    SniTargetConf::Detail {
                        remote,
                        dns,
                        interface,
                        through,
                        unknown,
                    } => (
                        remote,
                        dns.as_ref(),
                        interface.as_ref(),
                        through.as_ref(),
                        unknown.as_slice(),
                    ),
                };

                if !unknown.is_empty() {
                    eprintln!(
                        "[config] sni route \"{}\": unknown option(s) [{}] ignored",
                        name,
                        unknown.join(", ")
                    );
                }

                // route dns inherits the endpoint one (which inherits the global one)
                let resolver = dns.and_then(|dns| {
                    let mut conf = self.dns.clone();
                    conf.rst_field(dns);
                    conf.build_resolver()
                });

                SniRoute {
                    server_name: name.to_ascii_lowercase(),
                    raddr: Self::build_remote_x(remote),
                    resolver,
                    bind_interface: interface.cloned(),
                    bind_address: through.and_then(|x| Self::parse_through(x)),
                }
            })
            .collect();

        Some(SniRoutes {
            routes,
            timeout: self.sni_timeout.unwrap_or(DEFAULT_TIMEOUT),
        })
    }

    fn build_send_through(&self) -> Option<SocketAddr> {
        self.through.as_deref().and_then(Self::parse_through)
    }

    /// Parse a `through` option into a bind address.
    fn parse_through(through: &str) -> Option<SocketAddr> {
        match through.to_socket_addrs() {
            Ok(mut x) => Some(x.next().unwrap()),
            Err(_) => {
                let mut ipstr = String::from(through);
                ipstr.retain(|c| c != '[' && c != ']');
                ipstr.parse::<IpAddr>().map_or(None, |ip| Some(SocketAddr::new(ip, 0)))
            }
        }
    }

    #[cfg(feature = "balance")]
    fn build_balancer(&self) -> Balancer {
        if let Some(s) = &self.balance {
            Balancer::parse_from_str(s)
        } else {
            Balancer::default()
        }
    }

    #[cfg(feature = "transport")]
    fn build_transport(&self) -> Option<(MixAccept, MixConnect)> {
        use realm_core::kaminari::mix::{MixClientConf, MixServerConf};
        use realm_core::kaminari::opt::get_ws_conf;
        use realm_core::kaminari::opt::get_tls_client_conf;
        use realm_core::kaminari::opt::get_tls_server_conf;

        let Self {
            listen_transport,
            remote_transport,
            ..
        } = self;

        let listen_ws = listen_transport.as_ref().and_then(|s| get_ws_conf(s));
        let listen_tls = listen_transport.as_ref().and_then(|s| get_tls_server_conf(s));

        let remote_ws = remote_transport.as_ref().and_then(|s| get_ws_conf(s));
        let remote_tls = remote_transport.as_ref().and_then(|s| get_tls_client_conf(s));

        if matches!(
            (&listen_ws, &listen_tls, &remote_ws, &remote_tls),
            (None, None, None, None)
        ) {
            None
        } else {
            let ac = MixAccept::new_shared(MixServerConf {
                ws: listen_ws,
                tls: listen_tls,
            });
            let cc = MixConnect::new_shared(MixClientConf {
                ws: remote_ws,
                tls: remote_tls,
            });
            Some((ac, cc))
        }
    }
}

#[derive(Debug)]
pub struct EndpointInfo {
    pub no_tcp: bool,
    pub use_udp: bool,
    pub endpoint: Endpoint,
}

impl Config for EndpointConf {
    type Output = EndpointInfo;

    fn is_empty(&self) -> bool {
        false
    }

    fn build(self) -> Self::Output {
        let laddr = self.build_local();
        let raddr = self.build_remote();

        let extra_raddrs: Vec<RemoteAddr> = self.extra_remotes.iter().map(|r| Self::build_remote_x(r)).collect();

        let sni = self.build_sni();

        // build partial conn_opts from netconf
        let NetInfo {
            mut bind_opts,
            mut conn_opts,
            no_tcp,
            use_udp,
        } = self.network.build();

        #[cfg(feature = "balance")]
        {
            conn_opts.balancer = self.build_balancer();
        }

        #[cfg(feature = "transport")]
        {
            conn_opts.transport = self.build_transport();
        }

        // build left fields of bind_opts and conn_opts
        conn_opts.bind_address = self.build_send_through();
        conn_opts.bind_interface = self.interface;
        bind_opts.bind_interface = self.listen_interface;

        // per-endpoint dns resolver
        conn_opts.resolver = self.dns.build_resolver();

        if sni.is_some() {
            if !extra_raddrs.is_empty() {
                panic!("[tcp]sni endpoints do not support extra_remotes");
            }

            #[cfg(not(feature = "quic-sni"))]
            if use_udp {
                panic!("[tcp]sni over udp requires the `quic-sni` feature");
            }

            #[cfg(feature = "proxy")]
            if !no_tcp && conn_opts.proxy_opts.accept_proxy {
                panic!("[tcp]sni endpoints do not support accept_proxy");
            }

            #[cfg(feature = "transport")]
            if !no_tcp && conn_opts.transport.is_some() {
                panic!("[tcp]sni endpoints do not support transport");
            }

            let _ = use_udp;
        }

        EndpointInfo {
            no_tcp,
            use_udp,
            endpoint: Endpoint {
                laddr,
                raddr,
                bind_opts,
                conn_opts,
                extra_raddrs,
                sni,
            },
        }
    }

    fn rst_field(&mut self, _: &Self) -> &mut Self {
        unreachable!()
    }

    fn take_field(&mut self, _: &Self) -> &mut Self {
        unreachable!()
    }

    fn from_cmd_args(matches: &clap::ArgMatches) -> Self {
        let listen = matches.get_one("local").cloned().unwrap();
        let remote = matches.get_one("remote").cloned().unwrap();
        let through = matches.get_one("through").cloned();
        let interface = matches.get_one("interface").cloned();
        let listen_interface = matches.get_one("listen_interface").cloned();
        let listen_transport = matches.get_one("listen_transport").cloned();
        let remote_transport = matches.get_one("remote_transport").cloned();

        EndpointConf {
            listen,
            remote,
            through,
            interface,
            listen_interface,
            listen_transport,
            remote_transport,
            network: Default::default(),
            dns: Default::default(),
            sni: None,
            sni_timeout: None,
            extra_remotes: Vec::new(),
            balance: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf::FullConf;

    fn build_endpoint(conf: &str) -> Endpoint {
        let mut full = FullConf::from_conf_str(conf).unwrap();
        full.apply_global_opts();

        full.endpoints.into_iter().next().unwrap().build().endpoint
    }

    #[test]
    fn sni_route_options() {
        let endpoint = build_endpoint(
            r#"
[[endpoints]]
listen = "127.0.0.1:1000"
remote = "127.0.0.1:2000"

[endpoints.sni]
"a.test" = { remote = "example.com:443", interface = "eth1", through = "10.0.0.1", dns = { mode = "ipv4_only" }, oops = 1 }
"b.test" = "1.1.1.1:443"
"#,
        );

        let sni = endpoint.sni.unwrap();
        assert_eq!(sni.routes.len(), 2);

        let a = sni.routes.iter().find(|x| x.server_name == "a.test").unwrap();
        assert_eq!(a.raddr.to_string(), "example.com:443");
        assert_eq!(a.bind_interface.as_deref(), Some("eth1"));
        assert_eq!(a.bind_address, Some("10.0.0.1:0".parse().unwrap()));
        assert!(a.resolver.is_some());

        let b = sni.routes.iter().find(|x| x.server_name == "b.test").unwrap();
        assert!(b.bind_interface.is_none());
        assert!(b.bind_address.is_none());
        assert!(b.resolver.is_none());
    }
}
