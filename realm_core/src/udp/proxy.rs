use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub const PROXY_V2_MAX_LEN: usize = 16 + 36; // IPv6 + DGRAM

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

/// Build a PROXY protocol v2 header for a UDP datagram.
///
/// The returned length is 28 for IPv4 and 52 for IPv6.
pub fn build_udp_v2_header(src: SocketAddr, dst: SocketAddr) -> ([u8; PROXY_V2_MAX_LEN], usize) {
    // Dual-stack listeners often report IPv4 peers as ::ffff:a.b.c.d.
    let src = normalize_v4_mapped(src);

    let mut h = [0u8; PROXY_V2_MAX_LEN];
    h[..12].copy_from_slice(SIGNATURE);
    h[12] = 0x21; // v2 | PROXY

    match src {
        SocketAddr::V4(s) => {
            let d = match dst {
                SocketAddr::V4(d) => d,
                SocketAddr::V6(d) => match d.ip().to_ipv4_mapped() {
                    Some(v4) => SocketAddrV4::new(v4, d.port()),
                    None => s,
                },
            };

            h[13] = 0x12; // AF_INET | DGRAM
            h[14..16].copy_from_slice(&12u16.to_be_bytes());

            h[16..20].copy_from_slice(&s.ip().octets());
            h[20..24].copy_from_slice(&d.ip().octets());
            h[24..26].copy_from_slice(&s.port().to_be_bytes());
            h[26..28].copy_from_slice(&d.port().to_be_bytes());

            (h, 28)
        }
        SocketAddr::V6(s) => {
            let d = match dst {
                SocketAddr::V6(d) => d,
                SocketAddr::V4(d) => SocketAddrV6::new(d.ip().to_ipv6_mapped(), d.port(), 0, 0),
            };

            h[13] = 0x22; // AF_INET6 | DGRAM
            h[14..16].copy_from_slice(&36u16.to_be_bytes());

            h[16..32].copy_from_slice(&s.ip().octets());
            h[32..48].copy_from_slice(&d.ip().octets());
            h[48..50].copy_from_slice(&s.port().to_be_bytes());
            h[50..52].copy_from_slice(&d.port().to_be_bytes());

            (h, 52)
        }
    }
}

fn normalize_v4_mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        _ => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_header() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1234));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 443));
        let (h, n) = build_udp_v2_header(src, dst);

        assert_eq!(n, 28);
        assert_eq!(&h[..12], SIGNATURE);
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x12);
        assert_eq!(&h[14..16], &12u16.to_be_bytes());
        assert_eq!(&h[16..20], &[1, 2, 3, 4]);
        assert_eq!(&h[20..24], &[5, 6, 7, 8]);
        assert_eq!(&h[24..26], &1234u16.to_be_bytes());
        assert_eq!(&h[26..28], &443u16.to_be_bytes());
    }

    #[test]
    fn ipv4_mapped_header_is_normalized() {
        let src = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped(),
            1234,
            0,
            0,
        ));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 443));
        let (h, n) = build_udp_v2_header(src, dst);

        assert_eq!(n, 28);
        assert_eq!(h[13], 0x12);
        assert_eq!(&h[16..20], &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_header() {
        let src = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 0, 0));
        let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        let (h, n) = build_udp_v2_header(src, dst);

        assert_eq!(n, 52);
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x22);
        assert_eq!(&h[14..16], &36u16.to_be_bytes());
        assert_eq!(&h[16..32], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&h[48..50], &1234u16.to_be_bytes());
        assert_eq!(&h[50..52], &443u16.to_be_bytes());
    }
}
