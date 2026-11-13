use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::sleep;

use realm_core::endpoint::{ConnectOpts, Endpoint, RemoteAddr};
use realm_core::udp::run_udp;

#[cfg(feature = "proxy")]
use realm_core::endpoint::ProxyOpts;

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

#[tokio::test]
#[cfg(feature = "proxy")]
async fn udp_proxy_v2() {
    env_logger::init();

    let endpoint = Endpoint {
        laddr: "127.0.0.1:11000".parse().unwrap(),
        raddr: "127.0.0.1:11500"
            .parse::<SocketAddr>()
            .map(RemoteAddr::SocketAddr)
            .unwrap(),
        conn_opts: ConnectOpts {
            proxy_opts: ProxyOpts {
                send_proxy: true,
                ..Default::default()
            },
            ..Default::default()
        },
        bind_opts: Default::default(),
        extra_raddrs: Vec::new(),
        sni: None,
    };

    tokio::spawn(run_udp(endpoint));

    let receiver = UdpSocket::bind("127.0.0.1:11500").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:11000".parse().unwrap();

    sleep(Duration::from_millis(500)).await;

    let payload = b"Ping Ping Ping";
    let mut buf = [0u8; 2048];

    for _ in 0..5 {
        client.send_to(payload, server_addr).await.unwrap();

        let (n, proxy_addr) = receiver.recv_from(&mut buf).await.unwrap();
        assert!(n >= 28, "short PROXY datagram: {n}");

        assert_eq!(&buf[..12], SIGNATURE);
        assert_eq!(buf[12], 0x21);
        assert_eq!(buf[13], 0x12);
        assert_eq!(&buf[14..16], &12u16.to_be_bytes());

        assert_eq!(&buf[16..20], &[127, 0, 0, 1]);
        assert_eq!(&buf[20..24], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([buf[24], buf[25]]), client_addr.port());
        assert_eq!(u16::from_be_bytes([buf[26], buf[27]]), 11000);
        assert_eq!(&buf[28..n], payload);

        receiver.send_to(b"Pong Pong Pong", proxy_addr).await.unwrap();

        let (n, from) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, server_addr);
        assert_eq!(&buf[..n], b"Pong Pong Pong");
    }
}

/// Datagrams that would exceed the node's 1452-byte receive buffer once the
/// PROXY header is prepended must be forwarded without the header. Otherwise
/// the IP packet crosses the path MTU, gets fragmented or truncated, and the
/// QUIC connection stalls.
#[tokio::test]
#[cfg(feature = "proxy")]
async fn udp_proxy_v2_skips_header_for_large_datagrams() {
    let endpoint = Endpoint {
        laddr: "127.0.0.1:11100".parse().unwrap(),
        raddr: "127.0.0.1:11600"
            .parse::<SocketAddr>()
            .map(RemoteAddr::SocketAddr)
            .unwrap(),
        conn_opts: ConnectOpts {
            proxy_opts: ProxyOpts {
                send_proxy: true,
                ..Default::default()
            },
            ..Default::default()
        },
        bind_opts: Default::default(),
        extra_raddrs: Vec::new(),
        sni: None,
    };

    tokio::spawn(run_udp(endpoint));

    let receiver = UdpSocket::bind("127.0.0.1:11600").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = "127.0.0.1:11100".parse().unwrap();

    sleep(Duration::from_millis(500)).await;

    let mut buf = [0u8; 2048];

    // 1452 + 28 header would be 1480 bytes of UDP payload: over the 1452 limit.
    let large = vec![0xA5u8; 1452];
    client.send_to(&large, server_addr).await.unwrap();
    let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
    assert_eq!(n, large.len(), "large datagram should arrive without a header");
    assert_ne!(&buf[..12], SIGNATURE, "large datagram must not carry a PROXY header");
    assert_eq!(&buf[..n], &large[..]);

    // Small datagrams still carry the header, which keeps the node's mapping.
    let small = b"ping";
    client.send_to(small, server_addr).await.unwrap();
    let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..12], SIGNATURE, "small datagram should carry a PROXY header");
    assert_eq!(&buf[28..n], small);
}
