#![cfg(feature = "quic-sni")]

use std::net::SocketAddr;
use std::time::Duration;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::net::UdpSocket;

use realm_core::endpoint::{BindOpts, ConnectOpts, Endpoint, RemoteAddr};
use realm_core::sni::{SniRoute, SniRoutes};
use realm_core::udp::run_udp;

const VERSION_1: u32 = 0x0000_0001;

fn client_hello(server_name: &str) -> Vec<u8> {
    let name = server_name.as_bytes();

    let mut list = Vec::new();
    list.push(0u8); // host_name
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(name);

    let mut ext = Vec::new();
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    handshake
}

fn hkdf_expand_label(secret: &[u8], label: &str, out: &mut [u8]) {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).unwrap();
    let label = format!("tls13 {}", label);

    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);

    hkdf.expand(&info, out).unwrap();
}

struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_keys(version: u32, dcid: &[u8]) -> Keys {
    let salt: &[u8] = match version {
        VERSION_1 => &[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
            0x7f, 0x0a,
        ],
        _ => panic!("unsupported version"),
    };

    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), dcid);

    let mut client_secret = [0u8; 32];
    hkdf_expand_label(prk.as_slice(), "client in", &mut client_secret);

    let mut keys = Keys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };

    hkdf_expand_label(&client_secret, "quic key", &mut keys.key);
    hkdf_expand_label(&client_secret, "quic iv", &mut keys.iv);
    hkdf_expand_label(&client_secret, "quic hp", &mut keys.hp);

    keys
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.extend_from_slice(&(0x4000u16 | value as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&(0x8000_0000u32 | value as u32).to_be_bytes());
    }
}

fn build_initial(dcid: &[u8], plaintext: &[u8], pn: u64, offset: u64) -> Vec<u8> {
    let keys = derive_keys(VERSION_1, dcid);

    let mut payload = Vec::new();
    payload.push(0x06);
    push_varint(&mut payload, offset);
    push_varint(&mut payload, plaintext.len() as u64);
    payload.extend_from_slice(plaintext);

    let mut header = Vec::new();
    header.push(0xc0);
    header.extend_from_slice(&VERSION_1.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0); // scid length
    header.push(0); // token length

    let length = (1 + payload.len() + 16) as u16;
    header.extend_from_slice(&(0x4000u16 | length).to_be_bytes());

    let pn_offset = header.len();
    header.push(pn as u8);

    let mut nonce = keys.iv;
    for i in 0..8 {
        nonce[11 - i] ^= (pn >> (8 * i)) as u8;
    }

    let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &header,
            },
        )
        .unwrap();

    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    let sample_start = pn_offset + 4;
    let sample = &packet[sample_start..sample_start + 16];
    let hp = Aes128::new_from_slice(&keys.hp).unwrap();
    let mut mask = aes::Block::clone_from_slice(sample);
    hp.encrypt_block(&mut mask);

    packet[0] ^= mask[0] & 0x0f;
    packet[pn_offset] ^= mask[1];

    packet
}

fn free_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.local_addr().unwrap().port()
}

async fn spawn_backend(id: u8, expect: usize) -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];

        for i in 0..expect {
            let Ok(Ok((n, peer))) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await else {
                break;
            };

            got.push(buf[..n].to_vec());

            if i == 0 {
                sock.send_to(&[id], peer).await.unwrap();
            }
        }

        got
    });

    (addr, handle)
}

fn endpoint(port: u16, default: SocketAddr, route: SocketAddr) -> Endpoint {
    Endpoint {
        laddr: format!("127.0.0.1:{}", port).parse().unwrap(),
        raddr: RemoteAddr::SocketAddr(default),
        bind_opts: BindOpts::default(),
        conn_opts: ConnectOpts::default(),
        extra_raddrs: Vec::new(),
        sni: Some(SniRoutes {
            routes: vec![SniRoute {
                server_name: "a.test".to_string(),
                raddr: RemoteAddr::SocketAddr(route),
                resolver: None,
                bind_interface: None,
                bind_address: None,
            }],
            timeout: 5,
        }),
    }
}

async fn query(realm: SocketAddr, payloads: &[Vec<u8>]) -> u8 {
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    for payload in payloads {
        cli.send_to(payload, realm).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut buf = [0u8; 8];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(n, 1);
    buf[0]
}

#[tokio::test]
async fn quic_sni_routing() {
    let _ = env_logger::try_init();

    let (route_addr, route_backend) = spawn_backend(1, 1).await;
    let (default_addr, default_backend) = spawn_backend(2, 1).await;

    let port = free_port();
    tokio::spawn(run_udp(endpoint(port, default_addr, route_addr)));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let realm: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8];

    // matched route
    let hello = client_hello("a.test");
    let packet = build_initial(&dcid, &hello, 2, 0);
    assert_eq!(query(realm, std::slice::from_ref(&packet)).await, 1);
    assert_eq!(route_backend.await.unwrap(), vec![packet]);

    // unknown sni falls back to the default route
    let hello = client_hello("b.test");
    let packet = build_initial(&dcid, &hello, 2, 0);
    assert_eq!(query(realm, std::slice::from_ref(&packet)).await, 2);
    assert_eq!(default_backend.await.unwrap(), vec![packet]);
}

#[tokio::test]
async fn quic_sni_route_sticky_after_idle() {
    let _ = env_logger::try_init();

    let route_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let route_addr = route_sock.local_addr().unwrap();

    // backends reply with their id and record every datagram
    let route_backend = tokio::spawn(async move {
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];

        for _ in 0..2 {
            let Ok(Ok((n, peer))) = tokio::time::timeout(Duration::from_secs(5), route_sock.recv_from(&mut buf)).await
            else {
                break;
            };

            got.push(buf[..n].to_vec());
            route_sock.send_to(&[1], peer).await.unwrap();
        }

        got
    });

    let default_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let default_addr = default_sock.local_addr().unwrap();

    let port = free_port();
    let mut ep = endpoint(port, default_addr, route_addr);
    // associations expire after 1s of client silence
    ep.conn_opts.udp_idle_timeout = 1;

    tokio::spawn(run_udp(ep));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let realm: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut resp = [0u8; 8];

    let dcid = [5u8, 5, 5, 5, 5, 5, 5, 5];
    let hello = client_hello("a.test");
    let packet = build_initial(&dcid, &hello, 2, 0);

    cli.send_to(&packet, realm).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&resp[..n], &[1]);

    // let the association expire
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // short header packets cannot be sniffed: the cached route must be reused
    let short = vec![0x40u8; 64];
    cli.send_to(&short, realm).await.unwrap();

    let (n, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&resp[..n], &[1]);

    let got = route_backend.await.unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0], packet);
    assert_eq!(got[1], short);

    // the default backend must never be used
    let mut buf = [0u8; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), default_sock.recv_from(&mut buf))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn quic_sni_association_kept_alive_by_client() {
    let _ = env_logger::try_init();

    let route_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let route_addr = route_sock.local_addr().unwrap();

    let route_backend = tokio::spawn(async move {
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];

        for _ in 0..5 {
            let Ok(Ok((n, peer))) = tokio::time::timeout(Duration::from_secs(5), route_sock.recv_from(&mut buf)).await
            else {
                break;
            };

            got.push((peer, buf[..n].to_vec()));
            route_sock.send_to(&[1], peer).await.unwrap();
        }

        got
    });

    let port = free_port();
    let mut ep = endpoint(port, route_addr, route_addr);
    ep.conn_opts.udp_idle_timeout = 1;

    tokio::spawn(run_udp(ep));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let realm: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut resp = [0u8; 8];

    let dcid = [6u8, 6, 6, 6, 6, 6, 6, 6];
    let hello = client_hello("a.test");
    let packet = build_initial(&dcid, &hello, 2, 0);

    cli.send_to(&packet, realm).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&resp[..n], &[1]);

    // keep the client active longer than the idle timeout
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        cli.send_to(&vec![0x40u8; 32], realm).await.unwrap();

        let (n, _) = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut resp))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&resp[..n], &[1]);
    }

    let got = route_backend.await.unwrap();
    assert_eq!(got.len(), 5);

    // the same association (same source port) is reused, no reconnect
    let expected = got[0].0;
    assert!(got.iter().all(|(peer, _)| *peer == expected));
}

#[cfg(feature = "proxy")]
#[tokio::test]
async fn quic_sni_send_proxy_all_buffered() {
    use realm_core::endpoint::ProxyOpts;

    let _ = env_logger::try_init();

    let (route_addr, backend) = spawn_backend(1, 2).await;

    let port = free_port();
    let mut ep = endpoint(port, route_addr, route_addr);
    ep.conn_opts.proxy_opts = ProxyOpts {
        send_proxy: true,
        ..Default::default()
    };

    tokio::spawn(run_udp(ep));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let realm: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let dcid = [7u8, 7, 7, 7, 7, 7, 7, 7];
    let hello = client_hello("a.test");
    let split = 20;
    let first = build_initial(&dcid, &hello[..split], 2, 0);
    let second = build_initial(&dcid, &hello[split..], 3, split as u64);

    // no reply before both buffered datagrams are flushed, so both carry the header
    cli.send_to(&first, realm).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    cli.send_to(&second, realm).await.unwrap();

    let mut resp = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut resp))
        .await
        .unwrap()
        .unwrap();

    let got = backend.await.unwrap();
    assert_eq!(got.len(), 2);

    for (i, datagram) in got.iter().enumerate() {
        assert_eq!(&datagram[..12], b"\r\n\r\n\x00\r\nQUIT\n");
        assert_eq!(datagram[12], 0x21);
        assert_eq!(datagram[13], 0x12);
        assert_eq!(&datagram[28..], &[&first, &second][i][..]);
    }
}

#[cfg(feature = "proxy")]
#[tokio::test]
async fn quic_sni_with_send_proxy() {
    use realm_core::endpoint::ProxyOpts;

    let _ = env_logger::try_init();

    let (route_addr, backend) = spawn_backend(1, 1).await;

    let port = free_port();
    let mut ep = endpoint(port, route_addr, route_addr);
    ep.conn_opts.proxy_opts = ProxyOpts {
        send_proxy: true,
        ..Default::default()
    };

    tokio::spawn(run_udp(ep));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let realm: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let dcid = [3u8, 1, 4, 1, 5, 9, 2, 6];

    let hello = client_hello("a.test");
    let packet = build_initial(&dcid, &hello, 2, 0);
    assert_eq!(query(realm, std::slice::from_ref(&packet)).await, 1);

    let got = backend.await.unwrap();
    assert_eq!(got.len(), 1);

    // proxied datagram = proxy-v2 header + original quic initial packet
    let datagram = &got[0];
    assert_eq!(&datagram[..12], b"\r\n\r\n\x00\r\nQUIT\n");
    assert_eq!(datagram[12], 0x21);
    assert_eq!(datagram[13], 0x12); // AF_INET | DGRAM
    assert_eq!(&datagram[28..], &packet[..]);
}

#[tokio::test]
async fn quic_sni_fragmented() {
    let _ = env_logger::try_init();

    let (route_addr, route_backend) = spawn_backend(1, 2).await;

    let port = free_port();
    tokio::spawn(run_udp(endpoint(port, route_addr, route_addr)));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let realm: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let dcid = [9u8, 8, 7, 6, 5, 4, 3, 2];

    let hello = client_hello("a.test");
    let split = 20;
    let first = build_initial(&dcid, &hello[..split], 2, 0);
    let second = build_initial(&dcid, &hello[split..], 3, split as u64);

    assert_eq!(query(realm, &[first.clone(), second.clone()]).await, 1);

    let got = route_backend.await.unwrap();
    assert_eq!(got, vec![first, second]);
}
