use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use realm_core::endpoint::{BindOpts, ConnectOpts, Endpoint, RemoteAddr};
use realm_core::sni::{SniRoute, SniRoutes};
use realm_core::tcp::run_tcp;

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
    exts.extend_from_slice(&0u16.to_be_bytes()); // server_name
    exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id length
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1); // compression methods length
    body.push(0);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Spawn a backend which reads until `payload` then replies with `id`.
async fn spawn_backend(id: u8) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = lis.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let (mut sock, _) = lis.accept().await.unwrap();

        let mut buf = vec![0u8; 4096];
        let mut received = Vec::new();

        loop {
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            if received.ends_with(b"payload") {
                break;
            }
        }

        sock.write_all(&[id]).await.unwrap();
        received
    });

    (addr, handle)
}

async fn relaying(port: u16) -> TcpStream {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(&client_hello("a.test")).await.unwrap();
    sock.write_all(b"payload").await.unwrap();
    sock
}

async fn recv_id(sock: &mut TcpStream) -> u8 {
    let mut resp = [0u8; 1];
    sock.read_exact(&mut resp).await.unwrap();
    resp[0]
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
            }],
            timeout: 5,
        }),
    }
}

#[tokio::test]
async fn sni_routing() {
    let _ = env_logger::try_init();

    let (route_addr, route_backend) = spawn_backend(1).await;
    let (default_addr, default_backend) = spawn_backend(2).await;

    let port = free_port();
    tokio::spawn(run_tcp(endpoint(port, default_addr, route_addr)));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // matched route
    let mut sock = relaying(port).await;
    assert_eq!(recv_id(&mut sock).await, 1);

    let mut expected = client_hello("a.test");
    expected.extend_from_slice(b"payload");
    assert_eq!(route_backend.await.unwrap(), expected);

    // unknown sni falls back to the default route
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(&client_hello("b.test")).await.unwrap();
    sock.write_all(b"payload").await.unwrap();
    assert_eq!(recv_id(&mut sock).await, 2);

    let mut expected = client_hello("b.test");
    expected.extend_from_slice(b"payload");
    assert_eq!(default_backend.await.unwrap(), expected);
}

#[tokio::test]
async fn sni_fragmented_client_hello() {
    let _ = env_logger::try_init();

    let (route_addr, route_backend) = spawn_backend(1).await;

    let port = free_port();
    tokio::spawn(run_tcp(endpoint(port, route_addr, route_addr)));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let hello = client_hello("a.test");

    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(&hello[..10]).await.unwrap();
    sock.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    sock.write_all(&hello[10..]).await.unwrap();
    sock.write_all(b"payload").await.unwrap();

    assert_eq!(recv_id(&mut sock).await, 1);
    assert_eq!(route_backend.await.unwrap(), [hello, b"payload".to_vec()].concat());
}
