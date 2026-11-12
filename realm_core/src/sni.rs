//! TLS ClientHello sniffing and sni-based routing.

use std::io::{Result, Error, ErrorKind};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::dns::Resolver;
use crate::endpoint::RemoteAddr;
use crate::time::timeoutfut;

/// Max bytes read while sniffing a tls client hello.
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Default timeout (in seconds) of client hello sniffing.
pub const DEFAULT_TIMEOUT: usize = 5;

/// A single sni route.
#[derive(Debug, Clone)]
pub struct SniRoute {
    /// Server name to match, in lowercase.
    pub server_name: String,
    /// Remote address of this route.
    pub raddr: RemoteAddr,
    /// Dns resolver of this route, fallback to the endpoint one if none.
    pub resolver: Option<Resolver>,
}

/// Sni routes of an endpoint.
#[derive(Debug, Clone)]
pub struct SniRoutes {
    pub routes: Vec<SniRoute>,
    /// Timeout of sniffing, 0 means never timeout.
    pub timeout: usize,
}

impl SniRoutes {
    /// Find a route by server name: exact match first, then wildcard (`*.example.com`).
    pub fn find(&self, server_name: &str) -> Option<&SniRoute> {
        let name = server_name.to_ascii_lowercase();

        if let Some(route) = self.routes.iter().find(|route| route.server_name == name) {
            return Some(route);
        }

        self.routes
            .iter()
            .find(|route| wildcard_match(&route.server_name, &name))
    }
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    let suffix = match pattern.strip_prefix("*.") {
        Some(suffix) => suffix,
        None => match pattern.strip_prefix('.') {
            Some(suffix) => suffix,
            None => return false,
        },
    };

    name.len() > suffix.len() && name.ends_with(suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
}

/// Result of sniffing a connection.
#[derive(Debug)]
pub struct Sniffed {
    /// Server name of the client hello, if any.
    pub server_name: Option<String>,
    /// Bytes already read from the client, must be replayed to the remote.
    pub prefix: Vec<u8>,
}

/// Read (and consume) a tls client hello, to extract the server name.
pub async fn sniff(stream: &mut TcpStream, timeout: usize) -> Result<Sniffed> {
    let fut = async {
        let mut prefix = Vec::with_capacity(2048);
        let mut buf = [0u8; 2048];

        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "client closed before client hello",
                ));
            }

            prefix.extend_from_slice(&buf[..n]);

            match parse(&prefix) {
                Parsed::Complete(server_name) => return Ok(Sniffed { server_name, prefix }),
                Parsed::NotTls => {
                    return Ok(Sniffed {
                        server_name: None,
                        prefix,
                    })
                }
                Parsed::Incomplete => {
                    if prefix.len() >= MAX_CLIENT_HELLO {
                        return Err(Error::new(ErrorKind::InvalidData, "client hello too large"));
                    }
                }
            }
        }
    };

    timeoutfut(fut, timeout).await?
}

enum Parsed {
    Complete(Option<String>),
    Incomplete,
    NotTls,
}

fn parse(buf: &[u8]) -> Parsed {
    // tls record header: content type(1) + version(2) + length(2)
    if buf.len() < 5 {
        return Parsed::Incomplete;
    }
    if buf[0] != 0x16 {
        return Parsed::NotTls;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Parsed::Incomplete;
    }

    let record = &buf[5..5 + record_len];
    // handshake header: type(1) + length(3)
    if record.len() < 4 || record[0] != 0x01 {
        return Parsed::NotTls;
    }

    let msg_len = u32::from_be_bytes([0, record[1], record[2], record[3]]) as usize;
    // fragmented client hello, fallback to the default route
    if msg_len + 4 > record_len {
        return Parsed::NotTls;
    }

    match parse_handshake(&record[..4 + msg_len]) {
        HandshakeParsed::Complete(server_name) => Parsed::Complete(server_name),
        HandshakeParsed::Incomplete => Parsed::Incomplete,
        HandshakeParsed::NotTls => Parsed::NotTls,
    }
}

/// Result of parsing a tls handshake stream.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HandshakeParsed {
    Complete(Option<String>),
    Incomplete,
    NotTls,
}

/// Parse a client hello from a raw tls handshake stream (record layer removed,
/// as carried by quic crypto frames).
pub(crate) fn parse_handshake(stream: &[u8]) -> HandshakeParsed {
    // handshake header: type(1) + length(3)
    if stream.len() < 4 {
        return HandshakeParsed::Incomplete;
    }

    if stream[0] != 0x01 {
        return HandshakeParsed::NotTls;
    }

    let msg_len = u32::from_be_bytes([0, stream[1], stream[2], stream[3]]) as usize;
    if msg_len > MAX_CLIENT_HELLO {
        return HandshakeParsed::NotTls;
    }

    if stream.len() < 4 + msg_len {
        return HandshakeParsed::Incomplete;
    }

    match parse_client_hello(&stream[4..4 + msg_len]) {
        Some(server_name) => HandshakeParsed::Complete(server_name),
        None => HandshakeParsed::NotTls,
    }
}

fn parse_client_hello(body: &[u8]) -> Option<Option<String>> {
    let mut r = Reader::new(body);

    r.take(2)?; // legacy version
    r.take(32)?; // random

    let session_id_len = r.take_u8()? as usize;
    r.take(session_id_len)?;

    let cipher_suites_len = r.take_u16()? as usize;
    r.take(cipher_suites_len)?;

    let compression_len = r.take_u8()? as usize;
    r.take(compression_len)?;

    let extensions_len = match r.take_u16() {
        Some(len) => len as usize,
        // no extensions at all
        None => return Some(None),
    };
    let extensions = r.take(extensions_len)?;

    let mut e = Reader::new(extensions);
    while e.remaining() >= 4 {
        let ext_type = e.take_u16()?;
        let ext_len = e.take_u16()? as usize;
        let ext = e.take(ext_len)?;

        // server name indication
        if ext_type == 0x0000 {
            return Some(parse_server_name(ext));
        }
    }

    Some(None)
}

fn parse_server_name(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);

    r.take_u16()?; // server name list length

    while r.remaining() >= 3 {
        let name_type = r.take_u8()?;
        let name_len = r.take_u16()? as usize;
        let name = r.take(name_len)?;

        // host_name
        if name_type == 0 {
            return std::str::from_utf8(name).ok().map(|x| x.to_string());
        }
    }

    None
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn take_u8(&mut self) -> Option<u8> {
        self.take(1).map(|x| x[0])
    }

    fn take_u16(&mut self) -> Option<u16> {
        self.take(2).map(|x| u16::from_be_bytes([x[0], x[1]]))
    }
}

#[cfg(test)]
pub(crate) fn client_hello_handshake(server_name: Option<&str>) -> Vec<u8> {
    let mut exts = Vec::new();

    if let Some(name) = server_name {
        let name = name.as_bytes();

        let mut list = Vec::new();
        list.push(0u8); // host_name
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);

        let mut ext = Vec::new();
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);
    }

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
    handshake
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(server_name: Option<&str>) -> Vec<u8> {
        let handshake = client_hello_handshake(server_name);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parse_server_name() {
        assert!(matches!(
            parse(&client_hello(Some("example.com"))),
            Parsed::Complete(Some(name)) if name == "example.com"
        ));

        assert!(matches!(parse(&client_hello(None)), Parsed::Complete(None)));
    }

    #[test]
    fn parse_incomplete_and_not_tls() {
        assert!(matches!(parse(&[]), Parsed::Incomplete));

        let hello = client_hello(Some("example.com"));
        assert!(matches!(parse(&hello[..hello.len() - 1]), Parsed::Incomplete));

        assert!(matches!(parse(b"GET / HTTP/1.1\r\n"), Parsed::NotTls));
    }

    #[test]
    fn route_matching() {
        let routes = SniRoutes {
            routes: vec![
                SniRoute {
                    server_name: "a.example.com".to_string(),
                    raddr: RemoteAddr::DomainName("a.test".into(), 443),
                    resolver: None,
                },
                SniRoute {
                    server_name: "*.example.org".to_string(),
                    raddr: RemoteAddr::DomainName("b.test".into(), 443),
                    resolver: None,
                },
            ],
            timeout: 5,
        };

        assert_eq!(
            routes.find("A.Example.com").map(|x| &x.server_name),
            Some(&"a.example.com".to_string())
        );
        assert_eq!(
            routes.find("x.example.org").map(|x| &x.server_name),
            Some(&"*.example.org".to_string())
        );
        assert!(routes.find("example.org").is_none());
        assert!(routes.find("unknown.test").is_none());
    }
}
