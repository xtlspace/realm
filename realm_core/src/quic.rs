//! QUIC initial packet sniffing, to extract the tls server name.

use std::collections::BTreeMap;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::sni::{self, HandshakeParsed, MAX_CLIENT_HELLO};

const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;

const MAX_ACK_RANGES: u64 = 256;

/// Result of sniffing a quic initial.
#[derive(Debug, PartialEq, Eq)]
pub enum Sniff {
    /// Got the server name, `None` means the client hello carries no sni.
    Complete(Option<String>),
    /// Need more datagrams to complete the client hello.
    Pending,
    /// Not a supported quic initial.
    NotQuic,
}

/// Sniff server name from quic initial packets of a single connection.
#[derive(Default)]
pub struct Sniffer {
    dcid: Vec<u8>,
    crypto: CryptoAssembler,
}

impl Sniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one udp datagram, which may contain coalesced packets.
    pub fn feed(&mut self, datagram: &[u8]) -> Sniff {
        self.feed_inner(datagram).unwrap_or(Sniff::NotQuic)
    }

    fn feed_inner(&mut self, datagram: &[u8]) -> Option<Sniff> {
        // short header packet or garbage
        if datagram.len() < 7 || datagram[0] & 0x80 == 0 {
            return Some(Sniff::NotQuic);
        }

        let mut pos = 0;
        let mut saw_initial = false;

        while pos < datagram.len() {
            let first = datagram[pos];
            // coalesced short header packet, nothing more to sniff
            if first & 0x80 == 0 {
                break;
            }

            let version = u32::from_be_bytes(datagram.get(pos + 1..pos + 5)?.try_into().ok()?);
            // version negotiation packet
            if version == 0 {
                return Some(Sniff::NotQuic);
            }

            let packet_type = (first & 0x30) >> 4;

            let mut p = pos + 5;

            let dcid_len = *datagram.get(p)? as usize;
            p += 1;
            let dcid = datagram.get(p..p.checked_add(dcid_len)?)?;
            p += dcid_len;

            let scid_len = *datagram.get(p)? as usize;
            p += 1;
            p = p.checked_add(scid_len)?;
            if p > datagram.len() {
                return Some(Sniff::NotQuic);
            }

            // retry packet, no length field
            if packet_type == 3 {
                return Some(Sniff::NotQuic);
            }

            // token, only present in initial packets
            if packet_type == 0 {
                let token_len = get_varint(datagram, &mut p)? as usize;
                p = p.checked_add(token_len)?;
                if p > datagram.len() {
                    return Some(Sniff::NotQuic);
                }
            }

            let length = get_varint(datagram, &mut p)? as usize;
            let pn_offset = p;
            let end = pn_offset.checked_add(length)?;
            if end > datagram.len() {
                return Some(Sniff::NotQuic);
            }

            if packet_type == 0 && initial_salt(version).is_some() {
                saw_initial = true;

                // retry changes the dcid, so the crypto stream must be reset
                if self.dcid != dcid {
                    self.dcid.clear();
                    self.dcid.extend_from_slice(dcid);
                    self.crypto = CryptoAssembler::default();
                }

                if let Some(plaintext) = decrypt_initial(datagram, pos, pn_offset, end, version, dcid) {
                    self.parse_frames(&plaintext);

                    match self.check() {
                        Sniff::Pending => {}
                        result => return Some(result),
                    }
                }
            }

            pos = end;
        }

        if saw_initial {
            Some(Sniff::Pending)
        } else {
            Some(Sniff::NotQuic)
        }
    }

    fn parse_frames(&mut self, payload: &[u8]) {
        let mut pos = 0;

        while pos < payload.len() {
            let Some(frame) = get_varint(payload, &mut pos) else {
                return;
            };

            match frame {
                // padding / ping
                0x00 | 0x01 => {}

                // ack / ack with ecn
                0x02 | 0x03 => {
                    let (Some(_), Some(_), Some(count), Some(_)) = (
                        get_varint(payload, &mut pos),
                        get_varint(payload, &mut pos),
                        get_varint(payload, &mut pos),
                        get_varint(payload, &mut pos),
                    ) else {
                        return;
                    };

                    if count > MAX_ACK_RANGES {
                        return;
                    }

                    for _ in 0..count * 2 {
                        if get_varint(payload, &mut pos).is_none() {
                            return;
                        }
                    }

                    if frame == 0x03 {
                        for _ in 0..3 {
                            if get_varint(payload, &mut pos).is_none() {
                                return;
                            }
                        }
                    }
                }

                // crypto
                0x06 => {
                    let (Some(offset), Some(len)) = (get_varint(payload, &mut pos), get_varint(payload, &mut pos))
                    else {
                        return;
                    };

                    let Some(end) = pos.checked_add(len as usize) else {
                        return;
                    };

                    let Some(data) = payload.get(pos..end) else {
                        return;
                    };

                    pos = end;
                    self.crypto.insert(offset, data);
                }

                // connection close, nothing else to do
                0x1c | 0x1d => return,

                // frames we do not care about
                _ => return,
            }
        }
    }

    fn check(&self) -> Sniff {
        let buf = self.crypto.contiguous();

        if buf.len() > MAX_CLIENT_HELLO {
            return Sniff::NotQuic;
        }

        match sni::parse_handshake(buf) {
            HandshakeParsed::Complete(server_name) => Sniff::Complete(server_name),
            HandshakeParsed::Incomplete => Sniff::Pending,
            HandshakeParsed::NotTls => Sniff::NotQuic,
        }
    }
}

struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn initial_salt(version: u32) -> Option<&'static [u8]> {
    match version {
        VERSION_1 => Some(&[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
            0x7f, 0x0a,
        ]),
        VERSION_2 => Some(&[
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd,
            0x2e, 0xd9,
        ]),
        _ => None,
    }
}

fn initial_labels(version: u32) -> (&'static str, &'static str, &'static str) {
    if version == VERSION_2 {
        ("quicv2 key", "quicv2 iv", "quicv2 hp")
    } else {
        ("quic key", "quic iv", "quic hp")
    }
}

fn hkdf_expand_label(secret: &[u8], label: &str, out: &mut [u8]) -> Option<()> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).ok()?;

    let label = format!("tls13 {}", label);

    let mut info = Vec::with_capacity(4 + label.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);

    hkdf.expand(&info, out).ok()?;
    Some(())
}

fn derive_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let salt = initial_salt(version)?;

    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), dcid);

    let mut client_secret = [0u8; 32];
    hkdf_expand_label(prk.as_slice(), "client in", &mut client_secret)?;

    let (key_label, iv_label, hp_label) = initial_labels(version);

    let mut keys = InitialKeys {
        key: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };

    hkdf_expand_label(&client_secret, key_label, &mut keys.key)?;
    hkdf_expand_label(&client_secret, iv_label, &mut keys.iv)?;
    hkdf_expand_label(&client_secret, hp_label, &mut keys.hp)?;

    Some(keys)
}

fn decrypt_initial(
    datagram: &[u8],
    start: usize,
    pn_offset: usize,
    end: usize,
    version: u32,
    dcid: &[u8],
) -> Option<Vec<u8>> {
    let keys = derive_keys(version, dcid)?;

    // header protection sample
    let sample_start = pn_offset + 4;
    if sample_start + 16 > end {
        return None;
    }
    let sample = &datagram[sample_start..sample_start + 16];

    let hp = Aes128::new_from_slice(&keys.hp).ok()?;
    let mut mask = aes::Block::clone_from_slice(sample);
    hp.encrypt_block(&mut mask);

    let first = datagram[start] ^ (mask[0] & 0x0f);
    let pn_len = ((first & 0x03) + 1) as usize;

    if pn_offset + pn_len > end {
        return None;
    }

    let mut pn = 0u64;
    for i in 0..pn_len {
        pn = (pn << 8) | ((datagram[pn_offset + i] ^ mask[1 + i]) as u64);
    }

    let mut nonce = keys.iv;
    for i in 0..8 {
        nonce[11 - i] ^= (pn >> (8 * i)) as u8;
    }

    let mut aad = datagram[start..pn_offset + pn_len].to_vec();
    aad[0] = first;
    for i in 0..pn_len {
        aad[pn_offset - start + i] = (pn >> (8 * (pn_len - 1 - i))) as u8;
    }

    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let nonce = Nonce::from_slice(&nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &datagram[pn_offset + pn_len..end],
                aad: &aad,
            },
        )
        .ok()
}

fn get_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);

    if *pos + len > buf.len() {
        return None;
    }

    let mut value = (first & 0x3f) as u64;
    for &byte in &buf[*pos + 1..*pos + len] {
        value = (value << 8) | byte as u64;
    }

    *pos += len;
    Some(value)
}

/// Reassemble the crypto stream from out-of-order crypto frames.
#[derive(Default)]
struct CryptoAssembler {
    buf: Vec<u8>,
    pending: BTreeMap<u64, Vec<u8>>,
}

impl CryptoAssembler {
    fn insert(&mut self, offset: u64, data: &[u8]) {
        if offset <= self.buf.len() as u64 {
            let skip = (self.buf.len() as u64 - offset) as usize;
            if skip < data.len() {
                self.buf.extend_from_slice(&data[skip..]);
            }
        } else {
            self.pending.entry(offset).or_default().extend_from_slice(data);
        }

        while let Some(data) = self.pending.remove(&(self.buf.len() as u64)) {
            self.buf.extend_from_slice(&data);
        }
    }

    fn contiguous(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sni::client_hello_handshake;

    fn push_varint(out: &mut Vec<u8>, value: u64) {
        if value < 64 {
            out.push(value as u8);
        } else if value < 16384 {
            out.extend_from_slice(&(0x4000u16 | value as u16).to_be_bytes());
        } else {
            out.extend_from_slice(&(0x8000_0000u32 | value as u32).to_be_bytes());
        }
    }

    fn build_initial(version: u32, dcid: &[u8], plaintext: &[u8], pn: u64, offset: u64) -> Vec<u8> {
        let keys = derive_keys(version, dcid).unwrap();

        let mut payload = Vec::new();
        // crypto frame: type, offset, length, data
        payload.push(0x06);
        push_varint(&mut payload, offset);
        push_varint(&mut payload, plaintext.len() as u64);
        payload.extend_from_slice(plaintext);

        let mut header = Vec::new();
        // long header, initial, 1-byte packet number
        header.push(0xc0);
        header.extend_from_slice(&version.to_be_bytes());
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

    #[test]
    fn rfc9001_client_initial_keys() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_keys(VERSION_1, &dcid).unwrap();

        assert_eq!(
            keys.key,
            [0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d]
        );
        assert_eq!(
            keys.iv,
            [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]
        );
        assert_eq!(
            keys.hp,
            [0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2]
        );
    }

    #[test]
    fn sniff_v1_and_v2() {
        for version in [VERSION_1, VERSION_2] {
            let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
            let hello = client_hello_handshake(Some("a.test"));
            let datagram = build_initial(version, &dcid, &hello, 2, 0);

            let mut sniffer = Sniffer::new();
            assert_eq!(sniffer.feed(&datagram), Sniff::Complete(Some("a.test".to_string())));
        }
    }

    #[test]
    fn sniff_fragmented_client_hello() {
        let dcid = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let hello = client_hello_handshake(Some("frag.test"));

        let split = 20;
        let first = build_initial(VERSION_1, &dcid, &hello[..split], 2, 0);
        let second = build_initial(VERSION_1, &dcid, &hello[split..], 3, split as u64);

        let mut sniffer = Sniffer::new();
        assert_eq!(sniffer.feed(&first), Sniff::Pending);
        assert_eq!(sniffer.feed(&second), Sniff::Complete(Some("frag.test".to_string())));
    }

    #[test]
    fn sniff_not_quic() {
        let mut sniffer = Sniffer::new();
        assert_eq!(sniffer.feed(b"GET / HTTP/1.1\r\n"), Sniff::NotQuic);

        // short header
        let mut short = vec![0x40u8; 64];
        short[0] = 0x44;
        assert_eq!(sniffer.feed(&short), Sniff::NotQuic);
    }
}
