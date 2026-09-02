//! The rendezvous ticket a device shows as a QR code or prints on serial:
//! how to dial it (iroh endpoint id, optional relay and direct addresses)
//! and who it is (its `did:mata`). No heap; fixed-size fields.
//!
//! Text form: `janus1` followed by lowercase base32 of the binary form, the
//! same style as iroh's own tickets, so it survives a QR code, a chat
//! message and a serial console.
//!
//! Binary form, version 1:
//!
//! ```text
//! 0x01 | flags | endpoint_id[32] | [did[33]] | [relay_len u8, relay] | n_addrs u8 | addrs…
//! flags: bit0 = has DID, bit1 = has relay
//! addr:  0x04 ip[4] port_be[2]   or   0x06 ip[16] port_be[2]
//! ```

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rusty_esp_core::error::{Error, Result};
use rusty_esp_mid_core::did::{Did, PUBKEY_LEN};

use crate::base32;

/// Text prefix.
pub const PREFIX: &str = "janus1";
/// Ticket format version.
pub const VERSION: u8 = 1;
/// Direct addresses a ticket carries at most.
pub const MAX_ADDRS: usize = 4;
/// Longest relay URL a ticket carries.
pub const MAX_RELAY_LEN: usize = 96;
/// Largest binary ticket.
pub const MAX_BINARY_LEN: usize = 2 + 32 + PUBKEY_LEN + 1 + MAX_RELAY_LEN + 1 + MAX_ADDRS * 19;
/// Largest text ticket, prefix included.
pub const MAX_TEXT_LEN: usize = PREFIX.len() + base32::encoded_len(MAX_BINARY_LEN);

const FLAG_DID: u8 = 1;
const FLAG_RELAY: u8 = 2;

/// A rendezvous ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    /// The iroh endpoint id (an ed25519 public key).
    pub endpoint_id: [u8; 32],
    /// The device's DID, when the ticket carries identity.
    pub did: Option<Did>,
    relay: [u8; MAX_RELAY_LEN],
    relay_len: u8,
    addrs: [Option<SocketAddr>; MAX_ADDRS],
}

impl Ticket {
    /// A short ticket: just the endpoint id (needs a relay or discovery to dial).
    #[must_use]
    pub fn short(endpoint_id: [u8; 32]) -> Self {
        Ticket {
            endpoint_id,
            did: None,
            relay: [0; MAX_RELAY_LEN],
            relay_len: 0,
            addrs: [None; MAX_ADDRS],
        }
    }

    /// Attach the device's DID.
    #[must_use]
    pub fn with_did(mut self, did: Did) -> Self {
        self.did = Some(did);
        self
    }

    /// Attach the relay URL (at most [`MAX_RELAY_LEN`] bytes).
    pub fn with_relay(mut self, relay: &str) -> Result<Self> {
        if relay.len() > MAX_RELAY_LEN {
            return Err(Error::InvalidFormat);
        }
        self.relay[..relay.len()].copy_from_slice(relay.as_bytes());
        self.relay_len = relay.len() as u8;
        Ok(self)
    }

    /// Add a direct address; `Err(BufferTooSmall)` when [`MAX_ADDRS`] are set.
    pub fn with_addr(mut self, addr: SocketAddr) -> Result<Self> {
        let slot = self
            .addrs
            .iter_mut()
            .find(|a| a.is_none())
            .ok_or(Error::BufferTooSmall {
                needed: MAX_ADDRS + 1,
            })?;
        *slot = Some(addr);
        Ok(self)
    }

    /// The relay URL, if any.
    #[must_use]
    pub fn relay(&self) -> Option<&str> {
        if self.relay_len == 0 {
            return None;
        }
        core::str::from_utf8(&self.relay[..usize::from(self.relay_len)]).ok()
    }

    /// The direct addresses.
    pub fn addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.addrs.iter().flatten().copied()
    }

    /// Bytes [`encode`](Self::encode) produces.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut n = 2 + 32 + 1;
        if self.did.is_some() {
            n += PUBKEY_LEN;
        }
        if self.relay_len > 0 {
            n += 1 + usize::from(self.relay_len);
        }
        for a in self.addrs.iter().flatten() {
            n += match a {
                SocketAddr::V4(_) => 7,
                SocketAddr::V6(_) => 19,
            };
        }
        n
    }

    /// Binary form into `out`; returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let need = self.encoded_len();
        if out.len() < need {
            return Err(Error::BufferTooSmall { needed: need });
        }
        let mut w = 0usize;
        out[w] = VERSION;
        w += 1;
        let mut flags = 0u8;
        if self.did.is_some() {
            flags |= FLAG_DID;
        }
        if self.relay_len > 0 {
            flags |= FLAG_RELAY;
        }
        out[w] = flags;
        w += 1;
        out[w..w + 32].copy_from_slice(&self.endpoint_id);
        w += 32;
        if let Some(did) = &self.did {
            out[w..w + PUBKEY_LEN].copy_from_slice(did.pubkey());
            w += PUBKEY_LEN;
        }
        if self.relay_len > 0 {
            out[w] = self.relay_len;
            w += 1;
            let n = usize::from(self.relay_len);
            out[w..w + n].copy_from_slice(&self.relay[..n]);
            w += n;
        }
        let count = self.addrs.iter().flatten().count() as u8;
        out[w] = count;
        w += 1;
        for a in self.addrs.iter().flatten() {
            match a {
                SocketAddr::V4(v4) => {
                    out[w] = 4;
                    out[w + 1..w + 5].copy_from_slice(&v4.ip().octets());
                    out[w + 5..w + 7].copy_from_slice(&v4.port().to_be_bytes());
                    w += 7;
                }
                SocketAddr::V6(v6) => {
                    out[w] = 6;
                    out[w + 1..w + 17].copy_from_slice(&v6.ip().octets());
                    out[w + 17..w + 19].copy_from_slice(&v6.port().to_be_bytes());
                    w += 19;
                }
            }
        }
        debug_assert_eq!(w, need);
        Ok(w)
    }

    /// Parse the binary form.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { b: bytes, pos: 0 };
        if r.u8()? != VERSION {
            return Err(Error::Unsupported);
        }
        let flags = r.u8()?;
        if flags & !(FLAG_DID | FLAG_RELAY) != 0 {
            return Err(Error::InvalidFormat);
        }
        let mut endpoint_id = [0u8; 32];
        endpoint_id.copy_from_slice(r.take(32)?);
        let mut t = Ticket::short(endpoint_id);
        if flags & FLAG_DID != 0 {
            t.did = Some(Did::from_pubkey(r.take(PUBKEY_LEN)?)?);
        }
        if flags & FLAG_RELAY != 0 {
            let n = usize::from(r.u8()?);
            if n == 0 || n > MAX_RELAY_LEN {
                return Err(Error::InvalidFormat);
            }
            let s = r.take(n)?;
            core::str::from_utf8(s).map_err(|_| Error::InvalidFormat)?;
            t.relay[..n].copy_from_slice(s);
            t.relay_len = n as u8;
        }
        let count = usize::from(r.u8()?);
        if count > MAX_ADDRS {
            return Err(Error::InvalidFormat);
        }
        for i in 0..count {
            let addr = match r.u8()? {
                4 => {
                    let ip = r.take(4)?;
                    let port = r.take(2)?;
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                        u16::from_be_bytes([port[0], port[1]]),
                    )
                }
                6 => {
                    let ip = r.take(16)?;
                    let port = r.take(2)?;
                    let mut o = [0u8; 16];
                    o.copy_from_slice(ip);
                    SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(o)),
                        u16::from_be_bytes([port[0], port[1]]),
                    )
                }
                _ => return Err(Error::InvalidFormat),
            };
            t.addrs[i] = Some(addr);
        }
        if r.pos != bytes.len() {
            return Err(Error::InvalidFormat);
        }
        Ok(t)
    }

    /// Text form (`janus1…`) into `out`.
    pub fn write_text<'o>(&self, out: &'o mut [u8]) -> Result<&'o str> {
        let mut bin = [0u8; MAX_BINARY_LEN];
        let n = self.encode(&mut bin)?;
        let need = PREFIX.len() + base32::encoded_len(n);
        if out.len() < need {
            return Err(Error::BufferTooSmall { needed: need });
        }
        out[..PREFIX.len()].copy_from_slice(PREFIX.as_bytes());
        base32::encode(&bin[..n], &mut out[PREFIX.len()..])?;
        core::str::from_utf8(&out[..need]).map_err(|_| Error::InvalidFormat)
    }

    /// Parse the text form. Surrounding whitespace is ignored; the base32
    /// part is case-insensitive.
    pub fn parse_text(text: &str) -> Result<Self> {
        let text = text.trim();
        let body = text.strip_prefix(PREFIX).ok_or(Error::InvalidFormat)?;
        if body.len() > base32::encoded_len(MAX_BINARY_LEN) {
            return Err(Error::InvalidFormat);
        }
        let mut bin = [0u8; MAX_BINARY_LEN];
        let n = base32::decode(body, &mut bin)?;
        Self::decode(&bin[..n])
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::InvalidFormat)?;
        let s = self.b.get(self.pos..end).ok_or(Error::InvalidFormat)?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_esp_mid_core::key::DeviceKey;

    fn sample() -> Ticket {
        let key = DeviceKey::from_seed_for_tests("ticket", "janus");
        Ticket::short([7u8; 32])
            .with_did(key.did())
            .with_relay("https://use1-1.relay.n0.iroh-canary.iroh.link./")
            .unwrap()
            .with_addr("192.168.1.42:41641".parse().unwrap())
            .unwrap()
            .with_addr("[fe80::1]:41641".parse().unwrap())
            .unwrap()
    }

    #[test]
    fn binary_and_text_round_trip() {
        let t = sample();
        let mut bin = [0u8; MAX_BINARY_LEN];
        let n = t.encode(&mut bin).unwrap();
        assert_eq!(n, t.encoded_len());
        assert_eq!(n, 2 + 32 + 33 + 1 + 47 + 1 + 7 + 19);
        assert_eq!(Ticket::decode(&bin[..n]).unwrap(), t);
        let mut text = [0u8; MAX_TEXT_LEN];
        let s = t.write_text(&mut text).unwrap();
        assert!(s.starts_with("janus1"));
        assert!(s.len() <= MAX_TEXT_LEN, "{}", s.len());
        let back = Ticket::parse_text(&format!(
            "  {}\n",
            s.to_uppercase().replace("JANUS1", "janus1")
        ))
        .unwrap();
        assert_eq!(back, t);
        assert_eq!(back.relay(), t.relay());
        assert_eq!(back.addrs().count(), 2);
    }

    #[test]
    fn short_ticket_is_forty_bytes_of_text_plus_prefix() {
        let t = Ticket::short([0xAB; 32]);
        let mut text = [0u8; MAX_TEXT_LEN];
        let s = t.write_text(&mut text).unwrap();
        // 35 binary bytes → 56 base32 chars.
        assert_eq!(s.len(), 6 + 56);
        assert_eq!(Ticket::parse_text(s).unwrap(), t);
    }

    #[test]
    fn rejects_bad_versions_flags_and_tails() {
        let t = Ticket::short([1; 32]);
        let mut bin = [0u8; MAX_BINARY_LEN];
        let n = t.encode(&mut bin).unwrap();
        let mut bad = bin;
        bad[0] = 9;
        assert_eq!(Ticket::decode(&bad[..n]).err(), Some(Error::Unsupported));
        bad = bin;
        bad[1] = 0x80;
        assert_eq!(Ticket::decode(&bad[..n]).err(), Some(Error::InvalidFormat));
        assert_eq!(
            Ticket::decode(&bin[..n - 1]).err(),
            Some(Error::InvalidFormat)
        );
        assert_eq!(
            Ticket::parse_text("iroh1abc").err(),
            Some(Error::InvalidFormat)
        );
        assert!(Ticket::short([0; 32]).with_relay(&"x".repeat(97)).is_err());
        let mut full = Ticket::short([0; 32]);
        for _ in 0..MAX_ADDRS {
            full = full.with_addr("1.2.3.4:5".parse().unwrap()).unwrap();
        }
        assert!(full.with_addr("1.2.3.4:6".parse().unwrap()).is_err());
    }
}
