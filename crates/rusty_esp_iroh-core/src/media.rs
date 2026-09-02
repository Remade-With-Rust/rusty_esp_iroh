//! `janus/media/1`: a subscriber opens the connection, sends one
//! [`Subscribe`] frame on a bi-stream, and the device answers with packets —
//! each a fixed 24-byte [`PacketHeader`] followed by the payload — as QUIC
//! datagrams when they fit [`crate::alpn::MAX_MEDIA_DATAGRAM`] and as
//! uni-streams otherwise. The header is what `rusty_esp_video`'s and
//! `rusty_esp_audio`'s packets already carry: a sequence number, the
//! device-monotonic timestamp, a codec tag and flags.

use rusty_esp_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// What the subscriber wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscribe {
    /// Codec tag, e.g. `*b"mjpg"`, `*b"h264"`, `*b"s16l"`, `*b"flac"`; `*b"any "` for the device's default.
    pub codec: [u8; 4],
    /// Frame-rate cap (0 = the device's default).
    pub max_fps: u16,
    /// Bit-rate cap (0 = no cap).
    pub max_kbps: u32,
}

/// The wire header on every media packet.
pub const HEADER_LEN: usize = 24;
/// Magic that starts every header.
pub const MAGIC: [u8; 2] = *b"JM";
/// Flag: this packet is a keyframe (or an audio block, always decodable).
pub const FLAG_KEY: u8 = 1;
/// Flag: this packet is a fragment; the last fragment carries [`FLAG_LAST`].
pub const FLAG_FRAGMENT: u8 = 2;
/// Flag: last fragment of a fragmented packet.
pub const FLAG_LAST: u8 = 4;

/// The 24 bytes before the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Per-stream sequence number; gaps are loss.
    pub seq: u32,
    /// Device-monotonic microseconds.
    pub timestamp_us: u64,
    /// Codec tag.
    pub codec: [u8; 4],
    /// [`FLAG_KEY`] | [`FLAG_FRAGMENT`] | [`FLAG_LAST`].
    pub flags: u8,
    /// Payload bytes following the header.
    pub len: u32,
}

impl PacketHeader {
    /// `JM 0x01 flags seq_be32 ts_be64 codec[4] len_be32`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < HEADER_LEN {
            return Err(Error::BufferTooSmall { needed: HEADER_LEN });
        }
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = 1;
        out[3] = self.flags;
        out[4..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8..16].copy_from_slice(&self.timestamp_us.to_be_bytes());
        out[16..20].copy_from_slice(&self.codec);
        out[20..24].copy_from_slice(&self.len.to_be_bytes());
        Ok(HEADER_LEN)
    }

    /// Parse the first [`HEADER_LEN`] bytes of a packet.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::InvalidFormat);
        }
        if bytes[0..2] != MAGIC || bytes[2] != 1 {
            return Err(Error::InvalidFormat);
        }
        let mut codec = [0u8; 4];
        codec.copy_from_slice(&bytes[16..20]);
        Ok(PacketHeader {
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            timestamp_us: u64::from_be_bytes(
                bytes[8..16].try_into().map_err(|_| Error::InvalidFormat)?,
            ),
            codec,
            flags: bytes[3],
            len: u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        })
    }
}

/// Counts what a receiver sees: packets, bytes, and gaps in `seq`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LossCounter {
    /// Packets received.
    pub received: u64,
    /// Payload bytes received.
    pub bytes: u64,
    /// Sequence numbers skipped (each a lost packet).
    pub lost: u64,
    /// Packets that arrived with an older sequence than already seen.
    pub reordered: u64,
    next: Option<u32>,
}

impl LossCounter {
    /// Account for one received header.
    pub fn observe(&mut self, h: &PacketHeader) {
        self.received += 1;
        self.bytes += u64::from(h.len);
        match self.next {
            None => self.next = Some(h.seq.wrapping_add(1)),
            Some(expected) => {
                let gap = h.seq.wrapping_sub(expected);
                if gap == 0 {
                    self.next = Some(h.seq.wrapping_add(1));
                } else if gap < u32::MAX / 2 {
                    self.lost += u64::from(gap);
                    self.next = Some(h.seq.wrapping_add(1));
                } else {
                    self.reordered += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_and_subscribe_encodes() {
        let h = PacketHeader {
            seq: 0xDEAD_BEEF,
            timestamp_us: 1 << 40,
            codec: *b"mjpg",
            flags: FLAG_KEY | FLAG_LAST,
            len: 15_000,
        };
        let mut buf = [0u8; HEADER_LEN];
        assert_eq!(h.encode(&mut buf).unwrap(), HEADER_LEN);
        assert_eq!(&buf[..2], b"JM");
        assert_eq!(PacketHeader::parse(&buf).unwrap(), h);
        buf[2] = 2;
        assert_eq!(PacketHeader::parse(&buf).err(), Some(Error::InvalidFormat));
        let s = Subscribe {
            codec: *b"s16l",
            max_fps: 0,
            max_kbps: 256,
        };
        let f = crate::rpc::encode_frame(&s).unwrap();
        let (back, _): (Subscribe, usize) = crate::rpc::decode_frame(&f).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn loss_counter_sees_gaps_and_reorders() {
        let mut c = LossCounter::default();
        let mk = |seq| PacketHeader {
            seq,
            timestamp_us: 0,
            codec: *b"test",
            flags: 0,
            len: 10,
        };
        for seq in [0, 1, 2, 5, 6, 4, 7] {
            c.observe(&mk(seq));
        }
        assert_eq!(c.received, 7);
        assert_eq!(c.lost, 2); // 3 and 4 skipped at first…
        assert_eq!(c.reordered, 1); // …then 4 arrived late.
        assert_eq!(c.bytes, 70);
    }
}
