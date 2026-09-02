//! The protocol names and the frame limits every side agrees on.

/// Liveness: bytes back.
pub const ECHO: &[u8] = b"janus/echo/1";

/// Requests and responses in postcard, one bi-stream per call (see [`crate::rpc`]).
pub const RPC: &[u8] = b"janus/rpc/1";

/// Media packets after a subscribe (see [`crate::media`]).
pub const MEDIA: &[u8] = b"janus/media/1";

/// The home computer's existing OEM sidecar JSON RPC (see [`crate::sidecar`]).
pub const SIDECAR_RPC: &[u8] = b"mata-oem-sidecar/rpc/1";

/// Every ALPN a Janus node accepts, in the order a router registers them.
pub const ALL: [&[u8]; 4] = [ECHO, RPC, MEDIA, SIDECAR_RPC];

/// Largest `janus/rpc/1` frame (length prefix excluded). Adoption blobs and
/// manifests are hundreds of bytes; 64 KiB matches the sidecar's request cap.
pub const MAX_RPC_FRAME: usize = 64 * 1024;

/// Largest sidecar JSON request or reply, as `hardware-deployer-api` caps it.
pub const MAX_SIDECAR_BYTES: usize = 64 * 1024;

/// Largest media packet carried in one QUIC datagram; larger packets go on a
/// uni-stream.
pub const MAX_MEDIA_DATAGRAM: usize = 1200;

/// Largest media packet that travels as one uni stream when it does not fit
/// a datagram: a VGA JPEG is tens of kilobytes and a 720p one can pass a
/// hundred; 256 KiB leaves room without letting a peer ask for the heap.
pub const MAX_MEDIA_PACKET: usize = 256 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpns_are_distinct_ascii_and_versioned() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.is_ascii());
            assert!(a.ends_with(b"/1"), "{:?}", core::str::from_utf8(a));
            for b in &ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(SIDECAR_RPC, b"mata-oem-sidecar/rpc/1");
    }
}
