//! Real MJPEG for `janus/media/1`.
//!
//! Two [`MediaSource`]s that carry JPEG frames instead of a test pattern:
//!
//! - [`DirSource`]: every `.jpg` in a directory, in name order, looped at a
//!   fixed rate. The bench source: what a two-subscriber run or a
//!   frames-to-disk run measures against.
//! - [`HttpMjpegSource`] (feature `mjpeg`): J1's `multipart/x-mixed-replace`
//!   stream from `rusty_esp_video` (a device's `/stream`, or the host server
//!   example), pulled over TCP and republished frame by frame. The node
//!   becomes the bridge a Pi is in front of a camera.
//!
//! Both stamp packets `codec = "mjpg"`, one frame per packet, every frame a
//! key frame. A frame larger than a datagram travels as one uni stream (the
//! node does that, up to [`alpn::MAX_MEDIA_PACKET`]).

use std::io;
use std::path::Path;
use std::time::Duration;

use rusty_esp_iroh_core::media::{PacketHeader, FLAG_KEY};

use crate::node::MediaSource;

/// The codec tag MJPEG frames carry.
pub const CODEC_MJPEG: [u8; 4] = *b"mjpg";

/// Does `bytes` start with SOI and end with EOI?
#[must_use]
pub fn looks_like_jpeg(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..2] == [0xFF, 0xD8] && bytes[bytes.len() - 2..] == [0xFF, 0xD9]
}

/// A directory of JPEGs, looped at `fps`.
#[derive(Debug)]
pub struct DirSource {
    frames: Vec<Vec<u8>>,
    next: usize,
    seq: u32,
    interval: Duration,
    /// Stop after this many packets (`None` = loop forever).
    limit: Option<u32>,
}

impl DirSource {
    /// Load every `*.jpg` / `*.jpeg` under `dir` (sorted by name); refuse a
    /// directory without one, or a file that is not a whole JPEG.
    pub fn open(dir: &Path, fps: u32) -> io::Result<Self> {
        let mut names: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg"))
            })
            .collect();
        names.sort();
        let mut frames = Vec::with_capacity(names.len());
        for p in &names {
            let bytes = std::fs::read(p)?;
            if !looks_like_jpeg(&bytes) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not a whole JPEG", p.display()),
                ));
            }
            frames.push(bytes);
        }
        if frames.is_empty() || fps == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no JPEG frames under {} (or fps 0)", dir.display()),
            ));
        }
        Ok(DirSource {
            frames,
            next: 0,
            seq: 0,
            interval: Duration::from_micros(1_000_000 / u64::from(fps)),
            limit: None,
        })
    }

    /// Stop after `packets` packets instead of looping forever.
    #[must_use]
    pub fn limited(mut self, packets: u32) -> Self {
        self.limit = Some(packets);
        self
    }

    /// Distinct frames loaded.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Bytes of the largest frame.
    #[must_use]
    pub fn largest_frame(&self) -> usize {
        self.frames.iter().map(Vec::len).max().unwrap_or(0)
    }
}

impl MediaSource for DirSource {
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        if self.limit.is_some_and(|n| self.seq >= n) {
            return None;
        }
        let frame = self.frames[self.next].clone();
        self.next = (self.next + 1) % self.frames.len();
        let header = PacketHeader {
            seq: self.seq,
            timestamp_us: u64::from(self.seq) * self.interval.as_micros() as u64,
            codec: CODEC_MJPEG,
            flags: FLAG_KEY,
            len: frame.len() as u32,
        };
        self.seq = self.seq.wrapping_add(1);
        Some((header, frame))
    }

    fn interval(&self) -> Duration {
        self.interval
    }
}

#[cfg(feature = "mjpeg")]
pub use http::HttpMjpegSource;

#[cfg(feature = "mjpeg")]
mod http {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rusty_esp_iroh_core::media::{PacketHeader, FLAG_KEY};
    use rusty_esp_video_core::mjpeg_reader::Reader;

    use super::CODEC_MJPEG;
    use crate::node::MediaSource;

    /// J1's HTTP stream, republished frame by frame.
    ///
    /// A thread owns the socket and the multipart reader and hands whole
    /// JPEGs over a channel; `next_packet` blocks on that channel, which is
    /// what the node's blocking producer expects. The part's `X-Timestamp`
    /// becomes the packet timestamp when the device sent one, the wall clock
    /// (Unix microseconds) otherwise.
    #[derive(Debug)]
    pub struct HttpMjpegSource {
        rx: mpsc::Receiver<(Option<u64>, Vec<u8>)>,
        seq: u32,
        /// Frames the reader refused (a part that was not a JPEG, a full buffer).
        pub refused: u32,
    }

    impl HttpMjpegSource {
        /// Connect to `addr` (`host:port`) and `GET path` (`/stream` on a
        /// Janus device). `buffer` bytes hold the response in flight; make it
        /// a few frames.
        pub fn connect(addr: &str, path: &str, buffer: usize) -> std::io::Result<Self> {
            let mut stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: rusty_esp_iroh-host\r\n\r\n"
            )?;
            let (tx, rx) = mpsc::sync_channel::<(Option<u64>, Vec<u8>)>(4);
            thread::Builder::new()
                .name("mjpeg-http".into())
                .spawn(move || {
                    let mut buf = vec![0u8; buffer.max(64 * 1024)];
                    let mut reader = Reader::new(&mut buf);
                    let mut chunk = [0u8; 16 * 1024];
                    loop {
                        let n = match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        if reader.push(&chunk[..n]).is_err() {
                            return;
                        }
                        while let Ok(Some(part)) = reader.next_part() {
                            let jpeg = reader.part(&part).to_vec();
                            let ts = part.timestamp.map(|t| t.0);
                            reader.release(&part);
                            if tx.send((ts, jpeg)).is_err() {
                                return;
                            }
                        }
                    }
                })?;
            Ok(HttpMjpegSource {
                rx,
                seq: 0,
                refused: 0,
            })
        }
    }

    impl MediaSource for HttpMjpegSource {
        fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
            loop {
                let (ts, jpeg) = self.rx.recv().ok()?;
                if !super::looks_like_jpeg(&jpeg) {
                    self.refused += 1;
                    continue;
                }
                let timestamp_us = ts.unwrap_or_else(|| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_micros() as u64)
                        .unwrap_or(0)
                });
                let header = PacketHeader {
                    seq: self.seq,
                    timestamp_us,
                    codec: CODEC_MJPEG,
                    flags: FLAG_KEY,
                    len: jpeg.len() as u32,
                };
                self.seq = self.seq.wrapping_add(1);
                return Some((header, jpeg));
            }
        }

        fn interval(&self) -> Duration {
            Duration::ZERO
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg(n: u8) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 4, n, n];
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn a_directory_of_jpegs_loops_in_name_order_at_the_rate_asked() {
        let dir = std::env::temp_dir().join(format!("janus-dirsource-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, name) in ["b.jpg", "a.JPG", "c.jpeg", "not.txt"].iter().enumerate() {
            std::fs::write(dir.join(name), jpeg(i as u8)).unwrap();
        }
        let mut src = DirSource::open(&dir, 25).unwrap().limited(7);
        assert_eq!(src.frame_count(), 3);
        assert_eq!(src.interval(), Duration::from_millis(40));
        let mut seen = Vec::new();
        while let Some((h, bytes)) = src.next_packet() {
            assert_eq!(h.codec, CODEC_MJPEG);
            assert_eq!(h.flags, FLAG_KEY);
            assert_eq!(h.len as usize, bytes.len());
            assert_eq!(h.timestamp_us, u64::from(h.seq) * 40_000);
            seen.push(bytes[6]);
        }
        // a.JPG (1), b.jpg (0), c.jpeg (2), then around again
        assert_eq!(seen, [1, 0, 2, 1, 0, 2, 1]);
        std::fs::write(dir.join("d.jpg"), b"not a jpeg").unwrap();
        assert!(DirSource::open(&dir, 25).is_err(), "a non-JPEG is refused");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(DirSource::open(&dir, 25).is_err());
    }

    #[test]
    fn jpeg_shape_check() {
        assert!(looks_like_jpeg(&jpeg(0)));
        assert!(!looks_like_jpeg(&[0xFF, 0xD8, 0xFF]));
        assert!(!looks_like_jpeg(b"GIF89a"));
    }
}
