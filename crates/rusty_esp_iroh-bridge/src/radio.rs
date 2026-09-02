//! The radio seam: what the bridge needs from an ESP-NOW or LoRa
//! attachment, and an in-memory bus that stands in for one on the host.
//!
//! On a Pi the radio is a serial-attached C6 or SX1262 node speaking the
//! same frames; that driver is a board row. Everything above this trait —
//! the handshake, the sessions, the manifests, the iroh presence — is what
//! the host test exercises.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusty_esp_core::error::{Error, Result};

/// A radio address: an ESP-NOW MAC in the first six bytes, or a LoRa node
/// id. Eight bytes cover both.
pub type PeerAddr = [u8; 8];

/// Every peer on the radio.
pub const BROADCAST: PeerAddr = [0xFF; 8];

/// A datagram radio: frames of at most [`Radio::mtu`] bytes, addressed, no
/// delivery guarantee, no ordering guarantee.
pub trait Radio: Send {
    /// Send one frame to `to` (or [`BROADCAST`]).
    fn send(&mut self, to: &PeerAddr, frame: &[u8]) -> Result<()>;
    /// Wait up to `timeout` for one frame; `Ok(None)` on timeout.
    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> Result<Option<(PeerAddr, usize)>>;
    /// Largest frame this radio carries (250 for ESP-NOW, 255 for LoRa).
    fn mtu(&self) -> usize;
}

type Packet = (PeerAddr, PeerAddr, Vec<u8>);

/// An in-memory radio bus: every attached [`FakeRadio`] hears frames sent
/// to its address or to [`BROADCAST`]. `drop_every` on a radio drops that
/// radio's every n-th outgoing frame, for loss tests.
#[derive(Clone, Default)]
pub struct FakeBus {
    inner: Arc<Mutex<HashMap<PeerAddr, Sender<Packet>>>>,
}

impl FakeBus {
    /// An empty bus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a radio at `addr`.
    #[must_use]
    pub fn attach(&self, addr: PeerAddr, mtu: usize) -> FakeRadio {
        let (tx, rx) = mpsc::channel();
        self.inner.lock().expect("bus").insert(addr, tx);
        FakeRadio {
            me: addr,
            bus: self.clone(),
            rx,
            mtu,
            sent: 0,
            drop_every: None,
        }
    }

    fn deliver(&self, from: PeerAddr, to: PeerAddr, frame: &[u8]) {
        let peers = self.inner.lock().expect("bus");
        if to == BROADCAST {
            for (addr, tx) in peers.iter() {
                if *addr != from {
                    let _ = tx.send((from, to, frame.to_vec()));
                }
            }
        } else if let Some(tx) = peers.get(&to) {
            let _ = tx.send((from, to, frame.to_vec()));
        }
    }
}

/// One end on a [`FakeBus`].
pub struct FakeRadio {
    me: PeerAddr,
    bus: FakeBus,
    rx: Receiver<Packet>,
    mtu: usize,
    sent: u64,
    /// Drop every n-th frame this radio sends (a lossy link).
    pub drop_every: Option<u64>,
}

impl FakeRadio {
    /// This radio's address.
    #[must_use]
    pub const fn addr(&self) -> PeerAddr {
        self.me
    }
}

impl Radio for FakeRadio {
    fn send(&mut self, to: &PeerAddr, frame: &[u8]) -> Result<()> {
        if frame.len() > self.mtu {
            return Err(Error::Unsupported);
        }
        self.sent += 1;
        if self.drop_every.is_some_and(|n| n > 0 && self.sent % n == 0) {
            return Ok(());
        }
        self.bus.deliver(self.me, *to, frame);
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> Result<Option<(PeerAddr, usize)>> {
        match self.rx.recv_timeout(timeout) {
            Ok((from, _to, frame)) => {
                if frame.len() > buf.len() {
                    return Err(Error::BufferTooSmall {
                        needed: frame.len(),
                    });
                }
                buf[..frame.len()].copy_from_slice(&frame);
                Ok(Some((from, frame.len())))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(Error::Hardware),
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bus_delivers_addressed_and_broadcast_frames_and_drops_on_request() {
        let bus = FakeBus::new();
        let mut a = bus.attach([1; 8], 250);
        let mut b = bus.attach([2; 8], 250);
        let mut c = bus.attach([3; 8], 250);
        a.send(&[2; 8], b"to b").unwrap();
        a.send(&BROADCAST, b"all").unwrap();
        let mut buf = [0u8; 250];
        assert_eq!(
            b.recv(&mut buf, Duration::from_millis(50)).unwrap(),
            Some(([1; 8], 4))
        );
        assert_eq!(&buf[..4], b"to b");
        assert_eq!(
            b.recv(&mut buf, Duration::from_millis(50)).unwrap(),
            Some(([1; 8], 3))
        );
        assert_eq!(
            c.recv(&mut buf, Duration::from_millis(50)).unwrap(),
            Some(([1; 8], 3))
        );
        assert_eq!(
            a.recv(&mut buf, Duration::from_millis(20)).unwrap(),
            None,
            "not to itself"
        );
        assert!(a.send(&[2; 8], &[0u8; 251]).is_err(), "over the MTU");
        a.drop_every = Some(2);
        a.send(&[2; 8], b"1").unwrap();
        a.send(&[2; 8], b"2").unwrap(); // dropped (4th frame overall)
        a.send(&[2; 8], b"3").unwrap();
        let mut got = Vec::new();
        while let Some((_, n)) = b.recv(&mut buf, Duration::from_millis(20)).unwrap() {
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got, vec![b"1".to_vec(), b"3".to_vec()]);
    }
}
