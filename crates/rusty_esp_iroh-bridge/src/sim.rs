//! The neighbour's side, on the host: what a C6 or a LoRa node does over
//! `rusty_esp_signal` to appear behind a bridge. A firmware implements the
//! same four steps over its radio; this is the reference the tests and the
//! example drive.

use std::time::{Duration, Instant};

use rusty_esp_core::capability::Manifest;
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::Rng;
use rusty_esp_core::time::Micros;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_core::manifest::sign_manifest;
use rusty_esp_signal_core::link::{ACCEPT_LEN, DEFAULT_LIFETIME, Handshake, MAX_PAYLOAD, Session};

use crate::DynRng;
use crate::neighbour::{MSG_CSI, MSG_MANIFEST, MSG_TELEMETRY};
use crate::radio::{PeerAddr, Radio};

/// A simulated neighbour.
pub struct NeighbourSim<R: Radio> {
    key: DeviceKey,
    radio: R,
    bridge: PeerAddr,
    rng: DynRng,
    session: Option<Session>,
    manifest: Vec<u8>,
    sig: [u8; 64],
    last_sealed: Option<Vec<u8>>,
    started: Instant,
}

impl<R: Radio> NeighbourSim<R> {
    /// A neighbour with its own key (`seed` makes a deterministic test key)
    /// and its own signed manifest, on `radio`, talking to `bridge`.
    pub fn new(
        seed: &str,
        device_id: &str,
        manifest: &Manifest<'_>,
        radio: R,
        bridge: PeerAddr,
        rng: Box<dyn Rng + Send>,
    ) -> Result<Self> {
        let key = DeviceKey::from_seed_for_tests(seed, device_id);
        let mut bytes = vec![0u8; manifest.encoded_len()];
        let (n, sig) = sign_manifest(manifest, &key, &mut bytes)?;
        bytes.truncate(n);
        Ok(NeighbourSim {
            key,
            radio,
            bridge,
            rng: DynRng(rng),
            session: None,
            manifest: bytes,
            sig,
            last_sealed: None,
            started: Instant::now(),
        })
    }

    /// The neighbour's DID.
    #[must_use]
    pub fn did_string(&self) -> String {
        self.key.did().to_did_string()
    }

    /// The signed manifest bytes and signature this neighbour sends.
    #[must_use]
    pub fn signed_manifest(&self) -> (&[u8], &[u8; 64]) {
        (&self.manifest, &self.sig)
    }

    /// The last sealed frame sent (for a replay test).
    #[must_use]
    pub fn last_sealed(&self) -> Option<&[u8]> {
        self.last_sealed.as_deref()
    }

    fn now(&self) -> Micros {
        Micros(self.started.elapsed().as_micros() as u64)
    }

    /// Hello → accept → confirm, within `timeout`.
    pub fn link(&mut self, timeout: Duration) -> Result<()> {
        let (hs, hello) = Handshake::initiate(&self.key, &mut self.rng)?;
        self.radio.send(&self.bridge, &hello)?;
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; self.radio.mtu().max(ACCEPT_LEN)];
        let accept = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout);
            }
            match self.radio.recv(&mut buf, left)? {
                Some((from, n)) if from == self.bridge && n == ACCEPT_LEN => {
                    break buf[..n].to_vec();
                }
                Some(_) => continue,
                None => return Err(Error::Timeout),
            }
        };
        let now = self.now();
        let (session, confirm) = hs.finish(&self.key, &accept, |_| true, now, DEFAULT_LIFETIME)?;
        self.radio.send(&self.bridge, &confirm)?;
        self.session = Some(session);
        Ok(())
    }

    fn seal_and_send(&mut self, payload: &[u8]) -> Result<()> {
        let session = self.session.as_mut().ok_or(Error::Denied)?;
        let mut out = vec![0u8; self.radio.mtu()];
        let n = session.seal(payload, &mut out)?;
        self.radio.send(&self.bridge, &out[..n])?;
        self.last_sealed = Some(out[..n].to_vec());
        Ok(())
    }

    /// `sig ‖ manifest`, in as many parts as the link's payload allows.
    pub fn send_manifest(&mut self) -> Result<()> {
        let mut whole = self.sig.to_vec();
        whole.extend_from_slice(&self.manifest);
        let room = MAX_PAYLOAD - 3;
        let count = whole.len().div_ceil(room);
        if count > crate::neighbour::MAX_MANIFEST_PARTS {
            return Err(Error::Unsupported);
        }
        let parts: Vec<Vec<u8>> = whole.chunks(room).map(<[u8]>::to_vec).collect();
        for (i, part) in parts.iter().enumerate() {
            let mut payload = vec![MSG_MANIFEST, i as u8, count as u8];
            payload.extend_from_slice(part);
            self.seal_and_send(&payload)?;
        }
        Ok(())
    }

    /// One telemetry frame.
    pub fn send_telemetry(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() + 1 > MAX_PAYLOAD {
            return Err(Error::Unsupported);
        }
        let mut payload = vec![MSG_TELEMETRY];
        payload.extend_from_slice(bytes);
        self.seal_and_send(&payload)
    }

    /// Send one CSI sample's bytes (the W5 stream), sealed.
    pub fn send_csi(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() + 1 > MAX_PAYLOAD {
            return Err(Error::Unsupported);
        }
        let mut payload = vec![MSG_CSI];
        payload.extend_from_slice(bytes);
        self.seal_and_send(&payload)
    }

    /// Send raw bytes (a replayed frame, a forgery) as they are.
    pub fn send_raw(&mut self, frame: &[u8]) -> Result<()> {
        self.radio.send(&self.bridge, frame)
    }

    /// Re-sign the manifest with a key that is not this neighbour's (the
    /// impostor case): the bridge must refuse it.
    pub fn forge_signature(&mut self, other_seed: &str) {
        let other = DeviceKey::from_seed_for_tests(other_seed, "forger");
        self.sig = rusty_esp_mid_core::manifest::sign_manifest_bytes(&self.manifest, &other);
    }
}
