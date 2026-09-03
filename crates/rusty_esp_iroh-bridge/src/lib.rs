#![forbid(unsafe_code)]
//! `rusty_esp_iroh-bridge` — the Janus bridge (N3).
//!
//! A std process (a Pi, a P4, a laptop) holds **one iroh endpoint** and
//! fronts N radio neighbours that cannot run iroh themselves: a C6 over
//! ESP-NOW, a LoRa node. Each neighbour links to the bridge with
//! `rusty_esp_signal`'s authenticated session (the neighbour's key stays on
//! the neighbour; the bridge keeps the session), sends its **own signed
//! manifest**, and its telemetry is re-framed onto `janus/media/1`. The
//! home computer asks the bridge `Request::Neighbours` and gets each
//! neighbour's DID, manifest and signature verbatim — it verifies the
//! neighbour, not the bridge.
//!
//! - [`radio::Radio`] is the seam a Pi fills with a serial-attached C6 or
//!   SX1262; [`radio::FakeBus`] is the host's.
//! - [`neighbour::BridgeCore`] is the whole neighbour state machine, driven
//!   one frame at a time and free of threads.
//! - [`Bridge`] runs the radio loop on a thread and hands the iroh node its
//!   two seams: a [`NeighbourSource`] and a media factory for `nbrt`.
//! - [`sim::NeighbourSim`] is the neighbour's side, for tests and the example.

pub mod neighbour;
pub mod radio;
pub mod sim;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rusty_esp_core::hal::Rng;
use rusty_esp_core::time::Micros;
use rusty_esp_iroh_core::media::{FLAG_KEY, PacketHeader, Subscribe};
use rusty_esp_iroh_core::rpc::NeighbourInfo;
use rusty_esp_iroh_host::MediaSource;
use rusty_esp_iroh_host::node::{MediaFactory, NeighbourSource};

pub use neighbour::{
    BridgeCore, BridgeCounters, CODEC_NEIGHBOUR_TELEMETRY, Event, NeighbourPacket, Reach,
};
pub use radio::{BROADCAST, FakeBus, FakeRadio, PeerAddr, Radio};

/// The operating system's random source as the family's [`Rng`] seam, for
/// the bridge's handshakes on a host.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostRng;

impl Rng for HostRng {
    fn fill(&mut self, buf: &mut [u8]) -> rusty_esp_core::error::Result<()> {
        rand::RngCore::fill_bytes(&mut rand::rng(), buf);
        Ok(())
    }
}

/// A boxed [`Rng`] as a sized one: the link's handshake takes
/// `&mut impl Rng`, and a core that owns any RNG needs this shim.
pub struct DynRng(pub Box<dyn Rng + Send>);

impl Rng for DynRng {
    fn fill(&mut self, buf: &mut [u8]) -> rusty_esp_core::error::Result<()> {
        self.0.fill(buf)
    }
}

impl core::fmt::Debug for DynRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DynRng")
    }
}

/// A [`NeighbourSource`] over the shared core.
#[derive(Clone)]
pub struct CoreHandle {
    core: Arc<Mutex<BridgeCore>>,
    started: Instant,
}

impl CoreHandle {
    fn now(&self) -> Micros {
        Micros(self.started.elapsed().as_micros() as u64)
    }

    /// Lock the core.
    pub fn with<T>(&self, f: impl FnOnce(&mut BridgeCore) -> T) -> T {
        f(&mut self.core.lock().expect("bridge core"))
    }
}

impl NeighbourSource for CoreHandle {
    fn neighbours(&self) -> Vec<NeighbourInfo> {
        let now = self.now();
        self.with(|c| c.table(now))
    }
}

/// The radio loop and the fan-out of its events.
pub struct Bridge {
    handle: CoreHandle,
    subscribers: Arc<Mutex<Vec<SyncSender<Event>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Start the radio loop over `radio` with `core`.
    pub fn start(core: BridgeCore, mut radio: impl Radio + 'static) -> Self {
        let started = Instant::now();
        let handle = CoreHandle {
            core: Arc::new(Mutex::new(core)),
            started,
        };
        let subscribers: Arc<Mutex<Vec<SyncSender<Event>>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let handle = handle.clone();
            let subscribers = subscribers.clone();
            let stop = stop.clone();
            thread::Builder::new()
                .name("janus-bridge-radio".into())
                .spawn(move || {
                    let mut buf = vec![0u8; radio.mtu().max(256)];
                    while !stop.load(Ordering::Relaxed) {
                        match radio.recv(&mut buf, Duration::from_millis(100)) {
                            Ok(Some((from, n))) => {
                                let now = handle.now();
                                let reply = handle.with(|c| c.handle_frame(from, &buf[..n], now));
                                match reply {
                                    Ok(Some(bytes)) => {
                                        if let Err(e) = radio.send(&from, &bytes) {
                                            log::warn!("bridge: send to {from:?}: {e:?}");
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        log::debug!("bridge: frame from {from:?} refused: {e:?}")
                                    }
                                }
                                let events = handle.with(BridgeCore::take_events);
                                if !events.is_empty() {
                                    let mut subs = subscribers.lock().expect("subscribers");
                                    subs.retain(|s| {
                                        events.iter().all(|e| s.try_send(e.clone()).is_ok())
                                    });
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                log::error!("bridge: radio: {e:?}");
                                break;
                            }
                        }
                    }
                })
                .expect("spawn bridge thread")
        };
        Bridge {
            handle,
            subscribers,
            stop,
            thread: Some(thread),
        }
    }

    /// The shared core.
    #[must_use]
    pub fn core(&self) -> CoreHandle {
        self.handle.clone()
    }

    /// A receiver of every event from now on (bounded; a subscriber that
    /// stops reading is dropped).
    #[must_use]
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = mpsc::sync_channel(256);
        self.subscribers.lock().expect("subscribers").push(tx);
        rx
    }

    /// The seam `Request::Neighbours` is answered from.
    #[must_use]
    pub fn neighbour_source(&self) -> Arc<dyn NeighbourSource> {
        Arc::new(self.handle.clone())
    }

    /// The media factory: a subscriber asking for [`CODEC_NEIGHBOUR_TELEMETRY`]
    /// gets every neighbour's telemetry as [`NeighbourPacket`]s; anything
    /// else gets an empty stream.
    #[must_use]
    pub fn media_factory(&self) -> MediaFactory {
        let subscribers = self.subscribers.clone();
        Arc::new(move |sub: &Subscribe| -> Box<dyn MediaSource> {
            if sub.codec != CODEC_NEIGHBOUR_TELEMETRY && sub.codec != *b"any " {
                return Box::new(Empty);
            }
            let (tx, rx) = mpsc::sync_channel(256);
            subscribers.lock().expect("subscribers").push(tx);
            Box::new(NeighbourMedia { rx, seq: 0 })
        })
    }

    /// Stop the radio loop.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Neighbour telemetry as `janus/media/1` packets.
struct NeighbourMedia {
    rx: Receiver<Event>,
    seq: u32,
}

impl MediaSource for NeighbourMedia {
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        loop {
            match self.rx.recv_timeout(Duration::from_secs(1)) {
                Ok(Event::Telemetry {
                    did,
                    reach,
                    payload,
                    at,
                }) => {
                    let packet = NeighbourPacket {
                        did,
                        reach: String::from(reach.tag()),
                        payload,
                    };
                    let bytes = postcard::to_stdvec(&packet).ok()?;
                    let header = PacketHeader {
                        seq: self.seq,
                        timestamp_us: at.0,
                        codec: CODEC_NEIGHBOUR_TELEMETRY,
                        flags: FLAG_KEY,
                        len: bytes.len() as u32,
                    };
                    self.seq = self.seq.wrapping_add(1);
                    return Some((header, bytes));
                }
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    fn interval(&self) -> Duration {
        Duration::ZERO
    }
}

struct Empty;

impl MediaSource for Empty {
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        None
    }
    fn interval(&self) -> Duration {
        Duration::ZERO
    }
}
