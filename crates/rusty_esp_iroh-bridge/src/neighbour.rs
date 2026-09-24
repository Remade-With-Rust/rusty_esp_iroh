//! The bridge's side of every neighbour: the `rusty_esp_signal` handshake
//! answered, the session kept, the neighbour's own signed manifest received
//! and verified, its telemetry attributed.
//!
//! Inside a sealed frame the first byte says what follows:
//!
//! ```text
//! 0x01  manifest part: [part index][part count][bytes]   (sig ‖ manifest, split)
//! 0x02  telemetry:     [bytes]                            (opaque to the bridge)
//! ```
//!
//! The bridge verifies the manifest under the DID the handshake
//! authenticated — the neighbour's key, which never leaves the neighbour —
//! and relays the bytes and the signature verbatim, so anything upstream
//! can check the same signature and need not trust the bridge's word.

use std::string::String;
use std::vec::Vec;

use rusty_esp_core::capability::ParsedManifest;
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::Rng;
use rusty_esp_core::time::Micros;
use rusty_esp_iroh_core::rpc::NeighbourInfo;
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_core::manifest::verify_manifest;
use rusty_esp_signal_core::link::{
    CONFIRM_LEN, DEFAULT_LIFETIME, HELLO_LEN, Handshake, Pending, Session, VERSION,
};
use serde::{Deserialize, Serialize};

use crate::DynRng;
use crate::radio::PeerAddr;

/// The media codec tag of re-framed neighbour telemetry.
pub const CODEC_NEIGHBOUR_TELEMETRY: [u8; 4] = *b"nbrt";
/// Sealed-payload kind: a manifest part.
pub const MSG_MANIFEST: u8 = 0x01;
/// Sealed-payload kind: telemetry.
pub const MSG_TELEMETRY: u8 = 0x02;
/// Most parts a manifest may arrive in (≈ 900 bytes of manifest + signature).
pub const MAX_MANIFEST_PARTS: usize = 4;
/// The link's handshake kind bytes (`rusty_esp_signal::link`, wire constants).
const KIND_HELLO: u8 = 0x01;
const KIND_CONFIRM: u8 = 0x03;

/// How a neighbour reaches the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reach {
    /// ESP-NOW (a C6 or S3 on 2.4 GHz).
    EspNow,
    /// LoRa point-to-point (an SX1262 node).
    Lora,
}

impl Reach {
    /// The wire tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Reach::EspNow => "espnow",
            Reach::Lora => "lora",
        }
    }
}

/// What rides in one `nbrt` media packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighbourPacket {
    /// The neighbour's DID.
    pub did: String,
    /// [`Reach::tag`].
    pub reach: String,
    /// The telemetry bytes as the neighbour sent them.
    pub payload: Vec<u8>,
}

/// What the core reports as it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A neighbour completed the handshake.
    Linked {
        /// Its DID.
        did: String,
        /// Its radio.
        reach: Reach,
    },
    /// A neighbour's manifest arrived whole and verified under its DID.
    Manifest {
        /// Its DID.
        did: String,
    },
    /// Authenticated telemetry from a neighbour.
    Telemetry {
        /// Its DID.
        did: String,
        /// Its radio.
        reach: Reach,
        /// The bytes.
        payload: Vec<u8>,
        /// Bridge clock at receipt.
        at: Micros,
    },
    /// Something was refused, with the reason (a log line, never a panic).
    Refused {
        /// The radio address it came from.
        addr: PeerAddr,
        /// Why.
        why: &'static str,
    },
}

/// The bridge's counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BridgeCounters {
    /// Hellos answered.
    pub hellos: u32,
    /// Hellos refused because the DID was not on the roster. Nothing is
    /// sent back: a refused peer learns nothing, not even that it was seen.
    pub denied: u32,
    /// Sessions confirmed.
    pub linked: u32,
    /// Manifests that verified.
    pub manifests_ok: u32,
    /// Manifests that did not (bad signature, malformed, too many parts).
    pub manifests_bad: u32,
    /// Telemetry frames accepted.
    pub telemetry: u32,
    /// Frames from unknown addresses or that failed to open.
    pub dropped: u32,
}

struct Linked {
    session: Session,
    did_string: String,
    manifest: Option<(Vec<u8>, [u8; 64])>,
    parts: Vec<Option<Vec<u8>>>,
}

enum State {
    Empty,
    Pending(Box<Pending>),
    Linked(Box<Linked>),
}

struct Slot {
    addr: PeerAddr,
    reach: Reach,
    state: State,
    last_seen: Micros,
}

/// Every neighbour's state, driven one frame at a time. No threads, no
/// sockets: the radio loop in [`crate::Bridge`] feeds it and sends what it
/// returns.
pub struct BridgeCore {
    me: DeviceKey,
    rng: DynRng,
    reach_of: fn(&PeerAddr) -> Reach,
    slots: Vec<Slot>,
    events: Vec<Event>,
    lifetime: Micros,
    /// The DIDs whose hello is answered. Empty refuses everyone: the roster
    /// is the owner's, and a bridge that answered anyone would front
    /// strangers to the home computer.
    roster: Vec<Did>,
    /// Counters, for the ledger.
    pub counters: BridgeCounters,
}

impl BridgeCore {
    /// A core for the bridge whose device key is `me` (its iroh identity's
    /// key: the neighbours authenticate the bridge by it). `reach_of` says
    /// which radio an address is on.
    pub fn new(me: DeviceKey, rng: Box<dyn Rng + Send>, reach_of: fn(&PeerAddr) -> Reach) -> Self {
        BridgeCore {
            me,
            rng: DynRng(rng),
            reach_of,
            slots: Vec::new(),
            events: Vec::new(),
            lifetime: DEFAULT_LIFETIME,
            roster: Vec::new(),
            counters: BridgeCounters::default(),
        }
    }

    /// Admit `did`: its hello is answered from now on. Returns whether it
    /// was new. Until a DID is here, nothing is answered.
    pub fn allow(&mut self, did: Did) -> bool {
        if self.roster.contains(&did) {
            return false;
        }
        self.roster.push(did);
        true
    }

    /// Strike `did`: its next hello is refused. A session it already holds
    /// is not cut; that is the lifetime's job.
    pub fn disallow(&mut self, did: &Did) -> bool {
        let before = self.roster.len();
        self.roster.retain(|d| d != did);
        self.roster.len() != before
    }

    /// The DIDs the bridge answers, as `did:mata:…` strings.
    #[must_use]
    pub fn roster(&self) -> Vec<String> {
        self.roster.iter().map(Did::to_did_string).collect()
    }

    /// The bridge's own DID.
    #[must_use]
    pub fn did_string(&self) -> String {
        self.me.did().to_did_string()
    }

    fn slot_index(&self, addr: &PeerAddr) -> Option<usize> {
        self.slots.iter().position(|s| s.addr == *addr)
    }

    /// One frame from `from` at `now`; the reply to send back, if any.
    pub fn handle_frame(
        &mut self,
        from: PeerAddr,
        frame: &[u8],
        now: Micros,
    ) -> Result<Option<Vec<u8>>> {
        if frame.len() == HELLO_LEN && frame[0] == VERSION && frame[1] == KIND_HELLO {
            return self.on_hello(from, frame, now);
        }
        if frame.len() == CONFIRM_LEN && frame[0] == VERSION && frame[1] == KIND_CONFIRM {
            self.on_confirm(from, frame, now)?;
            return Ok(None);
        }
        self.on_sealed(from, frame, now)?;
        Ok(None)
    }

    fn on_hello(&mut self, from: PeerAddr, hello: &[u8], now: Micros) -> Result<Option<Vec<u8>>> {
        // The roster decides before any key material is derived (that is
        // where `Handshake::respond` asks). A refusal is counted and logged
        // as an event, and answered with silence.
        let roster = &self.roster;
        let (pending, accept) = match Handshake::respond(
            &self.me,
            &mut self.rng,
            hello,
            |did| roster.contains(did),
            now,
            self.lifetime,
        ) {
            Ok(answered) => answered,
            Err(Error::Denied) => {
                self.counters.denied += 1;
                self.events.push(Event::Refused {
                    addr: from,
                    why: "not on the roster",
                });
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        self.counters.hellos += 1;
        let reach = (self.reach_of)(&from);
        match self.slot_index(&from) {
            Some(i) => {
                self.slots[i].state = State::Pending(Box::new(pending));
                self.slots[i].last_seen = now;
                self.slots[i].reach = reach;
            }
            None => self.slots.push(Slot {
                addr: from,
                reach,
                state: State::Pending(Box::new(pending)),
                last_seen: now,
            }),
        }
        Ok(Some(accept.to_vec()))
    }

    fn on_confirm(&mut self, from: PeerAddr, confirm: &[u8], now: Micros) -> Result<()> {
        let Some(i) = self.slot_index(&from) else {
            self.counters.dropped += 1;
            return Ok(());
        };
        let state = std::mem::replace(&mut self.slots[i].state, State::Empty);
        match state {
            State::Pending(p) => match (*p).confirm(confirm) {
                Ok(session) => {
                    let did_string = session.peer().to_did_string();
                    self.counters.linked += 1;
                    self.events.push(Event::Linked {
                        did: did_string.clone(),
                        reach: self.slots[i].reach,
                    });
                    self.slots[i].state = State::Linked(Box::new(Linked {
                        session,
                        did_string,
                        manifest: None,
                        parts: Vec::new(),
                    }));
                    self.slots[i].last_seen = now;
                    Ok(())
                }
                Err(e) => {
                    self.counters.dropped += 1;
                    self.events.push(Event::Refused {
                        addr: from,
                        why: "confirm did not verify",
                    });
                    Err(e)
                }
            },
            other => {
                // a stray confirm; keep whatever state there was
                self.slots[i].state = other;
                self.counters.dropped += 1;
                Ok(())
            }
        }
    }

    fn on_sealed(&mut self, from: PeerAddr, frame: &[u8], now: Micros) -> Result<()> {
        let Some(i) = self.slot_index(&from) else {
            self.counters.dropped += 1;
            return Err(Error::Denied);
        };
        let reach = self.slots[i].reach;
        let State::Linked(linked) = &mut self.slots[i].state else {
            self.counters.dropped += 1;
            return Err(Error::Denied);
        };
        if linked.session.expired(now) {
            self.counters.dropped += 1;
            return Err(Error::Timeout);
        }
        let payload = match linked.session.open(frame) {
            Ok(p) => p.to_vec(),
            Err(e) => {
                self.counters.dropped += 1;
                return Err(e);
            }
        };
        self.slots[i].last_seen = now;
        let State::Linked(linked) = &mut self.slots[i].state else {
            unreachable!()
        };
        match payload.first() {
            Some(&MSG_TELEMETRY) => {
                self.counters.telemetry += 1;
                self.events.push(Event::Telemetry {
                    did: linked.did_string.clone(),
                    reach,
                    payload: payload[1..].to_vec(),
                    at: now,
                });
                Ok(())
            }
            Some(&MSG_MANIFEST) if payload.len() >= 3 => {
                let (index, count) = (usize::from(payload[1]), usize::from(payload[2]));
                if count == 0 || count > MAX_MANIFEST_PARTS || index >= count {
                    self.counters.manifests_bad += 1;
                    return Err(Error::InvalidFormat);
                }
                if linked.parts.len() != count {
                    linked.parts = vec![None; count];
                }
                linked.parts[index] = Some(payload[3..].to_vec());
                if linked.parts.iter().all(Option::is_some) {
                    let whole: Vec<u8> = linked.parts.drain(..).flatten().flatten().collect();
                    let did = linked.did_string.clone();
                    let verdict = Self::check_manifest(&whole, linked.session.peer());
                    match verdict {
                        Ok((bytes, sig)) => {
                            linked.manifest = Some((bytes, sig));
                            self.counters.manifests_ok += 1;
                            self.events.push(Event::Manifest { did });
                        }
                        Err(why) => {
                            self.counters.manifests_bad += 1;
                            self.events.push(Event::Refused { addr: from, why });
                        }
                    }
                }
                Ok(())
            }
            _ => {
                self.counters.dropped += 1;
                Err(Error::InvalidFormat)
            }
        }
    }

    /// `sig ‖ manifest`: the signature verifies under the neighbour's own
    /// DID and the manifest parses as the canonical form.
    fn check_manifest(
        whole: &[u8],
        peer: &Did,
    ) -> core::result::Result<(Vec<u8>, [u8; 64]), &'static str> {
        if whole.len() <= 64 {
            return Err("manifest too short");
        }
        let sig: [u8; 64] = whole[..64].try_into().map_err(|_| "signature length")?;
        let bytes = &whole[64..];
        verify_manifest(bytes, &sig, peer.pubkey()).map_err(|_| "manifest signature")?;
        ParsedManifest::parse(bytes).map_err(|_| "manifest form")?;
        Ok((bytes.to_vec(), sig))
    }

    /// Every neighbour that is linked and whose manifest verified, as the
    /// wire form `Request::Neighbours` answers with.
    #[must_use]
    pub fn table(&self, now: Micros) -> Vec<NeighbourInfo> {
        self.slots
            .iter()
            .filter_map(|s| match &s.state {
                State::Linked(l) if !l.session.expired(now) => {
                    let (manifest, sig) = l.manifest.as_ref()?;
                    Some(NeighbourInfo {
                        did: l.did_string.clone(),
                        reach: String::from(s.reach.tag()),
                        manifest: manifest.clone(),
                        sig: sig.to_vec(),
                        last_seen_us: now.since(s.last_seen),
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Neighbours with a live session, manifest or not.
    #[must_use]
    pub fn linked(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s.state, State::Linked(_)))
            .count()
    }

    /// The events since the last call.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
}
