//! Telemetry on `janus/media/1`: the codecs that carry it and the reading a
//! home computer keeps.
//!
//! A std device pushes its presence record through the facade's
//! `mesh::push_telemetry`, which frames it under [`CODEC_TELEMETRY`]; a
//! bridge re-frames each neighbour's record as a [`NeighbourPacket`] under
//! [`CODEC_NEIGHBOUR_TELEMETRY`]. The record itself is
//! `rusty_esp_signal_core::radar::presence::Presence` -- version 2 since
//! W3: breathing and heart with confidences, a fingerprint distance. This
//! crate does not decode it: the decoder is the signal crate's, and the host
//! (`rusty_esp_iroh-host::presence`) turns a decoded record into a
//! [`PresenceInfo`], the JSON shape the sidecar's `janusPresence` answers.
//! Until that existed the record was sent, framed, forwarded, and read by
//! nothing.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// A std device's own presence record on `janus/media/1`: the facade's
/// `mesh::CODEC_TELEMETRY`, mirrored here so a subscriber can name it.
pub const CODEC_TELEMETRY: [u8; 4] = *b"tlm ";

/// A bridge's neighbour telemetry: every packet a postcard
/// [`NeighbourPacket`], the neighbour's DID beside its bytes.
pub const CODEC_NEIGHBOUR_TELEMETRY: [u8; 4] = *b"nbrt";

/// What rides in one [`CODEC_NEIGHBOUR_TELEMETRY`] media packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighbourPacket {
    /// The neighbour's DID.
    pub did: String,
    /// How it reaches the bridge: `espnow`, `lora`, ...
    pub reach: String,
    /// The telemetry bytes as the neighbour sent them.
    pub payload: Vec<u8>,
}

/// One device's latest presence reading, as a reader keeps it and the
/// sidecar's `janusPresence` answers it. The fields are the record's,
/// version 2; a version 1 record reads with the vitals and the
/// fingerprint zero. A rate is non-zero only when the sensor accepted it;
/// its confidence is there either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceInfo {
    /// The device the reading is from.
    pub did: String,
    /// How the reading arrived: `espnow` or `lora` through a bridge, `iroh`
    /// straight from a std device.
    pub reach: String,
    /// The device's clock when it read the room, microseconds.
    pub at_us: u64,
    /// The reader's clock when the record arrived, microseconds.
    pub received_us: u64,
    /// `unknown`, `absent`, `moving`, `stationary` or `both`.
    pub state: String,
    /// Distance to the moving target, cm; 0 when none (always 0 from CSI).
    pub moving_cm: u16,
    /// Moving-target energy `0..=100`; from CSI, the motion level.
    pub moving_energy: u8,
    /// Distance to the stationary target, cm; 0 when none.
    pub stationary_cm: u16,
    /// Stationary-target energy `0..=100`.
    pub stationary_energy: u8,
    /// The sensor's own detection distance, cm; 0 when it reports none.
    pub detection_cm: u16,
    /// Breathing, tenths per minute; 0 when none was accepted.
    pub breathing_bpm_x10: u16,
    /// The breathing estimate's confidence, permille; 0 when none ran.
    pub breathing_confidence: u16,
    /// Heart rate, tenths per minute; 0 when none was accepted.
    pub heart_bpm_x10: u16,
    /// The heart estimate's confidence, permille; 0 when none ran.
    pub heart_confidence: u16,
    /// The room's distance from its calibrated fingerprint, permille; 0
    /// when uncalibrated.
    pub fingerprint: u16,
}
