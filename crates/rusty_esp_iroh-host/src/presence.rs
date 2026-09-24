//! The home computer's side of the presence record.
//!
//! A device's `Presence` (rusty_esp_signal; version 2 since W3: breathing
//! and heart with confidences, a fingerprint distance) rides `janus/media/1`
//! as bytes -- under `"tlm "` straight from a std device, or inside a
//! bridge's `"nbrt"` packet beside the neighbour's DID. This is where those
//! bytes become a reading: [`from_packet`] for a subscriber, [`info`] for a
//! bridge keeping the latest per neighbour. Until it existed the record was
//! sent, framed, forwarded, and read by nothing.

use rusty_esp_core::time::Micros;
use rusty_esp_iroh_core::telemetry::{
    CODEC_NEIGHBOUR_TELEMETRY, CODEC_TELEMETRY, NeighbourPacket, PresenceInfo,
};
use rusty_esp_signal_core::radar::presence::{Occupancy, Presence};

/// The occupancy's word on the wire.
#[must_use]
pub const fn state_word(state: Occupancy) -> &'static str {
    match state {
        Occupancy::Unknown => "unknown",
        Occupancy::Absent => "absent",
        Occupancy::Moving => "moving",
        Occupancy::Stationary => "stationary",
        Occupancy::Both => "both",
    }
}

/// A decoded record as the reading a reader keeps: from `did` over `reach`,
/// received at `received` on the reader's clock. The record's own fields,
/// nothing inferred: a rate is non-zero only when the sensor accepted it.
#[must_use]
pub fn info(did: &str, reach: &str, p: &Presence, received: Micros) -> PresenceInfo {
    PresenceInfo {
        did: did.to_owned(),
        reach: reach.to_owned(),
        at_us: p.at.0,
        received_us: received.0,
        state: state_word(p.state).to_owned(),
        moving_cm: p.moving_cm,
        moving_energy: p.moving_energy,
        stationary_cm: p.stationary_cm,
        stationary_energy: p.stationary_energy,
        detection_cm: p.detection_cm,
        breathing_bpm_x10: p.breathing_bpm_x10,
        breathing_confidence: p.breathing_confidence,
        heart_bpm_x10: p.heart_bpm_x10,
        heart_confidence: p.heart_confidence,
        fingerprint: p.fingerprint,
    }
}

/// One `janus/media/1` packet into a reading, when it carries one.
///
/// `"tlm "` is the subscribed device's own record, so `own_did` names it;
/// `"nbrt"` is a bridge's neighbour packet, which names its own device. Any
/// other codec, or bytes that are not a record (a version nobody knows, a
/// short frame), is `None`: telemetry that is not presence rides through
/// untouched, and a frame that lies about being one is dropped, not guessed.
#[must_use]
pub fn from_packet(
    codec: [u8; 4],
    payload: &[u8],
    own_did: &str,
    received: Micros,
) -> Option<PresenceInfo> {
    if codec == CODEC_TELEMETRY {
        let p = Presence::decode(payload).ok()?;
        return Some(info(own_did, "iroh", &p, received));
    }
    if codec == CODEC_NEIGHBOUR_TELEMETRY {
        let packet: NeighbourPacket = postcard::from_bytes(payload).ok()?;
        let p = Presence::decode(&packet.payload).ok()?;
        return Some(info(&packet.did, &packet.reach, &p, received));
    }
    None
}

#[cfg(test)]
mod tests {
    use rusty_esp_signal_core::radar::presence::{ENCODED_LEN, V1_LEN};

    use super::*;

    fn record() -> Presence {
        Presence {
            state: Occupancy::Moving,
            moving_energy: 40,
            at: Micros(1_234_567),
            breathing_bpm_x10: 152,
            breathing_confidence: 610,
            heart_bpm_x10: 0,
            heart_confidence: 70,
            fingerprint: 180,
            ..Presence::default()
        }
    }

    fn wire() -> Vec<u8> {
        let mut out = [0u8; ENCODED_LEN];
        let n = record().encode(&mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn a_devices_own_record_reads_with_every_field() {
        let r = from_packet(CODEC_TELEMETRY, &wire(), "did:mata:zDev", Micros(77)).unwrap();
        assert_eq!(r.did, "did:mata:zDev");
        assert_eq!(r.reach, "iroh");
        assert_eq!(r.at_us, 1_234_567);
        assert_eq!(r.received_us, 77);
        assert_eq!(r.state, "moving");
        assert_eq!(r.moving_energy, 40);
        assert_eq!(r.breathing_bpm_x10, 152);
        assert_eq!(r.breathing_confidence, 610);
        assert_eq!((r.heart_bpm_x10, r.heart_confidence), (0, 70));
        assert_eq!(r.fingerprint, 180);
    }

    #[test]
    fn a_version_one_record_reads_with_the_new_fields_zero() {
        // A device flashed before W3: the version byte says 1 and the record
        // stops where version 1 did.
        let mut v1 = wire();
        v1[0] = 1;
        v1.truncate(V1_LEN);
        let r = from_packet(CODEC_TELEMETRY, &v1, "d", Micros(0)).unwrap();
        assert_eq!(r.state, "moving");
        assert_eq!(r.moving_energy, 40);
        assert_eq!(r.breathing_bpm_x10, 0);
        assert_eq!(r.breathing_confidence, 0);
        assert_eq!(r.fingerprint, 0);
    }

    #[test]
    fn a_bridges_packet_names_the_neighbour_it_came_from() {
        let packet = NeighbourPacket {
            did: String::from("did:mata:zC6"),
            reach: String::from("espnow"),
            payload: wire(),
        };
        let bytes = postcard::to_stdvec(&packet).unwrap();
        let r = from_packet(
            CODEC_NEIGHBOUR_TELEMETRY,
            &bytes,
            "did:mata:zBridge",
            Micros(5),
        )
        .unwrap();
        assert_eq!(r.did, "did:mata:zC6", "the neighbour's, not the bridge's");
        assert_eq!(r.reach, "espnow");
        assert_eq!(r.breathing_bpm_x10, 152);
    }

    #[test]
    fn what_is_not_a_record_is_none_not_a_guess() {
        assert!(
            from_packet(*b"mjpg", &wire(), "d", Micros(0)).is_none(),
            "a JPEG is not presence"
        );
        assert!(
            from_packet(CODEC_TELEMETRY, &[0xC6, 1], "d", Micros(0)).is_none(),
            "two bytes"
        );
        let mut unknown = wire();
        unknown[0] = 9;
        assert!(
            from_packet(CODEC_TELEMETRY, &unknown, "d", Micros(0)).is_none(),
            "a version nobody knows"
        );
        let packet = NeighbourPacket {
            did: String::from("did:mata:zC6"),
            reach: String::from("lora"),
            payload: vec![0x1A, 2],
        };
        let bytes = postcard::to_stdvec(&packet).unwrap();
        assert!(
            from_packet(CODEC_NEIGHBOUR_TELEMETRY, &bytes, "d", Micros(0)).is_none(),
            "bytes inside a packet"
        );
        assert!(
            from_packet(CODEC_NEIGHBOUR_TELEMETRY, &wire(), "d", Micros(0)).is_none(),
            "a bare record under the wrong codec"
        );
    }
}
