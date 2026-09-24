//! The home computer's side of the CSI stream (the RuView plan's W5).
//!
//! A device's frames ride `janus/media/1` as `rusty_esp_signal_core::radar::
//! csi_stream::Sample`s -- under `"csi "` straight from a std device, or
//! inside a bridge's `"nbrc"` packet beside the neighbour's DID. This is
//! where they are read ([`from_packet`]) and where a recording is written
//! in the ledger's own fixture format ([`csv_row`]): `CSI_DATA,rssi,len,i,q,
//! i,q,…`, the shape every oracle under `rusty_esp_signal/tools` and every
//! fixture under `tests/fixtures/csi` already read. A LAN subscriber that
//! writes these lines is the recording rig the plan's hardware steps ask
//! for, with no new tooling.

use rusty_esp_iroh_core::telemetry::{CODEC_CSI, CODEC_NEIGHBOUR_CSI, NeighbourPacket};
use rusty_esp_signal_core::radar::csi_stream::Sample;

/// One sample, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The device the sample is from.
    pub did: String,
    /// `espnow` or `lora` through a bridge, `iroh` straight from a device.
    pub reach: String,
    /// The sample.
    pub sample: Sample,
}

/// One `janus/media/1` packet into a sample, when it carries one.
///
/// `"csi "` is the subscribed device's own stream, so `own_did` names it;
/// `"nbrc"` is a bridge's neighbour packet, which names its own device. Any
/// other codec, or bytes that are not a sample, is `None`: nothing is
/// guessed.
#[must_use]
pub fn from_packet(codec: [u8; 4], payload: &[u8], own_did: &str) -> Option<Received> {
    if codec == CODEC_CSI {
        let sample = Sample::decode(payload).ok()?;
        return Some(Received {
            did: own_did.to_owned(),
            reach: String::from("iroh"),
            sample,
        });
    }
    if codec == CODEC_NEIGHBOUR_CSI {
        let packet: NeighbourPacket = postcard::from_bytes(payload).ok()?;
        let sample = Sample::decode(&packet.payload).ok()?;
        return Some(Received {
            did: packet.did,
            reach: packet.reach,
            sample,
        });
    }
    None
}

/// The sample as one line of the ledger's fixture format:
/// `CSI_DATA,<rssi>,<len>,<i>,<q>,…` with no trailing newline.
#[must_use]
pub fn csv_row(sample: &Sample) -> String {
    let iq = sample.iq();
    let mut row = String::with_capacity(16 + 4 * iq.len());
    row.push_str("CSI_DATA,");
    row.push_str(&sample.rssi.to_string());
    row.push(',');
    row.push_str(&iq.len().to_string());
    for v in iq {
        row.push(',');
        row.push_str(&v.to_string());
    }
    row
}

#[cfg(test)]
mod tests {
    use rusty_esp_core::time::Micros;
    use rusty_esp_signal_core::radar::csi_stream::{MAX_ENCODED_LEN, MAX_IQ, TAG_LLTF_20MHZ};

    use super::*;

    fn sample() -> Sample {
        let mut iq = [0i8; MAX_IQ];
        for (k, v) in iq.iter_mut().enumerate() {
            *v = i8::try_from((k % 41) as i32 - 20).unwrap();
        }
        Sample::from_iq(Micros(1_234_567), -39, 6, TAG_LLTF_20MHZ, &iq).unwrap()
    }

    fn wire() -> Vec<u8> {
        let mut out = [0u8; MAX_ENCODED_LEN];
        let n = sample().encode(&mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn a_devices_own_stream_names_the_device() {
        let r = from_packet(CODEC_CSI, &wire(), "did:mata:zDev").unwrap();
        assert_eq!(r.did, "did:mata:zDev");
        assert_eq!(r.reach, "iroh");
        assert_eq!(r.sample, sample());
    }

    #[test]
    fn a_bridges_packet_names_the_neighbour() {
        let packet = NeighbourPacket {
            did: String::from("did:mata:zC6"),
            reach: String::from("espnow"),
            payload: wire(),
        };
        let bytes = postcard::to_stdvec(&packet).unwrap();
        let r = from_packet(CODEC_NEIGHBOUR_CSI, &bytes, "did:mata:zBridge").unwrap();
        assert_eq!(r.did, "did:mata:zC6");
        assert_eq!(r.reach, "espnow");
        assert_eq!(r.sample.at, Micros(1_234_567));
        assert!(r.sample.features().is_ok());
    }

    #[test]
    fn what_is_not_a_sample_is_none() {
        assert!(from_packet(*b"mjpg", &wire(), "d").is_none());
        assert!(
            from_packet(*b"tlm ", &wire(), "d").is_none(),
            "a presence record is not a sample"
        );
        assert!(from_packet(CODEC_CSI, &[1, 2, 3], "d").is_none());
        assert!(
            from_packet(CODEC_NEIGHBOUR_CSI, &wire(), "d").is_none(),
            "a bare sample under the wrong codec"
        );
    }

    #[test]
    fn a_csv_row_is_the_fixtures_own_format() {
        let row = csv_row(&sample());
        let mut fields = row.split(',');
        assert_eq!(fields.next(), Some("CSI_DATA"));
        assert_eq!(fields.next().and_then(|s| s.parse::<i8>().ok()), Some(-39));
        assert_eq!(
            fields.next().and_then(|s| s.parse::<usize>().ok()),
            Some(128)
        );
        let iq: Vec<i8> = fields.map(|s| s.parse().unwrap()).collect();
        assert_eq!(
            iq.len(),
            128,
            "the parser in tests/csi_capture.rs wants exactly 128"
        );
        assert_eq!(&iq[..], sample().iq());
        assert!(!row.ends_with('\n'));
    }
}
