//! The robustness gate: every decoder that reads bytes from a peer — the
//! ticket a QR code carries, the binding, an assertion, a media header, a
//! postcard RPC frame, the sidecar's JSON — returns an error on bad input;
//! it never panics. Random inputs from an LCG and mutations of valid
//! encodings, under `catch_unwind` so a failure names the decoder and prints
//! the input.

use std::panic::{AssertUnwindSafe, catch_unwind};

use rusty_esp_iroh_core::assertion::Assertion;
use rusty_esp_iroh_core::binding::Binding;
use rusty_esp_iroh_core::media::PacketHeader;
use rusty_esp_iroh_core::rpc::{Request, Response, decode_frame, frame_len};
use rusty_esp_iroh_core::sidecar::{DeviceInfo, PairState, Tier, handle};
use rusty_esp_iroh_core::ticket::Ticket;
use rusty_esp_iroh_core::{base32, mid};
use rusty_esp_mid_core::DeviceKey;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let n = self.below(max_len + 1);
        (0..n).map(|_| (self.next() >> 56) as u8).collect()
    }

    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        match self.below(6) {
            0 if !v.is_empty() => {
                let i = self.below(v.len());
                v[i] ^= 1 << self.below(8);
            }
            1 if !v.is_empty() => {
                let i = self.below(v.len());
                v[i] = (self.next() >> 56) as u8;
            }
            2 => v.truncate(self.below(v.len() + 1)),
            3 => {
                let extra = self.bytes(16);
                v.extend_from_slice(&extra);
            }
            4 => {
                let i = self.below(v.len() + 1);
                v.insert(i, (self.next() >> 56) as u8);
            }
            _ if !v.is_empty() => {
                let i = self.below(v.len());
                v.remove(i);
            }
            _ => {}
        }
        v
    }
}

fn check<R>(name: &str, input: &[u8], f: impl FnOnce() -> R) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        let hex: String = input.iter().take(256).map(|b| format!("{b:02x}")).collect();
        panic!("{name} panicked on {} bytes: {hex}", input.len());
    }
}

fn device() -> DeviceKey {
    DeviceKey::from_seed_for_tests("no-panic", "cam-1")
}

#[test]
fn ticket_binding_and_assertion_decoders_never_panic() {
    let mut rng = Lcg(0x1204_0001);
    let k = device();
    let did: mid::did::Did = k.did();
    let ticket = Ticket::short([7u8; 32])
        .with_did(did)
        .with_relay("https://relay.mata.network")
        .unwrap()
        .with_addr("192.168.1.42:41641".parse().unwrap())
        .unwrap()
        .with_addr("[fe80::1]:41641".parse().unwrap())
        .unwrap();
    let mut tbuf = [0u8; 512];
    let tn = ticket.encode(&mut tbuf).unwrap();
    let valid_ticket = tbuf[..tn].to_vec();
    let mut text_buf = [0u8; 1024];
    let valid_text = ticket
        .write_text(&mut text_buf)
        .unwrap()
        .as_bytes()
        .to_vec();
    let binding = Binding::sign(k.did(), [9u8; 32], &k);
    let mut bbuf = [0u8; 256];
    let bn = binding.encode(&mut bbuf).unwrap();
    let valid_binding = bbuf[..bn].to_vec();
    let caller = k.did().to_did_string();
    let audience = DeviceKey::from_seed_for_tests("no-panic", "hub")
        .did()
        .to_did_string();
    let assertion = Assertion::sign(&caller, &audience, &[3u8; 32], 1_700_000_000, 60, &k).unwrap();
    let mut abuf = [0u8; 512];
    let an = assertion.encode(&mut abuf).unwrap();
    let valid_assertion = abuf[..an].to_vec();

    for i in 0..20_000 {
        let input = match i % 4 {
            0 => rng.bytes(600),
            1 => rng.mutate(&valid_ticket),
            2 => rng.mutate(&valid_binding),
            _ => rng.mutate(&valid_assertion),
        };
        check("Ticket::decode", &input, || {
            Ticket::decode(&input).map(|t| {
                let mut out = [0u8; 1024];
                let _ = t.write_text(&mut out);
            })
        });
        check("Binding::decode", &input, || {
            Binding::decode(&input).map(|b| b.verify())
        });
        check("Assertion::decode", &input, || {
            Assertion::decode(&input).map(|_| ())
        });
        let text_input = if i % 2 == 0 {
            rng.mutate(&valid_text)
        } else {
            rng.bytes(400)
        };
        let text = String::from_utf8_lossy(&text_input);
        check("Ticket::parse_text", &text_input, || {
            Ticket::parse_text(&text).map(|_| ())
        });
        check("base32::decode", &text_input, || {
            let mut out = [0u8; 512];
            base32::decode(&text, &mut out)
        });
    }
}

#[test]
fn media_header_and_rpc_frames_never_panic() {
    let mut rng = Lcg(0x1204_0002);
    let ping = rusty_esp_iroh_core::rpc::encode_frame(&Request::Ping).unwrap();
    let pong = rusty_esp_iroh_core::rpc::encode_frame(&Response::Pong).unwrap();
    for i in 0..30_000 {
        let input = match i % 3 {
            0 => rng.bytes(300),
            1 => rng.mutate(&ping),
            _ => rng.mutate(&pong),
        };
        check("PacketHeader::parse", &input, || {
            PacketHeader::parse(&input).map(|_| ())
        });
        check("rpc::frame_len", &input, || {
            if input.len() >= 4 {
                let _ = frame_len(&[input[0], input[1], input[2], input[3]]);
            }
        });
        check("rpc::decode_frame::<Request>", &input, || {
            decode_frame::<Request>(&input).map(|_| ())
        });
        check("rpc::decode_frame::<Response>", &input, || {
            decode_frame::<Response>(&input).map(|_| ())
        });
    }
}

#[test]
fn sidecar_handler_never_panics() {
    let mut rng = Lcg(0x1204_0003);
    let k = device();
    let did = k.did().to_did_string();
    let info = DeviceInfo {
        did: &did,
        model: "acme/doorbell-2",
        box_device_id: "box-1",
        pair_state: PairState::Open,
        tier: Tier::BestEffort,
        maker_did: None,
        boots: None,
        crashes: None,
        last_reset: None,
        fw: "1.4.0",
        iroh_node_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        direct_addrs: &["192.168.1.42:41641"],
        relay_urls: &["https://relay.mata.network"],
    };
    let manifest_bytes = b"janus/1\nmodel=acme/doorbell-2\nfw=1.4.0\nchip=esp32s3\n";
    let sig = [5u8; 64];
    let seeds: [&[u8]; 6] = [
        br#"{"op":"ping"}"#,
        br#"{"op":"janusNeighbours"}"#,
        br#"{"op":"janusManifest","nonce":"abc","audience":"home"}"#,
        br#"{"op":"pair","jwt":"eyJ.eyJ.sig","seed":"0102","device_id":"box-1"}"#,
        br#"{"op":"catalog","authorization":"Bearer x"}"#,
        br#"{"op":"","jwt":null}"#,
    ];
    for i in 0..12_000 {
        let input = if i % 3 == 0 {
            rng.bytes(200)
        } else {
            rng.mutate(seeds[i % seeds.len()])
        };
        check("sidecar::handle", &input, || {
            let reply = handle(
                &input,
                &info,
                Some((manifest_bytes, &sig)),
                Some("janus1abc"),
                &[],
            );
            assert!(!reply.is_empty());
        });
    }
}
