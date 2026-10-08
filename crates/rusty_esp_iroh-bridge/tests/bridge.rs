//! N3 on one machine: a bridge over an in-memory radio bus fronting a C6
//! (ESP-NOW) and a LoRa node, each linked by the signal session and each
//! sending its own signed manifest; an iroh client lists them, verifies
//! each manifest under the neighbour's DID, and receives their telemetry
//! attributed to the right one. An impostor's manifest is refused, a
//! replayed frame is dropped.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rusty_esp_core::capability::{Capability, Chip, Declared, Manifest, ParsedManifest};
use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_iroh_bridge::sim::NeighbourSim;
use rusty_esp_iroh_bridge::{
    Bridge, BridgeCore, CODEC_NEIGHBOUR_TELEMETRY, FakeBus, HostRng, NeighbourPacket, PeerAddr,
    Reach,
};
use rusty_esp_iroh_core::media::Subscribe;
use rusty_esp_iroh_core::rpc::{Request, Response};
use rusty_esp_iroh_host::client::endpoint_addr;
use rusty_esp_iroh_host::{Client, Extras, Node, NodeConfig, NodeIdentity};
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_core::manifest::verify_manifest;

const BRIDGE: PeerAddr = [0x10, 0, 0, 0, 0, 0, 0, 0];
const C6: PeerAddr = [0x01, 0xC6, 0, 0, 0, 0, 0, 0];
const LORA: PeerAddr = [0x02, 0x1A, 0, 0, 0, 0, 0, 0];
const IMPOSTOR: PeerAddr = [0x01, 0xBA, 0xD0, 0, 0, 0, 0, 0];
const STRANGER: PeerAddr = [0x01, 0xBA, 0xD0, 0, 0, 0, 0, 0x77];

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn reach_of(addr: &PeerAddr) -> Reach {
    if addr[0] == 0x02 {
        Reach::Lora
    } else {
        Reach::EspNow
    }
}

#[tokio::test(flavor = "current_thread")]
async fn neighbours_appear_through_the_bridge_with_their_own_signed_manifests() {
    let bus = FakeBus::new();
    // The bridge: its iroh identity's device key is the key the neighbours
    // authenticate.
    let mut kv = MemoryKv::new();
    let mut rng = InsecureTestRng::seeded(0xB21D6E);
    let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "bridge").unwrap();
    // The bridge's own key is the iroh identity's device key (DeviceKey is
    // not Clone: rebuild it from the secret).
    let me = DeviceKey::from_secret(
        &identity.device.secret_bytes(),
        identity.device.device_id().as_str(),
    )
    .expect("bridge key");
    let core = BridgeCore::new(me, Box::new(HostRng), reach_of);
    let bridge = Bridge::start(core, bus.attach(BRIDGE, 250));
    let declared = [
        Declared::available(Capability::IrohLanDirect, "rusty_esp_iroh"),
        Declared::available(Capability::EspNow, "rusty_esp_signal"),
        Declared::available(Capability::LoraP2p, "rusty_esp_signal"),
        Declared::available(Capability::Telemetry, "rusty_esp_iroh-bridge"),
    ];
    let manifest = Manifest {
        model: "janus/bridge-pi",
        firmware: "0.1.0-test",
        chip: Chip::Esp32P4,
        declared: &declared,
    };
    let extras = Extras {
        maker_did: None,
        ota: None,
        neighbours: Some(bridge.neighbour_source()),
    };
    let node = Node::bind_with(
        identity,
        Box::new(kv),
        &manifest,
        Some(bridge.media_factory()),
        NodeConfig::default(),
        extras,
    )
    .await
    .unwrap();
    let ticket = node.refresh_ticket(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let addr = endpoint_addr(&ticket).unwrap();

    // Two neighbours with their own keys and manifests.
    let c6_declared = [
        Declared::available(Capability::RadarPresence, "rusty_esp_signal"),
        Declared::available(Capability::EspNow, "rusty_esp_signal"),
        Declared::available(Capability::MidDevice, "rusty_esp_mid"),
    ];
    let c6_manifest = Manifest {
        model: "janus/c6-radar",
        firmware: "0.3.0",
        chip: Chip::Esp32C6,
        declared: &c6_declared,
    };
    let mut c6 = NeighbourSim::new(
        "c6",
        "radar",
        &c6_manifest,
        bus.attach(C6, 250),
        BRIDGE,
        Box::new(HostRng),
    )
    .unwrap();
    let lora_declared = [
        Declared::available(Capability::LoraP2p, "rusty_esp_signal"),
        Declared::available(Capability::Telemetry, "rusty_esp_signal"),
    ];
    let lora_manifest = Manifest {
        model: "janus/lora-node",
        firmware: "0.2.0",
        chip: Chip::Esp32C6,
        declared: &lora_declared,
    };
    let mut lora = NeighbourSim::new(
        "lora",
        "node",
        &lora_manifest,
        bus.attach(LORA, 255),
        BRIDGE,
        Box::new(HostRng),
    )
    .unwrap();
    let mut impostor = NeighbourSim::new(
        "impostor",
        "x",
        &c6_manifest,
        bus.attach(IMPOSTOR, 250),
        BRIDGE,
        Box::new(HostRng),
    )
    .unwrap();
    impostor.forge_signature("someone-else");
    // Not on the roster: a valid key, a valid hello, and no answer.
    let mut stranger = NeighbourSim::new(
        "stranger",
        "y",
        &c6_manifest,
        bus.attach(STRANGER, 250),
        BRIDGE,
        Box::new(HostRng),
    )
    .unwrap();

    // The roster. The impostor is on it: it is an adopted device whose
    // manifest signature is forged, and that arm is the manifest check's,
    // not the handshake's. The stranger is not.
    for did in [c6.did_string(), lora.did_string(), impostor.did_string()] {
        bridge
            .core()
            .with(|c| assert!(c.allow(Did::parse(&did).unwrap()), "{did} listed twice"));
    }

    let t = Duration::from_secs(3);
    c6.link(t).unwrap();
    lora.link(t).unwrap();
    impostor.link(t).unwrap();
    assert!(
        stranger.link(Duration::from_millis(700)).is_err(),
        "a DID not on the roster gets no accept"
    );
    c6.send_manifest().unwrap();
    lora.send_manifest().unwrap();
    impostor.send_manifest().unwrap();
    for i in 0..5u8 {
        c6.send_telemetry(&[0xC6, i]).unwrap();
    }
    for i in 0..3u8 {
        lora.send_telemetry(&[0x1A, i]).unwrap();
    }
    // a replay of the LoRa node's last frame, and a forged frame
    let replay = lora.last_sealed().unwrap().to_vec();
    lora.send_raw(&replay).unwrap();
    lora.send_raw(&[0x01, 0, 0, 0, 0, 0, 0, 0xEE, 0xEE])
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let counters = bridge.core().with(|c| c.counters);
    assert_eq!(counters.hellos, 3, "answered: the three on the roster");
    assert_eq!(
        counters.denied, 1,
        "the stranger, refused before any key material"
    );
    assert_eq!(counters.linked, 3);
    assert_eq!(counters.manifests_ok, 2, "{counters:?}");
    assert_eq!(counters.manifests_bad, 1, "the impostor's manifest");
    assert_eq!(counters.telemetry, 8);
    assert!(counters.dropped >= 2, "replay + forgery: {counters:?}");

    // The home computer's view: two neighbours, each manifest verifying
    // under the neighbour's own DID, not the bridge's.
    let client = Client::bind(None, None, false).await.unwrap();
    let listed = match client
        .rpc_anonymous(&addr, Request::Neighbours)
        .await
        .unwrap()
    {
        Response::Neighbours(n) => n,
        other => panic!("{other:?}"),
    };
    assert_eq!(listed.len(), 2, "{listed:?}");
    let bridge_did = node.did().to_string();
    for n in &listed {
        assert_ne!(n.did, bridge_did);
        let did = Did::parse(&n.did).unwrap();
        let sig: [u8; 64] = n.sig.as_slice().try_into().unwrap();
        verify_manifest(&n.manifest, &sig, did.pubkey()).unwrap();
        let parsed = ParsedManifest::parse(&n.manifest).unwrap();
        match n.reach.as_str() {
            "espnow" => {
                assert_eq!(n.did, c6.did_string());
                assert_eq!(parsed.model, "janus/c6-radar");
                assert!(parsed.has(Capability::RadarPresence));
                assert_eq!(&n.manifest[..], c6.signed_manifest().0);
            }
            "lora" => {
                assert_eq!(n.did, lora.did_string());
                assert_eq!(parsed.model, "janus/lora-node");
            }
            other => panic!("reach {other}"),
        }
        assert!(n.last_seen_us < 5_000_000);
    }
    assert!(!listed.iter().any(|n| n.did == impostor.did_string()));
    assert!(!listed.iter().any(|n| n.did == stranger.did_string()));
    // The bridge's own manifest through the verified fetch.
    let own = client.manifest(&addr).await.unwrap();
    assert_eq!(own.did, bridge_did);
    assert_eq!(own.parsed.model, "janus/bridge-pi");
    assert!(own.parsed.has(Capability::EspNow));
    // And the same table over the home computer's sidecar RPC (N4).
    let reply = client
        .sidecar(&addr, r#"{"op":"janusNeighbours"}"#)
        .await
        .unwrap();
    assert!(reply.ok, "{reply:?}");
    let body = reply.body.unwrap();
    assert_eq!(body["did"], bridge_did);
    let over_sidecar = body["neighbours"].as_array().unwrap();
    assert_eq!(over_sidecar.len(), 2);
    for n in over_sidecar {
        let did = Did::parse(n["did"].as_str().unwrap()).unwrap();
        let manifest = hex_bytes(n["manifest_hex"].as_str().unwrap());
        let sig: [u8; 64] = hex_bytes(n["sig_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        verify_manifest(&manifest, &sig, did.pubkey()).unwrap();
        assert!(matches!(n["reach"].as_str(), Some("espnow" | "lora")));
    }

    // Telemetry over janus/media/1, attributed.
    let sub = Subscribe {
        codec: CODEC_NEIGHBOUR_TELEMETRY,
        max_fps: 0,
        max_kbps: 0,
    };
    let mut got: Vec<NeighbourPacket> = Vec::new();
    let subscriber = Client::bind(None, None, false).await.unwrap();
    // send while subscribed: the fan-out starts at subscription time
    let sender = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(500));
        for i in 10..14u8 {
            c6.send_telemetry(&[0xC6, i]).unwrap();
            lora.send_telemetry(&[0x1A, i]).unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        (c6, lora)
    });
    let counter = subscriber
        .subscribe(&addr, &sub, 8, Duration::from_secs(10), |h, payload| {
            assert_eq!(h.codec, CODEC_NEIGHBOUR_TELEMETRY);
            got.push(postcard::from_bytes(payload).unwrap());
        })
        .await
        .unwrap();
    let (c6, lora) = sender.await.unwrap();
    assert_eq!(counter.received, 8, "{counter:?}");
    assert_eq!(counter.lost, 0);
    let from_c6 = got
        .iter()
        .filter(|p| p.did == c6.did_string() && p.reach == "espnow")
        .count();
    let from_lora = got
        .iter()
        .filter(|p| p.did == lora.did_string() && p.reach == "lora")
        .count();
    assert_eq!((from_c6, from_lora), (4, 4), "{got:?}");
    assert!(got.iter().all(|p| p.payload.len() == 2));

    node.shutdown().await;
    bridge.stop();
}
