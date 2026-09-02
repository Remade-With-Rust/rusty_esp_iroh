//! The bridge on a laptop, fronting two simulated neighbours on an
//! in-memory radio bus (a Pi replaces the bus with its serial-attached
//! radios; nothing above the `Radio` seam changes).
//!
//! ```sh
//! cargo run -p rusty_esp_iroh-bridge --example bridge -- 192.168.0.224
//! # then, with the ticket it prints:
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> neighbours
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> media 20
//! ```

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rusty_esp_core::capability::{Capability, Chip, Declared, Manifest};
use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_iroh_bridge::sim::NeighbourSim;
use rusty_esp_iroh_bridge::{Bridge, BridgeCore, FakeBus, HostRng, PeerAddr, Reach};
use rusty_esp_iroh_host::{Extras, Node, NodeConfig, NodeIdentity};
use rusty_esp_mid_core::key::DeviceKey;

const BRIDGE: PeerAddr = [0x10, 0, 0, 0, 0, 0, 0, 0];
const C6: PeerAddr = [0x01, 0xC6, 0, 0, 0, 0, 0, 0];
const LORA: PeerAddr = [0x02, 0x1A, 0, 0, 0, 0, 0, 0];

fn reach_of(addr: &PeerAddr) -> Reach {
    if addr[0] == 0x02 {
        Reach::Lora
    } else {
        Reach::EspNow
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let ips: Vec<IpAddr> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let bus = FakeBus::new();
    let mut kv = MemoryKv::new();
    let mut rng = InsecureTestRng::seeded(rand::random());
    let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "bridge").expect("identity");
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
        model: "janus/bridge-host",
        firmware: env!("CARGO_PKG_VERSION"),
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
        NodeConfig {
            model: String::from("janus/bridge-host"),
            ..NodeConfig::default()
        },
        extras,
    )
    .await
    .expect("bind");
    let ticket = node.refresh_ticket(&ips);
    println!("did:         {}", node.did());
    println!("ticket:      {}", node.ticket_text());
    println!("addrs:       {:?}", ticket.addrs().collect::<Vec<_>>());

    // Two neighbours on the bus, each with its own key and manifest, each
    // sending telemetry once a second.
    let c6_declared = [
        Declared::available(Capability::RadarPresence, "rusty_esp_signal"),
        Declared::available(Capability::EspNow, "rusty_esp_signal"),
    ];
    let c6_manifest = Manifest {
        model: "janus/c6-radar",
        firmware: "0.3.0",
        chip: Chip::Esp32C6,
        declared: &c6_declared,
    };
    let lora_declared = [Declared::available(Capability::LoraP2p, "rusty_esp_signal")];
    let lora_manifest = Manifest {
        model: "janus/lora-node",
        firmware: "0.2.0",
        chip: Chip::Esp32C6,
        declared: &lora_declared,
    };
    let mut c6 = NeighbourSim::new(
        "c6",
        "radar",
        &c6_manifest,
        bus.attach(C6, 250),
        BRIDGE,
        Box::new(HostRng),
    )
    .expect("c6");
    let mut lora = NeighbourSim::new(
        "lora",
        "node",
        &lora_manifest,
        bus.attach(LORA, 255),
        BRIDGE,
        Box::new(HostRng),
    )
    .expect("lora");
    println!(
        "neighbours:  {} (espnow), {} (lora)",
        c6.did_string(),
        lora.did_string()
    );
    let core = bridge.core();
    std::thread::spawn(move || {
        c6.link(Duration::from_secs(3)).expect("c6 link");
        lora.link(Duration::from_secs(3)).expect("lora link");
        c6.send_manifest().expect("c6 manifest");
        lora.send_manifest().expect("lora manifest");
        let mut n = 0u32;
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let presence = u8::from(n % 7 < 3);
            let _ = c6.send_telemetry(&[presence, (n & 0xFF) as u8]);
            let _ = lora.send_telemetry(&(-(60 + (n % 20) as i16)).to_be_bytes());
            n += 1;
        }
    });
    let core = Arc::new(core);
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let c = core.with(|c| c.counters);
        let table = core.neighbours_len();
        println!(
            "bridge: hellos={} linked={} manifests ok/bad={}/{} telemetry={} dropped={} listed={table}",
            c.hellos, c.linked, c.manifests_ok, c.manifests_bad, c.telemetry, c.dropped
        );
    }
}

trait Len {
    fn neighbours_len(&self) -> usize;
}
impl Len for rusty_esp_iroh_bridge::CoreHandle {
    fn neighbours_len(&self) -> usize {
        use rusty_esp_iroh_host::node::NeighbourSource;
        self.neighbours().len()
    }
}
