//! A Janus node on the host: prints its DID, endpoint id and ticket, serves
//! echo / rpc / sidecar and a synthetic 10 fps media stream until killed.
//!
//! ```sh
//! cargo run -p rusty_esp_iroh-host --example node -- [ip-to-advertise ...]
//! ```
//!
//! The identity is in-memory here (a fresh DID per run); a device keeps it
//! in NVS through `rusty_esp_mid-esp`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rusty_esp_iroh_core::esp_core::capability::{Capability, Chip, Declared, Manifest};
use rusty_esp_iroh_core::esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_iroh_core::media::{FLAG_KEY, PacketHeader, Subscribe};
use rusty_esp_iroh_host::{MediaSource, Node, NodeConfig, NodeIdentity};

struct Synthetic {
    seq: u32,
    size: usize,
    interval: Duration,
}

impl MediaSource for Synthetic {
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        let header = PacketHeader {
            seq: self.seq,
            timestamp_us: u64::from(self.seq) * self.interval.as_micros() as u64,
            codec: *b"test",
            flags: FLAG_KEY,
            len: self.size as u32,
        };
        self.seq = self.seq.wrapping_add(1);
        Some((header, vec![(self.seq & 0xFF) as u8; self.size]))
    }
    fn interval(&self) -> Duration {
        self.interval
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let ips: Vec<IpAddr> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let mut kv = MemoryKv::new();
    let mut rng = InsecureTestRng::seeded(rand::random());
    let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus").expect("identity");
    let declared = [
        Declared::available(Capability::IrohLanDirect, "rusty_esp_iroh"),
        Declared::available(Capability::MidDevice, "rusty_esp_mid"),
        Declared::preview(Capability::VideoMjpeg, "rusty_esp_video"),
    ];
    let manifest = Manifest {
        model: "janus/host-node",
        firmware: env!("CARGO_PKG_VERSION"),
        chip: Chip::Esp32S3,
        declared: &declared,
    };
    let media = Arc::new(|sub: &Subscribe| -> Box<dyn MediaSource> {
        let fps = if sub.max_fps == 0 { 10 } else { sub.max_fps };
        Box::new(Synthetic {
            seq: 0,
            size: 900,
            interval: Duration::from_millis(1000 / u64::from(fps)),
        })
    });
    let node = Node::bind(
        identity,
        Box::new(kv),
        &manifest,
        Some(media),
        NodeConfig::default(),
    )
    .await
    .expect("bind");
    let ticket = node.refresh_ticket(&ips);
    println!("did:         {}", node.did());
    println!("endpoint id: {}", node.endpoint().id());
    println!("port:        {}", node.port());
    println!("ticket:      {}", node.ticket_text());
    println!("addrs:       {:?}", ticket.addrs().collect::<Vec<_>>());
    println!("sidecar TXT: {:?}", node.sidecar_txt(&ips));
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let c = &node.state().counters;
        println!(
            "echo={} rpc={} refused={} sidecar={} media_subs={} media_pkts={} media_err={}",
            c.echo.load(std::sync::atomic::Ordering::Relaxed),
            c.rpc.load(std::sync::atomic::Ordering::Relaxed),
            c.rpc_refused.load(std::sync::atomic::Ordering::Relaxed),
            c.sidecar.load(std::sync::atomic::Ordering::Relaxed),
            c.media_subscribers
                .load(std::sync::atomic::Ordering::Relaxed),
            c.media_packets.load(std::sync::atomic::Ordering::Relaxed),
            c.media_send_errors
                .load(std::sync::atomic::Ordering::Relaxed),
        );
    }
}
