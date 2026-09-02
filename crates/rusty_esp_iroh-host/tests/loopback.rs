//! N0 on one machine: a node and a client in one process over iroh
//! LAN-direct (relay disabled), pure-Rust TLS. Echo, the authorisation rule
//! end to end (anonymous, stranger, owner, adoption, replay), the signed
//! manifest verifying under the device DID, the sidecar JSON, and a
//! synthetic media stream with the loss counter.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusty_esp_iroh_core::esp_core::capability::{Capability, Chip, Declared, Manifest};
use rusty_esp_iroh_core::esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_iroh_core::media::{FLAG_KEY, PacketHeader, Subscribe};
use rusty_esp_iroh_core::mid::adoption::{AdoptionFields, CapList};
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::mid::manifest::verify_manifest;
use rusty_esp_iroh_core::rpc::{Request, Response, RpcError};
use rusty_esp_iroh_core::ticket::Ticket;
use rusty_esp_iroh_host::client::endpoint_addr;
use rusty_esp_iroh_host::{Client, MediaSource, Node, NodeConfig, NodeIdentity};

struct Synthetic {
    seq: u32,
    size: usize,
    interval: Duration,
    remaining: u32,
}

impl MediaSource for Synthetic {
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let h = PacketHeader {
            seq: self.seq,
            timestamp_us: u64::from(self.seq) * 1000,
            codec: *b"test",
            flags: FLAG_KEY,
            len: self.size as u32,
        };
        self.seq += 1;
        Some((h, vec![0xABu8; self.size]))
    }
    fn interval(&self) -> Duration {
        self.interval
    }
}

fn did_string(key: &DeviceKey) -> String {
    let mut buf = [0u8; 64];
    String::from(key.did().write(&mut buf).unwrap())
}

async fn start_node() -> (Node, Ticket) {
    let mut kv = MemoryKv::new();
    let mut rng = InsecureTestRng::seeded(0xC0FFEE);
    let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus").unwrap();
    let declared = [
        Declared::available(Capability::IrohLanDirect, "rusty_esp_iroh"),
        Declared::available(Capability::MidDevice, "rusty_esp_mid"),
    ];
    let manifest = Manifest {
        model: "janus/test-node",
        firmware: "0.1.0-test",
        chip: Chip::Esp32S3,
        declared: &declared,
    };
    let media = Arc::new(|sub: &Subscribe| -> Box<dyn MediaSource> {
        Box::new(Synthetic {
            seq: 0,
            size: if sub.max_kbps == 0 { 900 } else { 4000 },
            interval: Duration::from_millis(5),
            remaining: 400,
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
    .unwrap();
    let ticket = node.refresh_ticket(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    (node, ticket)
}

#[tokio::test(flavor = "current_thread")]
async fn echo_rpc_adoption_sidecar_and_media_over_loopback() {
    let (node, ticket) = start_node().await;
    let device_did = node.did().to_string();
    let addr = endpoint_addr(&ticket).unwrap();
    assert!(ticket.did.is_some());
    assert_eq!(ticket.addrs().count(), 1);

    let owner = DeviceKey::from_seed_for_tests("owner", "hub");
    let stranger = DeviceKey::from_seed_for_tests("stranger", "x");
    let anon = Client::bind(None, None, false).await.unwrap();
    let owner_client = Client::bind(
        None,
        Some(DeviceKey::from_seed_for_tests("owner", "hub")),
        false,
    )
    .await
    .unwrap();
    let stranger_client = Client::bind(None, Some(stranger), false).await.unwrap();

    // Echo, with the RTT for the ledger.
    let t0 = Instant::now();
    let reply = anon.echo(&addr, b"janus").await.unwrap();
    let echo_rtt = t0.elapsed();
    assert_eq!(reply, b"janus");
    let mut rtts = Vec::new();
    for _ in 0..10 {
        let t = Instant::now();
        anon.echo(&addr, b"x").await.unwrap();
        rtts.push(t.elapsed());
    }
    rtts.sort();
    eprintln!(
        "echo: first {echo_rtt:?}, then min {:?} median {:?} over 10",
        rtts[0], rtts[5]
    );

    // Public requests without an assertion.
    assert_eq!(
        anon.rpc_anonymous(&addr, Request::Ping).await.unwrap(),
        Response::Pong
    );
    match anon.rpc_anonymous(&addr, Request::Manifest).await.unwrap() {
        Response::Manifest { bytes, sig, did } => {
            assert_eq!(did, device_did);
            let sig: [u8; 64] = sig.try_into().unwrap();
            verify_manifest(&bytes, &sig, node.identity().did().pubkey()).unwrap();
            assert!(bytes.windows(15).any(|w| w == b"janus/test-node"));
        }
        other => panic!("{other:?}"),
    }
    // Owner-only without an assertion: Unauthorized.
    assert_eq!(
        anon.rpc_anonymous(&addr, Request::Telemetry).await.unwrap(),
        Response::Error(RpcError::Unauthorized)
    );
    // Stranger with a valid assertion before adoption: Denied.
    assert_eq!(
        stranger_client
            .rpc(&addr, &device_did, Request::Telemetry)
            .await
            .unwrap(),
        Response::Error(RpcError::Denied)
    );
    assert!(!node.is_adopted());

    // The owner adopts the device.
    let owner_did = did_string(&owner);
    let owner_did_obj = owner.did();
    let caps = ["media:subscribe@*", "telemetry:read@*"];
    let fields = AdoptionFields {
        device_did: &device_did,
        owner_did: &owner_did,
        owner_genesis_pubkey: owner_did_obj.pubkey(),
        hub_endpoint_id: &[0u8; 32],
        hub_relay: "",
        hub_host: "",
        caps: CapList::Slice(&caps),
        roster_version: 3,
        issued_at: 1_700_000_000,
        expires_at: 0,
    };
    let mut adoption = vec![0u8; 1024];
    let n = fields.sign_into(&owner, &mut adoption).unwrap();
    adoption.truncate(n);
    eprintln!("adoption: {n} bytes");
    // A stranger presenting the owner's adoption is refused.
    assert_eq!(
        stranger_client
            .rpc(&addr, &device_did, Request::Adopt(adoption.clone()))
            .await
            .unwrap(),
        Response::Error(RpcError::Denied)
    );
    assert_eq!(
        owner_client
            .rpc(&addr, &device_did, Request::Adopt(adoption.clone()))
            .await
            .unwrap(),
        Response::Adopted { roster_version: 3 }
    );
    assert!(node.is_adopted());
    // Now the owner may read telemetry; the stranger still may not; an older
    // roster version is refused (revocation by rotation).
    match owner_client
        .rpc(&addr, &device_did, Request::Telemetry)
        .await
        .unwrap()
    {
        Response::Telemetry(t) => assert!(t.fw.starts_with("rusty_esp_iroh")),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        stranger_client
            .rpc(&addr, &device_did, Request::Telemetry)
            .await
            .unwrap(),
        Response::Error(RpcError::Denied)
    );
    let stale = AdoptionFields {
        roster_version: 2,
        ..fields
    };
    let mut stale_bytes = vec![0u8; 1024];
    let m = stale.sign_into(&owner, &mut stale_bytes).unwrap();
    stale_bytes.truncate(m);
    assert_eq!(
        owner_client
            .rpc(&addr, &device_did, Request::Adopt(stale_bytes))
            .await
            .unwrap(),
        Response::Error(RpcError::Denied)
    );

    // Sidecar JSON, as the home computer speaks it.
    let ping = anon.sidecar(&addr, r#"{"op":"ping"}"#).await.unwrap();
    assert!(ping.ok);
    assert_eq!(ping.body.unwrap()["ping"], "mata-oem-sidecar-ok");
    let status = anon.sidecar(&addr, r#"{"op":"status"}"#).await.unwrap();
    let body = status.body.unwrap();
    assert_eq!(body["pair"], "paired");
    assert_eq!(body["model"], "janus/node");
    let tk = anon
        .sidecar(&addr, r#"{"op":"janusTicket"}"#)
        .await
        .unwrap();
    let text = tk.body.unwrap()["ticket"].as_str().unwrap().to_string();
    assert_eq!(
        Ticket::parse_text(&text).unwrap().endpoint_id,
        ticket.endpoint_id
    );
    let txt = node.sidecar_txt(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert!(txt.iter().any(|(k, v)| k == "kind" && v == "oem_sidecar"));
    assert!(txt.iter().any(|(k, v)| k == "pair_state" && v == "paired"));

    // Media: 400 packets at 5 ms as datagrams, then 4000-byte ones as uni-streams.
    let sub = Subscribe {
        codec: *b"test",
        max_fps: 0,
        max_kbps: 0,
    };
    let t0 = Instant::now();
    let mut bytes = 0u64;
    let counter = anon
        .subscribe(&addr, &sub, 400, Duration::from_secs(20), |_h, p| {
            bytes += p.len() as u64
        })
        .await
        .unwrap();
    let elapsed = t0.elapsed();
    eprintln!(
        "media datagrams: received {} lost {} reordered {} bytes {} in {elapsed:?}",
        counter.received, counter.lost, counter.reordered, bytes
    );
    assert!(counter.received >= 380, "received {}", counter.received);
    assert_eq!(bytes, counter.received * 900);
    let big = Subscribe {
        codec: *b"test",
        max_fps: 0,
        max_kbps: 1,
    };
    let counter2 = anon
        .subscribe(&addr, &big, 100, Duration::from_secs(20), |_h, p| {
            assert_eq!(p.len(), 4000)
        })
        .await
        .unwrap();
    eprintln!(
        "media uni-streams: received {} lost {}",
        counter2.received, counter2.lost
    );
    assert_eq!(counter2.received, 100);
    assert_eq!(counter2.lost, 0);

    let c = &node.state().counters;
    eprintln!(
        "node counters: echo {} rpc {} refused {} sidecar {} media_subs {} media_pkts {} media_err {}",
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
    assert_eq!(c.rpc_refused.load(std::sync::atomic::Ordering::Relaxed), 5);

    anon.close().await;
    owner_client.close().await;
    stranger_client.close().await;
    node.shutdown().await;
}
