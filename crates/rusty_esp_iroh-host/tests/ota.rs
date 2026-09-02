//! N5 on one machine: a maker-signed image over `janus/ota/1` into a
//! two-slot model. The order of refusals is the test: a stranger, a bad
//! signature, the wrong maker, chip or model, a tampered image and a power
//! cut all leave the running image alone; a good image commits, boots, and
//! reports its new firmware string; an unvalidated boot rolls back. Plus the
//! one-shot wall offset (C2) over the same link.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use iroh::EndpointAddr;
use rusty_esp_iroh_core::esp_core::capability::{Capability, Chip, Declared, Manifest};
use rusty_esp_iroh_core::esp_core::error::{Error, Result};
use rusty_esp_iroh_core::esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_iroh_core::mid::adoption::{AdoptionFields, CapList};
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::ota::{MemorySlots, OtaManifest, OtaSink};
use rusty_esp_iroh_core::rpc::{Request, Response, RpcError};
use rusty_esp_iroh_host::client::{endpoint_addr, OtaOutcome};
use rusty_esp_iroh_host::{Client, Extras, Node, NodeConfig, NodeIdentity};

/// The slots, shared with the test so it can boot and inspect them while the
/// node holds the sink.
#[derive(Clone)]
struct SharedSlots(Arc<Mutex<MemorySlots>>);

impl SharedSlots {
    fn with<T>(&self, f: impl FnOnce(&mut MemorySlots) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }
}

impl OtaSink for SharedSlots {
    fn begin(&mut self, image_len: u32) -> Result<()> {
        self.0.lock().map_err(|_| Error::Busy)?.begin(image_len)
    }
    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.0.lock().map_err(|_| Error::Busy)?.write(chunk)
    }
    fn finish(&mut self) -> Result<()> {
        self.0.lock().map_err(|_| Error::Busy)?.finish()
    }
    fn abort(&mut self) {
        if let Ok(mut s) = self.0.lock() {
            s.abort();
        }
    }
}

fn did_string(key: &DeviceKey) -> String {
    key.did().to_did_string()
}

const MODEL: &str = "janus/ota-node";

struct Started {
    node: Node,
    slots: SharedSlots,
    did: String,
    addr: EndpointAddr,
}

async fn start_node(maker_did: Option<String>, with_ota_cap: bool) -> Started {
    let mut kv = MemoryKv::new();
    let mut rng = InsecureTestRng::seeded(0x0BAD_F00D);
    let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus").unwrap();
    let mut declared = vec![
        Declared::available(Capability::IrohLanDirect, "rusty_esp_iroh"),
        Declared::available(Capability::MidDevice, "rusty_esp_mid"),
    ];
    if with_ota_cap {
        declared.push(Declared::available(Capability::Ota, "rusty_esp_iroh"));
    }
    let manifest = Manifest {
        model: MODEL,
        firmware: "1.0.0",
        chip: Chip::Esp32S3,
        declared: &declared,
    };
    let slots = SharedSlots(Arc::new(Mutex::new(MemorySlots::new(
        MemorySlots::image("1.0.0", b"the running image"),
        1 << 20,
    ))));
    let extras = Extras {
        maker_did,
        ota: Some(Box::new(slots.clone())),
        neighbours: None,
    };
    let config = NodeConfig {
        model: MODEL.to_string(),
        ..NodeConfig::default()
    };
    let node = Node::bind_with(identity, Box::new(kv), &manifest, None, config, extras)
        .await
        .unwrap();
    let ticket = node.refresh_ticket(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let addr = endpoint_addr(&ticket).unwrap();
    let did = node.did().to_string();
    Started {
        node,
        slots,
        did,
        addr,
    }
}

async fn owner_client() -> Client {
    Client::bind(
        None,
        Some(DeviceKey::from_seed_for_tests("owner", "hub")),
        false,
    )
    .await
    .unwrap()
}

async fn adopt(owner: &DeviceKey, client: &Client, s: &Started) {
    let owner_did = did_string(owner);
    let owner_did_obj = owner.did();
    let caps = ["ota:push@*"];
    let fields = AdoptionFields {
        device_did: &s.did,
        owner_did: &owner_did,
        owner_genesis_pubkey: owner_did_obj.pubkey(),
        hub_endpoint_id: &[0u8; 32],
        hub_relay: "",
        hub_host: "",
        caps: CapList::Slice(&caps),
        roster_version: 1,
        issued_at: 1_700_000_000,
        expires_at: 0,
    };
    let mut adoption = vec![0u8; 1024];
    let n = fields.sign_into(owner, &mut adoption).unwrap();
    adoption.truncate(n);
    assert_eq!(
        client
            .rpc(&s.addr, &s.did, Request::Adopt(adoption))
            .await
            .unwrap(),
        Response::Adopted { roster_version: 1 }
    );
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 131 % 253) as u8).collect()
}

fn refused(o: OtaOutcome) -> String {
    match o {
        OtaOutcome::Refused(RpcError::Refused(s)) => s,
        other => panic!("expected a refusal: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn signed_images_commit_and_every_refusal_leaves_the_running_image_alone() {
    let maker = DeviceKey::from_seed_for_tests("acme", "maker");
    let maker_did = did_string(&maker);
    let s = start_node(Some(maker_did.clone()), true).await;
    let owner = DeviceKey::from_seed_for_tests("owner", "hub");
    let owner_client = owner_client().await;
    let stranger_client = Client::bind(
        None,
        Some(DeviceKey::from_seed_for_tests("stranger", "x")),
        false,
    )
    .await
    .unwrap();
    let anon = Client::bind(None, None, false).await.unwrap();

    let image = MemorySlots::image("1.5.0", &payload(200_000));
    let good =
        OtaManifest::sign(MODEL, "1.5.0", Chip::Esp32S3, &image, &maker_did, &maker).unwrap();
    let running_before = s.slots.with(|m| m.active().to_vec());

    // C2 over the link: the one-shot wall offset is known and bounded.
    let w = anon.time(&s.addr).await.unwrap();
    assert!(w.is_known());
    let err = w.error_us().unwrap();
    assert!(err > 0 && err < 5_000_000, "error {err} us");
    assert!(w.to_wall(w.measured_at()).unwrap() > 1_600_000_000_000_000);

    // Nobody but the owner: anonymous is Unauthorized, a stranger Denied.
    assert_eq!(
        anon.ota(&s.addr, &s.did, &good, &image).await.unwrap(),
        OtaOutcome::Refused(RpcError::Unauthorized)
    );
    adopt(&owner, &owner_client, &s).await;
    assert_eq!(
        stranger_client
            .ota(&s.addr, &s.did, &good, &image)
            .await
            .unwrap(),
        OtaOutcome::Refused(RpcError::Denied)
    );
    // The image rides its own ALPN: Ota on janus/rpc/1 is Unsupported.
    assert_eq!(
        owner_client
            .rpc(&s.addr, &s.did, Request::Ota(good.clone()))
            .await
            .unwrap(),
        Response::Error(RpcError::Unsupported)
    );

    // Every lie is refused before a byte is written.
    let mut bad_sig = good.clone();
    bad_sig.sig[3] ^= 0x40;
    assert_eq!(
        refused(
            owner_client
                .ota(&s.addr, &s.did, &bad_sig, &image)
                .await
                .unwrap()
        ),
        "BadSignature"
    );
    let other_maker = DeviceKey::from_seed_for_tests("evil", "maker");
    let other = OtaManifest::sign(
        MODEL,
        "1.5.0",
        Chip::Esp32S3,
        &image,
        &did_string(&other_maker),
        &other_maker,
    )
    .unwrap();
    assert_eq!(
        refused(
            owner_client
                .ota(&s.addr, &s.did, &other, &image)
                .await
                .unwrap()
        ),
        "WrongMaker"
    );
    let wrong_chip =
        OtaManifest::sign(MODEL, "1.5.0", Chip::Esp32C6, &image, &maker_did, &maker).unwrap();
    assert_eq!(
        refused(
            owner_client
                .ota(&s.addr, &s.did, &wrong_chip, &image)
                .await
                .unwrap()
        ),
        "WrongChip"
    );
    let wrong_model = OtaManifest::sign(
        "janus/other",
        "1.5.0",
        Chip::Esp32S3,
        &image,
        &maker_did,
        &maker,
    )
    .unwrap();
    assert_eq!(
        refused(
            owner_client
                .ota(&s.addr, &s.did, &wrong_model, &image)
                .await
                .unwrap()
        ),
        "WrongModel"
    );
    assert_eq!(s.slots.with(|m| m.active().to_vec()), running_before);
    assert!(!s.slots.with(|m| m.pending()));

    // A tampered image: the manifest passes, the digest does not.
    let mut tampered = image.clone();
    tampered[100_000] ^= 1;
    assert_eq!(
        refused(
            owner_client
                .ota(&s.addr, &s.did, &good, &tampered)
                .await
                .unwrap()
        ),
        "DigestMismatch"
    );
    assert_eq!(s.slots.with(|m| m.active().to_vec()), running_before);
    assert!(!s.slots.with(|m| m.pending()));

    // A power cut after 70 000 bytes: the sink fails, nothing is pending,
    // the running image is byte-identical; the retry commits.
    s.slots.with(|m| m.fail_after = Some(70_000));
    assert_eq!(
        refused(
            owner_client
                .ota(&s.addr, &s.did, &good, &image)
                .await
                .unwrap()
        ),
        "SinkFailed"
    );
    assert_eq!(s.slots.with(|m| m.active().to_vec()), running_before);
    assert!(!s.slots.with(|m| m.pending()));
    s.slots.with(|m| m.fail_after = None);
    match owner_client
        .ota(&s.addr, &s.did, &good, &image)
        .await
        .unwrap()
    {
        OtaOutcome::Committed { firmware, sha256 } => {
            assert_eq!(firmware, "1.5.0");
            assert_eq!(sha256, good.image_sha256);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(s.node.last_ota().as_deref(), Some("1.5.0"));
    assert_eq!(
        s.slots.with(|m| m.active().to_vec()),
        running_before,
        "not until reboot"
    );
    assert!(s.slots.with(|m| m.pending()));
    // Boot: the new image runs and reports its fw line; not validated, the
    // next boot rolls back; validated, it stays.
    s.slots.with(|m| {
        assert_eq!(MemorySlots::firmware_of(m.boot()), Some("1.5.0"));
        assert_eq!(m.boot(), &running_before[..], "rollback");
    });
    match owner_client
        .ota(&s.addr, &s.did, &good, &image)
        .await
        .unwrap()
    {
        OtaOutcome::Committed { .. } => {}
        other => panic!("{other:?}"),
    }
    s.slots.with(|m| {
        m.boot();
        m.mark_valid();
        assert_eq!(MemorySlots::firmware_of(m.boot()), Some("1.5.0"));
        assert_eq!(m.running_firmware(), Some("1.5.0"));
    });
    let c = &s.node.state().counters;
    assert_eq!(c.ota_committed.load(Ordering::Relaxed), 2);
    assert_eq!(c.ota_refused.load(Ordering::Relaxed), 6);
    s.node.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_device_without_the_capability_or_a_maker_refuses_first() {
    let maker = DeviceKey::from_seed_for_tests("acme", "maker");
    let maker_did = did_string(&maker);
    let image = MemorySlots::image("1.5.0", &payload(1000));
    let good =
        OtaManifest::sign(MODEL, "1.5.0", Chip::Esp32S3, &image, &maker_did, &maker).unwrap();
    let owner = DeviceKey::from_seed_for_tests("owner", "hub");
    // No `ota` in the manifest.
    {
        let s = start_node(Some(maker_did.clone()), false).await;
        let client = owner_client().await;
        adopt(&owner, &client, &s).await;
        assert_eq!(
            client.ota(&s.addr, &s.did, &good, &image).await.unwrap(),
            OtaOutcome::Refused(RpcError::Refused("NoOtaCapability".into()))
        );
        assert!(!s.slots.with(|m| m.pending()));
        s.node.shutdown().await;
    }
    // The capability but no trusted maker.
    {
        let s = start_node(None, true).await;
        let client = owner_client().await;
        adopt(&owner, &client, &s).await;
        assert_eq!(
            client.ota(&s.addr, &s.did, &good, &image).await.unwrap(),
            OtaOutcome::Refused(RpcError::Refused("NoMaker".into()))
        );
        assert!(!s.slots.with(|m| m.pending()));
        s.node.shutdown().await;
    }
}
