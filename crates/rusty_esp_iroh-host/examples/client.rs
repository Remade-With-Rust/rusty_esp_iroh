//! Dial a Janus node by ticket.
//!
//! ```sh
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> echo
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> ping|manifest|telemetry|sidecar
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> media <seconds>
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> adopt
//! ```
//!
//! `telemetry` needs an owner key; this example mints a throwaway caller
//! key, so a device that already has an owner answers `Denied` — which is
//! the point.
//!
//! `adopt` makes this example's caller key the device's owner, which the
//! device keeps. It is a deterministic bench key, not a person's identity,
//! and the device says so afterwards by advertising `pair_state=paired`.

use std::time::{Duration, Instant};

use rusty_esp_iroh_core::media::Subscribe;
use rusty_esp_iroh_core::mid::adoption::{AdoptionFields, CapList};
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::ota::OtaManifest;
use rusty_esp_iroh_core::rpc::{Request, Response, RpcError};
use rusty_esp_iroh_core::ticket::Ticket;
use rusty_esp_iroh_host::Client;
use rusty_esp_iroh_host::client::endpoint_addr;

/// The one key this example acts as. Deterministic on purpose: a device it
/// adopts must still recognise it on the next run, and a bench that mints a
/// fresh owner every time can never test what adoption is for.
fn caller_key() -> DeviceKey {
    DeviceKey::from_seed_for_tests("example-client", "laptop")
}

/// A key's `did:mata` as text.
fn did_string(key: &DeviceKey) -> String {
    let mut buf = [0u8; 64];
    key.did()
        .write(&mut buf)
        .map(String::from)
        .unwrap_or_default()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let mut args = std::env::args().skip(1);
    let ticket_text = args.next().expect("ticket");
    let op = args.next().unwrap_or_else(|| "ping".to_string());
    // Before the ticket is parsed, because asking a binary what it can do
    // must not require a device to ask it about.
    if op == "ops" || ticket_text == "ops" {
        println!(
            "ops: echo ping manifest ticket telemetry sidecar neighbours time ota media adopt ops"
        );
        return;
    }
    let ticket = Ticket::parse_text(&ticket_text).expect("valid janus1 ticket");
    let addr = endpoint_addr(&ticket).expect("addr");
    let device_did = ticket
        .did
        .map(|d| {
            let mut buf = [0u8; 64];
            d.write(&mut buf).map(String::from).unwrap_or_default()
        })
        .unwrap_or_default();
    let caller = caller_key();
    let client = Client::bind(None, Some(caller), ticket.relay().is_some())
        .await
        .expect("bind");
    let started = Instant::now();
    match op.as_str() {
        "echo" => {
            let reply = client.echo(&addr, b"hello janus").await.expect("echo");
            println!(
                "echo: {:?} in {:?}",
                String::from_utf8_lossy(&reply),
                started.elapsed()
            );
        }
        "ping" => println!(
            "{:?} in {:?}",
            client.rpc_anonymous(&addr, Request::Ping).await,
            started.elapsed()
        ),
        "manifest" => match client.manifest(&addr).await {
            Ok(m) => {
                println!(
                    "manifest of {} verifies under its DID ({} bytes):",
                    m.did,
                    m.bytes.len()
                );
                if let Ok(text) = std::str::from_utf8(&m.bytes) {
                    for line in text.lines() {
                        println!("  {line}");
                    }
                }
                println!(
                    "  chip {:?}, {} declaration(s)",
                    m.parsed.chip,
                    m.parsed.declared.len()
                );
            }
            Err(e) => println!("manifest: {e}"),
        },
        "ticket" => println!("{:?}", client.rpc_anonymous(&addr, Request::Ticket).await),
        "telemetry" => println!(
            "{:?}",
            client.rpc(&addr, &device_did, Request::Telemetry).await
        ),
        "sidecar" => {
            for req in [
                r#"{"op":"ping"}"#,
                r#"{"op":"status"}"#,
                r#"{"op":"janusTicket"}"#,
            ] {
                println!("{req} -> {:?}", client.sidecar(&addr, req).await);
            }
        }
        "neighbours" => {
            match client
                .rpc_anonymous(&addr, Request::Neighbours)
                .await
                .expect("neighbours")
            {
                Response::Neighbours(list) => {
                    println!("{} neighbour(s)", list.len());
                    for n in list {
                        let ok = rusty_esp_iroh_core::mid::did::Did::parse(&n.did)
                            .ok()
                            .and_then(|d| {
                                let sig: [u8; 64] = n.sig.as_slice().try_into().ok()?;
                                rusty_esp_iroh_core::mid::manifest::verify_manifest(
                                    &n.manifest,
                                    &sig,
                                    d.pubkey(),
                                )
                                .ok()
                            })
                            .is_some();
                        println!(
                            "  {} via {} seen {} ms ago, manifest {} bytes, signature {}",
                            n.did,
                            n.reach,
                            n.last_seen_us / 1000,
                            n.manifest.len(),
                            if ok { "verifies" } else { "DOES NOT VERIFY" }
                        );
                        if let Ok(text) = std::str::from_utf8(&n.manifest) {
                            for line in text.lines() {
                                println!("      {line}");
                            }
                        }
                    }
                }
                other => println!("{other:?}"),
            }
        }
        "time" => {
            let w = client.time(&addr).await.expect("time");
            println!(
                "time: offset known={} error_us={:?} device_at={} -> wall {:?}",
                w.is_known(),
                w.error_us(),
                w.measured_at(),
                w.to_wall(w.measured_at())
            );
        }
        "ota" => {
            // client <ticket> ota <image> <manifest.jota>
            let image_path = args.next().expect("image path");
            let manifest_path = args.next().expect("manifest path (.jota)");
            let image = std::fs::read(&image_path).expect("read image");
            let manifest: OtaManifest =
                serde_json::from_slice(&std::fs::read(&manifest_path).expect("read manifest"))
                    .expect("parse manifest");
            let outcome = client
                .ota(&addr, &device_did, &manifest, &image)
                .await
                .expect("ota");
            println!("ota: {outcome:?}");
        }
        "media" => {
            // client <ticket> media [secs] [out-dir]: with an out-dir every
            // "mjpg" packet is written as frame-<seq>.jpg.
            let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);
            let out_dir = args.next().map(std::path::PathBuf::from);
            if let Some(d) = &out_dir {
                std::fs::create_dir_all(d).expect("out dir");
            }
            let sub = Subscribe {
                codec: *b"any ",
                max_fps: 0,
                max_kbps: 0,
            };
            let mut bytes = 0u64;
            let mut frames = 0u64;
            let mut written = 0u64;
            let mut first_ts = None;
            let mut last_ts = 0u64;
            let mut largest = 0usize;
            let wall = Instant::now();
            let counter = client
                .subscribe(
                    &addr,
                    &sub,
                    u64::MAX,
                    Duration::from_secs(secs),
                    |h, payload| {
                        bytes += payload.len() as u64;
                        largest = largest.max(payload.len());
                        if &h.codec == b"mjpg" {
                            frames += 1;
                            first_ts.get_or_insert(h.timestamp_us);
                            last_ts = h.timestamp_us;
                            let saved = out_dir.as_ref().is_some_and(|d| {
                                std::fs::write(d.join(format!("frame-{:06}.jpg", h.seq)), payload)
                                    .is_ok()
                            });
                            if saved {
                                written += 1;
                            }
                        }
                    },
                )
                .await
                .expect("subscribe");
            let elapsed = wall.elapsed().as_secs_f64();
            println!(
                "media {secs}s: received={} lost={} reordered={} bytes={} ({:.1} pkt/s)",
                counter.received,
                counter.lost,
                counter.reordered,
                bytes,
                counter.received as f64 / elapsed
            );
            if frames > 0 {
                let source_span = last_ts.saturating_sub(first_ts.unwrap_or(0)) as f64 / 1e6;
                println!(
                    "mjpeg: frames={frames} written={written} largest={largest} B receiver_fps={:.2} source_fps={:.2} (source span {:.1} s)",
                    frames as f64 / elapsed,
                    if source_span > 0.0 {
                        (frames - 1) as f64 / source_span
                    } else {
                        0.0
                    },
                    source_span
                );
            }
        }
        "adopt" => {
            // The device's own DID, from its signed manifest rather than from
            // the ticket: adopting the wrong identity is exactly what the
            // device is supposed to refuse, so ask it who it is.
            let did = match client.manifest(&addr).await {
                Ok(m) => m.did,
                Err(e) => {
                    println!("ADOPT fail: no manifest: {e}");
                    return;
                }
            };
            let owner_did = did_string(&caller_key());
            println!("adopt: device {did}");
            println!("adopt: owner  {owner_did}  (a deterministic bench key, not a person)");

            let key = caller_key();
            // The DID has to outlive the borrow of its key material.
            let key_did = key.did();
            let caps = ["media:subscribe@*", "telemetry:read@*"];
            let fields = AdoptionFields {
                device_did: &did,
                owner_did: &owner_did,
                owner_genesis_pubkey: key_did.pubkey(),
                hub_endpoint_id: &[0u8; 32],
                hub_relay: "",
                hub_host: "",
                caps: CapList::Slice(&caps),
                roster_version: 3,
                // The device has no wall clock on a LAN-direct link, so an
                // expiry it cannot evaluate would be worse than none.
                issued_at: 1_700_000_000,
                expires_at: 0,
            };
            let mut buf = vec![0u8; 1024];
            let n = match fields.sign_into(&key, &mut buf) {
                Ok(n) => n,
                Err(e) => {
                    println!("ADOPT fail: could not sign: {e:?}");
                    return;
                }
            };
            buf.truncate(n);
            println!("adopt: signed {n} bytes");

            let accepted = match client.rpc(&addr, &did, Request::Adopt(buf.clone())).await {
                Ok(Response::Adopted { roster_version }) => {
                    println!("adopt: accepted roster_version={roster_version}");
                    true
                }
                Ok(other) => {
                    println!("adopt: refused {other:?}");
                    false
                }
                Err(e) => {
                    println!("adopt: error {e}");
                    false
                }
            };

            // A stranger presenting the owner's own record must be refused:
            // the record is public once it has been sent, and only the key
            // named inside it may use it.
            let stranger = DeviceKey::from_seed_for_tests("adopt-stranger", "laptop");
            let stranger_refused = match Client::bind(None, Some(stranger), false).await {
                Ok(sc) => {
                    let r = matches!(
                        sc.rpc(&addr, &did, Request::Adopt(buf.clone())).await,
                        Ok(Response::Error(RpcError::Denied))
                    );
                    sc.close().await;
                    r
                }
                Err(e) => {
                    println!("adopt: could not bind a stranger: {e}");
                    false
                }
            };
            println!("adopt: stranger presenting the same record refused = {stranger_refused}");

            // An older roster version is how revocation works: once the owner
            // rotates, the device must not accept the superseded record.
            let stale = AdoptionFields {
                roster_version: 2,
                ..fields
            };
            let mut sbuf = vec![0u8; 1024];
            let sn = stale.sign_into(&key, &mut sbuf).unwrap_or(0);
            sbuf.truncate(sn);
            let stale_refused = sn > 0
                && matches!(
                    client.rpc(&addr, &did, Request::Adopt(sbuf)).await,
                    Ok(Response::Error(RpcError::Denied))
                );
            println!("adopt: an older roster version refused = {stale_refused}");

            // And the consequence: being the owner is worth something.
            let owner_reads = matches!(
                client.rpc(&addr, &did, Request::Telemetry).await,
                Ok(Response::Telemetry(_))
            );
            println!("adopt: the owner may read telemetry = {owner_reads}");

            let ok = accepted && stranger_refused && stale_refused && owner_reads;
            println!(
                "ADOPT {} adopted={accepted} stranger_refused={stranger_refused} stale_refused={stale_refused} owner_reads={owner_reads}",
                if ok { "ok" } else { "fail" }
            );
        }
        other => eprintln!("unknown op {other}"),
    }
    client.close().await;
}
