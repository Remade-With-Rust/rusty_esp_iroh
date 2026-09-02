//! Dial a Janus node by ticket.
//!
//! ```sh
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> echo
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> ping|manifest|telemetry|sidecar
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> media <seconds>
//! ```
//!
//! `telemetry` needs an owner key; this example mints a throwaway caller
//! key, so a device that already has an owner answers `Denied` — which is
//! the point.

use std::time::{Duration, Instant};

use rusty_esp_iroh_core::media::Subscribe;
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::rpc::Request;
use rusty_esp_iroh_core::ticket::Ticket;
use rusty_esp_iroh_host::Client;
use rusty_esp_iroh_host::client::endpoint_addr;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let mut args = std::env::args().skip(1);
    let ticket_text = args.next().expect("ticket");
    let op = args.next().unwrap_or_else(|| "ping".to_string());
    let ticket = Ticket::parse_text(&ticket_text).expect("valid janus1 ticket");
    let addr = endpoint_addr(&ticket).expect("addr");
    let device_did = ticket
        .did
        .map(|d| {
            let mut buf = [0u8; 64];
            d.write(&mut buf).map(String::from).unwrap_or_default()
        })
        .unwrap_or_default();
    let caller = DeviceKey::from_seed_for_tests("example-client", "laptop");
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
        "manifest" => println!("{:?}", client.rpc_anonymous(&addr, Request::Manifest).await),
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
        "media" => {
            let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);
            let sub = Subscribe {
                codec: *b"any ",
                max_fps: 0,
                max_kbps: 0,
            };
            let mut bytes = 0u64;
            let counter = client
                .subscribe(
                    &addr,
                    &sub,
                    u64::MAX,
                    Duration::from_secs(secs),
                    |_h, payload| bytes += payload.len() as u64,
                )
                .await
                .expect("subscribe");
            println!(
                "media {secs}s: received={} lost={} reordered={} bytes={} ({:.1} pkt/s)",
                counter.received,
                counter.lost,
                counter.reordered,
                bytes,
                counter.received as f64 / secs as f64
            );
        }
        other => eprintln!("unknown op {other}"),
    }
    client.close().await;
}
