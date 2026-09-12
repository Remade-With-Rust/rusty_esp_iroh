//! `probe <janus1-ticket> [alpn]` — dial a Janus node with iroh 0.97 and
//! report exactly what happens.
//!
//! The answer this exists for: Janus speaks iroh 1.1, mata-master speaks
//! 0.97, and whether 0.97 can complete a QUIC handshake with 1.1 on a local
//! network had never been tested. A refutation is permanent, so this prints
//! the error verbatim rather than a verdict.
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, PublicKey};
use rusty_esp_iroh_core::ticket::Ticket;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let text = args.next().expect("usage: probe <janus1-ticket> [alpn]");
    let alpn = args.next().unwrap_or_else(|| "janus/echo/1".to_string());
    // A third argument sends real protocol instead of a greeting, so the
    // probe can speak the sidecar contract a pair client speaks.
    let payload_arg = args.next();

    let ticket = match Ticket::parse_text(&text) {
        Ok(t) => t,
        Err(e) => {
            println!("RESULT ticket-parse-failed {e:?}");
            return;
        }
    };
    let addrs: Vec<SocketAddr> = ticket.addrs().collect();
    println!(
        "ticket: endpoint_id {} direct {:?} relay {:?}",
        hex32(&ticket.endpoint_id),
        addrs,
        ticket.relay()
    );

    // 0.97's shape, copied from the client that would really do this:
    // PublicKey -> EndpointAddr::new -> with_ip_addr per direct address.
    let key = match PublicKey::from_bytes(&ticket.endpoint_id) {
        Ok(k) => k,
        Err(e) => {
            println!("RESULT key-rejected-by-097 {e}");
            return;
        }
    };
    println!("0.97 parsed the endpoint key: {key}");
    let mut ea = EndpointAddr::new(key);
    for a in &addrs {
        ea = ea.with_ip_addr(*a);
    }

    // 0.97 takes a preset; N0DisableRelay is the LAN-direct shape a Janus
    // node uses, and it keeps the probe off n0's relays entirely.
    let endpoint = match Endpoint::builder(presets::N0DisableRelay).bind().await {
        Ok(e) => e,
        Err(e) => {
            println!("RESULT 097-bind-failed {e}");
            return;
        }
    };
    println!("0.97 endpoint bound; dialing {alpn:?}");

    let started = Instant::now();
    let conn = match tokio::time::timeout(
        Duration::from_secs(20),
        endpoint.connect(ea, alpn.as_bytes()),
    )
    .await
    {
        Err(_) => {
            println!("RESULT connect-timed-out after 20s under {alpn}");
            return;
        }
        Ok(Err(e)) => {
            println!("RESULT connect-failed after {:?}: {e}", started.elapsed());
            println!("  debug: {e:?}");
            return;
        }
        Ok(Ok(c)) => c,
    };
    println!("CONNECTED in {:?}", started.elapsed());

    // A connection is not an answer. Echo is bytes in, the same bytes out.
    let (mut send, mut recv) = match conn.open_bi().await {
        Ok(p) => p,
        Err(e) => {
            println!("RESULT connected-but-open_bi-failed {e}");
            return;
        }
    };
    let payload: &[u8] = match &payload_arg {
        Some(p) => p.as_bytes(),
        None => b"hello from iroh 0.97",
    };
    if let Err(e) = send.write_all(payload).await {
        println!("RESULT connected-but-write-failed {e}");
        return;
    }
    if let Err(e) = send.finish() {
        println!("RESULT connected-but-finish-failed {e}");
        return;
    }
    match tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(4096)).await {
        Err(_) => println!("RESULT connected-but-no-reply-in-10s"),
        Ok(Err(e)) => println!("RESULT connected-but-read-failed {e}"),
        Ok(Ok(reply)) => {
            let same = reply == payload;
            println!(
                "RESULT ok round-trip {:?} reply {:?} identical={same}",
                started.elapsed(),
                String::from_utf8_lossy(&reply)
            );
        }
    }
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
