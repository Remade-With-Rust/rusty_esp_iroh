#![forbid(unsafe_code)]
//! `rusty_esp_iroh-host` — a Janus node and its client over iroh 1.x, in std.
//!
//! The same code runs on a laptop, a Pi and, as Track A, on ESP-IDF; only the
//! key store and the radio bring-up differ (`rusty_esp_iroh-esp`). TLS is pure
//! Rust throughout — rustls with the rustls-rustcrypto provider n0 proved on
//! ESP32 — so there is no `ring` and no `aws-lc` anywhere in the graph.
//!
//! | module | what |
//! |---|---|
//! | [`identity`] | the device key (P-256, mID) and the endpoint key (ed25519, iroh) from the `Kv` seam, bound by a signed [`core::binding::Binding`] |
//! | [`node`] | a Janus node: `janus/echo/1`, `janus/rpc/1`, `janus/media/1` and `mata-oem-sidecar/rpc/1` on one endpoint |
//! | [`client`] | dial by ticket: echo, rpc with an mID assertion, sidecar JSON, media subscribe with a loss counter |
//! | [`crypto`] | the QUIC-capable rustls-rustcrypto provider (AES-128-GCM + X25519), vendored from n0's ESP32 examples |

pub use rusty_esp_iroh_core as core;

pub mod client;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod node;

pub use client::Client;
pub use error::HostError;
pub use identity::NodeIdentity;
pub use node::{MediaSource, Node, NodeConfig};

/// Unix seconds now, when the clock looks set (after Sept 2020); `None`
/// before SNTP on a chip, which the assertion and adoption checks accept.
#[must_use]
pub fn now_unix() -> Option<u64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    (secs > 1_600_000_000).then_some(secs)
}
