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
pub mod csi;
pub mod error;
pub mod identity;
pub mod mjpeg;
pub mod node;
pub mod presence;
#[cfg(feature = "relay")]
pub mod relay;

pub use client::Client;
pub use error::HostError;
pub use identity::NodeIdentity;
pub use node::{BootStats, Extras, MediaSource, NeighbourSource, Node, NodeConfig};

/// Apply the reach tier to an endpoint builder: LAN-direct (relay disabled)
/// or, with the `relay` feature, n0's relays + pkarr through [`relay::apply`].
/// Asking for relay without the feature is an error, not a silent downgrade.
pub fn configure_reach(
    builder: iroh::endpoint::Builder,
    relay: bool,
) -> error::Result<iroh::endpoint::Builder> {
    if !relay {
        return Ok(builder.relay_mode(iroh::RelayMode::Disabled));
    }
    #[cfg(feature = "relay")]
    {
        Ok(relay::apply(builder))
    }
    #[cfg(not(feature = "relay"))]
    {
        Err(HostError::Bind(String::from(
            "relay requested but rusty_esp_iroh-host was built without the `relay` feature",
        )))
    }
}

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
