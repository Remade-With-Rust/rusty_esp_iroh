#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_iroh` — The MATA mesh on the chip: an iroh endpoint on ESP32 (std/ESP-IDF track), Janus ALPN protocols (rpc, media, telemetry), a host client, and a bridge that fronts no_std nodes on the mesh. Replaces cloud-IoT device SDKs.
//!
//! This is the facade: it re-exports the `no_std` core and exposes the
//! chip backends under [`esp`]. Depend on this crate; reach into the
//! sub-crates only when you are building a backend.
//!
//! Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_iroh.md`.

pub use rusty_esp_iroh_core::*;

/// Chip backends (`esp-hal` for Track B, `esp-idf` for Track A).
pub mod esp {
    pub use rusty_esp_iroh_esp::*;
}

/// The names a sketch or firmware wants in scope.
pub mod prelude {
    pub use rusty_esp_iroh_core::prelude::*;
}
