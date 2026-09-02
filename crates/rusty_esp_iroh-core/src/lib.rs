#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_iroh-core` — the Janus mesh protocols, with no sockets in them.
//!
//! iroh itself runs on Track A only (`rusty_esp_iroh-esp`) and on hosts
//! (`rusty_esp_iroh-host`). What every node, host, bridge and `no_std`
//! neighbour must agree on lives here, testable on a laptop:
//!
//! | module | what |
//! |---|---|
//! | [`alpn`] | the ALPN strings and frame limits |
//! | [`ticket`] | the QR / serial rendezvous ticket: endpoint id, DID, relay, addresses — `janus1…` text, no heap |
//! | [`binding`] | the device key's signature over its iroh `EndpointId` — how a DID resolves to an endpoint |
//! | [`assertion`] | the caller's mID assertion every RPC carries (the kms nonce-envelope shape) |
//! | [`rpc`] | `janus/rpc/1`: postcard requests and responses with length-prefixed framing, and the authorisation rule |
//! | [`media`] | `janus/media/1`: subscribe message and the packet header |
//! | [`sidecar`] | `mata-oem-sidecar/rpc/1`: the home computer's existing JSON RPC and mDNS TXT contract, answered by a device |
//!
//! Rules (from the Janus mission plan): `no_std` by default; `alloc` is a
//! feature; nothing here allocates on a per-packet path except the postcard
//! codec, which is what `alloc` is for; every type that crosses to another
//! Janus package comes from `rusty_esp_core` or `rusty_esp_mid-core`;
//! `forbid(unsafe)`.

#[cfg(feature = "alloc")]
extern crate alloc;

pub use rusty_esp_core as esp_core;
pub use rusty_esp_mid_core as mid;

pub mod alpn;
pub mod assertion;
pub mod base32;
pub mod binding;
pub mod ticket;

#[cfg(feature = "alloc")]
pub mod media;
#[cfg(feature = "alloc")]
pub mod rpc;
#[cfg(feature = "alloc")]
pub mod sidecar;

pub use binding::Binding;
pub use ticket::Ticket;

/// The names a firmware or a host wants in scope.
pub mod prelude {
    pub use crate::alpn;
    pub use crate::assertion::Assertion;
    pub use crate::binding::Binding;
    pub use crate::ticket::Ticket;
    pub use rusty_esp_core::prelude::*;
    pub use rusty_esp_mid_core::prelude::*;
}

/// Crate version, for capability manifests and logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
