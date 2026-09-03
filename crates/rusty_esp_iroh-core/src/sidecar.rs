//! `mata-oem-sidecar/rpc/1` and `_mata-oem-sidecar._tcp.local.`: the home
//! computer's **existing** contract for a maker's box, answered by a Janus
//! device so it shows up in the owner app on day one with no home-computer
//! change. Shapes and field names follow `mata-oem-sidecar`
//! (`hardware-deployer-core::wire`, `hardware-deployer-api::{rpc, mesh}`) and
//! what `home-computer-pair-client::discovery` reads back.
//!
//! What a Janus device answers: `ping`, `catalog`, `status` (public: a device
//! has nothing secret in its status), and two Janus ops the sidecar does not
//! have — `janusManifest` (the signed capability manifest) and `janusTicket`
//! (the rendezvous ticket). Everything else is `unknown op`, in the sidecar's
//! own words.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::rpc::NeighbourInfo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// mDNS service type (the pair client browses for it).
pub const SERVICE_TYPE: &str = "_mata-oem-sidecar._tcp.local.";
/// Port the sidecar publishes; a Janus device publishes its iroh UDP port instead.
pub const DEFAULT_PORT: u16 = 4243;
/// TXT `protocol=`.
pub const MDNS_PROTOCOL: &str = "1";
/// TXT `kind=`; what makes the pair client render it as an OEM box.
pub const TXT_KIND: &str = "oem_sidecar";
/// The `ping` reply body.
pub const PING_REPLY: &str = "mata-oem-sidecar-ok";
/// The ALPN label as the TXT record spells it.
pub const ALPN_LABEL: &str = "mata-oem-sidecar/rpc/1";

/// Pair state wire tags (`hardware-deployer-core::PairState::wire_tag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Not yet adopted: `open`.
    Open,
    /// Adopted: `paired`.
    Paired,
}

impl PairState {
    /// The TXT / JSON tag.
    #[must_use]
    pub const fn wire_tag(self) -> &'static str {
        match self {
            PairState::Open => "open",
            PairState::Paired => "paired",
        }
    }
}

/// Provenance tier wire tags (`ProvenanceTier::wire_tag`): `r` / `c` / `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Reference (key never leaves silicon).
    Reference,
    /// Certified (maker manifest verifies).
    Certified,
    /// Best effort / bring-your-own.
    BestEffort,
}

impl Tier {
    /// The TXT / JSON tag.
    #[must_use]
    pub const fn wire_tag(self) -> &'static str {
        match self {
            Tier::Reference => "r",
            Tier::Certified => "c",
            Tier::BestEffort => "b",
        }
    }
}

/// What the device advertises and answers about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo<'a> {
    /// The device DID.
    pub did: &'a str,
    /// `model=` — `janus/<kind>`, e.g. `janus/camera`.
    pub model: &'a str,
    /// `box_device_id=` — the pair client parses this as a UUID; give it one
    /// (derive it from the DID: [`device_uuid`]).
    pub box_device_id: &'a str,
    /// Adopted or not.
    pub pair_state: PairState,
    /// Provenance tier.
    pub tier: Tier,
    /// The maker's DID when the maker manifest is present.
    pub maker_did: Option<&'a str>,
    /// Firmware identifier for `version=`.
    pub fw: &'a str,
    /// The iroh endpoint id (base32 as iroh prints it) when the endpoint is up.
    pub iroh_node_id: Option<&'a str>,
    /// Direct `ip:port` strings.
    pub direct_addrs: &'a [&'a str],
    /// Relay URLs.
    pub relay_urls: &'a [&'a str],
}

/// A UUID-shaped string derived from a DID so `box_device_id` parses on the
/// pair client: the first 16 bytes of SHA-256(did), version nibble 4.
#[must_use]
pub fn device_uuid(did: &str) -> String {
    let h = rusty_esp_mid_core::sha256(did.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|x| format!("{x:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

/// The TXT record, key by key, as `hardware-deployer-api::mesh::mesh_txt`
/// builds it, plus `did=`.
#[must_use]
pub fn txt_record(info: &DeviceInfo<'_>) -> Vec<(String, String)> {
    let mut txt: Vec<(String, String)> = Vec::new();
    let mut put = |k: &str, v: String| txt.push((k.to_string(), v));
    put("version", info.fw.to_string());
    put("protocol", MDNS_PROTOCOL.to_string());
    put("kind", TXT_KIND.to_string());
    put("sku", "best_effort".to_string());
    put("tier", info.tier.wire_tag().to_string());
    put("capability", "mesh+radio".to_string());
    put("pair_state", info.pair_state.wire_tag().to_string());
    put("box_device_id", info.box_device_id.to_string());
    put("iroh_alpns", ALPN_LABEL.to_string());
    match info.iroh_node_id {
        Some(id) if !id.is_empty() => {
            put("iroh_node_id", id.to_string());
            put("iroh_endpoint", "up".to_string());
            if !info.direct_addrs.is_empty() {
                put("iroh_direct", info.direct_addrs.join(","));
            }
            if !info.relay_urls.is_empty() {
                put("iroh_relay", info.relay_urls.join(","));
            }
        }
        _ => put("iroh_endpoint", "down".to_string()),
    }
    if let Some(m) = info.maker_did {
        put("maker_did", m.to_string());
    }
    put("model", info.model.to_string());
    put("did", info.did.to_string());
    txt
}

/// The request the sidecar accepts (`hardware-deployer-api::rpc::RpcRequest`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RpcRequest {
    /// The operation.
    pub op: String,
    /// Sign-in token (unused by a device).
    #[serde(default)]
    pub jwt: Option<String>,
    /// Sign-in nonce (unused by a device).
    #[serde(default)]
    pub nonce: Option<String>,
    /// Sign-in audience (unused by a device).
    #[serde(default)]
    pub audience: Option<String>,
    /// Session ticket (unused by a device).
    #[serde(default)]
    pub authorization: Option<String>,
    /// Seed sign-in (never honoured by a device).
    #[serde(default)]
    pub seed: Option<String>,
    /// Device id override (unused).
    #[serde(default)]
    pub device_id: Option<String>,
}

/// The reply shape (`hardware-deployer-api::rpc::RpcReply`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReply {
    /// Success flag.
    pub ok: bool,
    /// Result body on success.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub body: Option<Value>,
    /// Message on failure.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

impl RpcReply {
    fn ok(body: Value) -> Self {
        RpcReply {
            ok: true,
            body: Some(body),
            error: None,
        }
    }
    fn err(msg: String) -> Self {
        RpcReply {
            ok: false,
            body: None,
            error: Some(msg),
        }
    }
}

/// The ops a Janus device answers, in the sidecar's catalog shape.
#[must_use]
pub fn catalog() -> Value {
    let op = |service: &str, method: &str, path: &str, name: &str| {
        json!({
            "service": service, "method": method, "path": path, "capability": "",
            "status": "available", "backing": "rusty_esp_iroh", "name": name
        })
    };
    json!([
        op("health", "GET", "/v1/ping", "ping"),
        op("catalog", "GET", "/v1/catalog", "catalog"),
        op("status", "GET", "/v1/status", "status"),
        op("janus", "GET", "/v1/janus/manifest", "janusManifest"),
        op("janus", "GET", "/v1/janus/ticket", "janusTicket"),
        op("janus", "GET", "/v1/janus/neighbours", "janusNeighbours"),
    ])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Answer one sidecar request. `manifest` is the encoded capability manifest
/// with its device signature; `ticket_text` the current `janus1…` ticket.
#[must_use]
pub fn handle(
    request_bytes: &[u8],
    info: &DeviceInfo<'_>,
    manifest: Option<(&[u8], &[u8; 64])>,
    ticket_text: Option<&str>,
    neighbours: &[NeighbourInfo],
) -> Vec<u8> {
    let reply = match serde_json::from_slice::<RpcRequest>(request_bytes) {
        Ok(req) => dispatch(&req, info, manifest, ticket_text, neighbours),
        Err(e) => RpcReply::err(format!("malformed RpcRequest: {e}")),
    };
    serde_json::to_vec(&reply)
        .unwrap_or_else(|_| br#"{"ok":false,"error":"serialize RpcReply"}"#.to_vec())
}

fn dispatch(
    req: &RpcRequest,
    info: &DeviceInfo<'_>,
    manifest: Option<(&[u8], &[u8; 64])>,
    ticket_text: Option<&str>,
    neighbours: &[NeighbourInfo],
) -> RpcReply {
    match req.op.as_str() {
        "ping" => RpcReply::ok(json!({ "ping": PING_REPLY })),
        "catalog" => RpcReply::ok(catalog()),
        "status" => RpcReply::ok(json!({
            "pair": info.pair_state.wire_tag(),
            "provenance": info.tier.wire_tag(),
            "capability": { "storage": false, "mesh": true, "gpu": false, "radio": true },
            "maker_did": info.maker_did,
            "model": info.model,
            "service_type": SERVICE_TYPE,
            "bind": "iroh",
            "did": info.did,
        })),
        "janusManifest" => match manifest {
            Some((bytes, sig)) => RpcReply::ok(json!({
                "did": info.did,
                "manifest_hex": hex(bytes),
                "sig_hex": hex(sig),
                "domain": "janus-manifest-v1",
            })),
            None => RpcReply::err("no manifest".to_string()),
        },
        "janusTicket" => match ticket_text {
            Some(t) => RpcReply::ok(json!({ "ticket": t, "did": info.did })),
            None => RpcReply::err("endpoint not up".to_string()),
        },
        // The devices a bridge fronts (N3): each with its own DID and its own
        // signed manifest, verbatim, so the home computer verifies the
        // neighbour rather than this node.
        "janusNeighbours" => RpcReply::ok(json!({
            "did": info.did,
            "neighbours": neighbours
                .iter()
                .map(|n| json!({
                    "did": n.did,
                    "reach": n.reach,
                    "manifest_hex": hex(&n.manifest),
                    "sig_hex": hex(&n.sig),
                    "domain": "janus-manifest-v1",
                    "last_seen_ms": n.last_seen_us / 1000,
                }))
                .collect::<Vec<_>>(),
        })),
        other => RpcReply::err(format!("unknown op {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info<'a>(addrs: &'a [&'a str]) -> DeviceInfo<'a> {
        DeviceInfo {
            did: "did:mata:z6MkDevice",
            model: "janus/camera",
            box_device_id: "1b4e28ba-2fa1-4d01-9a3e-0c3bb2e1c9f0",
            pair_state: PairState::Open,
            tier: Tier::BestEffort,
            maker_did: None,
            fw: "janus-mesh 0.1.0",
            iroh_node_id: Some("abc123"),
            direct_addrs: addrs,
            relay_urls: &[],
        }
    }

    #[test]
    fn txt_has_the_pair_client_fields() {
        let addrs = ["192.168.1.5:41641"];
        let txt = txt_record(&info(&addrs));
        let get = |k: &str| txt.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("kind"), Some("oem_sidecar"));
        assert_eq!(get("protocol"), Some("1"));
        assert_eq!(get("pair_state"), Some("open"));
        assert_eq!(get("tier"), Some("b"));
        assert_eq!(get("model"), Some("janus/camera"));
        assert_eq!(get("iroh_node_id"), Some("abc123"));
        assert_eq!(get("iroh_endpoint"), Some("up"));
        assert_eq!(get("iroh_direct"), Some("192.168.1.5:41641"));
        assert_eq!(get("iroh_alpns"), Some("mata-oem-sidecar/rpc/1"));
        assert_eq!(
            get("box_device_id"),
            Some("1b4e28ba-2fa1-4d01-9a3e-0c3bb2e1c9f0")
        );
        let down = DeviceInfo {
            iroh_node_id: None,
            ..info(&addrs)
        };
        let txt2 = txt_record(&down);
        assert!(
            txt2.iter()
                .any(|(k, v)| k == "iroh_endpoint" && v == "down")
        );
        assert!(!txt2.iter().any(|(k, _)| k == "iroh_node_id"));
    }

    #[test]
    fn device_uuid_is_a_v4_shaped_uuid() {
        let u = device_uuid("did:mata:z6MkDevice");
        assert_eq!(u.len(), 36);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
        assert_eq!(u, device_uuid("did:mata:z6MkDevice"));
        assert_ne!(u, device_uuid("did:mata:other"));
    }

    #[test]
    fn answers_ping_catalog_status_and_janus_ops() {
        let addrs: [&str; 0] = [];
        let i = info(&addrs);
        let sig = [7u8; 64];
        let reply = |req: &str| -> RpcReply {
            serde_json::from_slice(&handle(
                req.as_bytes(),
                &i,
                Some((&[1, 2, 3], &sig)),
                Some("janus1abc"),
                &[],
            ))
            .unwrap()
        };
        let p = reply(r#"{"op":"ping"}"#);
        assert!(p.ok);
        assert_eq!(p.body.unwrap()["ping"], PING_REPLY);
        let c = reply(r#"{"op":"catalog"}"#);
        assert_eq!(c.body.unwrap().as_array().unwrap().len(), 6);
        let s = reply(r#"{"op":"status","authorization":"ignored"}"#);
        let body = s.body.unwrap();
        assert_eq!(body["pair"], "open");
        assert_eq!(body["capability"]["mesh"], true);
        assert_eq!(body["model"], "janus/camera");
        let m = reply(r#"{"op":"janusManifest"}"#);
        assert_eq!(m.body.unwrap()["manifest_hex"], "010203");
        let t = reply(r#"{"op":"janusTicket"}"#);
        assert_eq!(t.body.unwrap()["ticket"], "janus1abc");
        let u = reply(r#"{"op":"signin","seed":"x"}"#);
        assert!(!u.ok);
        assert_eq!(u.error.unwrap(), "unknown op signin");
        let bad: RpcReply =
            serde_json::from_slice(&handle(b"not json", &i, None, None, &[])).unwrap();
        assert!(!bad.ok);
        assert!(bad.error.unwrap().starts_with("malformed RpcRequest"));
    }
}
