//! Two keys, one identity: the P-256 device key (`did:mata`, from
//! `rusty_esp_mid`) and the ed25519 endpoint key iroh requires, both living
//! in the `Kv` seam (`mid.key`, `iroh.key`), bound together by a
//! [`Binding`] the device key signs.

use iroh::{EndpointId, SecretKey};
use rusty_esp_iroh_core::binding::Binding;
use rusty_esp_iroh_core::esp_core::error::Result;
use rusty_esp_iroh_core::esp_core::hal::{Kv, Rng};
use rusty_esp_iroh_core::mid::did::{Did, MAX_DID_LEN};
use rusty_esp_iroh_core::mid::key::DeviceKey;

/// Where the endpoint secret lives.
pub const KV_ENDPOINT_KEY: &str = "iroh.key";

/// A node's identity.
pub struct NodeIdentity {
    /// The device key; its DID is the device.
    pub device: DeviceKey,
    /// The iroh endpoint secret.
    pub endpoint: SecretKey,
    /// The device key's signature over the endpoint id.
    pub binding: Binding,
}

impl core::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("did", &self.did_string())
            .field("endpoint_id", &self.endpoint_id())
            .finish_non_exhaustive()
    }
}

impl NodeIdentity {
    /// Load both keys from `kv`, generating what is missing from `rng`, and
    /// sign the binding. Idempotent: a second call with the same store yields
    /// the same DID and endpoint id — that is the "stable across reflash"
    /// property, given a persistent `Kv`.
    pub fn load_or_create(kv: &mut impl Kv, rng: &mut impl Rng, device_id: &str) -> Result<Self> {
        let device = DeviceKey::load_or_generate(kv, rng, device_id)?;
        let mut secret = [0u8; 32];
        let endpoint = match kv.get(KV_ENDPOINT_KEY, &mut secret)? {
            Some(32) => SecretKey::from_bytes(&secret),
            _ => {
                rng.fill(&mut secret)?;
                let k = SecretKey::from_bytes(&secret);
                kv.put(KV_ENDPOINT_KEY, &secret)?;
                k
            }
        };
        let binding = Binding::sign(device.did(), *endpoint.public().as_bytes(), &device);
        Ok(NodeIdentity {
            device,
            endpoint,
            binding,
        })
    }

    /// The device DID.
    #[must_use]
    pub fn did(&self) -> Did {
        self.device.did()
    }

    /// The DID as text.
    #[must_use]
    pub fn did_string(&self) -> String {
        let mut buf = [0u8; MAX_DID_LEN];
        self.device
            .did()
            .write(&mut buf)
            .map(String::from)
            .unwrap_or_default()
    }

    /// The iroh endpoint id.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_esp_iroh_core::esp_core::hal::host::{InsecureTestRng, MemoryKv};

    #[test]
    fn identity_is_stable_across_loads_and_binding_verifies() {
        let mut kv = MemoryKv::new();
        let mut rng = InsecureTestRng::seeded(42);
        let a = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus").unwrap();
        let mut rng2 = InsecureTestRng::seeded(7);
        let b = NodeIdentity::load_or_create(&mut kv, &mut rng2, "janus").unwrap();
        assert_eq!(a.did(), b.did());
        assert_eq!(a.endpoint_id(), b.endpoint_id());
        a.binding.verify().unwrap();
        assert_eq!(a.binding.endpoint_id, *a.endpoint_id().as_bytes());
        assert!(a.did_string().starts_with("did:mata:"));
        assert_eq!(kv.len(), 2);
    }
}
