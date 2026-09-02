//! The DID-to-endpoint binding: the device's P-256 key signs its ed25519
//! iroh `EndpointId`, so anyone holding the DID can check that an endpoint
//! is that device — the mesh notes' "publish the endpoint on the identity
//! anchor", and the family's only use of ed25519 (iroh requires it).
//!
//! Canonical bytes: `janus-binding-v1\n` `0x01` `did[33]` `endpoint_id[32]`;
//! the signature is over SHA-256 of that. Encoded: `0x01 did endpoint_id sig`
//! = 130 bytes.

use rusty_esp_core::error::{Error, Result};
use rusty_esp_mid_core::did::{Did, PUBKEY_LEN};
use rusty_esp_mid_core::{DeviceSigner, sha256, verify_prehash};

/// Domain separator.
pub const DOMAIN: &[u8] = b"janus-binding-v1\n";
/// Format version.
pub const VERSION: u8 = 1;
/// Encoded length.
pub const LEN: usize = 1 + PUBKEY_LEN + 32 + 64;

/// A signed binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// The device.
    pub did: Did,
    /// Its iroh endpoint id.
    pub endpoint_id: [u8; 32],
    /// The device key's low-s signature over the canonical bytes.
    pub sig: [u8; 64],
}

fn prehash(did: &Did, endpoint_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; DOMAIN.len() + 1 + PUBKEY_LEN + 32];
    let mut w = 0;
    buf[w..w + DOMAIN.len()].copy_from_slice(DOMAIN);
    w += DOMAIN.len();
    buf[w] = VERSION;
    w += 1;
    buf[w..w + PUBKEY_LEN].copy_from_slice(did.pubkey());
    w += PUBKEY_LEN;
    buf[w..w + 32].copy_from_slice(endpoint_id);
    sha256(&buf)
}

impl Binding {
    /// Sign `endpoint_id` with the device key behind `signer`, whose DID is `did`.
    #[must_use]
    pub fn sign(did: Did, endpoint_id: [u8; 32], signer: &impl DeviceSigner) -> Self {
        let sig = signer.sign_prehash(&prehash(&did, &endpoint_id));
        Binding {
            did,
            endpoint_id,
            sig,
        }
    }

    /// Check the signature under the DID's own key.
    pub fn verify(&self) -> Result<()> {
        verify_prehash(
            self.did.pubkey(),
            &prehash(&self.did, &self.endpoint_id),
            &self.sig,
        )
    }

    /// Encode into `out`; returns [`LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < LEN {
            return Err(Error::BufferTooSmall { needed: LEN });
        }
        out[0] = VERSION;
        out[1..1 + PUBKEY_LEN].copy_from_slice(self.did.pubkey());
        out[1 + PUBKEY_LEN..1 + PUBKEY_LEN + 32].copy_from_slice(&self.endpoint_id);
        out[1 + PUBKEY_LEN + 32..LEN].copy_from_slice(&self.sig);
        Ok(LEN)
    }

    /// Decode (does not verify; call [`verify`](Self::verify)).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != LEN {
            return Err(Error::InvalidFormat);
        }
        if bytes[0] != VERSION {
            return Err(Error::Unsupported);
        }
        let did = Did::from_pubkey(&bytes[1..1 + PUBKEY_LEN])?;
        let mut endpoint_id = [0u8; 32];
        endpoint_id.copy_from_slice(&bytes[1 + PUBKEY_LEN..1 + PUBKEY_LEN + 32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[1 + PUBKEY_LEN + 32..LEN]);
        Ok(Binding {
            did,
            endpoint_id,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_esp_mid_core::key::DeviceKey;

    #[test]
    fn signs_verifies_and_round_trips() {
        let key = DeviceKey::from_seed_for_tests("binding", "janus");
        let b = Binding::sign(key.did(), [3u8; 32], &key);
        b.verify().unwrap();
        let mut buf = [0u8; LEN];
        assert_eq!(b.encode(&mut buf).unwrap(), LEN);
        let back = Binding::decode(&buf).unwrap();
        assert_eq!(back, b);
        back.verify().unwrap();
    }

    #[test]
    fn a_different_endpoint_or_key_fails() {
        let key = DeviceKey::from_seed_for_tests("binding", "janus");
        let other = DeviceKey::from_seed_for_tests("other", "janus");
        let mut b = Binding::sign(key.did(), [3u8; 32], &key);
        b.endpoint_id[0] ^= 1;
        assert_eq!(b.verify().err(), Some(Error::Crypto));
        let forged = Binding::sign(other.did(), [3u8; 32], &key);
        assert_eq!(forged.verify().err(), Some(Error::Crypto));
        assert_eq!(
            Binding::decode(&[0u8; LEN - 1]).err(),
            Some(Error::InvalidFormat)
        );
        let mut bad = [0u8; LEN];
        bad[0] = 2;
        assert_eq!(Binding::decode(&bad).err(), Some(Error::Unsupported));
    }
}
