//! The caller's mID assertion every `janus/rpc/1` request carries.
//!
//! It is the kms **nonce envelope** shape `rusty_esp_mid-core` already
//! reproduces byte-for-byte (`kms::NonceEnvelopeRef`), with fixed purpose and
//! issuer strings, signed by the caller's key: `did` = the caller, `audience`
//! = the device's DID, so an assertion for one device is useless at another.
//! The device verifies the signature under the caller's own DID (the DID *is*
//! the public key), checks the audience, the expiry when it has a clock, and
//! the nonce against its replay window. No heap.

use rusty_esp_core::error::{Error, Result};
use rusty_esp_mid_core::did::{Did, MAX_DID_LEN};
use rusty_esp_mid_core::kms::{ENVELOPE_VERSION, MAX_TTL_SECS, NonceEnvelopeRef};
use rusty_esp_mid_core::nonce::NonceWindow;
use rusty_esp_mid_core::{DeviceSigner, verify_prehash};

/// The `purpose` field of every Janus RPC assertion.
pub const PURPOSE: &str = "janus-rpc";
/// The `issuer` field: the caller mints its own nonce.
pub const ISSUER: &str = "janus-caller";
/// Default lifetime of an assertion.
pub const DEFAULT_TTL_SECS: u64 = 60;
/// Largest encoded assertion.
pub const MAX_LEN: usize = 2 + MAX_DID_LEN + 2 + MAX_DID_LEN + 32 + 8 + 8 + 64;

/// A signed assertion over borrowed strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion<'a> {
    /// Who is calling.
    pub caller_did: &'a str,
    /// Which device this assertion is for.
    pub audience_did: &'a str,
    /// Single-use random bytes.
    pub nonce: &'a [u8; 32],
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; at most [`MAX_TTL_SECS`] after `issued_at`.
    pub expires_at: u64,
    /// The caller's low-s signature over the kms canonical prehash.
    pub sig: [u8; 64],
}

impl<'a> Assertion<'a> {
    fn envelope(&self) -> NonceEnvelopeRef<'a> {
        NonceEnvelopeRef {
            envelope_version: ENVELOPE_VERSION,
            nonce: self.nonce,
            did: self.caller_did,
            audience: self.audience_did,
            purpose: PURPOSE,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            issuer: ISSUER,
        }
    }

    /// Mint and sign an assertion from `caller` (whose DID is `caller_did`)
    /// for `audience_did`, valid `ttl_secs` from `issued_at`.
    pub fn sign(
        caller_did: &'a str,
        audience_did: &'a str,
        nonce: &'a [u8; 32],
        issued_at: u64,
        ttl_secs: u64,
        caller: &impl DeviceSigner,
    ) -> Result<Self> {
        let mut a = Assertion {
            caller_did,
            audience_did,
            nonce,
            issued_at,
            expires_at: issued_at.saturating_add(ttl_secs.min(MAX_TTL_SECS)),
            sig: [0; 64],
        };
        a.sig = a.envelope().sign(caller)?;
        Ok(a)
    }

    /// The full check a device runs; returns the caller's DID.
    ///
    /// 1. shape (as `kms-types` validates it);
    /// 2. audience is `my_did`;
    /// 3. the signature verifies under the caller's own key;
    /// 4. not expired at `now` (skip with `None` before the device has a clock);
    /// 5. the nonce has not been seen (`window`).
    pub fn verify<const N: usize>(
        &self,
        my_did: &str,
        now: Option<u64>,
        window: &mut NonceWindow<N>,
    ) -> Result<Did> {
        let env = self.envelope();
        env.validate()?;
        if self.audience_did != my_did {
            return Err(Error::Denied);
        }
        let caller = Did::parse(self.caller_did)?;
        verify_prehash(caller.pubkey(), &env.canonical_bytes(), &self.sig)?;
        if let Some(now) = now {
            if now >= self.expires_at || now + MAX_TTL_SECS < self.issued_at {
                return Err(Error::Denied);
            }
        }
        if !window.check_and_insert(self.nonce) {
            return Err(Error::Denied);
        }
        Ok(caller)
    }

    /// Bytes [`encode`](Self::encode) produces.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2 + self.caller_did.len() + 2 + self.audience_did.len() + 32 + 8 + 8 + 64
    }

    /// `len16 caller len16 audience nonce issued expires sig` into `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let need = self.encoded_len();
        if out.len() < need {
            return Err(Error::BufferTooSmall { needed: need });
        }
        if self.caller_did.len() > MAX_DID_LEN || self.audience_did.len() > MAX_DID_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut w = 0;
        for s in [self.caller_did, self.audience_did] {
            out[w..w + 2].copy_from_slice(&(s.len() as u16).to_be_bytes());
            w += 2;
            out[w..w + s.len()].copy_from_slice(s.as_bytes());
            w += s.len();
        }
        out[w..w + 32].copy_from_slice(self.nonce);
        w += 32;
        out[w..w + 8].copy_from_slice(&self.issued_at.to_be_bytes());
        w += 8;
        out[w..w + 8].copy_from_slice(&self.expires_at.to_be_bytes());
        w += 8;
        out[w..w + 64].copy_from_slice(&self.sig);
        w += 64;
        Ok(w)
    }

    /// Parse the encoded form (borrowing from `bytes`); does not verify.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        let mut pos = 0usize;
        let mut str_field = |bytes: &'a [u8]| -> Result<&'a str> {
            let len = bytes.get(pos..pos + 2).ok_or(Error::InvalidFormat)?;
            let n = usize::from(u16::from_be_bytes([len[0], len[1]]));
            if n > MAX_DID_LEN {
                return Err(Error::InvalidFormat);
            }
            let s = bytes
                .get(pos + 2..pos + 2 + n)
                .ok_or(Error::InvalidFormat)?;
            pos += 2 + n;
            core::str::from_utf8(s).map_err(|_| Error::InvalidFormat)
        };
        let caller_did = str_field(bytes)?;
        let audience_did = str_field(bytes)?;
        let rest = bytes.get(pos..).ok_or(Error::InvalidFormat)?;
        if rest.len() != 32 + 8 + 8 + 64 {
            return Err(Error::InvalidFormat);
        }
        let nonce: &[u8; 32] = rest[..32].try_into().map_err(|_| Error::InvalidFormat)?;
        let issued_at =
            u64::from_be_bytes(rest[32..40].try_into().map_err(|_| Error::InvalidFormat)?);
        let expires_at =
            u64::from_be_bytes(rest[40..48].try_into().map_err(|_| Error::InvalidFormat)?);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&rest[48..112]);
        Ok(Assertion {
            caller_did,
            audience_did,
            nonce,
            issued_at,
            expires_at,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_esp_mid_core::key::DeviceKey;

    fn dids() -> (DeviceKey, [u8; 60], DeviceKey, [u8; 60]) {
        let owner = DeviceKey::from_seed_for_tests("owner", "hub");
        let device = DeviceKey::from_seed_for_tests("device", "janus");
        let mut o = [0u8; 60];
        let mut d = [0u8; 60];
        owner.did().write(&mut o).unwrap();
        device.did().write(&mut d).unwrap();
        (owner, o, device, d)
    }

    fn s(buf: &[u8; 60]) -> &str {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(60);
        core::str::from_utf8(&buf[..end]).unwrap()
    }

    #[test]
    fn signs_verifies_encodes_and_rejects_replay() {
        let (owner, o, _device, d) = dids();
        let nonce = [9u8; 32];
        let a = Assertion::sign(s(&o), s(&d), &nonce, 1_700_000_000, 60, &owner).unwrap();
        let mut window = NonceWindow::<8>::new();
        let caller = a.verify(s(&d), Some(1_700_000_010), &mut window).unwrap();
        assert_eq!(caller, owner.did());
        // Same nonce again: replay.
        assert_eq!(
            a.verify(s(&d), Some(1_700_000_010), &mut window).err(),
            Some(Error::Denied)
        );
        let mut buf = [0u8; MAX_LEN];
        let n = a.encode(&mut buf).unwrap();
        assert_eq!(n, a.encoded_len());
        let back = Assertion::decode(&buf[..n]).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn wrong_audience_expired_or_forged_is_denied() {
        let (owner, o, device, d) = dids();
        let nonce = [1u8; 32];
        let a = Assertion::sign(s(&o), s(&d), &nonce, 1_000, 60, &owner).unwrap();
        let mut w = NonceWindow::<8>::new();
        assert_eq!(
            a.verify("did:mata:other", Some(1_010), &mut w).err(),
            Some(Error::Denied)
        );
        assert_eq!(
            a.verify(s(&d), Some(1_060), &mut w).err(),
            Some(Error::Denied)
        );
        assert_eq!(
            a.verify(s(&d), Some(100), &mut w).err(),
            Some(Error::Denied)
        );
        // Signed by the device itself but claiming to be the owner.
        let forged = Assertion::sign(s(&o), s(&d), &nonce, 1_000, 60, &device).unwrap();
        assert_eq!(
            forged.verify(s(&d), None, &mut w).err(),
            Some(Error::Crypto)
        );
        // Without a clock the expiry is skipped and the nonce still counts.
        a.verify(s(&d), None, &mut w).unwrap();
        assert_eq!(
            Assertion::decode(&[0u8; 5]).err(),
            Some(Error::InvalidFormat)
        );
    }
}
