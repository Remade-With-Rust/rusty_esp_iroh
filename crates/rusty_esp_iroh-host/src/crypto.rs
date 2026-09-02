//! A QUIC-capable rustls `CryptoProvider` over rustls-rustcrypto — pure Rust,
//! AES-128-GCM + X25519 only.
//!
//! Vendored from n0's `iroh-esp32-examples` (`quic_crypto_provider.rs`,
//! MIT OR Apache-2.0, © n0 computer) with formatting changes only. It is the
//! configuration that makes iroh build for Xtensa, and it is what keeps `ring`
//! and `aws-lc` out of every Janus graph, host included. rustls-rustcrypto
//! provides the TLS 1.3 suites but leaves `quic: None`; this adds the QUIC
//! header protection (RFC 9001 §5.4) and packet encryption for AES-128-GCM.
//!
//! `aes` 0.8 / `aes-gcm` 0.10 still speak `generic-array` 0.14, which newer
//! releases mark deprecated; those are the versions rustls-rustcrypto's
//! branch pins, so the deprecation is allowed here until the branch moves.
#![allow(deprecated)]

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::AeadInPlace as _;
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::crypto::{CipherSuiteCommon, CryptoProvider};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite, quic};

/// Build the provider: rustls-rustcrypto with QUIC support, AES-128-GCM and
/// X25519 only (ChaCha20 and the NIST curves are dropped for binary size;
/// iroh authenticates peers with ed25519 at the QUIC layer, not with TLS
/// certificates).
#[must_use]
pub fn provider() -> CryptoProvider {
    let base = rustls_rustcrypto::provider();
    let cipher_suites: Vec<SupportedCipherSuite> = base
        .cipher_suites
        .iter()
        .filter_map(|suite| match suite {
            SupportedCipherSuite::Tls13(tls13)
                if tls13.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256 =>
            {
                Some(SupportedCipherSuite::Tls13(QUIC_AES_128_GCM))
            }
            _ => None,
        })
        .collect();
    let kx_groups = base
        .kx_groups
        .into_iter()
        .filter(|g| g.name() == rustls::NamedGroup::X25519)
        .collect();
    CryptoProvider {
        cipher_suites,
        kx_groups,
        ..base
    }
}

static QUIC_AES_128_GCM: &Tls13CipherSuite = {
    #[allow(unreachable_patterns)]
    match &rustls_rustcrypto::TLS13_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls13(inner) => &Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: inner.common.suite,
                hash_provider: inner.common.hash_provider,
                confidentiality_limit: inner.common.confidentiality_limit,
            },
            hkdf_provider: inner.hkdf_provider,
            aead_alg: inner.aead_alg,
            quic: Some(&Aes128GcmQuic),
        },
        _ => unreachable!(),
    }
};

struct Aes128GcmQuic;

impl quic::Algorithm for Aes128GcmQuic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(Aes128GcmPacketKey::new(key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(AesHeaderProtectionKey(key))
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

/// QUIC header protection with AES-ECB (RFC 9001 §5.4.3).
struct AesHeaderProtectionKey(AeadKey);

impl quic::HeaderProtectionKey for AesHeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        let mask = self.mask(sample);
        apply_header_mask(&mask, first, packet_number, false);
        Ok(())
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        let mask = self.mask(sample);
        apply_header_mask(&mask, first, packet_number, true);
        Ok(())
    }

    #[inline]
    fn sample_len(&self) -> usize {
        16
    }
}

impl AesHeaderProtectionKey {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        use aes::cipher::generic_array::GenericArray;
        let cipher = aes::Aes128::new(GenericArray::from_slice(self.0.as_ref()));
        let mut block = GenericArray::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        mask
    }
}

/// QUIC packet protection with AES-128-GCM.
struct Aes128GcmPacketKey {
    iv: Iv,
    key: aes_gcm::Aes128Gcm,
}

impl Aes128GcmPacketKey {
    fn new(key: AeadKey, iv: Iv) -> Self {
        use aes_gcm::KeyInit;
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).expect("16-byte key");
        Self { iv, key: cipher }
    }

    fn seal(
        &self,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let tag = self
            .key
            .encrypt_in_place_detached(nonce, aad, payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn open<'a>(
        &self,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let payload_len = payload
            .len()
            .checked_sub(16)
            .ok_or(rustls::Error::DecryptError)?;
        let (msg, tag_bytes) = payload.split_at_mut(payload_len);
        let tag = aes_gcm::Tag::from_slice(tag_bytes);
        self.key
            .decrypt_in_place_detached(nonce, aad, msg, tag)
            .map_err(|_| rustls::Error::DecryptError)?;
        Ok(&payload[..payload_len])
    }
}

impl quic::PacketKey for Aes128GcmPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        self.seal(
            rustls::crypto::cipher::Nonce::new(&self.iv, packet_number).0,
            aad,
            payload,
        )
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, rustls::Error> {
        self.seal(
            rustls::crypto::cipher::Nonce::for_path(path_id, &self.iv, packet_number).0,
            aad,
            payload,
        )
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        self.open(
            rustls::crypto::cipher::Nonce::new(&self.iv, packet_number).0,
            aad,
            payload,
        )
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        self.open(
            rustls::crypto::cipher::Nonce::for_path(path_id, &self.iv, packet_number).0,
            aad,
            payload,
        )
    }

    #[inline]
    fn tag_len(&self) -> usize {
        16
    }

    fn integrity_limit(&self) -> u64 {
        1 << 52
    }

    fn confidentiality_limit(&self) -> u64 {
        1 << 23
    }
}

/// RFC 9001 §5.4.1: mask the first byte's low bits and the packet-number bytes.
fn apply_header_mask(mask: &[u8; 5], first: &mut u8, packet_number: &mut [u8], masked: bool) {
    let bits = if *first & 0x80 == 0x80 { 0x0f } else { 0x1f };
    let first_plain = if masked {
        *first ^ (mask[0] & bits)
    } else {
        *first
    };
    let pn_len = (first_plain & 0x03) as usize + 1;
    *first ^= mask[0] & bits;
    for (b, m) in packet_number.iter_mut().zip(&mask[1..]).take(pn_len) {
        *b ^= m;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_offers_exactly_aes128gcm_and_x25519() {
        let p = provider();
        assert_eq!(p.cipher_suites.len(), 1);
        assert_eq!(
            p.cipher_suites[0].suite(),
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );
        assert_eq!(p.kx_groups.len(), 1);
        assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::X25519);
    }

    #[test]
    fn header_mask_round_trips() {
        let mask = [0xA5, 0x01, 0x02, 0x03, 0x04];
        let mut first = 0x43u8; // short header, pn_len = 4
        let mut pn = [10u8, 20, 30, 40];
        apply_header_mask(&mask, &mut first, &mut pn, false);
        assert_ne!(first, 0x43);
        apply_header_mask(&mask, &mut first, &mut pn, true);
        assert_eq!(first, 0x43);
        assert_eq!(pn, [10, 20, 30, 40]);
    }
}
