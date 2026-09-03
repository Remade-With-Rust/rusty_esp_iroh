//! OTA over iroh (N5): a maker-signed image manifest, the bytes streamed
//! behind it, and the two-slot sink that makes a bad image harmless.
//!
//! The order of checks is the whole design:
//!
//! 1. The caller must be the owner (the RPC authorisation rule, unchanged).
//! 2. The device must declare `Capability::Ota` available and know its
//!    maker's DID; the manifest must name that maker, this chip and this
//!    model, and its signature must verify under the maker's key — all
//!    **before a single image byte is accepted**.
//! 3. The bytes stream into the inactive slot while SHA-256 runs; the
//!    length and the digest must match the manifest before the slot is
//!    finished and made the boot slot.
//! 4. The running image is never touched. A power cut mid-write leaves the
//!    inactive slot half-written and the device booting what it booted
//!    before; a new image that fails to validate after boot rolls back
//!    (`esp-ota`'s two-slot rollback on the chip, [`MemorySlots`] here).

use alloc::string::String;
use alloc::vec::Vec;

use rusty_esp_core::capability::Chip;
use rusty_esp_core::error::{Error, Result};
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::signer::{DeviceSigner, verify_prehash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator of the maker's signature.
pub const OTA_DOMAIN: &[u8] = b"janus-ota-v1";

/// Largest image a manifest may describe (the biggest app partition in the
/// family is 6 MiB; 16 MiB bounds a hostile manifest).
pub const MAX_IMAGE_LEN: u32 = 16 * 1024 * 1024;

/// Bytes the host pushes per chunk.
pub const CHUNK_LEN: usize = 16 * 1024;

/// What a maker signs over an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtaManifest {
    /// The model the image is for (must equal the device's).
    pub model: String,
    /// The firmware string the image will report once it runs.
    pub firmware: String,
    /// The part, as `Chip::tag`.
    pub chip: String,
    /// Image length in bytes.
    pub image_len: u32,
    /// SHA-256 of the image.
    pub image_sha256: [u8; 32],
    /// The maker's `did:mata`, whose key signed this.
    pub maker_did: String,
    /// 64-byte low-s P-256 signature over [`OtaManifest::prehash`].
    pub sig: Vec<u8>,
}

/// Why an image was refused. Every variant is a distinct fact a log line
/// can carry; none leaks anything the caller did not already know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// The device does not declare `ota` available.
    NoOtaCapability,
    /// The device has no maker DID to trust.
    NoMaker,
    /// The manifest names another maker.
    WrongMaker,
    /// The signature does not verify under the maker's key.
    BadSignature,
    /// The manifest is for another part.
    WrongChip,
    /// The manifest is for another model.
    WrongModel,
    /// Longer than [`MAX_IMAGE_LEN`] or than the slot.
    TooLarge,
    /// More or fewer bytes arrived than the manifest said.
    LengthMismatch,
    /// The bytes hashed to something else.
    DigestMismatch,
    /// The slot refused a write (a power cut, a flash error).
    SinkFailed,
    /// Another update is in progress.
    Busy,
}

impl OtaManifest {
    /// The bytes the maker signs: domain, then each field length-prefixed.
    #[must_use]
    pub fn prehash(
        model: &str,
        firmware: &str,
        chip: &str,
        image_len: u32,
        image_sha256: &[u8; 32],
        maker_did: &str,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(OTA_DOMAIN);
        for field in [model, firmware, chip, maker_did] {
            h.update((field.len() as u16).to_be_bytes());
            h.update(field.as_bytes());
        }
        h.update(image_len.to_be_bytes());
        h.update(image_sha256);
        h.finalize().into()
    }

    /// Sign `image` for `model` on `chip`, as the maker `maker_did` whose
    /// key is `maker`.
    pub fn sign(
        model: &str,
        firmware: &str,
        chip: Chip,
        image: &[u8],
        maker_did: &str,
        maker: &impl DeviceSigner,
    ) -> Result<Self> {
        let image_len = u32::try_from(image.len()).map_err(|_| Error::Unsupported)?;
        if image_len == 0 || image_len > MAX_IMAGE_LEN {
            return Err(Error::Unsupported);
        }
        let image_sha256: [u8; 32] = Sha256::digest(image).into();
        let prehash = Self::prehash(
            model,
            firmware,
            chip.tag(),
            image_len,
            &image_sha256,
            maker_did,
        );
        Ok(OtaManifest {
            model: String::from(model),
            firmware: String::from(firmware),
            chip: String::from(chip.tag()),
            image_len,
            image_sha256,
            maker_did: String::from(maker_did),
            sig: maker.sign_prehash(&prehash).to_vec(),
        })
    }

    /// The device's checks before any byte: maker, chip, model, size, and
    /// the signature under the maker's own key (the DID carries it).
    pub fn verify(
        &self,
        device_chip: Chip,
        device_model: &str,
        trusted_maker_did: Option<&str>,
    ) -> core::result::Result<(), Refusal> {
        let maker = trusted_maker_did.ok_or(Refusal::NoMaker)?;
        if self.maker_did != maker {
            return Err(Refusal::WrongMaker);
        }
        if self.chip != device_chip.tag() {
            return Err(Refusal::WrongChip);
        }
        if self.model != device_model {
            return Err(Refusal::WrongModel);
        }
        if self.image_len == 0 || self.image_len > MAX_IMAGE_LEN {
            return Err(Refusal::TooLarge);
        }
        let sig: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| Refusal::BadSignature)?;
        let did = Did::parse(maker).map_err(|_| Refusal::WrongMaker)?;
        let prehash = Self::prehash(
            &self.model,
            &self.firmware,
            &self.chip,
            self.image_len,
            &self.image_sha256,
            &self.maker_did,
        );
        verify_prehash(did.pubkey(), &prehash, &sig).map_err(|_| Refusal::BadSignature)
    }
}

/// Where the bytes go: the inactive slot on a chip (`esp-ota`), memory on
/// the host. `begin` must refuse an image the slot cannot hold; `finish`
/// makes the written slot the boot slot; `abort` leaves the running image
/// as it was.
pub trait OtaSink {
    /// Start an update of `image_len` bytes into the inactive slot.
    fn begin(&mut self, image_len: u32) -> Result<()>;
    /// Append bytes.
    fn write(&mut self, chunk: &[u8]) -> Result<()>;
    /// The image is complete and verified: make it the boot slot.
    fn finish(&mut self) -> Result<()>;
    /// Discard the partial image.
    fn abort(&mut self);
}

/// One update in flight: bytes in, hash running, the manifest's promises
/// checked at the end.
pub struct OtaSession<'s, S: OtaSink + ?Sized> {
    manifest: OtaManifest,
    sink: &'s mut S,
    hasher: Sha256,
    written: u32,
    open: bool,
}

impl<'s, S: OtaSink + ?Sized> OtaSession<'s, S> {
    /// Open the slot for a manifest that has already passed
    /// [`OtaManifest::verify`].
    pub fn begin(manifest: OtaManifest, sink: &'s mut S) -> core::result::Result<Self, Refusal> {
        sink.begin(manifest.image_len).map_err(|e| match e {
            Error::BufferTooSmall { .. } | Error::Unsupported => Refusal::TooLarge,
            Error::Busy => Refusal::Busy,
            _ => Refusal::SinkFailed,
        })?;
        Ok(OtaSession {
            manifest,
            sink,
            hasher: Sha256::new(),
            written: 0,
            open: true,
        })
    }

    /// Bytes accepted so far.
    #[must_use]
    pub const fn written(&self) -> u32 {
        self.written
    }

    /// Append a chunk. Too many bytes is a refusal and the slot is
    /// abandoned; a sink error likewise.
    pub fn push(&mut self, chunk: &[u8]) -> core::result::Result<(), Refusal> {
        let len = u32::try_from(chunk.len()).map_err(|_| Refusal::LengthMismatch)?;
        if self.written.saturating_add(len) > self.manifest.image_len {
            self.abort();
            return Err(Refusal::LengthMismatch);
        }
        if self.sink.write(chunk).is_err() {
            self.abort();
            return Err(Refusal::SinkFailed);
        }
        self.hasher.update(chunk);
        self.written += len;
        Ok(())
    }

    /// All bytes are in: check the length and the digest against the
    /// manifest, then make the slot the boot slot. Returns the digest.
    pub fn finish(mut self) -> core::result::Result<[u8; 32], Refusal> {
        if self.written != self.manifest.image_len {
            self.abort();
            return Err(Refusal::LengthMismatch);
        }
        let digest: [u8; 32] = core::mem::take(&mut self.hasher).finalize().into();
        if digest != self.manifest.image_sha256 {
            self.abort();
            return Err(Refusal::DigestMismatch);
        }
        if self.sink.finish().is_err() {
            self.abort();
            return Err(Refusal::SinkFailed);
        }
        self.open = false;
        Ok(digest)
    }

    /// Give up; the running image is untouched.
    pub fn abort(&mut self) {
        if self.open {
            self.sink.abort();
            self.open = false;
        }
    }

    /// The manifest this session serves.
    #[must_use]
    pub fn manifest(&self) -> &OtaManifest {
        &self.manifest
    }
}

impl<S: OtaSink + ?Sized> Drop for OtaSession<'_, S> {
    fn drop(&mut self) {
        self.abort();
    }
}

/// The host's model of a two-slot flash with `esp-ota`'s rollback rule:
/// `finish` marks the written slot pending; the next [`MemorySlots::boot`]
/// runs it; if that image is not [`MemorySlots::mark_valid`]-ed before the
/// following boot, the device falls back to the previous slot. `fail_after`
/// is the test's power cut: the sink errors once that many bytes have been
/// written.
#[derive(Debug, Clone)]
pub struct MemorySlots {
    slots: [Vec<u8>; 2],
    active: usize,
    pending: Option<usize>,
    writing: Option<usize>,
    awaiting_validation: bool,
    /// Simulated power cut: fail the write that passes this many bytes.
    pub fail_after: Option<usize>,
    /// Bytes a slot can hold.
    pub slot_len: u32,
}

impl MemorySlots {
    /// Marker the host image format starts with; the firmware string
    /// follows to the first newline, then the payload. Stands in for the
    /// chip's app descriptor.
    pub const HEADER: &'static [u8] = b"JANUS-FW ";

    /// Two slots of `slot_len` bytes, `running` in the active one.
    #[must_use]
    pub fn new(running: Vec<u8>, slot_len: u32) -> Self {
        MemorySlots {
            slots: [running, Vec::new()],
            active: 0,
            pending: None,
            writing: None,
            awaiting_validation: false,
            fail_after: None,
            slot_len,
        }
    }

    /// Build a host image: `JANUS-FW <firmware>\n<payload>`.
    #[must_use]
    pub fn image(firmware: &str, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::HEADER.len() + firmware.len() + 1 + payload.len());
        v.extend_from_slice(Self::HEADER);
        v.extend_from_slice(firmware.as_bytes());
        v.push(b'\n');
        v.extend_from_slice(payload);
        v
    }

    /// The firmware string a host image reports, if it is one.
    #[must_use]
    pub fn firmware_of(image: &[u8]) -> Option<&str> {
        let rest = image.strip_prefix(Self::HEADER)?;
        let end = rest.iter().position(|&b| b == b'\n')?;
        core::str::from_utf8(&rest[..end]).ok()
    }

    /// The image that is running.
    #[must_use]
    pub fn active(&self) -> &[u8] {
        &self.slots[self.active]
    }

    /// The firmware string of the running image.
    #[must_use]
    pub fn running_firmware(&self) -> Option<&str> {
        Self::firmware_of(self.active())
    }

    /// Is a finished image waiting for the next boot?
    #[must_use]
    pub const fn pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Reboot: run the pending slot if there is one; roll back if the
    /// last new image never validated. Returns the image now running.
    pub fn boot(&mut self) -> &[u8] {
        if let Some(p) = self.pending.take() {
            self.active = p;
            self.awaiting_validation = true;
        } else if self.awaiting_validation {
            // The new image booted last time and never said it was fine.
            self.active = 1 - self.active;
            self.awaiting_validation = false;
        }
        self.writing = None;
        &self.slots[self.active]
    }

    /// The running image declares itself good (the firmware's
    /// `esp_ota_mark_app_valid_cancel_rollback`).
    pub fn mark_valid(&mut self) {
        self.awaiting_validation = false;
    }
}

impl OtaSink for MemorySlots {
    fn begin(&mut self, image_len: u32) -> Result<()> {
        if self.writing.is_some() {
            return Err(Error::Busy);
        }
        if image_len > self.slot_len {
            return Err(Error::BufferTooSmall {
                needed: image_len as usize,
            });
        }
        let inactive = 1 - self.active;
        self.slots[inactive].clear();
        self.writing = Some(inactive);
        self.pending = None;
        Ok(())
    }

    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        let slot = self.writing.ok_or(Error::Busy)?;
        if let Some(limit) = self.fail_after {
            if self.slots[slot].len() + chunk.len() > limit {
                // the power cut: whatever was written stays, nothing more comes
                let room = limit.saturating_sub(self.slots[slot].len());
                self.slots[slot].extend_from_slice(&chunk[..room]);
                self.writing = None;
                return Err(Error::Hardware);
            }
        }
        self.slots[slot].extend_from_slice(chunk);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let slot = self.writing.take().ok_or(Error::Busy)?;
        self.pending = Some(slot);
        Ok(())
    }

    fn abort(&mut self) {
        if let Some(slot) = self.writing.take() {
            self.slots[slot].clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_esp_mid_core::key::DeviceKey;

    fn maker() -> (DeviceKey, String) {
        let k = DeviceKey::from_seed_for_tests("acme-maker", "maker");
        let did = k.did().to_did_string();
        (k, did)
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn a_signed_manifest_verifies_and_every_lie_is_named() {
        let (key, did) = maker();
        let image = MemorySlots::image("1.5.0", &payload(5000));
        let m = OtaManifest::sign("janus/cam", "1.5.0", Chip::Esp32S3, &image, &did, &key).unwrap();
        assert_eq!(m.image_len, image.len() as u32);
        assert_eq!(m.verify(Chip::Esp32S3, "janus/cam", Some(&did)), Ok(()));
        assert_eq!(
            m.verify(Chip::Esp32S3, "janus/cam", None),
            Err(Refusal::NoMaker)
        );
        let other = DeviceKey::from_seed_for_tests("other", "maker")
            .did()
            .to_did_string();
        assert_eq!(
            m.verify(Chip::Esp32S3, "janus/cam", Some(&other)),
            Err(Refusal::WrongMaker)
        );
        assert_eq!(
            m.verify(Chip::Esp32C6, "janus/cam", Some(&did)),
            Err(Refusal::WrongChip)
        );
        assert_eq!(
            m.verify(Chip::Esp32S3, "janus/mic", Some(&did)),
            Err(Refusal::WrongModel)
        );
        let mut forged = m.clone();
        forged.firmware = String::from("9.9.9");
        assert_eq!(
            forged.verify(Chip::Esp32S3, "janus/cam", Some(&did)),
            Err(Refusal::BadSignature)
        );
        let mut bad_sig = m.clone();
        bad_sig.sig[10] ^= 1;
        assert_eq!(
            bad_sig.verify(Chip::Esp32S3, "janus/cam", Some(&did)),
            Err(Refusal::BadSignature)
        );
        let mut short = m.clone();
        short.sig.truncate(10);
        assert_eq!(
            short.verify(Chip::Esp32S3, "janus/cam", Some(&did)),
            Err(Refusal::BadSignature)
        );
        let mut huge = m;
        huge.image_len = MAX_IMAGE_LEN + 1;
        assert_eq!(
            huge.verify(Chip::Esp32S3, "janus/cam", Some(&did)),
            Err(Refusal::TooLarge)
        );
        assert!(OtaManifest::sign("m", "f", Chip::Esp32, &[], &did, &key).is_err());
    }

    #[test]
    fn a_session_streams_verifies_and_commits_into_the_inactive_slot() {
        let (key, did) = maker();
        let old = MemorySlots::image("1.0.0", b"old");
        let new = MemorySlots::image("1.5.0", &payload(40_000));
        let m = OtaManifest::sign("janus/cam", "1.5.0", Chip::Esp32S3, &new, &did, &key).unwrap();
        let mut slots = MemorySlots::new(old.clone(), 1 << 20);
        let mut s = OtaSession::begin(m.clone(), &mut slots).unwrap();
        for chunk in new.chunks(CHUNK_LEN) {
            s.push(chunk).unwrap();
        }
        assert_eq!(s.written(), new.len() as u32);
        let digest = s.finish().unwrap();
        assert_eq!(digest, m.image_sha256);
        assert_eq!(
            slots.active(),
            &old[..],
            "the running image is untouched until boot"
        );
        assert!(slots.pending());
        assert_eq!(MemorySlots::firmware_of(slots.boot()), Some("1.5.0"));
        assert_eq!(slots.running_firmware(), Some("1.5.0"));
        // never validated: the next boot rolls back
        assert_eq!(MemorySlots::firmware_of(slots.boot()), Some("1.0.0"));
        // again, validated this time: stays
        let mut s = OtaSession::begin(m, &mut slots).unwrap();
        s.push(&new).unwrap();
        s.finish().unwrap();
        slots.boot();
        slots.mark_valid();
        assert_eq!(MemorySlots::firmware_of(slots.boot()), Some("1.5.0"));
    }

    #[test]
    fn tampered_bytes_short_bytes_and_a_power_cut_leave_the_running_image_alone() {
        let (key, did) = maker();
        let old = MemorySlots::image("1.0.0", b"old");
        let new = MemorySlots::image("1.5.0", &payload(30_000));
        let m = OtaManifest::sign("janus/cam", "1.5.0", Chip::Esp32S3, &new, &did, &key).unwrap();
        let mut slots = MemorySlots::new(old.clone(), 1 << 20);
        // tampered
        let mut tampered = new.clone();
        tampered[20_000] ^= 0x80;
        let mut s = OtaSession::begin(m.clone(), &mut slots).unwrap();
        s.push(&tampered).unwrap();
        assert_eq!(s.finish(), Err(Refusal::DigestMismatch));
        assert_eq!(slots.active(), &old[..]);
        assert!(!slots.pending());
        // short
        let mut s = OtaSession::begin(m.clone(), &mut slots).unwrap();
        s.push(&new[..1000]).unwrap();
        assert_eq!(s.finish(), Err(Refusal::LengthMismatch));
        // long
        let mut s = OtaSession::begin(m.clone(), &mut slots).unwrap();
        s.push(&new).unwrap();
        assert_eq!(s.push(b"x"), Err(Refusal::LengthMismatch));
        drop(s);
        assert_eq!(slots.active(), &old[..]);
        // power cut after 12 000 bytes, then a retry succeeds
        slots.fail_after = Some(12_000);
        let mut s = OtaSession::begin(m.clone(), &mut slots).unwrap();
        let mut result = Ok(());
        for chunk in new.chunks(4096) {
            result = s.push(chunk);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(Refusal::SinkFailed));
        drop(s);
        assert_eq!(slots.active(), &old[..]);
        assert!(!slots.pending());
        slots.fail_after = None;
        let mut s = OtaSession::begin(m, &mut slots).unwrap();
        s.push(&new).unwrap();
        s.finish().unwrap();
        assert_eq!(MemorySlots::firmware_of(slots.boot()), Some("1.5.0"));
        // too big for the slot
        let mut small = MemorySlots::new(old, 100);
        let m2 =
            OtaManifest::sign("janus/cam", "2", Chip::Esp32S3, &[1u8; 200], &did, &key).unwrap();
        assert!(matches!(
            OtaSession::begin(m2, &mut small),
            Err(Refusal::TooLarge)
        ));
    }
}
