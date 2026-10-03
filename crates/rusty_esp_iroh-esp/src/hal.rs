//! Track B — the chip's half of N5 on esp-hal: the two-slot sink over
//! `esp-bootloader-esp-idf`'s OTA data and `esp-storage`'s flash, and the
//! "this image works" mark a freshly booted firmware sets.
//!
//! iroh itself has no Track B (the crate docs say why); what this module
//! gives a `no_std` firmware is everything under the transport: the same
//! [`OtaSink`] the ESP-IDF sink implements, so the core's [`OtaSession`]
//! — the maker's signature, the length, the digest, in that order — runs
//! unchanged over whatever carried the bytes (the page's HTTP in the X6
//! cells, a bridge tomorrow). The ESP-IDF twin wrote through `esp_ota_*`;
//! this writes the inactive slot through the C bootloader's own data
//! formats, read and written in Rust, and the bootloader that boots the
//! result is the one espflash embeds, unchanged (killing-C plan, X7).
//!
//! [`OtaSession`]: rusty_esp_iroh_core::ota::OtaSession

use embedded_storage::nor_flash::NorFlash;
use esp_bootloader_esp_idf::ota::OtaImageState;
use esp_bootloader_esp_idf::ota_updater::OtaUpdater;
use esp_bootloader_esp_idf::partitions::{
    AppPartitionSubType, PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
};
use esp_storage::FlashStorage;
use rusty_esp_iroh_core::esp_core::error::{Error, Result};
use rusty_esp_iroh_core::ota::OtaSink;

/// Flash writes are whole words: the sink carries up to three bytes of a
/// chunk over to the next, and pads the last.
const WORD: usize = 4;
/// The flash's program unit: an aligned 256-byte page. A write that
/// straddles two is two program operations (W15).
const PAGE: usize = 256;
/// Erase granularity of the slot.
const SECTOR: u32 = 4096;

/// What the bootloader will do with the running image, read from the OTA
/// data on boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningImage {
    /// The slot this image runs from: the cache MMU's word when the table
    /// gave one (a bootloader that fell back leaves `otadata` naming the
    /// other slot), else what `otadata` names.
    pub selected: AppPartitionSubType,
    /// Its state in `otadata`; `Undefined` when `otadata` names the other
    /// slot.
    pub state: OtaImageState,
}

/// The inactive slot as an [`OtaSink`], and the running slot's mark.
///
/// One sink per firmware: it owns the flash handle for as long as updates
/// may arrive. Nothing here touches the running slot, and nothing is made
/// bootable until the session's digest matched: [`OtaSink::finish`] is the
/// only call that writes `otadata`.
pub struct FlashSlots<'a, 'd> {
    updater: OtaUpdater<'a, 'd>,
    /// An update in progress: bytes written so far, and the length begun.
    writing: Option<Writing>,
    /// The slot this image runs from, by the cache MMU's word (the page the
    /// bootloader mapped); `None` when the table could not say.
    booted: Option<AppPartitionSubType>,
}

#[derive(Debug, Clone, Copy)]
struct Writing {
    len: u32,
    /// Bytes programmed so far: a whole number of pages until `finish`.
    written: u32,
    /// The page being filled (W15: the flash programs whole pages).
    page: [u8; PAGE],
    held: usize,
}

impl core::fmt::Debug for FlashSlots<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlashSlots")
            .field("writing", &self.writing)
            .finish_non_exhaustive()
    }
}

impl<'a, 'd> FlashSlots<'a, 'd> {
    /// Over `flash`, reading the partition table into `table`. Refused on a
    /// table without two OTA app slots and an OTA data partition — a device
    /// on the one-slot table cannot take an update, and says so at boot
    /// rather than at the first push.
    pub fn new(
        flash: &'a mut FlashStorage<'d>,
        table: &'a mut [u8; PARTITION_TABLE_MAX_LEN],
    ) -> Result<Self> {
        // The slot this image runs from is the cache MMU's word, read before
        // the updater takes the table: after a rollback `otadata` still names
        // the slot that was aborted, and on a blank `otadata` the updater's
        // own "next" slot is this one.
        let booted = read_partition_table(&mut *flash, &mut table[..])
            .ok()
            .and_then(|pt| pt.booted_partition().ok().flatten())
            .and_then(|entry| match entry.partition_type() {
                PartitionType::App(slot) => Some(slot),
                _ => None,
            });
        let updater = OtaUpdater::new(flash, table).map_err(|_| Error::Unsupported)?;
        Ok(FlashSlots {
            updater,
            writing: None,
            booted,
        })
    }

    /// The running image's slot and state, as `otadata` has them.
    pub fn running(&mut self) -> Result<RunningImage> {
        let (selected, state, _) = self.observed()?;
        Ok(RunningImage { selected, state })
    }

    /// The running slot, its state, and whether `otadata` names it: the
    /// MMU's word for the slot when the table gave one, else `otadata`'s;
    /// the state is `Undefined` when `otadata` names the other slot (a
    /// bootloader fell back to this one).
    fn observed(&mut self) -> Result<(AppPartitionSubType, OtaImageState, bool)> {
        let named = self
            .updater
            .selected_partition()
            .map_err(|_| Error::Hardware)?;
        let state = self
            .updater
            .current_ota_state()
            .map_err(|_| Error::Hardware)?;
        Ok(match self.booted {
            Some(slot) if slot != named => (slot, OtaImageState::Undefined, false),
            Some(slot) => (slot, state, true),
            None => (named, state, true),
        })
    }

    /// What a freshly booted image does once it finds itself working: tell
    /// the bootloader so, which cancels the rollback. Returns the state it
    /// found; `New` or `PendingVerify` is the first boot after an update,
    /// `Undefined` means `otadata` named the other slot (a bootloader fell
    /// back to this one, and `otadata` now names this one, `Valid`, as
    /// `esp_ota_mark_app_valid_cancel_rollback` would have it), anything
    /// else means there was nothing to confirm.
    pub fn mark_running_valid(&mut self) -> Result<OtaImageState> {
        let (slot, state, named) = self.observed()?;
        if !named {
            self.updater
                .ota_data()
                .map_err(|_| Error::Hardware)?
                .set_current_app_partition(slot)
                .map_err(|_| Error::Hardware)?;
            self.updater
                .set_current_ota_state(OtaImageState::Valid)
                .map_err(|_| Error::Hardware)?;
        } else if matches!(state, OtaImageState::New | OtaImageState::PendingVerify) {
            self.updater
                .set_current_ota_state(OtaImageState::Valid)
                .map_err(|_| Error::Hardware)?;
        }
        Ok(state)
    }

    /// The slot an update would be written into.
    pub fn next_slot(&mut self) -> Result<AppPartitionSubType> {
        let (_, slot) = self.updater.next_partition().map_err(|_| Error::Hardware)?;
        Ok(slot)
    }
}

/// Program `words` (whole 4-byte words, `offset` word-aligned) into the
/// slot an update goes to, through the region's NOR path: a plain page
/// program into sectors `begin` erased. The region's own `write` is
/// esp-storage's `Storage` write, which reads the 4 KB sector, erases it and
/// programs it back for every call -- on the XIAO that was 39 ms per
/// 220-byte chunk of an update over the link (X9), and nineteen erases of
/// every sector per image.
fn program(updater: &mut OtaUpdater<'_, '_>, offset: u32, words: &[u8]) -> Result<()> {
    let (mut region, _) = updater.next_partition().map_err(|_| Error::Hardware)?;
    let mut nor = region.as_nor_flash().map_err(|_| Error::Hardware)?;
    NorFlash::write(&mut nor, offset, words).map_err(|_| Error::Hardware)
}

impl OtaSink for FlashSlots<'_, '_> {
    fn begin(&mut self, image_len: u32) -> Result<()> {
        if self.writing.is_some() {
            return Err(Error::Busy);
        }
        let (mut region, slot) = self.updater.next_partition().map_err(|_| Error::Hardware)?;
        // never the slot this image runs from, whatever `otadata` says: on
        // a blank `otadata` the updater's "next" is this one
        if Some(slot) == self.booted {
            return Err(Error::Denied);
        }
        let capacity = u32::try_from(region.capacity()).map_err(|_| Error::Hardware)?;
        if image_len == 0 || image_len > capacity {
            return Err(Error::BufferTooSmall {
                needed: image_len as usize,
            });
        }
        // the sectors the image will occupy, and nothing past them
        let end = image_len.div_ceil(SECTOR) * SECTOR;
        region
            .erase(0, end.min(capacity))
            .map_err(|_| Error::Hardware)?;
        self.writing = Some(Writing {
            len: image_len,
            written: 0,
            page: [0xFF; PAGE],
            held: 0,
        });
        Ok(())
    }

    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        let Some(w) = self.writing.as_mut() else {
            return Err(Error::InvalidFormat);
        };
        let total = w.written as usize + w.held + chunk.len();
        if total > w.len as usize {
            self.writing = None;
            return Err(Error::BufferTooSmall { needed: total });
        }
        let mut rest = chunk;
        // fill the held page first; a full one is programmed whole
        if w.held > 0 {
            let take = (PAGE - w.held).min(rest.len());
            w.page[w.held..w.held + take].copy_from_slice(&rest[..take]);
            w.held += take;
            rest = &rest[take..];
            if w.held == PAGE {
                program(&mut self.updater, w.written, &w.page)?;
                w.written += PAGE as u32;
                w.held = 0;
            }
        }
        // whole pages straight from the chunk, aligned because `written` is
        if w.held == 0 {
            let whole = rest.len() / PAGE * PAGE;
            if whole > 0 {
                program(&mut self.updater, w.written, &rest[..whole])?;
                w.written += whole as u32;
                rest = &rest[whole..];
            }
            // the rest waits for the next chunk, or for `finish`
            w.page[..rest.len()].copy_from_slice(rest);
            w.held = rest.len();
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let Some(w) = self.writing.take() else {
            return Err(Error::InvalidFormat);
        };
        if w.written as usize + w.held != w.len as usize {
            return Err(Error::InvalidFormat);
        }
        if w.held > 0 {
            // the last partial page, whole words, the last one padded with
            // the erased value
            let mut page = w.page;
            let words = w.held.div_ceil(WORD) * WORD;
            page[w.held..words].fill(0xFF);
            program(&mut self.updater, w.written, &page[..words])?;
        }
        // only now: the slot becomes the boot slot, marked New so a
        // bootloader with rollback tries it once
        self.updater
            .activate_next_partition()
            .map_err(|_| Error::Hardware)?;
        self.updater
            .set_current_ota_state(OtaImageState::New)
            .map_err(|_| Error::Hardware)
    }

    fn abort(&mut self) {
        // the inactive slot is half-written and stays inactive: nothing to undo
        self.writing = None;
    }
}
