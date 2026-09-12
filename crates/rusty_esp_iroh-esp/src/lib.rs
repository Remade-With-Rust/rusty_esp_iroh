#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
//! `rusty_esp_iroh-esp` — what a chip adds to the std node.
//!
//! iroh runs on **Track A only** (std on ESP-IDF, the configuration n0
//! proved). The node and client are `rusty_esp_iroh-host`, unchanged; this
//! crate holds the ESP-IDF specifics: registering `eventfd` so tokio's I/O
//! driver works, SNTP before any TLS, the mDNS advertisement the home
//! computer's pair client browses for, and the identity loaded from NVS
//! through `rusty_esp_mid-esp`.
//!
//! `unsafe` is denied crate-wide; the one FFI call (`esp_vfs_eventfd_register`)
//! opts in per block with a `// SAFETY:` comment.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "esp-hal")]
compile_error!(
    "rusty_esp_iroh has no Track B: iroh needs std (tokio, rustls). A no_std node reaches the \
     mesh through rusty_esp_iroh-bridge on a Pi, a P4 or a PSRAM ESP32-S3. Enable `esp-idf` instead."
);

pub use rusty_esp_iroh_core as core;

/// Which track this build of the crate was compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    /// No chip backend compiled in.
    Host,
    /// Track A — std on ESP-IDF.
    EspIdf,
}

/// The track this crate was built with.
pub const TRACK: Track = if cfg!(feature = "esp-idf") {
    Track::EspIdf
} else {
    Track::Host
};

#[cfg(feature = "esp-idf")]
pub mod idf {
    //! Track A glue over esp-idf-svc 0.52.

    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    use std::net::IpAddr;
    use std::time::Duration;

    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    use esp_idf_svc::mdns::EspMdns;
    use esp_idf_svc::sntp::{EspSntp, SyncStatus};
    use esp_idf_svc::sys::EspError;
    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    use rusty_esp_iroh_core::sidecar::SERVICE_TYPE;
    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    use rusty_esp_iroh_host::Node;

    /// Whether the `espressif/mdns` IDF component was compiled into this
    /// firmware (it arrives through `[package.metadata.esp-idf-sys]`, which
    /// esp-idf-sys only reads when its `cargo metadata --locked` succeeds —
    /// mission plan §8). Without it `advertise_sidecar` does not exist and
    /// the device is reachable by ticket only.
    pub const MDNS_COMPILED_IN: bool = cfg!(any(
        esp_idf_comp_mdns_enabled,
        esp_idf_comp_espressif__mdns_enabled
    ));

    pub use rusty_esp_mid_esp::idf::{EspNvsKv, EspRng, Protection};

    pub use ota::EspOtaSink;

    /// The two-slot OTA sink (N5) over ESP-IDF's `esp_ota_*` API.
    ///
    /// The inactive app partition takes the bytes, `finish` ends the write
    /// and makes that partition the boot partition, and
    /// [`EspOtaSink::mark_running_valid`] is what a freshly booted image
    /// calls once its endpoint is up — without it the bootloader rolls
    /// back on the next reset (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`).
    ///
    /// **The one fenced `unsafe` in this crate.** `esp-idf-svc`'s safe
    /// `EspOta` / `EspOtaUpdate` pair ties the update handle's lifetime to
    /// a borrow of the singleton, which cannot live inside a `Box<dyn
    /// OtaSink + Send>` without a self-reference; the C API's handle is a
    /// plain integer and the partition a pointer ESP-IDF owns for the life
    /// of the program, so the sink keeps those and calls the same six
    /// functions `esp-idf-svc` does, in the same order.
    #[allow(unsafe_code)]
    mod ota {
        use esp_idf_svc::sys::{
            EspError, esp, esp_ota_abort, esp_ota_begin, esp_ota_end,
            esp_ota_get_next_update_partition, esp_ota_handle_t,
            esp_ota_mark_app_valid_cancel_rollback, esp_ota_set_boot_partition, esp_ota_write,
            esp_partition_t,
        };
        use rusty_esp_iroh_core::esp_core::error::{Error, Result};
        use rusty_esp_iroh_core::ota::OtaSink;

        /// The inactive slot as an [`OtaSink`].
        #[derive(Debug, Default)]
        pub struct EspOtaSink {
            /// `*const esp_partition_t` as an address: ESP-IDF owns the
            /// partition table for the life of the program, and an address
            /// is `Send` where a raw pointer is not.
            partition: usize,
            handle: Option<esp_ota_handle_t>,
        }

        impl EspOtaSink {
            /// A sink over the next update partition.
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            /// Tell the bootloader the running image is good (cancels the
            /// pending rollback). Call once the endpoint is up.
            pub fn mark_running_valid() -> core::result::Result<(), EspError> {
                // SAFETY: a plain ESP-IDF call with no arguments.
                esp!(unsafe { esp_ota_mark_app_valid_cancel_rollback() })
            }
        }

        impl OtaSink for EspOtaSink {
            fn begin(&mut self, image_len: u32) -> Result<()> {
                if self.handle.is_some() {
                    return Err(Error::Busy);
                }
                // SAFETY: a null argument asks ESP-IDF for the partition after
                // the running one; the returned pointer is into the partition
                // table ESP-IDF keeps for the life of the program.
                let partition = unsafe { esp_ota_get_next_update_partition(core::ptr::null()) };
                if partition.is_null() {
                    return Err(Error::Unsupported);
                }
                // SAFETY: `partition` is the pointer ESP-IDF just returned;
                // `handle` is a local ESP-IDF fills.
                let size = unsafe { (*partition).size };
                if u64::from(image_len) > u64::from(size) {
                    return Err(Error::BufferTooSmall {
                        needed: image_len as usize,
                    });
                }
                let mut handle: esp_ota_handle_t = 0;
                // SAFETY: as above; `image_len` is the exact size, which lets
                // ESP-IDF erase only what it must.
                esp!(unsafe { esp_ota_begin(partition, image_len as usize, &mut handle) })
                    .map_err(|_| Error::Hardware)?;
                self.partition = partition as usize;
                self.handle = Some(handle);
                Ok(())
            }

            fn write(&mut self, chunk: &[u8]) -> Result<()> {
                let handle = self.handle.ok_or(Error::Busy)?;
                if chunk.is_empty() {
                    return Ok(());
                }
                // SAFETY: `handle` came from `esp_ota_begin`; the buffer is a
                // live slice for the duration of the call.
                esp!(unsafe { esp_ota_write(handle, chunk.as_ptr().cast(), chunk.len()) })
                    .map_err(|_| Error::Hardware)
            }

            fn finish(&mut self) -> Result<()> {
                let handle = self.handle.take().ok_or(Error::Busy)?;
                let partition = self.partition as *const esp_partition_t;
                // SAFETY: the handle is live until `esp_ota_end` consumes it;
                // the partition pointer is the one `begin` stored.
                esp!(unsafe { esp_ota_end(handle) }).map_err(|_| Error::Corrupt)?;
                esp!(unsafe { esp_ota_set_boot_partition(partition) }).map_err(|_| Error::Hardware)
            }

            fn abort(&mut self) {
                if let Some(handle) = self.handle.take() {
                    // SAFETY: the handle is live; abort releases it.
                    let _ = unsafe { esp_ota_abort(handle) };
                }
            }
        }
    }

    /// Register the `eventfd` VFS tokio's I/O driver (mio) needs. Call once
    /// before building the runtime; `max_fds` of 5 is what n0 uses.
    pub fn register_eventfd(max_fds: usize) -> Result<(), EspError> {
        let config = esp_idf_svc::sys::esp_vfs_eventfd_config_t {
            max_fds,
            ..Default::default()
        };
        // SAFETY: `config` is a fully initialised POD struct that outlives the
        // call; the function registers a VFS driver and has no other
        // preconditions. Called once at boot.
        #[allow(unsafe_code)]
        let code = unsafe { esp_idf_svc::sys::esp_vfs_eventfd_register(&config) };
        EspError::convert(code)
    }

    /// Start SNTP and wait up to `timeout` for the first sync. TLS (the relay,
    /// pkarr) needs a sane clock; LAN-direct does not, so a timeout is a
    /// warning, not an error. Keep the returned handle alive to keep syncing.
    pub fn sync_time(timeout: Duration) -> Result<(EspSntp<'static>, bool), EspError> {
        let sntp = EspSntp::new_default()?;
        let started = std::time::Instant::now();
        while sntp.get_sync_status() != SyncStatus::Completed {
            if started.elapsed() > timeout {
                return Ok((sntp, false));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok((sntp, true))
    }

    /// Advertise `_mata-oem-sidecar._tcp.local.` with the node's TXT record so
    /// the home computer's pair client lists the device. The service port is
    /// the iroh UDP port (the record's `iroh_direct` carries the same); the
    /// instance name is the model. Keep the returned handle alive.
    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    pub fn advertise_sidecar(
        node: &Node,
        hostname: &str,
        ips: &[IpAddr],
    ) -> Result<EspMdns, EspError> {
        advertise_parts(
            hostname,
            "Janus device",
            SERVICE_TYPE,
            node.port(),
            &node.sidecar_txt(ips),
        )
    }

    /// The same advertisement from its parts, for a caller that has the TXT
    /// record and the port but not the [`Node`] — a generated sketch, whose
    /// node lives inside the `rusty_esp_arduino` facade and is never handed
    /// out. `service_type` is the full mDNS type; ESP-IDF wants the service
    /// and protocol labels separately, and splitting it is this function's
    /// job so no caller has to know that. Keep the returned handle alive.
    #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
    pub fn advertise_parts(
        hostname: &str,
        instance: &str,
        service_type: &str,
        port: u16,
        txt: &[(String, String)],
    ) -> Result<EspMdns, EspError> {
        let mut mdns = EspMdns::take()?;
        mdns.set_hostname(hostname)?;
        mdns.set_instance_name(instance)?;
        let pairs: Vec<(&str, &str)> = txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let (service, rest) = service_type
            .split_once('.')
            .unwrap_or(("_mata-oem-sidecar", "_tcp.local."));
        let proto = rest.split_once('.').map_or("_tcp", |(p, _)| p);
        mdns.add_service(Some(instance), service, proto, port, &pairs)?;
        log::info!("mdns: {hostname}.local {service}.{proto} port {port} with {} TXT keys", pairs.len());
        Ok(mdns)
    }
}
