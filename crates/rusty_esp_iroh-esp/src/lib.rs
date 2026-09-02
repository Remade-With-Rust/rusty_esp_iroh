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

    use std::net::IpAddr;
    use std::time::Duration;

    use esp_idf_svc::mdns::EspMdns;
    use esp_idf_svc::sntp::{EspSntp, SyncStatus};
    use esp_idf_svc::sys::EspError;
    use rusty_esp_iroh_core::sidecar::SERVICE_TYPE;
    use rusty_esp_iroh_host::Node;

    pub use rusty_esp_mid_esp::idf::{EspNvsKv, EspRng, Protection};

    /// Register the `eventfd` VFS tokio's I/O driver (mio) needs. Call once
    /// before building the runtime; `max_fds` of 5 is what n0 uses.
    pub fn register_eventfd(max_fds: usize) -> Result<(), EspError> {
        let config = esp_idf_svc::sys::esp_vfs_eventfd_config_t {
            max_fds: max_fds as u32,
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
    pub fn advertise_sidecar(
        node: &Node,
        hostname: &str,
        ips: &[IpAddr],
    ) -> Result<EspMdns, EspError> {
        let mut mdns = EspMdns::take()?;
        mdns.set_hostname(hostname)?;
        mdns.set_instance_name("Janus device")?;
        let txt = node.sidecar_txt(ips);
        let pairs: Vec<(&str, &str)> = txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        // SERVICE_TYPE is "_mata-oem-sidecar._tcp.local."; ESP-IDF wants the
        // service and protocol parts separately.
        let (service, rest) = SERVICE_TYPE
            .split_once('.')
            .unwrap_or(("_mata-oem-sidecar", "_tcp.local."));
        let proto = rest.split_once('.').map_or("_tcp", |(p, _)| p);
        mdns.add_service(Some("Janus device"), service, proto, node.port(), &pairs)?;
        log::info!(
            "mdns: {service}.{proto} port {} with {} TXT keys",
            node.port(),
            pairs.len()
        );
        Ok(mdns)
    }
}
