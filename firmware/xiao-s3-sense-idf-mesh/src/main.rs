//! Janus J3 on the XIAO ESP32-S3 Sense: a mesh node with its own DID.
//!
//! Boot → Wi-Fi → SNTP → identity from NVS (P-256 device key + ed25519
//! endpoint key, generated on first boot from the hardware RNG) → iroh
//! endpoint with the Janus ALPNs and the OEM-sidecar RPC → mDNS
//! advertisement → serial prints the DID, endpoint id and the `janus1…`
//! ticket to scan. The M1/N1 kill tests read that serial line:
//!
//! ```sh
//! JANUS_WIFI_SSID=mynet JANUS_WIFI_PASS=secret cargo run --release
//! # on the laptop:
//! cargo run -p rusty_esp_iroh-host --example client -- <ticket> echo
//! ```

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::link_patches;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use rusty_esp_core::capability::{Capability, Chip, Declared, Manifest};
use rusty_esp_iroh_core::media::{PacketHeader, Subscribe, FLAG_KEY};
use rusty_esp_iroh_esp::idf::{register_eventfd, sync_time, EspNvsKv, EspRng, Protection, MDNS_COMPILED_IN};
use rusty_esp_iroh_host::{MediaSource, Node, NodeConfig, NodeIdentity};

const SSID: &str = env!("JANUS_WIFI_SSID");
const PASS: &str = env!("JANUS_WIFI_PASS");

/// ESP-IDF has no `gethostname`, but hickory-resolver's `resolv_conf` (still
/// linked by iroh-dns even though the std DNS shim replaces it at runtime)
/// references it. The same one-line shim n0's `iroh-esp32-examples` carry:
/// report an empty hostname.
///
/// SAFETY: writes one NUL byte into `name` only when the caller passed a
/// non-null buffer of at least one byte, which is the C contract of the call.
#[unsafe(no_mangle)]
unsafe extern "C" fn gethostname(name: *mut core::ffi::c_char, len: usize) -> core::ffi::c_int {
    if len > 0 && !name.is_null() {
        unsafe { *name = 0 };
    }
    0
}

/// A stand-in media source until the camera pipeline (J1) is wired in:
/// 900-byte test packets at 10 per second.
struct TestPattern {
    seq: u32,
}

impl MediaSource for TestPattern {
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)> {
        let h = PacketHeader {
            seq: self.seq,
            timestamp_us: u64::from(self.seq) * 100_000,
            codec: *b"test",
            flags: FLAG_KEY,
            len: 900,
        };
        self.seq = self.seq.wrapping_add(1);
        Some((h, vec![(self.seq & 0xFF) as u8; 900]))
    }
    fn interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}

fn main() -> Result<()> {
    link_patches();
    EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs_partition = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs_partition.clone()))?,
        sysloop,
    )?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().map_err(|_| anyhow::anyhow!("SSID too long"))?,
        password: PASS.try_into().map_err(|_| anyhow::anyhow!("password too long"))?,
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.connect()?;
    wifi.wait_netif_up()?;
    let ip = wifi.wifi().sta_netif().get_ip_info()?.ip;
    let ip = IpAddr::V4(std::net::Ipv4Addr::from(ip.octets()));
    log::info!("janus j3: wifi up at {ip}");

    let (_sntp, synced) = sync_time(Duration::from_secs(20)).context("sntp")?;
    log::info!("janus j3: sntp synced = {synced}");

    // Identity: the device key and the endpoint key live in NVS. The radio is
    // up, so the hardware RNG is a true one.
    let mut kv = EspNvsKv::open(nvs_partition, "janus").context("nvs (plaintext partition refused unless allow-insecure-dev)")?;
    log::info!("janus j3: nvs protection = {:?}", kv.protection());
    if kv.protection() == Protection::Plaintext {
        log::warn!("janus j3: DEVELOPMENT BUILD — the device key sits in a plaintext partition");
    }
    let mut rng = EspRng::after_radio_start();
    let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus").context("identity")?;
    log::info!("janus j3: did = {}", identity.did_string());
    log::info!("janus j3: endpoint id = {}", identity.endpoint_id());

    register_eventfd(5).context("eventfd")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .thread_stack_size(4096)
        .build()
        .context("tokio")?;

    rt.block_on(async move {
        let declared = [
            Declared::available(Capability::IrohLanDirect, "rusty_esp_iroh"),
            Declared::available(Capability::MidDevice, "rusty_esp_mid"),
            Declared::planned(Capability::IrohRelay),
            Declared::preview(Capability::VideoMjpeg, "rusty_esp_video"),
        ];
        let manifest = Manifest {
            model: "janus/xiao-s3-sense",
            firmware: env!("CARGO_PKG_VERSION"),
            chip: Chip::Esp32S3,
            declared: &declared,
        };
        let media = Arc::new(|_sub: &Subscribe| -> Box<dyn MediaSource> { Box::new(TestPattern { seq: 0 }) });
        let config = NodeConfig {
            relay: cfg!(feature = "relay"),
            model: String::from("janus/xiao-s3-sense"),
            firmware: format!("janus-mesh {}", env!("CARGO_PKG_VERSION")),
        };
        let node = Node::bind(identity, Box::new(kv), &manifest, Some(media), config)
            .await
            .map_err(|e| anyhow::anyhow!("bind: {e}"))?;
        node.refresh_ticket(&[ip]);
        log::info!("janus j3: port = {}", node.port());
        log::info!("janus j3: TICKET {}", node.ticket_text());
        #[cfg(any(esp_idf_comp_mdns_enabled, esp_idf_comp_espressif__mdns_enabled))]
        let _mdns = rusty_esp_iroh_esp::idf::advertise_sidecar(&node, "janus-xiao", &[ip]).context("mdns")?;
        if !MDNS_COMPILED_IN {
            log::warn!("janus j3: mdns component not compiled in — reachable by ticket only (mission plan §8, wall 5)");
        }

        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let c = &node.state().counters;
            log::info!(
                "echo={} rpc={} refused={} sidecar={} media_subs={} media_pkts={} media_err={} adopted={}",
                c.echo.load(std::sync::atomic::Ordering::Relaxed),
                c.rpc.load(std::sync::atomic::Ordering::Relaxed),
                c.rpc_refused.load(std::sync::atomic::Ordering::Relaxed),
                c.sidecar.load(std::sync::atomic::Ordering::Relaxed),
                c.media_subscribers.load(std::sync::atomic::Ordering::Relaxed),
                c.media_packets.load(std::sync::atomic::Ordering::Relaxed),
                c.media_send_errors.load(std::sync::atomic::Ordering::Relaxed),
                node.is_adopted()
            );
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}
