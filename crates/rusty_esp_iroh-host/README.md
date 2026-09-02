# rusty_esp_iroh-host

The `std` half of [`rusty_esp_iroh`](https://crates.io/crates/rusty_esp_iroh):
a Janus **node** (one iroh 1.x endpoint answering `janus/echo/1`,
`janus/rpc/1`, `janus/media/1` and the home computer's
`mata-oem-sidecar/rpc/1`) and the **client** that dials it by ticket. The
same code runs on a laptop, a Raspberry Pi and — as Track A — on ESP-IDF;
`rusty_esp_iroh-esp` adds only what a chip needs (NVS, Wi-Fi, SNTP, mDNS).

TLS is pure Rust: rustls with the rustls-rustcrypto provider n0 proved on
ESP32 (`crypto.rs`, vendored from `iroh-esp32-examples`), so there is no
`ring` and no `aws-lc` in the graph.

Reach: LAN-direct by default (relay disabled, the no-PSRAM tier). The `relay`
feature adds n0's relays and pkarr lookup with the two shims the minimal
provider needs (`relay.rs`: getaddrinfo DNS, a no-op relay certificate
verifier — iroh authenticates peers by their keys, not by TLS certificates);
`NodeConfig::relay = true` / `Client::bind(.., true)` then reach beyond the
LAN, and refuse instead of silently downgrading when the feature is off.

```sh
cargo run -p rusty_esp_iroh-host --example node -- 192.168.1.20
cargo run -p rusty_esp_iroh-host --example client -- <janus1 ticket> echo|ping|manifest|telemetry|sidecar|media 10
cargo test -p rusty_esp_iroh-host          # node + client in one process, loopback
```

Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_iroh.md` in the repo.
