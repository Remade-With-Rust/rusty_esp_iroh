# xiao-s3-sense-idf-mesh

Janus **J3** firmware, Track A (std on ESP-IDF), PSRAM tier: the XIAO
ESP32-S3 Sense as a mesh node with its own `did:mata`.

Boot → Wi-Fi → SNTP → identity from NVS (`rusty_esp_mid-esp`: P-256 device
key + ed25519 endpoint key, generated once from the hardware RNG after the
radio is up) → an iroh 1.1 endpoint (`rusty_esp_iroh-host`, the same node
code the laptop runs, pure-Rust TLS) answering `janus/echo/1`, `janus/rpc/1`,
`janus/media/1` and `mata-oem-sidecar/rpc/1` → mDNS
`_mata-oem-sidecar._tcp.local.` so the home computer's pair client lists it →
serial prints the DID, the endpoint id and the `janus1…` ticket.

## Prerequisites

As for the J1/J2 firmware: `espup`, `ldproxy`, `espflash`, the esp env, a
non-venv Python 3, and on Windows a short `CARGO_TARGET_DIR` plus
`git config --global core.longpaths true`. Run `cargo generate-lockfile` once
before the very first `cargo build` (mission plan §8).

## Build, flash, dial

```sh
export CARGO_TARGET_DIR=C:/janus-i                 # Windows only
export JANUS_WIFI_SSID=yournet JANUS_WIFI_PASS=yourpass
cargo build --release
cargo run --release                                # espflash flash --monitor
```

Serial prints `TICKET janus1…`. On the laptop:

```sh
cargo run -p rusty_esp_iroh-host --example client -- <ticket> echo
cargo run -p rusty_esp_iroh-host --example client -- <ticket> manifest
cargo run -p rusty_esp_iroh-host --example client -- <ticket> sidecar
cargo run -p rusty_esp_iroh-host --example client -- <ticket> media 10
```

## The kill tests this firmware carries

- **mid M1:** the DID is stable across reflash (the key lives in NVS); the
  signed manifest verifies under it (`client … manifest`).
- **iroh N1:** echo RTT and the `EndpointId` stable across reflash; the
  short-ticket relay dial is **not** in this build (LAN-direct only, see
  Notes).
- **N4 / M2 (host side ready):** the pair client's mDNS browse shows the
  device as an OEM sidecar; adoption over `janus/rpc/1` pins the owner.

## Build status

Not yet built; the ledger records the first build.

## Notes

- `rusty_esp_mid-esp` is built with `allow-insecure-dev` because the bench
  board has neither flash encryption nor NVS encryption enabled; the firmware
  logs a warning when the partition is plaintext. A shipping build drops the
  feature and `EspNvsKv::open` refuses a plaintext partition.
- Relay + pkarr (reach from another network) needs n0's std DNS shim and the
  relay-certificate verifier from `iroh-esp32-examples`; that is the next step
  on this firmware and lands behind `NodeConfig::relay`.
- The media source is a test pattern until the J1 camera pipeline is wired in.
