# rusty_esp_iroh

[![crates.io](https://img.shields.io/crates/v/rusty_esp_iroh.svg)](https://crates.io/crates/rusty_esp_iroh)
[![docs.rs](https://docs.rs/rusty_esp_iroh/badge.svg)](https://docs.rs/rusty_esp_iroh)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The MATA mesh on the chip: an iroh endpoint on ESP32 (std/ESP-IDF track), Janus ALPN protocols (rpc, media, telemetry), a host client, and a bridge that fronts no_std nodes on the mesh. Replaces cloud-IoT device SDKs.

Part of **Janus**, the Remade-With-Rust programme that rebuilds the Espressif
ESP32 and Arduino application portfolio in memory-safe Rust so hardware makers
can ship products that plug straight into the MATA home computer.

- This package's plan: [docs/plans/rusty_esp_iroh.md](docs/plans/rusty_esp_iroh.md)
- The family plan: Janus `docs/plans/janus-mission.md` (umbrella repo)

**Claims discipline:** this README makes no performance or capability claim that
is not backed by a test, a benchmark ledger entry, or a kill test recorded in the
plan. "Scaffold" means scaffold.

## Status

**N0 shipped on the host (2026-09-01); N1 and N4 host halves done.** The
Janus protocols are defined and tested in `no_std` (ALPNs, the `janus1…` QR
ticket, the DID↔endpoint `Binding`, postcard RPC with mID assertions, media
framing, the home computer's OEM-sidecar JSON), and a `Node` + `Client` over
iroh 1.1 with pure-Rust TLS prove them end to end on one machine: an RPC
without an assertion is refused, a stranger is denied, the owner adopts, media
streams with zero loss. The XIAO ESP32-S3 Sense firmware builds (4.66 MB
image, 2026-09-02); nothing has run on a chip yet. `docs/LEDGER.md` has every number.

**N2 host half (2026-09-02):** real MJPEG over `janus/media/1` — a directory
source and, behind the `mjpeg` feature, J1's HTTP stream republished by the
node (the Pi-in-front-of-a-camera bridge); every subscriber's source on its
own thread; the client writes frames to disk. One subscriber for a minute:
591 frames written, every one byte-identical to its source
file, 0 lost; two subscribers at once: 0 and
0 lost; the HTTP bridge at 16.06 fps against the
server's 16.05.

## What is in it

| crate / module | what |
|---|---|
| `-core` `alpn` | `janus/echo/1`, `janus/rpc/1`, `janus/media/1`, `mata-oem-sidecar/rpc/1` |
| `-core` `ticket` | the rendezvous ticket: endpoint id + DID + relay + addresses, `janus1…` base32 text for QR and serial, no heap |
| `-core` `binding` | the device key's signature over its iroh `EndpointId` |
| `-core` `assertion` | the caller's mID assertion (kms nonce-envelope shape) with replay window |
| `-core` `rpc` | append-only `Request`/`Response`, length-prefixed postcard frames, the authorisation rule |
| `-core` `media` | subscribe message, 24-byte packet header, loss counter |
| `-core` `sidecar` | the home computer's existing JSON RPC and mDNS TXT record, answered by a device |
| `-host` | `Node` (all four ALPNs), `Client`, `NodeIdentity` (both keys from the `Kv` seam), n0's QUIC crypto provider; `examples/{node,client}` |
| `-esp` (`esp-idf`) | eventfd, SNTP, mDNS advertisement, NVS identity — the chip's glue around the std node |
| `firmware/xiao-s3-sense-idf-mesh` | the J3 firmware |

## What it is

- A pure-Rust remake of the *application* layer Espressif ships in C for this
  function. Same job, same protocols and file formats, new code, permissive
  licence, `forbid(unsafe)` in the core.
- Track-agnostic: the core crate is `no_std + alloc` and knows nothing about
  ESP-IDF or `esp-hal`. Backends are thin and feature-gated.

## What it is not

- Not a rewrite of the radio PHY, the ROM, or Espressif's Wi-Fi/BT controller
  blob. Where the silicon must be touched, the `-esp` crate **wraps** the
  esp-rs HAL or ESP-IDF and says so.
- Not a fork of esp-hal, esp-radio, espflash or ESP-IDF. Those are dependencies.

## Layout

```text
crates/rusty_esp_iroh          facade: re-exports + prelude; the crate you depend on
crates/rusty_esp_iroh-core     no_std + alloc; forbid(unsafe); types, traits, algorithms
crates/rusty_esp_iroh-esp      the WRAP crate: `esp-hal` (Track B) | `esp-idf` (Track A)
firmware/                per-chip example projects, excluded from the workspace
docs/plans/              the mission plan for this package
```

## Two tracks, one core

| Track | Feature | Runtime | Use when |
|---|---|---|---|
| **A** | `esp-idf` | `std` on ESP-IDF (FreeRTOS) | you need iroh, TLS, or a driver ESP-IDF has and esp-hal lacks |
| **B** | `esp-hal` | `no_std` + Embassy | the purity path; every driver upstream in esp-rs |

The core compiles on both and on the host, which is where its tests run.

## Build

```sh
cargo test --workspace                                   # host: the tests
cargo check -p rusty_esp_iroh-core --no-default-features \
  --target riscv32imac-unknown-none-elf                  # ESP32-C6 class, no alloc
cargo check -p rusty_esp_iroh-core --no-default-features --features alloc \
  --target riscv32imac-unknown-none-elf
```

Firmware examples (Xtensa needs `espup`; RISC-V works on stable) are built from
their own directories under `firmware/`.

## License

MIT OR Apache-2.0, at your option.
