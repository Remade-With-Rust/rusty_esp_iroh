# rusty_esp_iroh — ledger

Every number a README or plan claims lives here first, with how it was taken.
Discipline: external oracle before self-metric; nothing on a chip is claimed
until a chip ran it.

## N0 — the protocols and a node on the host (2026-09-01)

Machine: Windows 11, Rust 1.98.0 stable, iroh 1.1.0, rustls 0.23 with the
rustls-rustcrypto provider (`feature-flag-algorithms-v0.0.2` branch), relay
disabled, node and client in one process over loopback.

| gate | result |
|---|---|
| unit tests, `rusty_esp_iroh-core` | **18** pass |
| unit tests, `rusty_esp_iroh-host` (crypto provider shape, identity) | **3** pass |
| `tests/loopback.rs` (below) | **1** pass, 8.5 s |
| clippy `--all-targets -D warnings` (core, host, esp on host), `cargo fmt --check` | clean |
| `riscv32imac-unknown-none-elf` core-only and `alloc` | check green |
| `ring` / `aws-lc-sys` in the graph | **none** — `iroh` with `default-features = false`, our provider |

### The loopback run

A `Node` (four ALPNs) and three `Client`s — anonymous, a stranger with a key,
the owner — on one machine:

| step | result |
|---|---|
| `janus/echo/1`, a fresh QUIC connection each call | first 34.5 ms; then min **19.9 ms**, median 20.5 ms over 10 |
| `Ping`, `Manifest` without an assertion | answered; the manifest signature verifies under the device DID (`verify_manifest`) |
| `Telemetry` without an assertion | `Error(Unauthorized)` |
| `Telemetry` from a stranger with a valid assertion | `Error(Denied)` |
| a stranger presenting the owner's adoption | `Error(Denied)` |
| the owner's `Adopt` (320-byte adoption, roster v3) | `Adopted { roster_version: 3 }`; `Telemetry` now answered; the stranger still `Denied` |
| the owner re-adopting with roster v2 (rotation went backwards) | `Error(Denied)` |
| `mata-oem-sidecar/rpc/1` `ping` / `status` / `janusTicket` | `mata-oem-sidecar-ok`; `pair=paired`, `model=janus/node`; the ticket parses back to the endpoint id |
| `janus/media/1`, 400 × 900-byte packets at 5 ms as QUIC datagrams | **400 received, 0 lost, 0 reordered**, 360 000 bytes in 6.22 s |
| `janus/media/1`, 100 × 4 000-byte packets as uni-streams | **100 received, 0 lost** |
| node counters | echo 11 · rpc 9 · refused 5 · sidecar 3 · media subscribers 2 · media packets 500 · send errors 0 |

The N0 kill test asked for ten minutes between two laptops; this is one
machine and seconds. The `node` and `client` examples are the two-laptop run
and its numbers go here when it happens.

## Not yet measured

- **Anything on a chip**: the `xiao-s3-sense-idf-mesh` firmware's first
  build (below when it happens), then N1's echo RTT and `EndpointId`
  stability across reflash.
- The relay path (short ticket from another network): the host node runs
  LAN-direct; the relay configuration is written for the chip, not yet on.
- Two laptops for ten minutes.
