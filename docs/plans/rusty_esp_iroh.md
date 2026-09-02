# rusty_esp_iroh — mission plan

**One sentence:** the MATA mesh on the chip — an iroh endpoint on ESP32 (the
`std`/ESP-IDF track n0 has already proven), the Janus protocols on top of it
(rpc, media, telemetry), a host client the home computer and the Pi embed,
and a bridge that fronts `no_std` nodes on the mesh — replacing every
"device SDK for somebody's cloud" Espressif ships.

Family plan: Janus `docs/plans/janus-mission.md` (§3.6 and §4). Layer 1 ·
connectivity. Depends on `rusty_esp_core` and `rusty_esp_mid` (the endpoint
key is bound to the device DID).

Written 2026-09-01. Status: **N0 shipped on the host; N1 and N4 host halves
done (node + client, the sidecar contract, the JanusFleet proposal in
mata-master); the mesh firmware builds (2026-09-02, 4.66 MB image); the board
is next.** Numbers in `docs/LEDGER.md`.

---

## 1. Espressif map

| Espressif item | Job | Class | Janus |
|---|---|---|---|
| ESP RainMaker, AWS IoT / Azure / Google device SDKs, `esp_mqtt` to a cloud | "the device talks to a cloud" | **REPLACE** | the mesh is the cloud: an iroh endpoint dialed by public key |
| `esp_https_ota` | OTA | REMAKE the flow (signed image over iroh), WRAP `esp-ota` for the partitions | milestone N5 |
| `esp-tls` / mbedTLS | TLS | WRAP through iroh: `rustls` with n0's `rustls-rustcrypto` fork | never `ring` / `aws-lc` (platform assembly; will not build for Xtensa) |
| `mdns` component | LAN discovery | WRAP (esp-idf-svc) | advertise `_mata-oem-sidecar._tcp.local.` with `model=janus/<kind>` so the home computer app sees the device on day one |
| ESP-Hosted (Wi-Fi/BT for P4 through a C6 companion over SDIO) | radio for P4 | WRAP (managed component) | the P4 tier |
| **iroh itself** | QUIC by public key, relay, hole punching, discovery | **DEPEND** (n0's branches for ESP) | `-esp` Track A only |

## 2. What n0 proved (the configuration this package reproduces)

`n0-computer/iroh-esp32-examples` (2026): ESP32-WROVER, S3, C6, C61, P4.

| Tier | Boards | Reach | Notes |
|---|---|---|---|
| **no PSRAM** | C6, S3-no-PSRAM, bare ESP32 | LAN-direct; long tickets (endpoint id + IP) | relay disabled, QUIC buffers tuned; < 8 MiB flash needs the `esp32-no-spiram` reduced-dependency branch |
| **PSRAM** | S3 + PSRAM (XIAO Sense), WROVER, C61-PSRAM, P4 (32 MB) | relay + pkarr discovery; short ticket works from anywhere | `refactor-hickory` branch; `CONFIG_SPIRAM_USE_MALLOC=y`, main task stack 96 KB |

Constants: ESP-IDF v5.5.x, `esp-idf-svc` 0.52 (first with the C61 table),
single-threaded tokio (`rt` only), `rustls` 0.23 with the
`feature-flag-algorithms-v0.0.2` fork of `rustls-rustcrypto`
(`TLS13_AES_128_GCM_SHA256` + X25519 only; RSA and relay cert verification
off for size), `opt-level = "s"`, LTO, `codegen-units = 1`, `panic = "abort"`
(`immediate-abort` saves ~75 KB for shipping builds). Binaries land at
3.6–3.9 MB of a 4 MB partition on 4 MB parts; **8 MiB flash is the practical
floor**. The smart-fan example keeps the endpoint secret in NVS so the
`EndpointId` survives reboot and reflash, exposes two ALPNs (echo + an `irpc`
sensor RPC), and adds RPC methods only at the end of the enum for
compatibility.

## 3. Crate surface — the one package with five crates

```text
crates/rusty_esp_iroh          facade
crates/rusty_esp_iroh-core     no_std: protocol definitions, tickets, framing (serde + postcard behind `alloc`)
crates/rusty_esp_iroh-esp      Track A ONLY: the endpoint on ESP-IDF; `esp-hal` feature is a compile_error with a message
crates/rusty_esp_iroh-host     std: the client (dial by ticket or DID, subscribe media, call rpc); embeds in the home computer, the Pi, rff tooling
crates/rusty_esp_iroh-bridge   std: fronts no_std neighbours (ESP-NOW / LoRa / BLE / LAN-UDP) as mesh presences
```

### ALPNs and messages (`-core`)

| ALPN | Carries | Shape |
|---|---|---|
| `janus/echo/1` | liveness | bytes back |
| `janus/rpc/1` | `Manifest::get`, `Telemetry::get`, `Capability::call { gpio, snapshot, … }`, `Adopt` (delegates to `rusty_esp_mid`) | `irpc` + `postcard`; enum extended at the end only; every request carries the caller's mID assertion and is authorised by the device's adoption grant |
| `janus/media/1` | `MediaPacket`s from `rusty_esp_video` / PCM from audio | one uni-stream per packet for keyframes/large, QUIC datagrams for RTP-sized packets; a subscriber sends `{codec, max_fps, max_kbps}` |
| `mata-oem-sidecar/rpc/1` | the home computer's existing JSON RPC (64 KiB cap) for discovery, status, pairing | so the day-one UI path needs no home-computer change |

```rust
pub struct Binding { pub did: Did, pub endpoint_id: [u8; 32], pub sig: [u8; 64] }   // device key signs its EndpointId
pub enum Ticket { Short { endpoint_id }, Long { endpoint_id, relay: Option<Url>, addrs: heapless::Vec<SocketAddr, 4> } }
```

The `Binding` is the mesh notes' "publish the endpoint on the identity
anchor": the home computer's `resolve(did) -> EndpointId` seam reads it.

### The bridge (`-bridge`)

A std process (Pi, P4, laptop) holding one iroh endpoint that represents N
neighbours: each neighbour's authenticated `rusty_esp_signal` session maps to
a virtual presence with its own manifest; media and telemetry are re-framed
onto `janus/media/1` and `janus/rpc/1`; the bridge never holds a neighbour's
key, only its adoption-verified session. The Pi hub of `pi-mission.md` is
this crate plus MQTT ingest.

## 4. House crates and seams

| Need | Use | Note |
|---|---|---|
| iroh / relay / tickets / rpc | `iroh` 1.1 (+ n0 ESP branches, pinned by rev), `iroh-relay`, `iroh-tickets` 1.0, `irpc` 0.17 | **skew:** `mata-master` pins iroh 0.97 in eight crates; the wire is compatible, the APIs are not; the bridge is where they meet until the home computer upgrades |
| TLS provider | n0's `rustls-rustcrypto` fork | never `ring` / `aws-lc-sys` (`deny.toml`) |
| endpoint key at rest | `Kv` seam (`iroh.key`) — encrypted NVS; bound to the DID by `Binding` | |
| relay membership | `mata-relay-auth` (`POST /v1/relay/register` under the DID) | "EndpointId auth proves key ownership, not membership" |
| serialization | `postcard` 1.1 + `serde` (`alloc`) | in a Layer-1 core this is allowed; Layer 0 stays serde-free |

## 5. Milestones and kill tests

| # | Deliverable | Kill test |
|---|---|---|
| **N0** ✅ host 2026-09-01 | `-core`: ALPNs, `janus1…` ticket (QR text, no heap), `Binding` (device key over `EndpointId`), the kms-shaped caller `Assertion`, postcard `janus/rpc/1` with the authorisation rule, `janus/media/1` framing + loss counter, the `mata-oem-sidecar/rpc/1` JSON + TXT contract — 18 tests, riscv32 both rungs. `-host`: `Node` (four ALPNs on iroh 1.1, pure-Rust TLS) + `Client`; `examples/{node,client}`; loopback test | **passed on one machine:** rpc without an assertion → `Unauthorized`, stranger → `Denied`, owner adopts (320 B), rotation backwards refused; media 400/400 datagrams and 100/100 uni-streams, 0 lost; echo min 19.9 ms per fresh connection. **Two laptops for ten minutes: not yet run** (`docs/LEDGER.md`) |
| **N1** (J3) ◐ host half 2026-09-01 | `-esp` on XIAO S3 Sense (PSRAM tier): n0's configuration reproduced with the Janus ALPNs; endpoint key in NVS bound to the mID DID. **Written:** `idf::{register_eventfd, sync_time, advertise_sidecar}`, `NodeIdentity` from NVS via `rusty_esp_mid-esp`, `firmware/xiao-s3-sense-idf-mesh` **builds 2026-09-02** (4.66 MB image, LAN-direct; `relay.rs` written behind the host `relay` feature) | short-ticket dial from another network through a relay; echo RTT recorded; `EndpointId` stable across reflash — **needs the board** |
| **N2** ◐ host half 2026-09-02 | `janus/media/1` carrying J1's MJPEG; `-host` writes frames to disk. **Done on the host:** `mjpeg::DirSource` and `mjpeg::HttpMjpegSource` (feature `mjpeg`, J1's stream through `rusty_esp_video`'s reader), sources on a blocking thread per subscriber, frames up to 256 KiB as uni streams, the client writing frames | FPS at the receiver vs at the source recorded; a second subscriber does not stall the first — **done host-to-host** (ledger: 9.85 vs 10.00 fps, frames byte-identical to the source; two clients 9.88 / 9.93 fps, 0 lost; the HTTP bridge 16.06 vs 16.05 fps); the device as source is the row in `hardware-verify.md` |
| **N3** ◐ host half 2026-09-02 | `-bridge` on a Pi fronting a C6 (ESP-NOW) and a LoRa node. **Done on the host:** `rusty_esp_iroh-bridge` — the `Radio` seam (+ `FakeBus`), `BridgeCore` (the neighbour state machine over `rusty_esp_signal`'s session: hello/accept/confirm answered, the neighbour's `sig ‖ manifest` reassembled and verified under its own DID, telemetry attributed), `Bridge` (the radio thread, the `NeighbourSource` for `Request::Neighbours`, the `nbrt` media factory), `sim::NeighbourSim` (the device side) | the C6, which cannot run iroh, appears in the home computer's app through the Pi; its manifest is the C6's own signed manifest — **done host-to-host** (two simulated neighbours listed with manifests that verify under their DIDs, an impostor refused, telemetry attributed, a replay dropped); the radios are rows in `hardware-verify.md` |
| **N4** ◐ host half 2026-09-01 | the home-computer joint: `mata-oem-sidecar/rpc/1` answered (`sidecar::handle`, the pair client's TXT fields); `DeviceAttachment` stored; `JanusFleet` `HostAdapter` on the home computer — **proposed in `mata-master` branch `janus-fleet-proposal`**: `ResourceClass::MediaCapture` + `ResourceType::Media` + a rate-card row, and `packages/janus-fleet` with the adapter, tests green | the device shows under its own DID in the app after QR adoption; removing it from the roster ends its session within one reconnect — **needs the board and the daemon glue** |
| **N5** ◐ host half 2026-09-02 | OTA over iroh: image signed by the vendor key, verified against the manifest's `Ota` capability, `esp-ota` two-slot rollback. **Done on the host:** `ota::OtaManifest` (maker-signed, domain-separated), `OtaSession` + the `OtaSink` seam, `MemorySlots` (the two-slot model with `esp-ota`'s rollback rule), `janus/ota/1` on the node (owner-only, every check before a byte), `Client::ota`, `ota_sign`; `-esp::EspOtaSink` over `esp_ota_*` written | a bad signature never boots; a good one boots and reports its new `fw=` line — **done host-to-host** (a stranger, a bad signature, the wrong maker / chip / model, a tampered image and a power cut each leave the running image byte-identical; the good image commits, boots, reports `1.5.0`, rolls back when not validated, stays when validated); the board is the row in `hardware-verify.md` |
| **N6** | C6 LAN-direct tier with the reduced-dependency branch; size ledger | binary size, heap high-water and stack use recorded per tier |

## 6. Measurement

- Counters: packets sent/received/dropped per ALPN, reconnects, relay vs
  direct paths, heap high-water mark, binary size per tier.
- Latency and RTT are best-of-N with the method line printed; the box is a
  chip on Wi-Fi, so every number carries its channel conditions.
- `docs/LEDGER.md` from the first number.

## 7. Risks

| Risk | Mitigation |
|---|---|
| n0's ESP branches drift or are abandoned | pin revs; upstreaming is n0's stated intent and several reductions are already on `main`; track per release |
| iroh 0.97 ↔ 1.x API skew with the home computer | the bridge and the `-host` crate isolate it; the home computer upgrades on its own schedule |
| 4 MB-flash boards (ESP32-CAM) | bridge tier by design; never a 4 MB iroh build |
| FreeRTOS stack sizing for tokio | copy n0's sdkconfig; record the numbers per board in the ledger |
| Track B (`no_std`) users expect iroh | the bridge is the answer, stated in the README's first paragraph |

## 8. Decision log

| Date | Decision |
|---|---|
| 2026-09-01 | iroh runs on Track A only; `no_std` reaches the mesh through the bridge; the Pi hub is the first bridge. |
| 2026-09-01 | Five crates in this package (facade, core, esp, host, bridge) — the documented exception to the three-crate shape. |
| 2026-09-01 | Speak `mata-oem-sidecar/rpc/1` and advertise the sidecar mDNS service for day-one visibility; `janus/*` ALPNs for everything new. |
| 2026-09-01 | The endpoint key is a separate ed25519 key (iroh's requirement) bound to the P-256 device DID by a signed `Binding`; the family itself introduces no ed25519 identity. |
| 2026-09-01 | **Plain postcard frames, not `irpc`, for `janus/rpc/1`**: a `u32` length prefix and one request/response per bi-stream keeps `-core` `no_std` and the wire trivially inspectable; the append-only enum rule is what irpc would have given us. irpc can wrap it later without changing bytes. |
| 2026-09-01 | The caller assertion is the kms nonce-envelope canonical form with fixed `purpose`/`issuer`, so the home computer signs RPCs with the same code that signs gateway assertions. The device pins the owner's genesis DID; roster-chain verification stays upstream (mid M5). |
| 2026-09-01 | `-host` is the Track A implementation too: the node is std and runs on ESP-IDF unchanged; `-esp` holds only eventfd, SNTP, mDNS and the NVS identity. Pure-Rust TLS everywhere (rustls-rustcrypto, n0's provider vendored) — no `ring` on the host either. |
| 2026-09-01 | `MediaCapture` is priced per **stream-second**; bit-rate is an attribute. Proposed to `mata-master` on a branch, not merged: metering (`UsageAmount`) is the next lockstep step. |
| 2026-09-02 | **A media source gets its own thread.** `MediaSource::next_packet` may block (a camera, an HTTP pull, a paced file); the node runs it on `spawn_blocking` behind a four-deep channel, so one slow source can never stall the executor and every other subscriber with it. |
| 2026-09-02 | **One frame, one packet.** A JPEG bigger than a datagram rides as one uni stream (`MAX_MEDIA_PACKET`, 256 KiB) rather than being fragmented in our framing; QUIC already does loss and ordering per stream, and the receiver gets whole frames or nothing. |
| 2026-09-02 | **Every OTA check before a byte.** Owner, `ota` capability, trusted maker, chip, model, size and the maker's signature are all decided on the envelope; only then does the device say `OtaReady` and read the image, hashing as it goes, into the inactive slot. The image rides its own ALPN (`janus/ota/1`) so `janus/rpc/1` stays one frame per call. |
| 2026-09-02 | **The bridge relays signatures, not trust.** `Request::Neighbours` carries each neighbour's DID, its manifest bytes and its own signature verbatim; the home computer verifies the neighbour. The bridge holds sessions, never keys. Telemetry is attributed per packet (`nbrt`: `NeighbourPacket { did, reach, payload }`). |
| 2026-09-02 | **`Extras` instead of a wider `bind`.** The maker DID, the OTA slot and the neighbour table are optional seams passed to `Node::bind_with`; `bind` is unchanged, so firmwares and examples that do not need them do not change. |
