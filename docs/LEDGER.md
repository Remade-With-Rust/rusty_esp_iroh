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
| `-host` with `--features relay`: check, clippy `-D warnings`, unit tests (2026-09-02) | clean, 3 pass — compiled, no relay dialled |

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
machine and seconds. The ten-minute run on the Wi-Fi address is below.

## The Xtensa toolchain wall (2026-09-01)

The mesh firmware's first builds stopped inside the compiler, not in Janus
code: esp 1.97.0.0 (rustc 1.97.0-nightly 2026-07-08, Xtensa LLVM) aborts on
`rustls` with `Cannot select: XtensaISD::PCREL_WRAPPER TargetConstantPool …
"u16"` in `NewSessionTicketExtensions::read`. Reproduced with rustls alone in
a scratch crate for `xtensa-esp32s3-espidf` (no IDF needed; ~25 s a variant):

| variant | result |
|---|---|
| 0.23.41, `std+logging+tls12`, opt `s`, codegen-units 1 (the firmware's) | **crash** |
| same, opt `z` | compiles |
| same, opt `s`, codegen-units 16 | compiles |
| same, opt `3` | **crash** (in the same function, different constant) |
| without `tls12`, opt `s` | **crash** |
| rustls 0.23.35, opt `s` | **crash** |

With only rustls at `z` the build still stopped in the compiler; the profile
that builds is `opt-level = "z"` for everything and `lto = false` (fat LTO
re-hits it even at `z`), `codegen-units = 1`, `panic = "abort"`. esp-rs has
published a 1.98.0.0 Xtensa toolchain; whether it fixes this is unmeasured,
and LTO returns when it does.

## The first mesh firmware build (2026-09-02)

`firmware/xiao-s3-sense-idf-mesh`, Windows 11, esp 1.97.0.0 (rustc
1.97.0-nightly, Xtensa LLVM), ESP-IDF v5.5.1 from the global tools dir
(`esp-idf-build.json` → `~/.espressif/esp-idf/v5.5.1`), `espressif/mdns`
1.8, release profile `opt-level = "z"`, `lto = false`, `codegen-units = 1`,
`panic = "abort"`, `build-std-features = ["optimize_for_size"]`, relay off,
`rusty_esp_mid-esp` with `allow-insecure-dev`. Builds and links; no board
has run it.

| measure | value | method |
|---|---|---|
| app image | **4 660 544 B**, 74.08 % of the 6 MiB factory partition | `espflash save-image --chip esp32s3 --flash-size 8mb --partition-table partitions.csv` |
| `.flash.text` / `.flash.rodata` | 3 645 480 B / 894 364 B | `xtensa-esp-elf-size -A` |
| `.iram0.text` / `.dram0.data` / `.dram0.bss` | 88 815 B / 30 420 B / 28 584 B | same |
| ELF with debug info | 10 296 192 B | `ls -l` |
| final link after a source edit | 1 min 50 s | `cargo build --release`, warm target dir |

Symbol census of the ELF (`xtensa-esp-elf-nm -C`): `mdns_init` and
`mdns_service_add` are linked and `advertise_sidecar` is present, so the
`esp_idf_comp_espressif__mdns_enabled` gate resolved true through the `-esp`
crate's embuild `build.rs`; `esp_sntp_init`, `esp_vfs_eventfd_register`, the
`gethostname` shim, 32 `aes_gcm` symbols (the rustcrypto provider), 338
`iroh::endpoint` and 2 503 `rustls::` symbols.

Two build facts worth their line. `gethostname` is the one symbol ESP-IDF
lacks that the graph references (hickory-resolver's `resolv_conf`, linked
even though iroh's DNS is replaced at runtime); the firmware `main.rs`
carries n0's one-line shim (an empty hostname). And cargo prints "patch
`rusty_esp_core` … was not used" three times per build: that is the
`build-std` sysroot graph reading the umbrella's per-repo patches, not the
firmware graph — the lockfile has zero `[[patch.unused]]` rows and
`cargo metadata --locked --filter-platform=xtensa-esp32s3-espidf` passed 8
of 8 runs (the wall in mission plan §8 is closed for this firmware).

n0's blog figures for their examples are 3.6–4.35 MB with fat LTO and
`opt-level = "s"`; this image is 4.66 MB without LTO, with the mDNS
component and the mID crates on top.

## The ten-minute run on the Wi-Fi address (2026-09-02)

The N0 kill test asks for ten minutes between two laptops. There is one
laptop, so this is the honest substitute: the `node` and `client` examples as
two processes on this machine, the node advertising **only the Wi-Fi
adapter's address** (`[192.168.0.224:61156]`, not loopback), the client subscribing to
`janus/media/1` for 600 s with the synthetic 10 packet/s source (900 B
payloads). Method: `cargo build --release --examples`, then
`node.exe 192.168.0.224` and `client.exe <ticket> media 600`; the counters
are the client's `LossCounter` and the node's own counters, both printed by
the examples.

| measure | value |
|---|---|
| duration | 600 s |
| packets received | **5 496** |
| packets lost (sequence gaps) | **0** |
| packets reordered | 0 |
| payload bytes | 4 946 400 |
| rate seen by the client | 9.2 pkt/s |
| node: subscribers · packets sent · send errors | 1 · 5 481 · 0 |

Two processes on one host do not exercise a radio, a switch or a second
clock; what they exercise is the endpoint, the framing, the sequence
accounting and the subscription lifetime over ten real minutes on a real
interface address. The two-laptop row stays in
`docs/plans/hardware-verify.md`.

## N2 host half - real MJPEG over `janus/media/1` (2026-09-02)

Two media sources that carry JPEG frames (`rusty_esp_iroh-host::mjpeg`):
`DirSource` (every `.jpg` in a directory, looped at a rate) and, behind the
`mjpeg` feature, `HttpMjpegSource` (J1's `multipart/x-mixed-replace` stream
pulled over TCP through `rusty_esp_video`'s reader and republished frame by
frame: the node as the bridge a Pi is in front of a camera). The node now
runs every subscriber's source on a blocking thread with a short channel,
so a source that blocks cannot hold the executor, and a frame larger than a
datagram travels as one uni stream up to `alpn::MAX_MEDIA_PACKET` (256 KiB).
The `client` example writes `mjpg` packets to a directory and reports the
receiver's frame rate against the source's timestamps.

All three runs below are node and client(s) as separate processes on this
machine, the node advertising only the Wi-Fi adapter's address
(192.168.0.224). The source for the first two is 50 JPEGs of
ffmpeg's `testsrc` at 320x240 (432 791 bytes), looped at 10 fps.

### One subscriber, frames to disk, 60 s

| measure | value |
|---|---|
| packets received · lost · reordered | **591 · 0 · 0** |
| frames written | **591** |
| receiver fps · source fps (from packet timestamps) | **9.85 · 10.00** |
| bytes · largest frame | 5 116 804 · 8 972 B |
| node: subscribers · packets at its last report · send errors | 1 · 569 · 0 |

Byte identity, in a second 20 s run of the same source: every one of
the **198** frames written equals the source file it came from
(frame `k` against file `k mod 50`, `cmp`), **0 different**.

### Two subscribers at once, 60 s

The second client starts two seconds after the first.

| | client A | client B |
|---|---|---|
| packets received · lost · reordered | 593 · 0 · 0 | 596 · 0 · 0 |
| receiver fps · source fps | 9.88 · 10.00 | 9.93 · 10.00 |
| frames received · written to disk | 593 · 479 | 596 · 459 |

Node: 2 subscribers, 1 150 packets at its last report,
0 send errors. The first subscriber's rate did not move when the
second joined. The frames received are complete on both; the shortfall in
"written" is `std::fs::write` failing on this Windows host with two
processes each creating ten files a second into their own directories, not
the transport (one writer alone wrote every frame, above).

### The HTTP bridge: `mjpeg_server` → node → client, 30 s

`rusty_esp_video-esp`'s `mjpeg_server` example (colour bars, 320x240, 15
fps, `rusty_jpeg` quality 80) on `127.0.0.1:8090`, pulled by the node with
`JANUS_MJPEG_URL` (feature `mjpeg`) and republished.

| measure | value |
|---|---|
| packets received · lost · reordered | **482 · 0 · 0** |
| receiver fps · source fps (from the stream's `X-Timestamp`) | **16.06 · 16.05** |
| frames written · largest | 482 · 6 015 B |
| first and last written frame probe | mjpeg,320,240 / mjpeg,320,240 |
| node: subscribers · packets · send errors | 1 · 482 · 0 |

## N5 and N3 host halves (2026-09-02)

### N5 — OTA over iroh

`ota::OtaManifest` is what a maker signs: model, firmware string, chip tag,
image length, SHA-256 and the maker's DID, length-prefixed under a domain
separator, a low-s P-256 signature over the hash. The device checks, in
this order and all before a byte: owner (the RPC rule), `ota` declared
available in its own manifest, a trusted maker configured, that maker,
this chip, this model, the size, the signature under the maker's key (the
DID carries it). Then `OtaReady`, the bytes into the inactive slot through
the `OtaSink` seam with SHA-256 running, the length and digest against the
manifest, and only then the slot becomes the boot slot. `MemorySlots` is
the host's two-slot model with `esp-ota`'s rule: a new image that is not
marked valid before the next boot rolls back.

| Gate (host, loopback) | Result |
|---|---|
| Every lie named: no maker → `NoMaker`, another maker → `WrongMaker`, other chip / model, a forged firmware string or a flipped signature byte → `BadSignature`, an over-size manifest → `TooLarge` | pass |
| A session streams 40 000 bytes in chunks, verifies, commits; the running image is untouched until `boot()`; an unvalidated boot rolls back, a validated one stays | pass |
| Tampered bytes → `DigestMismatch`; short → `LengthMismatch`; a byte too many → `LengthMismatch`; a power cut after 12 000 bytes → `SinkFailed`; in every case the running image byte-identical and nothing pending; the retry commits; a slot too small → `TooLarge` | pass |
| Over the link: anonymous → `Unauthorized`, a stranger → `Denied`, `Ota` on `janus/rpc/1` → `Unsupported`; owner + bad signature / wrong maker / chip / model / tampered image / power cut at 70 000 of 200 000 bytes → each refused by name, slot unchanged; the good image → `Committed { firmware: "1.5.0" }`, `last_ota()` says so, boot reports `1.5.0`, rollback without validation, stays with it; counters 2 committed / 6 refused | pass |
| No `ota` capability → `NoOtaCapability`; capability but no maker → `NoMaker`; nothing pending either way | pass |
| C2 over the link: `Client::time` gives a known `WallOffset` with a finite, positive error bound | pass |

`-esp::EspOtaSink` is the same seam over ESP-IDF's `esp_ota_begin` /
`esp_ota_write` / `esp_ota_end` / `esp_ota_set_boot_partition`, with
`mark_running_valid` for the freshly booted image; the mesh firmware
declares `ota` and accepts images when `JANUS_MAKER_DID` names a maker at
build time (see the firmware row below for its build state).

### N3 — the bridge

`rusty_esp_iroh-bridge`: one iroh endpoint fronting N radio neighbours
over an in-memory bus on the host. A neighbour links with the signal
session (its key stays on it), sends `sig ‖ manifest` in sealed parts, the
bridge verifies under the neighbour's DID and lists it; telemetry is
re-framed onto `janus/media/1` as `nbrt` packets carrying the DID.

| Gate (host) | Result |
|---|---|
| A bus delivers addressed and broadcast frames, refuses over-MTU frames, drops on request | pass |
| Two neighbours (a C6 on ESP-NOW, a LoRa node) and an impostor with a forged manifest signature all link; two manifests verify, one is refused; 8 telemetry frames accepted; a replayed sealed frame and a forged frame are dropped | pass |
| `Request::Neighbours` lists exactly the two, each manifest verifying under the neighbour's own DID and parsing canonically, with the right reach tag and model, the impostor absent | pass |
| A subscriber to `nbrt` receives 8 packets, 0 lost, 4 attributed to each neighbour's DID and reach | pass |

Test totals after N3 + N5: 1 + 1 + 21 + 5 + 1 + 2 = **31** across the core, host and bridge suites.

## Not yet measured

- **Anything on a chip**: the `xiao-s3-sense-idf-mesh` firmware builds
  (above) but no board has run it — boot, Wi-Fi, SNTP, the NVS key, N1's
  echo RTT and `EndpointId` stability across reflash all wait for hardware.
- The relay path (short ticket from another network): written behind the
  `-host` crate's `relay` feature (`relay.rs`: n0's std DNS resolver and the
  relay-certificate verifier), clippy-clean on the host; no relay has been
  dialled. The firmware now has a `relay` feature of its own that turns it on
  (`NodeConfig::relay = cfg!(feature = "relay")`), and **the relay-on
  firmware compiles** (2026-09-02, `cargo build --release --features relay`,
  Xtensa, 5 min 5 s in a cold target dir with the IDF already installed): app image **4 766 784 B**,
  75.77 % of the 6 MiB factory partition, against 4 660 544 B
  with relay off — so the relay tier costs 106 240 B of flash
  on top of the LAN tier. Nothing has run it.
- Two laptops for ten minutes (the one-machine run above is the substitute
  until there are two).
- **N5 on a board:** the relay-on and OTA-declaring mesh firmware flashed,
  a signed image pushed over Wi-Fi, the new `fw=` line on serial, and a
  deliberately unvalidated image rolling back on the second reset.
- **N3 on radios:** the `Radio` seam over a serial-attached C6 and an SX1262
  on a Pi; everything above it is the host test.
