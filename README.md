# rusty_esp_iroh

[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/remade-with-rust) [![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network) [![crates.io](https://img.shields.io/crates/v/rusty_esp_iroh.svg)](https://crates.io/crates/rusty_esp_iroh) [![docs.rs](https://docs.rs/rusty_esp_iroh/badge.svg)](https://docs.rs/rusty_esp_iroh) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/rusty_esp_iroh/blob/main/LICENSE-MIT)

A peer-to-peer node on a microcontroller: QUIC with pure-Rust TLS, a signed
capability manifest, media streaming, adoption, and signed over-the-air
updates — on a part with half a megabyte of internal memory. Pure Rust, no C,
no FFI.

* **It runs on the chip, from a data file.** A nine-line manifest becomes a
  firmware whose node is up **3.2 seconds after boot**, advertising itself on
  the local network and streaming its camera to a subscriber.
* **A camera over the mesh, with nothing lost.** Sixty seconds, **721 packets,
  none lost, none out of order**, reproduced three times from cold boots — and
  the board's own count agrees with the subscriber's to **0.14%**.
* **Adopted, with both refusals holding.** A stranger presenting the owner's own
  record is refused; a superseded record is refused; the owner then reads
  private telemetry. Measured on silicon.
* **It answers the contract a home computer already speaks**, so a device shows
  up in the owner's app with no change at the other end.

## What has run on hardware

Measured on a Seeed XIAO ESP32-S3 Sense, over a Wi-Fi network **the board
hosts itself**, with both ends counting at once.

| what the trip asked | at the laptop | at the board |
|---|---|---|
| can anything **find** it? | a service query answered, carrying the tag that makes an owner's app render it as a device | publishes 14 record keys, for 36 KB of firmware |
| does it **answer**? | ten connections of ten, **520 ms median** | — |
| does the camera **arrive**? | **721 packets in 60 s, none lost, none reordered** | one subscriber, **zero send failures** |
| do the ends **agree**? | 12.017 packets/s | 12.000/s — **0.14% apart** |
| is the identity stable? | the same endpoint key before and after a whole-image reflash | — |

The connection figures are **not round-trip times**: every call opens a fresh
encrypted connection from a fresh process, so each is a full handshake with a
chip doing the cryptography. That is what a caller waits for on first contact
and nothing faster.

**Three things only a board could say**, each now a rule with a test: the
compiler crashes on the TLS library at two optimisation settings; without
whole-program optimisation the linker drags in a retired bus driver's start-up
check, which aborts the boot 1.8 seconds in while protecting nothing; and the
async runtime cannot open the notification descriptor it needs until a driver
is registered.

**Open defects, written down rather than hidden:** the device reports itself as
owned when asked directly and goes on advertising itself as free to claim,
because the broadcast record is composed once at start-up and never revisited.
And a media subscription costs **19,088 bytes** of internal memory, which is
why it fails outright on a memory configuration leaving under 22,000 free.

Every number, with the run that produced it:
[`docs/LEDGER.md`](https://github.com/Remade-With-Rust/rusty_esp_iroh/blob/main/docs/LEDGER.md).

## Using it

```rust
use rusty_esp_iroh_host::{Node, NodeConfig, NodeIdentity};

let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus")?;
let node = Node::bind_with(identity, kv, &manifest, Some(factory), config, extras).await?;
println!("{}", node.ticket_text());   // hand this to a subscriber
```

## Two tracks

| track | what it is | this crate |
|---|---|---|
| **A** | `std` on ESP-IDF — the only track a peer-to-peer node runs on, because it needs an async runtime and TLS | `rusty_esp_iroh-esp --features esp-idf` |
| **B** | `no_std` on `esp-hal` — **a compile error by design**, with a message: a bare-metal chip reaches the mesh through the bridge, not by running a node | `rusty_esp_iroh-core`, default |

## Part of Janus

**Janus** rebuilds the Espressif ESP32 and Arduino application portfolio as
independent, memory-safe Rust packages — so a hardware maker can ship a device
that the [MATA](https://www.mata.network) home computer discovers, catalogs honestly, adopts
under its own identity, and pays for. Ten packages, three layers, and the
dependency direction never reverses.

| layer | packages |
|---|---|
| **0 — the vocabulary** | [`rusty_esp_core`](https://crates.io/crates/rusty_esp_core) · [`rusty_esp_dsp`](https://crates.io/crates/rusty_esp_dsp) |
| **1 — the functions** | [`rusty_esp_image`](https://crates.io/crates/rusty_esp_image) · [`rusty_esp_video`](https://crates.io/crates/rusty_esp_video) · [`rusty_esp_audio`](https://crates.io/crates/rusty_esp_audio) · [`rusty_esp_signal`](https://crates.io/crates/rusty_esp_signal) · [`rusty_esp_mid`](https://crates.io/crates/rusty_esp_mid) · [`rusty_esp_iroh`](https://crates.io/crates/rusty_esp_iroh) |
| **2 — the surfaces** | [`rusty_esp_arduino`](https://crates.io/crates/rusty_esp_arduino) — the sketch facade · [`espino`](https://crates.io/crates/espino) — the maker's CLI |

Every package is host-verified against an external oracle and keeps a ledger
in which no number appears without the run that produced it. **Five of seven
device profiles have now run their kill tests on real silicon**, three of them
over a Wi-Fi network the board hosts itself.

Also check out the rest of [Remade With Rust](https://github.com/remade-with-rust) — including
[`rusty_alloc`](https://crates.io/crates/rusty_alloc), the pure-Rust rebuild of
mimalloc that these firmwares run on, and
[`rusty_jpeg`](https://crates.io/crates/rusty_jpeg), the JPEG engine behind the
camera path — and our sister project
[remade_ffmpeg_rs](https://github.com/Remade-With-Rust/remade_ffmpeg_rs), a ground-up Rust rebuild of FFmpeg.

## About Mata Network

[Mata Network](https://www.mata.network) builds sovereign, self-hostable infrastructure.
**Remade With Rust** is our open-source home for the permissively-licensed
building blocks that work depends on.

## License

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](https://github.com/Remade-With-Rust/rusty_esp_iroh/blob/main/LICENSE-MIT)
and [LICENSE-APACHE](https://github.com/Remade-With-Rust/rusty_esp_iroh/blob/main/LICENSE-APACHE).
