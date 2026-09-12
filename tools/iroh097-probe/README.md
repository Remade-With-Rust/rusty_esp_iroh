# iroh097-probe — can a 0.97 client reach a 1.1 Janus node?

Janus pins `iroh = "1.1"`. MATA's home computer resolves `iroh 0.97.0` across
eight packages, and its pair client is what would dial a Janus device. As of
2026-09-11 nobody in either repository had tried it, and "blocked on the iroh
version skew" was being written into plans as though it were a finding. It was
an assumption. This settles it.

## The answer

**A 0.97 client reaches a 1.1 Janus node and speaks its protocols**, measured
2026-09-11 against `rusty_esp_iroh-host`'s own `node` example on loopback:

| what | result |
|---|---|
| `janus/echo/1` | connected in 3.3 ms, round trip 4.1 ms, reply byte-identical — and the node counted it (`echo=1`) |
| `mata-oem-sidecar/rpc/1`, `{"op":"ping"}` | `{"ok":true,"body":{"ping":"mata-oem-sidecar-ok"}}` — the contract's own reply |
| `mata-oem-sidecar/rpc/1`, `{"op":"janusManifest"}` | `{"ok":true,"body":{"did":"did:mata:bihZ…","domain":"janus-manifest-v1","manifest_hex":"…"}}` |
| garbage on the sidecar ALPN | `{"ok":false,"error":"malformed RpcRequest…"}` — the application rejecting a payload, which is the transport working |

**What this does not say.** It was loopback with the address taken from a
ticket: no Wi-Fi link, no relay (`presets::N0DisableRelay`), no discovery, and
not the chip. Dialling the board itself over its own access point is an
offline trip and has not been run.

## Building it

Two traps, both cargo resolution rather than iroh:

1. iroh 0.97 requires `ed25519-dalek 3.0.0-pre.1`, and a fresh resolve picks
   release candidates around it that no longer compile together. **Copy
   mata-master's `Cargo.lock` into this directory** and build `--offline`;
   that is the resolution a real 0.97 consumer actually has, so the probe
   fails or succeeds on the transport and never on a version nobody ships.
2. `Endpoint::builder()` takes a preset in 0.97: `Endpoint::builder(presets::N0DisableRelay)`.

```sh
cp <mata-master>/Cargo.lock .
cargo build --release --offline
./target/release/probe <janus1-ticket> [alpn] [payload]
```

This crate declares its own `[workspace]`, so it never joins the
`rusty_esp_iroh` build and never puts a second iroh major in that graph.
