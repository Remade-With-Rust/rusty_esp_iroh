# rusty_esp_iroh-bridge

The Janus bridge (N3): one std process, one iroh endpoint, N radio
neighbours that cannot run iroh themselves.

A C6 on ESP-NOW or an SX1262 node on LoRa links to the bridge with
`rusty_esp_signal`'s authenticated session (its key never leaves it; the
bridge keeps the session), sends its **own signed manifest**, and its
telemetry is re-framed onto `janus/media/1`. The home computer asks the
bridge `Request::Neighbours` and receives each neighbour's DID, manifest
bytes and signature verbatim, so it verifies the neighbour and never has to
take the bridge's word.

| Piece | What it is |
|---|---|
| `radio::Radio` | the seam a Pi fills with a serial-attached C6 or SX1262; `FakeBus` / `FakeRadio` are the host's |
| `neighbour::BridgeCore` | the whole neighbour state machine, one frame at a time, no threads |
| `Bridge` | the radio loop on a thread; hands the iroh node a `NeighbourSource` and a media factory for `nbrt` |
| `sim::NeighbourSim` | the neighbour's side, as a firmware will implement it |

Inside a sealed link frame the first byte says what follows: `0x01` a
manifest part (`[index][count][bytes]` of `sig ‖ manifest`), `0x02`
telemetry. Nothing else is defined yet.

```sh
cargo run -p rusty_esp_iroh-bridge --example bridge -- 192.168.0.224
cargo run -p rusty_esp_iroh-host --example client -- <ticket> neighbours
```

The host test links two simulated neighbours and an impostor, lists the
two, verifies both manifests under their own DIDs, receives their telemetry
attributed, and drops a replayed and a forged frame. The radios themselves
are board rows in the umbrella's `docs/plans/hardware-verify.md`.
