# esp32-c6-idf-mesh

The Janus mesh node on the **LAN-direct tier**: an ESP32-C6 (RISC-V, 512 KB
SRAM, no PSRAM, 8 MB flash) running the same `rusty_esp_iroh` node as the
XIAO S3 Sense firmware, with relay and pkarr off and long tickets (endpoint
id + IP). This is n0's `server-esp32-c6` configuration with Janus's
identity, ALPNs and sidecar on top.

Same prerequisites as `xiao-s3-sense-idf-mesh`, on the `esp` toolchain,
target `riscv32imac-esp-espidf` (ESP-IDF installs the RISC-V GCC on the
first build). Build:

```sh
export CARGO_TARGET_DIR=C:/janus-c6                # Windows only
export JANUS_WIFI_SSID=yournet JANUS_WIFI_PASS=yourpass
cargo build --release
espflash save-image --chip esp32c6 --flash-size 8mb --partition-table partitions.csv \
    C:/janus-c6/riscv32imac-esp-espidf/release/esp32-c6-idf-mesh mesh-c6.bin
```

The size ledger (`docs/LEDGER.md`, N6) records what this image weighs
against the S3 tiers. Heap high-water and stack use are board rows.
