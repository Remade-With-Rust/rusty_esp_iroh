//! The maker's side of N5: sign an image for a model and a chip.
//!
//! ```sh
//! JANUS_MAKER_SEED=acme cargo run -p rusty_esp_iroh-host --example ota_sign -- \
//!     janus/host-node 1.5.0 esp32s3 firmware.bin firmware.jota
//! ```
//!
//! Prints the maker DID (what a device must be told to trust) and writes the
//! manifest as JSON next to the image. The seed makes a deterministic test
//! key; a real maker signs with a key that never leaves its HSM.

use rusty_esp_iroh_core::esp_core::capability::Chip;
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::ota::OtaManifest;

fn main() {
    let mut args = std::env::args().skip(1);
    let (model, firmware, chip, image, out) = match (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
        _ => {
            eprintln!("usage: ota_sign <model> <firmware> <chip> <image> <out.jota>");
            std::process::exit(2);
        }
    };
    let chip = Chip::parse(&chip).unwrap_or_else(|| {
        eprintln!("unknown chip {chip}");
        std::process::exit(2);
    });
    let seed = std::env::var("JANUS_MAKER_SEED").unwrap_or_else(|_| "janus-maker".to_string());
    let maker = DeviceKey::from_seed_for_tests(&seed, "maker");
    let maker_did = maker.did().to_did_string();
    let bytes = std::fs::read(&image).expect("read image");
    let manifest =
        OtaManifest::sign(&model, &firmware, chip, &bytes, &maker_did, &maker).expect("sign");
    std::fs::write(&out, serde_json::to_vec_pretty(&manifest).expect("json")).expect("write");
    println!("maker:    {maker_did}");
    println!(
        "image:    {} bytes, sha256 {}",
        bytes.len(),
        hex(&manifest.image_sha256)
    );
    println!("manifest: {out}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
