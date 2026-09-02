//! Re-emit esp-idf-sys's environment (the `esp_idf_*` and `esp_idf_comp_*`
//! cfgs, the link args) for this crate, the way esp-idf-svc and esp-idf-hal
//! do. Without it a library crate never sees `esp_idf_comp_espressif__mdns_enabled`
//! even when the component is compiled in, and gates its items out while the
//! firmware binary (which has this build script) sees them as present. On the
//! host there is no esp-idf-sys and this is a no-op.
fn main() {
    embuild::espidf::sysenv::output();
}
