use std::path::Path;

fn main() {
    // toml-cfg reads cfg.toml inside a proc macro, which cargo can't track.
    println!("cargo:rerun-if-changed=cfg.toml");
    assert!(Path::new("cfg.toml").exists(), "copy cfg.toml.example to cfg.toml and fill it in");
    check_idf_patched();
    embuild::espidf::sysenv::output();
}

/// An unpatched ESP-IDF still builds, but the TEE then loses its attestation key on every boot.
fn check_idf_patched() {
    let idf = std::env::var("IDF_PATH").expect("IDF_PATH comes from .cargo/config.toml");
    let file = Path::new(&idf).join("components/bootloader_support/bootloader_flash/src/bootloader_flash.c");
    println!("cargo:rerun-if-changed={}", file.display());
    let source = std::fs::read_to_string(&file).unwrap_or_default();
    assert!(
        source.contains("re-arm SPI1 before each read"),
        "ESP-IDF is missing the TEE flash-read fix; run ./patch-idf.sh"
    );
}
