use std::path::Path;

fn main() {
    // toml-cfg reads cfg.toml inside a proc macro, which cargo can't track.
    println!("cargo:rerun-if-changed=cfg.toml");
    assert!(Path::new("cfg.toml").exists(), "copy cfg.toml.example to cfg.toml and fill it in");
    check_idf_patched();
    declare_app_desc_cfgs();
    embuild::espidf::sysenv::output();
}

/// `esp_app_desc!` expands to cfgs that embuild sets in this crate but never declares.
fn declare_app_desc_cfgs() {
    for cfg in [
        "esp_idf_app_build_type_pure_ram_app",
        "esp_idf_app_compile_time_date",
        "esp_idf_app_reproducible_build",
        "esp_idf_idf_target_linux",
        "esp_idf_version_at_least_5_3_2",
        "esp_idf_version_at_least_5_4_0",
        "esp_idf_version_at_least_6_1_0",
        "esp_idf_version_patch_at_least_5_1_7",
        "esp_idf_version_patch_at_least_5_2_3",
        "esp_idf_version_patch_at_least_5_3_2",
    ] {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }
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
