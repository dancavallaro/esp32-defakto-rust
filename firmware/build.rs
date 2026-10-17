fn main() {
    // toml-cfg reads cfg.toml inside a proc macro, which cargo can't track.
    println!("cargo:rerun-if-changed=cfg.toml");
    assert!(std::path::Path::new("cfg.toml").exists(), "copy cfg.toml.example to cfg.toml and fill it in");
    embuild::espidf::sysenv::output();
}
