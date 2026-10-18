use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Args, Parser, Subcommand};
use esp32_attestor::reload::{self, FileWatcher};
use esp32_attestor::verifier::Verifier;
use esp32_attestor::{enroll, enrollment, webhook};

/// The Defakto serverless attestation extension webhook for ESP32 devices.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the attestation webhook over HTTPS.
    Serve(ServeArgs),
    /// Print enrollment entries for a device.
    #[command(subcommand)]
    Enroll(EnrollCommand),
}

#[derive(Subcommand)]
enum EnrollCommand {
    /// Make a new secret for a device, with its enrollment entry and the NVS CSV to flash.
    Hmac { device_id: String },
    /// Make the enrollment entry for a device's TEE attestation key.
    Tee {
        device_id: String,
        /// The key from the device's "TEE attestation key: ..." boot log line.
        pubkey_hex: String,
    },
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,
    #[arg(long, default_value = "/tls/tls.crt")]
    tls_cert: PathBuf,
    #[arg(long, default_value = "/tls/tls.key")]
    tls_key: PathBuf,
    #[arg(long, default_value = "/enrollment/enrollment.json")]
    enrollment: PathBuf,
    /// The most an evidence timestamp may differ from now, in seconds.
    #[arg(long, default_value_t = 60)]
    skew: u64,
    /// How often to check the enrollment file and TLS pair for changes, in seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    reload_interval: u64,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => serve(args),
        Command::Enroll(command) => run_enroll(command),
    }
}

fn run_enroll(command: EnrollCommand) -> Result<()> {
    match command {
        EnrollCommand::Hmac { device_id } => {
            esp_attest::validate_device_id(&device_id).map_err(|e| anyhow!(e))?;
            let secret = enroll::new_secret();
            let entry = enroll::hmac_entry(&device_id, &secret)?;
            println!("device_id: {device_id}\nsecret:    {secret}\n");
            println!("--- enrollment entry (merge into your enrollment file) ---\n{entry}\n");
            println!("--- nvs.csv (flash to the device) ---\n{}", enroll::nvs_csv(&secret));
        }
        EnrollCommand::Tee { device_id, pubkey_hex } => {
            let entry = enroll::tee_entry(&device_id, &pubkey_hex)?;
            println!("--- enrollment entry (merge into your enrollment file, keeping any secret) ---\n{entry}");
        }
    }
    Ok(())
}

#[tokio::main]
async fn serve(args: ServeArgs) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("a rustls crypto provider is already installed"))?;

    // Read here rather than with `enrollment::load`, so the watcher starts from these bytes.
    let body = std::fs::read(&args.enrollment).with_context(|| format!("reading {}", args.enrollment.display()))?;
    let devices = enrollment::parse(&body).with_context(|| format!("loading {}", args.enrollment.display()))?;
    println!("loaded {} enrolled devices from {}", devices.len(), args.enrollment.display());
    let verifier = Arc::new(Verifier::new(devices, Duration::from_secs(args.skew)));

    let tls = RustlsConfig::from_pem_file(&args.tls_cert, &args.tls_key)
        .await
        .with_context(|| format!("loading TLS pair {} and {}", args.tls_cert.display(), args.tls_key.display()))?;

    tokio::spawn(reload::run(
        verifier.clone(),
        FileWatcher::new(args.enrollment, body),
        tls.clone(),
        args.tls_cert,
        args.tls_key,
        Duration::from_secs(args.reload_interval),
    ));

    println!("serving attestation webhook on {}", args.listen);
    axum_server::bind_rustls(args.listen, tls)
        .serve(webhook::router(verifier).into_make_service())
        .await
        .with_context(|| format!("serving on {}", args.listen))
}
