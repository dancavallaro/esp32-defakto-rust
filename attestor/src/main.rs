use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Args, Parser, Subcommand};
use esp32_attestor::reload::{self, FileWatcher};
use esp32_attestor::verifier::Verifier;
use esp32_attestor::{enrollment, webhook};

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
    }
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
