//! Runs the demo's protocol from the Mac, so every server-side setting can be
//! proven before the firmware exists. Settings come from `OBO_*` env vars,
//! optionally loaded from `host/.env`.

mod http;

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand};
use obo_core::attest::{HmacAttestor, SoftwareHmacKey};
use obo_core::evidence::{new_nonce, validate_device_id};
use obo_core::flow::{self, Config};
use obo_core::jwt::decode_claims;
use obo_core::oauth::TOKEN_TYPE_ID_TOKEN;
use obo_core::serverless::SvidToken;

use crate::http::UreqClient;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Attest and fetch a JWT-SVID, then print its claims.
    Svid,
    /// Run the full device login and OBO token exchange.
    Login,
}

fn main() -> Result<()> {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    let cli = Cli::parse();
    let cfg = config();
    let mut http = UreqClient::new();
    match cli.command {
        Command::Svid => {
            let svid = fetch_svid(&mut http, &cfg)?;
            println!("spiffe_id: {}", svid.spiffe_id);
            print_claims(&svid.token)?;
        }
        Command::Login => login(&mut http, &cfg)?,
    }
    Ok(())
}

fn login(_http: &mut UreqClient, _cfg: &Config) -> Result<()> {
    anyhow::bail!("not implemented yet")
}

fn config() -> Config {
    Config {
        serverless_url: var_or("OBO_SERVERLESS_URL", flow::SERVERLESS_URL),
        token_url: var_or("OBO_TOKEN_URL", flow::TOKEN_URL),
        svid_audience: var_or("OBO_SVID_AUDIENCE", ""),
        auth0_domain: var_or("OBO_AUTH0_DOMAIN", ""),
        auth0_client_id: var_or("OBO_AUTH0_CLIENT_ID", ""),
        subject_token_type: var_or("OBO_SUBJECT_TOKEN_TYPE", TOKEN_TYPE_ID_TOKEN),
    }
}

fn var_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn fetch_svid(http: &mut UreqClient, cfg: &Config) -> Result<SvidToken> {
    anyhow::ensure!(!cfg.svid_audience.is_empty(), "set OBO_SVID_AUDIENCE");
    let device_id = var_or("OBO_DEVICE_ID", "c6-demo");
    validate_device_id(&device_id).map_err(anyhow::Error::msg)?;
    let secret = STANDARD
        .decode(env::var("OBO_SECRET_B64").context("set OBO_SECRET_B64")?)
        .context("OBO_SECRET_B64 is not base64")?;
    let attestor = HmacAttestor::new(device_id, SoftwareHmacKey(secret), "software HMAC");

    let nonce = new_nonce(|b| getrandom::getrandom(b).expect("OS RNG"));
    Ok(flow::fetch_svid(http, cfg, &attestor, unix_now(), &nonce)?)
}

fn print_claims(jwt: &str) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&decode_claims(jwt)?)?);
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_secs() as i64
}
