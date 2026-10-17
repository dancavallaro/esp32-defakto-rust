# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A tech demo for the Waveshare ESP32-C6-Touch-LCD-1.47, written in Rust. The device shows a Defakto logo; tapping it
shows a QR code for an OIDC device-flow login (Pocket ID at home, Auth0 on-site). The device then attests to Defakto's serverless API for a JWT-SVID
(`spiffe://prod.cavallaro.local/iot/defakto-demo`), exchanges the user's ID token for an OBO token (RFC 8693), and shows
its claims on screen.

## Layout

A Cargo workspace of three packages, plus the firmware as a separate project:

- `defakto/`: the Defakto client. It covers the attestors (`attest`, `evidence`), the serverless JWT-SVID call
  (`serverless`, `grpcweb`), token exchange (`token_exchange`, `oauth`), and unverified JWT decoding.
  This crate is the seed of a Rust libcommon, so keep it free of demo-specific code and of hardware. Anything a
  platform must supply goes behind a trait: `http::HttpClient` for transport, `attest::HmacKey` for the key.
- `demo/`: the demo's own logic, shared by host and firmware. It holds the device-code login (`login`), the
  orchestration with its polling and cancellation (`flow`), the screen state machine (`app`), and what the result
  screen shows (`claims`).
- `host/` (`demo-host`): a Mac CLI that runs the same flow against the live servers before any hardware is
  involved. It has two subcommands: `svid` and `login`.
- `firmware/` (`demo-firmware`, when present): ESP-IDF std firmware for `riscv32imac-esp-espidf`. It is excluded
  from the workspace because it builds on nightly with `build-std`, through its own `rust-toolchain.toml`.

Everything that can be tested without hardware lives in `defakto` or `demo`, so the firmware stays a thin layer
that drives the display, touch, WiFi and keys. This mirrors libcommon's `*_core` split.

## Commands

- Tests: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets`, which should produce no warnings.
- Host CLI: `cargo run -p demo-host -- svid` and `cargo run -p demo-host -- login`. Settings come from `DEMO_*` env
  vars, loaded from `host/.env`. The variables are `DEMO_SECRET_B64`, `DEMO_SVID_AUDIENCE`, `DEMO_LOGIN_DEVICE_URL`,
  `DEMO_LOGIN_TOKEN_URL`, `DEMO_LOGIN_CLIENT_ID` (the two URLs come from the IdP's OIDC discovery document), and
  optionally `DEMO_DEVICE_ID`, `DEMO_SUBJECT_TOKEN_TYPE`, `DEMO_SERVERLESS_URL` and
  `DEMO_TOKEN_URL`.
- Toolchain: the rustup proxies in `~/.cargo/bin` must come before Homebrew's `cargo` on PATH. Homebrew's
  stable-only Rust ignores `rust-toolchain.toml`, so it can't build the firmware. On its first build, the firmware
  downloads ESP-IDF into `firmware/.embuild/` through `esp-idf-sys`.

## Constraints

- **The HMAC evidence must stay byte-identical to `telemetry/pkg/espattest`.** That package is what the
  `esp32-attestor` webhook verifies. The golden test in `defakto/src/attest.rs` comes from `esp32-enroll golden`.
  If it fails, the format has drifted; don't change the expected value to make it pass.
- **Attestation must stay swappable.** HMAC from software, HMAC from an eFuse key, and the ESP-TEE token must all
  sit behind `Attestor`, so the device can switch between them at runtime. Don't add anything that only works for
  HMAC.
- **Never commit secrets:** `host/.env`, `firmware/cfg.toml`, `nvs.csv`, `nvs.bin` and `secret.bin` are
  gitignored.
- **Dan makes every external change.** That covers the IdPs (Pocket ID, Auth0), `~/workspace/homelab` (the Terraform
  `TokenExchangePolicy`, the enrollment parameter) and `~/workspace/telemetry`. Hand those steps over rather than
  editing them.
- **Burning an eFuse key is irreversible, and only Dan does it.**
