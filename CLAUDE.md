# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A tech demo for the Waveshare ESP32-C6-Touch-LCD-1.47, written in Rust. The device shows a Defakto logo; tapping it
shows a QR code for an OIDC device-flow login (Pocket ID at home, Auth0 on-site). The device then attests to Defakto's serverless API for a JWT-SVID
(`spiffe://prod.cavallaro.local/iot/defakto-demo`), exchanges the user's ID token for an OBO token (RFC 8693), and shows
its claims on screen. The demo's story is a check-in badge reader: when `checkin_url` is set, the device presents
the OBO token to that attendance service as a bearer token, recording who checked in and through which device.

## Layout

A Cargo workspace of three packages, plus the firmware as a separate project:

- `defakto/`: the Defakto client. It covers the attestors (`attest`, `evidence`, and `tee_evidence` for the
  ESP-TEE envelope), the serverless JWT-SVID call (`serverless`, `grpcweb`), token exchange (`token_exchange`,
  `oauth`), and unverified JWT decoding. This crate is the seed of a Rust libcommon, so keep it free of
  demo-specific code and of hardware. Anything a platform must supply goes behind a trait: `http::HttpClient` for
  transport, `attest::HmacKey` for the HMAC key, `attest::TeeTokenSource` for the TEE's tokens.
- `demo/`: the demo's own logic, shared by host and firmware. It holds the device-code login (`login`), the
  orchestration with its polling and cancellation (`flow`), the screen state machine (`app`), tap and long-press
  detection (`gesture`), and what the result screen shows (`claims`).
- `host/` (`demo-host`): a Mac CLI that runs the same flow against the live servers before any hardware is
  involved. It has two subcommands: `svid` and `login`.
- `firmware/` (`demo-firmware`): ESP-IDF std firmware for `riscv32imac-esp-espidf`. It is excluded from the
  workspace because it builds on nightly with `build-std`, through its own `rust-toolchain.toml`. Settings come
  from `firmware/cfg.toml` (see `cfg.toml.example`) at build time. `display` drives the JD9853 panel one
  strip at a time (there's no RAM for a full framebuffer) and `ui` draws the screens. `console.rs` also prints
  each screen to serial (the QR code as text), and is the only output with `--features xiao`. `touch` polls the
  AXS5106L, and `demo::gesture` turns its samples into taps and long presses. The BOOT button (GPIO9) also taps.
  A long press on the idle screen switches the attestor between `efuse` (the default) and `tee` and re-attests; the choice
  is kept in NVS (namespace `demo`, key `attestor`). The Waveshare board's secret is burned into eFuse key block 5
  (`HMAC_UP`, read-protected), which `efuse_hmac_key` in `cfg.toml` names. Under ESP-TEE the HMAC call is a
  TEE secure service; TEE secure storage stays in development mode, so it never claims that key block.

Everything that can be tested without hardware lives in `defakto` or `demo`, so the firmware stays a thin layer
that drives the display, touch, WiFi and keys. This mirrors libcommon's `*_core` split.

## Commands

- Tests: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets`, which should produce no warnings.
- Host CLI: `cargo run -p demo-host -- svid` and `cargo run -p demo-host -- login`. Settings come from `DEMO_*` env
  vars, loaded from `host/.env`. The variables are `DEMO_SECRET_B64`, `DEMO_SVID_AUDIENCE`, `DEMO_LOGIN_DEVICE_URL`,
  `DEMO_LOGIN_TOKEN_URL`, `DEMO_LOGIN_CLIENT_ID` (the two URLs come from the IdP's OIDC discovery document), and
  optionally `DEMO_DEVICE_ID`, `DEMO_SUBJECT_TOKEN_TYPE`, `DEMO_REQUESTED_TOKEN_TYPE`, `DEMO_OBO_AUDIENCE`, `DEMO_CHECKIN_URL`,
  `DEMO_SERVERLESS_URL` and `DEMO_TOKEN_URL`.
- Toolchain: the rustup proxies in `~/.cargo/bin` must come before Homebrew's `cargo` on PATH. Homebrew's
  stable-only Rust ignores `rust-toolchain.toml`, so it can't build the firmware.
- ESP-IDF: before the first firmware build, run `firmware/patch-idf.sh`. It sets up `firmware/.embuild/esp-idf`
  (v5.5.5 plus `firmware/patches/esp-tee-rom-read.patch`), which `IDF_PATH` points at. Without the patch, the
  TEE's flash reads break once the app has used flash, and it loses its attestation key on every boot. `build.rs`
  refuses to build without the patch. Without the tree, the build fails early with `esp-idf-sys` unable to
  "determine esp-idf version from …/.embuild/esp-idf/tools/cmake/version.cmake"; run the script.
  `esp-idf-sys` still installs its tools under `firmware/.embuild/espressif/`.
- Firmware, from `firmware/`: `cargo run --release` builds, flashes and opens the serial monitor. Add
  `--features xiao` for the Seeed XIAO ESP32C6 stand-in board, which needs its RF switch enabled. It has no
  burned eFuse key, so it can only attest with the TEE. The firmware no longer reads a secret from NVS; software
  HMAC remains only in `defakto` and the host CLI.
- ESP-TEE: the firmware always builds with the TEE, which `default_attestor = "tee"` in `cfg.toml` (or a long
  press) attests with. The runner is `flash.sh`, because `espflash` can't parse the
  `tee_0` partition subtype. It writes the bootloader, `partitions.csv`, the TEE image and the app by offset. The
  layout keeps `nvs` at `0x9000`, followed by `tee` at `0x10000`, `secure_storage` at `0x40000` and the app at
  `0x50000`. Flash with `TEE_PROVISION=1` on a board's first TEE flash, or after `secure_storage` held anything
  else: it erases the region, so the TEE makes a new attestation key, which must then be enrolled again. The boot
  log prints the key as `TEE attestation key: …`. The TEE reports the crate version in `firmware/Cargo.toml` as
  `app_version`.

## Constraints

- **The HMAC evidence must stay byte-identical to `telemetry/pkg/espattest`.** That package is what the
  `esp32-attestor` webhook verifies. The golden test in `defakto/src/attest.rs` comes from `esp32-enroll golden`.
  If it fails, the format has drifted; don't change the expected value to make it pass. The same holds for the TEE
  envelope, which must match what the `esp32-attestor` verifier expects. `tee_envelope_golden` in
  `defakto/src/tee_evidence.rs` pins it with a token captured from the device (`defakto/testdata/`) and checks the
  TEE's signature. Don't recapture it to make the test pass.
- **Attestation must stay swappable.** HMAC from an eFuse key and the ESP-TEE token must both sit behind
  `Attestor`, so the device can switch between them at runtime, and the host keeps software HMAC. Don't add anything that only works for
  HMAC.
- **Never commit secrets:** `host/.env`, `firmware/cfg.toml`, `nvs.csv`, `nvs.bin` and `secret.bin` are
  gitignored.
- **Dan makes every external change.** That covers the IdPs (Pocket ID, Auth0), `~/workspace/homelab` (the Terraform
  `TokenExchangePolicy`, the enrollment parameter) and `~/workspace/telemetry`. Hand those steps over rather than
  editing them.
- **Burning an eFuse key is irreversible, and only Dan does it.**
