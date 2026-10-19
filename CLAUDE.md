# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A tech demo for the Waveshare ESP32-C6-Touch-LCD-1.47, written in Rust. The device shows a Defakto logo; tapping it
shows a QR code for an OIDC device-flow login (Pocket ID at home, Auth0 on-site). The device then attests to
Defakto's serverless API, which calls this repo's `esp32-attestor`, for a JWT-SVID
(`spiffe://prod.cavallaro.local/iot/defakto-demo`), exchanges the user's ID token for an OBO token (RFC 8693), and shows
its claims on screen. The demo's story is a check-in badge reader: when `checkin_url` is set, the device presents
the OBO token to that check-in service as a bearer token, recording who checked in and through which device.

## Layout

A Cargo workspace of six packages, plus the firmware as a separate project:

- `defakto/`: the Defakto client. It covers the attestors (`attest`, over `esp-attest`'s evidence formats), the
  serverless JWT-SVID call (`serverless`, `grpcweb`), token exchange (`token_exchange`, `oauth`), unverified JWT
  decoding, and, behind its `verify` feature, RS256 JWT-SVID verification against a trust domain's JWKS
  (`verify`). This crate is the seed of a Rust libcommon, so keep it free of demo-specific code and of hardware.
  Anything a platform must supply goes behind a trait: `http::HttpClient` for transport, `attest::HmacKey` for the
  HMAC key, `attest::TeeTokenSource` for the TEE's tokens.
- `esp-attest/`: the evidence formats the device signs and the attestor verifies (device IDs, HMAC evidence, the
  ESP-TEE envelope). Its `verify` feature adds the checks, so the firmware builds without P-256. It is also a seed
  of libcommon, so the same rules apply as for `defakto`: no demo-specific code and no hardware. Its golden vectors
  are in `esp-attest/README.md`.
- `attestor/` (`esp32-attestor`): the webhook behind Defakto's `extension` attestor. It holds the webhook
  (`webhook`, `verifier`), the enrollment file (`enrollment`), polling reload of the enrollment file and TLS pair
  (`reload`), and the `enroll` subcommands (`enroll`). It builds into a container with `attestor/Dockerfile`, and
  `attestor/build.sh` pushes it to ghcr, as for `checkin`. Bump `attestor/Cargo.toml`'s version for each release.
  It serves real devices, so keep its behaviour compatible.
- `demo/`: the demo's own logic, shared by host and firmware. It holds the device-code login (`login`), the
  orchestration with its polling and cancellation (`flow`), the screen state machine (`app`), tap and long-press
  detection (`gesture`), what the result screen shows (`claims`), and the setup wizard's settings, portal page
  and captive DNS (`setup`, `captive`).
- `host/` (`demo-host`): a Mac CLI that runs the same flow against the live servers before any hardware is
  involved. It has two subcommands: `svid` and `login`.
- `checkin/`: the check-in service the device checks people in with. It verifies each OBO token against the
  trust domain's JWKS (found through OIDC discovery), keeps the roster in memory (and, with `CHECKIN_DATA`, in a
  JSON Lines journal it replays at startup), and serves a live page at `/` over server-sent events. A second
  listener, always on `127.0.0.1:8081`, serves an unauthenticated `POST /reset` to empty the roster. It's
  demo-side, so it stays out of `defakto`. It builds into a container with `checkin/Dockerfile`, from the repo root;
  `checkin/build.sh` builds it for amd64 and arm64 (cross-compiling, not emulating) and pushes it to ghcr. Bump
  `checkin/Cargo.toml`'s version for each release.
- `firmware/` (`demo-firmware`): ESP-IDF std firmware for `riscv32imac-esp-espidf`. It is excluded from the
  workspace because it builds on nightly with `build-std`, through its own `rust-toolchain.toml`. Settings come
  from the setup wizard, saved in NVS (namespace `demo`, key `settings`), over defaults from `firmware/cfg.toml`
  (see `cfg.toml.example`) at build time, all of which may be left empty. The first boot of a newly flashed build (by its ELF SHA-256,
  key `build`) writes `cfg.toml`'s non-empty values over the saved settings, so flashing re-applies `cfg.toml`. The wizard (`setup`) runs when the
  settings are incomplete, or when the screen or BOOT is held from just after the logo appears (a finger already
  down at power-on is invisible to touch): it starts an access point `defakto-setup-XXXX` with a random password, shows a QR code that joins it, and answers every DNS query with
  itself so the phone opens the portal. `demo::setup` and `demo::captive` hold its form, validation and DNS.
  With `devid_issuer` and `devid_subjects` in `cfg.toml`, saving also takes a Defakto DevID JWT-SVID whose audience
  is the device ID. The settings wait in NVS (key `pending`) until the next boot has joined their network and
  verified the DevID, and are dropped if it fails, with the reason (key `problem`) shown by the wizard. `display`
  drives the JD9853 panel one strip at a time (there's no RAM for a full framebuffer) and `ui` draws the screens.
  `console.rs` also prints each screen to serial (the QR code as text), and is the only output with
  `--features xiao`. `touch` polls the AXS5106L, and `demo::gesture` turns its samples into taps and long presses.
  The BOOT button (GPIO9) also taps. A long press on the idle screen switches the attestor between those the
  `attestors` setting enables (`efuse` and `tee`, from the wizard's checkboxes) and re-attests; the choice is kept
  in NVS (namespace `demo`, key `attestor`). With one enabled, a long press does nothing. The Waveshare
  board's secret is burned into eFuse key block 5 (`HMAC_UP`, read-protected), which `efuse_hmac_key` in `cfg.toml`
  names. Under ESP-TEE the HMAC call is a TEE secure service; TEE secure storage stays in development mode, so it
  never claims that key block.

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
- Attestor: `cargo run -p esp32-attestor -- serve --enrollment … --tls-cert … --tls-key …` (the other flags have
  defaults, see `--help`), and `cargo run -p esp32-attestor -- enroll hmac <device_id>` or `-- enroll tee <device_id>
  <pubkey-hex>` for enrollment entries.
- Check-in service: `cargo run -p checkin`, with settings from `CHECKIN_*` env vars or `checkin/.env`:
  `CHECKIN_ISSUER` and `CHECKIN_AUDIENCE`, plus optional comma-separated `CHECKIN_DEVICES` and
  `CHECKIN_USER_ISSUERS` allow-lists, `CHECKIN_LISTEN` and `CHECKIN_DATA`.
- Toolchain: the rustup proxies in `~/.cargo/bin` must come before Homebrew's `cargo` on PATH. Homebrew's
  stable-only Rust ignores `rust-toolchain.toml`, so it can't build the firmware.
- ESP-IDF: before the first firmware build, run `firmware/patch-idf.sh`. It sets up `firmware/.embuild/esp-idf`
  (v5.5.5 plus `firmware/patches/esp-tee-rom-read.patch`), which `IDF_PATH` points at. Without the patch, the
  TEE's flash reads break once the app has used flash, and it loses its attestation key on every boot. `build.rs`
  refuses to build without the patch. Without the tree, `check-idf.sh` (the rustc wrapper) stops a fresh build
  at its first compile and says to run the script. When `core` is already built, the build instead fails with
  `esp-idf-sys` unable to "determine esp-idf version from …/.embuild/esp-idf/tools/cmake/version.cmake".
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

- **The HMAC evidence and the TEE envelope must stay byte-compatible with what `esp-attest` verifies.** Its golden
  vectors pin both: the HMAC one in `esp-attest/src/hmac.rs` and the TEE token captured from a device in
  `esp-attest/testdata/` (see `esp-attest/README.md`). `defakto/src/attest.rs` has the device-side HMAC golden test.
  Four libcommon devices (C++, `libcommon/src/spiffe_core.cpp`) sign the HMAC format in production, so a format change
  breaks them too. If a golden test fails, the format has drifted; don't change the expected value or recapture the
  token to make it pass. The attestor serves real devices, so its behaviour must stay compatible too.
- **Attestation must stay swappable.** HMAC from an eFuse key and the ESP-TEE token must both sit behind
  `Attestor`, so the device can switch between them at runtime, and the host keeps software HMAC. Don't add anything that only works for
  HMAC.
- **Never commit secrets:** `host/.env`, `firmware/cfg.toml`, `nvs.csv`, `nvs.bin` and `secret.bin` are
  gitignored.
- **Dan makes every external change.** That covers the IdPs (Pocket ID, Auth0), `~/workspace/homelab` (the Terraform
  `TokenExchangePolicy`, the enrollment parameter) and `~/workspace/esp32/libcommon`. Hand those steps over rather
  than editing them.
- **Burning an eFuse key is irreversible, and only Dan does it.**
