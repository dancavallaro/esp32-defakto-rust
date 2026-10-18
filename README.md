# Defakto check-in badge reader

A palm-sized check-in kiosk for offsites, meetups and remote sites, built on an ESP32-C6 and Defakto workload
identity. Put one by the door: attendees tap it, scan the QR code, and sign in on their phone with the company IdP.
The device then holds a token that proves two things at once: **who** checked in, and **which device** they checked
in through.

There's no shared API key baked into the device, and no user password ever touches it.

<p align="center">
  <img src="docs/images/idle.png" width="180" alt="Idle screen: the Defakto logo and a pulsing 'tap to check in' prompt">
  <img src="docs/images/qr.png" width="180" alt="Sign-in screen: a QR code, the IdP's device URL and a one-time code">
  <img src="docs/images/progress.png" width="180" alt="Progress screen: attested, signed in, got JWT-SVID, token exchange, checking in">
  <img src="docs/images/receipt.png" width="180" alt="Receipt: 'Hi, Alice!', checked in, with the user, IdP and the device's SPIFFE ID">
</p>
<p align="center"><sub>Tap, scan, sign in on your phone, and you're checked in. (Renders, with example values.)</sub></p>

## How it works

1. **The device proves what it is.** At boot it attests to Defakto and receives a JWT-SVID, such
   as `spiffe://example.org/iot/badge-reader`. It attests in one of two ways: an HMAC over a secret burned
   into read-protected eFuse, or a token signed by the chip's ESP-TEE. The TEE's token also reports which firmware
   version is running.
2. **The attendee proves who they are.** A tap starts an OAuth device-code login (RFC 8628), and the screen shows
   a QR code. The attendee signs in on their own phone, and the device receives their ID token.
3. **Defakto binds the two together.** The device exchanges the attendee's ID token and its own SVID for an
   on-behalf-of token (RFC 8693). In that token, `obo.sub` is the attendee and `obo.act.sub` is the device's SPIFFE
   ID, and Defakto signs it.
4. **The check-in is recorded.** The device presents the OBO token to your check-in service, which verifies it
   against Defakto's trust bundle and records the attendee, the device and the time.

Because the check-in service verifies the token rather than trusting the device, it can also enforce policy: it
accepts check-ins only from enrolled devices, and only for users of your IdP.

## Setting one up

The firmware is open source. To deploy it, you:

- **Register an OIDC client** for the device-code grant with your IdP. Pocket ID and Auth0 are both tested.
- **Enroll the device with Defakto.** Register its attestation key, and add a token-exchange policy that lets the
  device act on behalf of your IdP's users.
- **Fill in `firmware/cfg.toml`** (see `cfg.toml.example`). It holds the WiFi credentials, the IdP's device and
  token endpoints, the client ID, and the trust domain's issuer.
- **Flash it.** See [Building the firmware](#building-the-firmware).

## Building the firmware

On a Mac, you need:

- **Xcode's command line tools**, for git, Python 3 and a C compiler: `xcode-select --install`.
- **rustup**, from [rustup.rs](https://rustup.rs). The firmware builds on nightly, which `firmware/rust-toolchain.toml`
  pins and rustup installs on the first build. Homebrew's `rust` formula won't work, because it ignores that file. If
  you have it, put `~/.cargo/bin` ahead of it on your `PATH`.
- **ldproxy and espflash**, which link and flash the firmware: `cargo install --locked ldproxy espflash`. `flash.sh`
  needs espflash 4 or later.

Then, from `firmware/`:

```sh
./patch-idf.sh                  # once: fetches ESP-IDF v5.5.5 and applies the TEE flash-read fix
cp cfg.toml.example cfg.toml    # then fill it in
cargo run --release             # builds, flashes and opens the serial monitor
```

The first build also downloads ESP-IDF's toolchain (the RISC-V compiler, cmake and ninja) into `firmware/.embuild/`,
so it takes a while. On a board's first TEE flash, use `TEE_PROVISION=1 cargo run --release`, which gives the TEE a
fresh attestation key to enroll.

## The check-in endpoint

<img src="docs/images/error.png" width="150" align="right" alt="Error screen: 'Check-in failed: check-in refused: HTTP 403'">

The device sends `POST <checkin_url>` with `Authorization: Bearer <OBO token>` and a body of `{}`. Any 2xx response
means the check-in was recorded. Anything else shows "Check-in failed" with the status code. Everything the service
needs is in the token, so it should check:

- the signature, against the trust domain's JWKS
- that `aud` is the service's own audience (`obo_audience` in `cfg.toml`)
- that `obo.act.sub` is a device it trusts
- that `obo.iss` is your IdP

Without a `checkin_url`, the device stops after the exchange and shows the token's claims.

## The check-in service

<p align="center">
  <img src="docs/images/checkin-page.png" width="640" alt="Check-in page: '4 people checked in', a card per attendee with their email, IdP, the badge reader's SPIFFE ID and an 'OBO verified' badge">
</p>
<p align="center"><sub>The check-in page, live as people arrive. (Render, with example values.)</sub></p>

`checkin/` is a ready-made check-in endpoint. It does the checks above, keeps a list of who's checked in, and
serves a page at `/` that updates live as people arrive. Run it with your trust domain's issuer and the device's
`obo_audience`:

```sh
CHECKIN_ISSUER=https://… CHECKIN_AUDIENCE=defakto-demo cargo run -p checkin
```

Then open `http://localhost:8080` and point the device at it with `checkin_url = "http://<host>:8080/checkins"`.
Its settings can also live in `checkin/.env`:

| Variable | |
| --- | --- |
| `CHECKIN_ISSUER` | The trust domain's issuer. The service finds its signing keys through OIDC discovery. |
| `CHECKIN_AUDIENCE` | The `obo_audience` the device asks for. |
| `CHECKIN_DEVICES` | Optional, comma-separated: the device SPIFFE IDs allowed to check people in. Unset allows any. |
| `CHECKIN_USER_ISSUERS` | Optional, comma-separated: the user IdPs allowed. Unset allows any. |
| `CHECKIN_LISTEN` | Where to listen. The default is `0.0.0.0:8080`. |
| `CHECKIN_DATA` | Optional: a file to keep check-ins in, so they survive a restart. Unset keeps them in memory only. |

`CHECKIN_DATA` is a JSON Lines journal: the service appends each check-in and reset, and replays the file when it
starts. `POST /reset` empties the list. It has no authentication, so it listens only on `127.0.0.1:8081`. A reset
leaves the earlier check-ins in the file, but they're no longer replayed. To start a fresh demo in Kubernetes,
forward the admin port to the pod:

```sh
kubectl port-forward deploy/checkin 8081 &
curl -X POST localhost:8081/reset
```

`checkin/build.sh` tests the service, then builds a container image
for amd64 and arm64 and pushes it to `ghcr.io/dancavallaro/esp32-spiffe-rust/checkin`, tagged `latest` and with the
version in `checkin/Cargo.toml`. Pass `--no-push` to only build.

## Hardware

The device is a Waveshare ESP32-C6-Touch-LCD-1.47. A tap on the screen or the BOOT button starts a check-in. A long
press on the idle screen switches between eFuse and TEE attestation.

A Seeed XIAO ESP32C6 also works, headless and with TEE attestation only. It prints each screen to serial.

## Development

- `cargo test --workspace` runs the tests.
- `cargo run -p demo-host -- svid` and `cargo run -p demo-host -- login` run the same flow from a Mac, without the
  hardware.

`CLAUDE.md` covers the code layout, the ESP-IDF patch and the TEE flashing details.
