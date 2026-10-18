#!/usr/bin/env bash
# Builds the attestor for amd64 and arm64 and pushes it, tagged latest
# and with attestor/Cargo.toml's version. Pass --no-push to only build.
set -euo pipefail

cd "$(dirname "$0")/.."
image=ghcr.io/dancavallaro/esp32-defakto-rust/esp32-attestor
version=$(sed -n 's/^version = "\(.*\)"/\1/p' attestor/Cargo.toml)
output=--push
if [[ "${1:-}" == --no-push ]]; then
  output=
fi

cargo test -p esp-attest -p esp32-attestor
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag "$image:latest" \
  --tag "$image:$version" \
  --file attestor/Dockerfile \
  $output \
  .
