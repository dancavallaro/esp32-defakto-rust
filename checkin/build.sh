#!/usr/bin/env bash
# Builds the check-in service for amd64 and arm64 and pushes it, tagged latest
# and with checkin/Cargo.toml's version. Pass --no-push to only build.
set -euo pipefail

cd "$(dirname "$0")/.."
image=ghcr.io/dancavallaro/esp32-spiffe-rust/checkin
version=$(sed -n 's/^version = "\(.*\)"/\1/p' checkin/Cargo.toml)
output=--push
if [[ "${1:-}" == --no-push ]]; then
  output=
fi

cargo test -p checkin
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag "$image:latest" \
  --tag "$image:$version" \
  --file checkin/Dockerfile \
  $output \
  .
