# Build from the repo root, since the service shares the workspace's lockfile:
#   docker build -f checkin/Dockerfile -t checkin .
# The build stage runs natively and cross-compiles, which is much faster than
# building the other architecture under emulation.
FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS build
ARG BUILDARCH
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) pkg=x86-64-linux-gnu libc=amd64; target=x86_64-unknown-linux-gnu ;; \
      arm64) pkg=aarch64-linux-gnu libc=arm64; target=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends "gcc-$pkg" "libc6-dev-$libc-cross"; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    rustup target add "$target"; \
    echo "$target" > /rust-target
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
WORKDIR /src
COPY . .
RUN target=$(cat /rust-target) && \
    cargo build --release --locked -p checkin --target "$target" && \
    cp "target/$target/release/checkin" /checkin

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /checkin /checkin
ENV CHECKIN_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/checkin"]
