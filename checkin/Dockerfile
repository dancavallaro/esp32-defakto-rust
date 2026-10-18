# Build from the repo root, since the service shares the workspace's lockfile:
#   docker build -f checkin/Dockerfile -t checkin .
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p checkin

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/checkin /checkin
ENV CHECKIN_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/checkin"]
