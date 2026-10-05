# Build with `docker build -t proof-seeder:local -f proof_seeder/Dockerfile .`
FROM rust:1.90-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin proof_seeder

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/proof_seeder /usr/local/bin/proof_seeder
ENTRYPOINT ["proof_seeder"]
