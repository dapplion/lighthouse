# Build with `docker build -t mock-proof-engine:local -f testing/mock_proof_engine/Dockerfile .`
FROM rust:1.90-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin mock_proof_engine

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/mock_proof_engine /usr/local/bin/mock_proof_engine
ENTRYPOINT ["mock_proof_engine"]
