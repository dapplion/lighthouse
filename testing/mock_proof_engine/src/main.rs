//! A mock EIP-8025 proof engine.
//!
//! Stands in for a real proving service so a devnet can run the proof producer and consumer end
//! to end. It implements the two proof-engine routes those two sides need:
//!
//! - `GET  /v1/execution_proofs/{new_payload_request_root}/{proof_type}` hands a producer the
//!   proof bytes to sign and gossip.
//! - `POST /v1/execution_proof_verifications` tells a consumer whether proof bytes verify.
//!
//! There is no cryptography here. A proof is `sha2` expanded from the request root and the proof
//! type, so the two routes agree, distinct proof types produce distinct proofs, and bytes that
//! were not minted by this engine are rejected. That last part matters: it keeps the consumer's
//! REJECT path reachable, which an always-`VALID` mock would hide.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

/// Domain separator, so mock proofs can never be confused with anything real.
const MOCK_DOMAIN: &[u8] = b"EIP8025-MOCK-PROOF";

#[derive(Parser)]
#[command(name = "mock_proof_engine", about = "Mock EIP-8025 proof engine")]
struct Config {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8025")]
    listen_address: SocketAddr,
    /// Size in bytes of the proofs this engine mints.
    #[arg(long, default_value_t = 1024)]
    proof_size: usize,
    /// Reject every proof, to exercise the consumer's REJECT path.
    #[arg(long)]
    reject_all: bool,
}

#[derive(Clone)]
struct Engine {
    proof_size: usize,
    reject_all: bool,
}

impl Engine {
    /// Deterministically expand `(root, proof_type)` into `proof_size` bytes.
    fn mint(&self, root: &str, proof_type: u8) -> Vec<u8> {
        let mut seed = Sha256::new();
        seed.update(MOCK_DOMAIN);
        seed.update(normalise_root(root).as_bytes());
        seed.update([proof_type]);
        let mut block = seed.finalize();

        let mut out = Vec::with_capacity(self.proof_size);
        while out.len() < self.proof_size {
            out.extend_from_slice(&block);
            block = Sha256::digest(block);
        }
        out.truncate(self.proof_size);
        out
    }
}

/// Roots reach us as query or path strings from more than one client, so compare them by value
/// rather than by spelling: lowercase, without the `0x`.
fn normalise_root(root: &str) -> String {
    root.trim_start_matches("0x").to_lowercase()
}

#[derive(Deserialize)]
struct VerifyQuery {
    new_payload_request_root: String,
    proof_type: u8,
    #[allow(dead_code)]
    beacon_block_root: Option<String>,
}

/// `POST /v1/execution_proof_verifications`
async fn verify(
    State(engine): State<Engine>,
    Query(query): Query<VerifyQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let expected = engine.mint(&query.new_payload_request_root, query.proof_type);
    let valid = !engine.reject_all && body.as_ref() == expected.as_slice();

    println!(
        "verify root={} type={} bytes={} -> {}",
        query.new_payload_request_root,
        query.proof_type,
        body.len(),
        if valid { "VALID" } else { "INVALID" }
    );

    let status = if valid { "VALID" } else { "INVALID" };
    (
        [("content-type", "application/json")],
        format!(r#"{{"status":"{status}"}}"#),
    )
}

/// `GET /v1/execution_proofs/{new_payload_request_root}/{proof_type}`
async fn get_proof(
    State(engine): State<Engine>,
    Path((root, proof_type)): Path<(String, u8)>,
) -> impl IntoResponse {
    if normalise_root(&root).len() != 64 {
        return (StatusCode::BAD_REQUEST, Vec::new());
    }
    println!(
        "mint  root={root} type={proof_type} bytes={}",
        engine.proof_size
    );
    (StatusCode::OK, engine.mint(&root, proof_type))
}

#[tokio::main]
async fn main() {
    let config = Config::parse();
    let engine = Engine {
        proof_size: config.proof_size,
        reject_all: config.reject_all,
    };

    let app = Router::new()
        .route("/v1/execution_proof_verifications", post(verify))
        .route("/v1/execution_proofs/{root}/{proof_type}", get(get_proof))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {}: {e}", config.listen_address));

    println!(
        "mock proof engine on {} (proof_size={}, reject_all={})",
        config.listen_address, config.proof_size, config.reject_all
    );
    axum::serve(listener, app).await.expect("server failed");
}
