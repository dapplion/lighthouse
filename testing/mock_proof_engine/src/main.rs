//! A mock EIP-8025 proof engine.
//!
//! Stands in for a real proving service so a devnet can run proof seeding and proof gating end to
//! end. It implements the two proof-engine routes a beacon node needs:
//!
//! - `GET  /v1/execution_proofs` hands back the signed proofs this engine has for a payload.
//! - `POST /v1/execution_proof_verifications` says whether proof bytes verify.
//!
//! There is no cryptography in the proofs themselves. By default a proof is `sha2` expanded from
//! the request root and the proof type, so any two instances agree, distinct proof types give
//! distinct proofs, and bytes that were not minted by this engine are rejected. That last part
//! matters: it keeps the consumer's REJECT path reachable, which an always-`VALID` mock would hide.
//!
//! `--proof-dir` swaps the synthetic bytes for real zkEVM proofs downloaded from Ethproofs, so the
//! devnet carries realistic sizes and encodings rather than a round kilobyte. Real proofs are not
//! derived from the payload, so in this mode a proof no longer binds to a particular request root;
//! everything else, including the reject path for corrupt or mistyped bytes, still holds.
//!
//! The BLS signature over each proof is real, because consumers check it. Give the engine a
//! validator key with `--secret-key` and it produces; leave it out and it only verifies, which is
//! how a devnet decides which nodes seed.

use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use bls::SecretKey;
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssz::Encode;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::execution::{
    ExecutionProof, MAX_PROOF_SIZE, ProofData, ProofType, PublicInput, SignedExecutionProof,
};
use types::{Hash256, SigningData};

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
    /// Reject every proof, to exercise the consumer's reject path.
    #[arg(long)]
    reject_all: bool,
    /// Hex BLS secret key to sign produced proofs with. Without it this engine only verifies.
    #[arg(long)]
    secret_key: Option<String>,
    /// Index of the validator whose key signs produced proofs. Must be active, or consumers
    /// reject the proofs.
    #[arg(long, default_value_t = 0)]
    validator_index: u64,
    /// Comma separated proof types to produce for each payload.
    #[arg(long, value_delimiter = ',', default_value = "0,1")]
    proof_types: Vec<ProofType>,
    /// Directory of real proof artifacts named `<proof_type>.bin`, as written by
    /// `fetch_ethproofs.py`. Without it the engine mints synthetic proofs.
    #[arg(long)]
    proof_dir: Option<PathBuf>,
}

struct Prover {
    secret_key: SecretKey,
    validator_index: u64,
    proof_types: Vec<ProofType>,
}

#[derive(Clone)]
struct Engine {
    proof_size: usize,
    reject_all: bool,
    prover: Option<Arc<Prover>>,
    /// Real proof artifacts by proof type. Takes precedence over minting.
    fixtures: Arc<HashMap<ProofType, Vec<u8>>>,
}

impl Engine {
    /// The bytes this engine considers to be the proof for `(root, proof_type)`.
    fn mint(&self, root: Hash256, proof_type: ProofType) -> Vec<u8> {
        if let Some(fixture) = self.fixtures.get(&proof_type) {
            return fixture.clone();
        }

        let mut seed = Sha256::new();
        seed.update(MOCK_DOMAIN);
        seed.update(root.as_slice());
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

/// Roots reach us as strings from more than one client, so compare them by value rather than by
/// spelling: lowercase, without the `0x`.
fn parse_root(root: &str) -> Option<Hash256> {
    let bytes = hex::decode(root.trim_start_matches("0x").to_lowercase()).ok()?;
    (bytes.len() == 32).then(|| Hash256::from_slice(&bytes))
}

#[derive(Deserialize)]
struct VerifyQuery {
    new_payload_request_root: String,
    proof_type: ProofType,
    #[allow(dead_code)]
    beacon_block_root: Option<String>,
}

/// `POST /v1/execution_proof_verifications`
async fn verify(
    State(engine): State<Engine>,
    Query(query): Query<VerifyQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let valid = !engine.reject_all
        && parse_root(&query.new_payload_request_root)
            .is_some_and(|root| body.as_ref() == engine.mint(root, query.proof_type).as_slice());

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

#[derive(Deserialize)]
struct ProofsQuery {
    beacon_block_root: String,
    new_payload_request_root: String,
    /// Signing domain, supplied by the caller so this engine needs no chain configuration.
    domain: String,
}

/// `GET /v1/execution_proofs`
///
/// Returns an SSZ list of `SignedExecutionProof`, empty for a verify-only engine.
async fn get_proofs(
    State(engine): State<Engine>,
    Query(query): Query<ProofsQuery>,
) -> impl IntoResponse {
    let Some(prover) = engine.prover.clone() else {
        return (
            StatusCode::OK,
            Vec::<SignedExecutionProof>::new().as_ssz_bytes(),
        );
    };

    let (Some(beacon_block_root), Some(new_payload_request_root), Some(domain)) = (
        parse_root(&query.beacon_block_root),
        parse_root(&query.new_payload_request_root),
        parse_root(&query.domain),
    ) else {
        return (StatusCode::BAD_REQUEST, Vec::new());
    };

    let proofs = prover
        .proof_types
        .iter()
        .map(|proof_type| {
            let message = ExecutionProof {
                proof_data: ProofData::new(engine.mint(new_payload_request_root, *proof_type))
                    .expect("proof exceeds MAX_PROOF_SIZE"),
                proof_type: *proof_type,
                public_input: PublicInput {
                    new_payload_request_root,
                },
                beacon_block_root,
            };
            let signing_root = SigningData {
                object_root: message.tree_hash_root(),
                domain,
            }
            .tree_hash_root();

            SignedExecutionProof {
                message,
                validator_index: prover.validator_index,
                signature: prover.secret_key.sign(signing_root),
            }
        })
        .collect::<Vec<_>>();

    println!(
        "produce block_root={} root={} bytes={:?}",
        query.beacon_block_root,
        query.new_payload_request_root,
        proofs
            .iter()
            .map(|proof| (proof.proof_type(), proof.message.proof_data.len()))
            .collect::<Vec<_>>()
    );

    (StatusCode::OK, proofs.as_ssz_bytes())
}

/// Load `<proof_type>.bin` artifacts, rejecting anything the SSZ type could not carry.
fn load_fixtures(dir: &PathBuf) -> HashMap<ProofType, Vec<u8>> {
    let mut fixtures = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        println!("no proof artifacts in {dir:?}, minting synthetic proofs instead");
        return fixtures;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "bin") {
            continue;
        }
        let Some(proof_type) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.parse::<ProofType>().ok())
        else {
            continue;
        };

        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
        assert!(
            bytes.len() <= MAX_PROOF_SIZE,
            "{path:?} is {} bytes, over MAX_PROOF_SIZE",
            bytes.len()
        );
        println!(
            "loaded proof type {proof_type} from {path:?} ({} bytes)",
            bytes.len()
        );
        fixtures.insert(proof_type, bytes);
    }

    if fixtures.is_empty() {
        println!("no <proof_type>.bin artifacts in {dir:?}, minting synthetic proofs instead");
    }
    fixtures
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    let prover = config.secret_key.as_ref().map(|key| {
        let secret_key = SecretKey::deserialize(
            &hex::decode(key.trim_start_matches("0x")).expect("secret key is not hex"),
        )
        .expect("secret key is not a BLS key");
        Arc::new(Prover {
            secret_key,
            validator_index: config.validator_index,
            proof_types: config.proof_types.clone(),
        })
    });

    let fixtures = config
        .proof_dir
        .as_ref()
        .map(load_fixtures)
        .unwrap_or_default();

    let engine = Engine {
        proof_size: config.proof_size,
        reject_all: config.reject_all,
        prover,
        fixtures: Arc::new(fixtures),
    };

    let app = Router::new()
        .route("/v1/execution_proof_verifications", post(verify))
        .route("/v1/execution_proofs", get(get_proofs))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind(config.listen_address)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {}: {e}", config.listen_address));

    println!(
        "mock proof engine on {} (proof_size={}, reject_all={}, produces={})",
        config.listen_address,
        config.proof_size,
        config.reject_all,
        if config.secret_key.is_some() {
            format!("{:?}", config.proof_types)
        } else {
            "no".to_string()
        }
    );
    axum::serve(listener, app).await.expect("server failed");
}
