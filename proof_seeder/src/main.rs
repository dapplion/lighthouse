//! An EIP-8025 proof engine that seeds the network with proofs from Ethproofs.
//!
//! It serves the two routes a beacon node asks of a proof engine:
//!
//! - `GET  /v1/execution_proofs` hands back the signed proofs it holds for a payload.
//! - `POST /v1/execution_proof_verifications` says whether proof bytes are a proof of that payload.
//!
//! Ethproofs has no feed, so this emulates one. A payload the beacon node asks about and nobody has
//! proven yet goes on a queue, which is polled on a backoff until the proofs appear or the payload
//! ages out. The first proofs for a block land about five minutes after it, so seeding is always
//! retroactive: a payload is proven long after it stopped being the head. That is the point of the
//! queue.
//!
//! Proving and signing both live here, so the beacon node holds no validator key and only relays
//! what this hands it. An engine without a key verifies and seeds nothing, which is how a node opts
//! out of seeding.

mod ethproofs;

use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use bls::SecretKey;
use clap::{Parser, ValueEnum};
use lru::LruCache;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssz::Encode;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tree_hash::TreeHash;
use types::ExecutionBlockHash;
use types::execution::{
    ExecutionProof, ProofData, ProofType, PublicInput, SignedExecutionProof, ZkevmProof,
};
use types::{Hash256, SigningData};

/// Domain separator, so synthetic proofs can never be confused with anything real.
const SYNTHETIC_DOMAIN: &[u8] = b"EIP8025-SYNTHETIC-PROOF";

/// How often the queue is examined. Polls themselves are paced by the request budget.
const QUEUE_TICK: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Source {
    /// Proofs from Ethproofs for the payload that was asked about. For a network whose execution
    /// blocks are mainnet blocks.
    Live,
    /// Proofs of one pinned mainnet block, served for any payload. For a devnet, whose payloads
    /// Ethproofs has never seen, so that proof sizes and encodings are realistic anyway.
    Fixture,
    /// Bytes expanded from the payload hash. No network, and two engines agree.
    Synthetic,
}

#[derive(Parser)]
#[command(
    name = "proof_seeder",
    about = "EIP-8025 proof engine backed by Ethproofs"
)]
struct Config {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8025")]
    listen_address: SocketAddr,
    /// Where proofs come from.
    #[arg(long, value_enum, default_value_t = Source::Live)]
    source: Source,
    /// Mainnet block whose proofs are served for every payload, in fixture mode.
    #[arg(long, default_value_t = 25_778_500)]
    fixture_block: u64,
    /// Size in bytes of a synthetic proof.
    #[arg(long, default_value_t = 1024)]
    proof_size: usize,
    /// Reject every proof, to exercise a consumer's reject path.
    #[arg(long)]
    reject_all: bool,
    /// Hex BLS secret key to sign proofs with. For devnets; prefer a keystore.
    #[arg(long)]
    secret_key: Option<String>,
    /// EIP-2335 keystore holding the key to sign proofs with.
    #[arg(long, requires = "keystore_password_file")]
    keystore: Option<String>,
    /// File holding the password for `--keystore`.
    #[arg(long)]
    keystore_password_file: Option<String>,
    /// Index of the validator whose key signs proofs. Must be in the registry, or consumers reject
    /// them.
    #[arg(long, default_value_t = 0)]
    validator_index: u64,
    /// Proofs to serve per payload. A consumer needs proofs from this many distinct systems.
    #[arg(long, default_value_t = 4)]
    max_proofs_per_payload: usize,
    /// Payloads to keep proofs for. Each can hold several megabytes.
    #[arg(long, default_value_t = 16)]
    cache_payloads: usize,
    /// Ethproofs requests a minute. Their quota is ten.
    #[arg(long, default_value_t = 8)]
    requests_per_minute: u32,
    /// How long to keep asking Ethproofs about a payload before giving up on it.
    #[arg(long, default_value_t = 45)]
    give_up_after_minutes: u64,
    /// How long to wait before the first poll for a payload. Nothing is proven sooner.
    #[arg(long, default_value_t = 5)]
    first_poll_after_minutes: u64,
}

struct Prover {
    secret_key: SecretKey,
    validator_index: u64,
}

/// A payload whose proofs have not turned up yet.
struct Pending {
    first_seen: Instant,
    next_poll: Instant,
    attempts: u32,
}

struct Budget {
    tokens: u32,
    per_minute: u32,
    refilled_at: Instant,
}

impl Budget {
    fn take(&mut self) -> bool {
        let elapsed = self.refilled_at.elapsed();
        if elapsed >= Duration::from_secs(60) {
            self.tokens = self.per_minute;
            self.refilled_at = Instant::now();
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Clone)]
struct Engine {
    config: Arc<Config>,
    prover: Option<Arc<Prover>>,
    http: reqwest::Client,
    /// Proofs served per payload, which is also what the verify route checks against.
    served: Arc<Mutex<LruCache<ExecutionBlockHash, Vec<ethproofs::FetchedProof>>>>,
    /// Payloads waiting on Ethproofs.
    pending: Arc<Mutex<HashMap<ExecutionBlockHash, Pending>>>,
    budget: Arc<Mutex<Budget>>,
    /// Proofs of the pinned block, in fixture mode.
    fixtures: Arc<Vec<ethproofs::FetchedProof>>,
}

impl Engine {
    /// The proofs this engine holds for `block_hash`, fetching or queueing as the source requires.
    async fn proofs_for(&self, block_hash: ExecutionBlockHash) -> Vec<(ProofType, Vec<u8>)> {
        match self.config.source {
            Source::Synthetic => (0..self.config.max_proofs_per_payload)
                .map(|proof_type| {
                    let proof_type = proof_type as ProofType;
                    (proof_type, self.synthesise(block_hash, proof_type))
                })
                .collect(),
            Source::Fixture => self
                .fixtures
                .iter()
                .map(|proof| (proof.proof_type, proof.bytes.clone()))
                .collect(),
            Source::Live => {
                if let Some(held) = self.served.lock().get(&block_hash) {
                    return held
                        .iter()
                        .map(|proof| (proof.proof_type, proof.bytes.clone()))
                        .collect();
                }
                self.queue(block_hash);
                vec![]
            }
        }
    }

    /// Put a payload on the queue, unless it is already there.
    fn queue(&self, block_hash: ExecutionBlockHash) {
        let now = Instant::now();
        self.pending.lock().entry(block_hash).or_insert_with(|| {
            println!("queued {block_hash:?}");
            Pending {
                first_seen: now,
                next_poll: now
                    + Duration::from_secs(self.config.first_poll_after_minutes.saturating_mul(60)),
                attempts: 0,
            }
        });
    }

    /// Ask Ethproofs about every queued payload that is due, within the request budget.
    async fn poll_queue(&self) {
        let give_up = Duration::from_secs(self.config.give_up_after_minutes.saturating_mul(60));
        let now = Instant::now();

        let mut due = vec![];
        {
            let mut pending = self.pending.lock();
            pending.retain(|block_hash, state| {
                if state.first_seen.elapsed() > give_up {
                    println!(
                        "giving up on {block_hash:?} after {} attempts",
                        state.attempts
                    );
                    return false;
                }
                true
            });
            for (block_hash, state) in pending.iter_mut() {
                if state.next_poll > now || !self.budget.lock().take() {
                    continue;
                }
                state.attempts += 1;
                // Back off, since a block nobody has proven in ten minutes is unlikely to be proven
                // in the next ten seconds.
                state.next_poll = now + Duration::from_secs(60 * state.attempts.min(5) as u64);
                due.push(*block_hash);
            }
        }

        for block_hash in due {
            match ethproofs::fetch_by_hash(
                &self.http,
                block_hash,
                self.config.max_proofs_per_payload,
            )
            .await
            {
                Ok(proofs) if proofs.is_empty() => {}
                Ok(proofs) => {
                    println!(
                        "fetched {} proofs for {block_hash:?}: {:?}",
                        proofs.len(),
                        proofs
                            .iter()
                            .map(|proof| (proof.proof_type, &proof.team, proof.bytes.len()))
                            .collect::<Vec<_>>()
                    );
                    self.pending.lock().remove(&block_hash);
                    self.served.lock().put(block_hash, proofs);
                }
                Err(e) => println!("ethproofs error for {block_hash:?}: {e}"),
            }
        }
    }

    /// Whether `bytes` are a proof of `block_hash` from `proof_type`.
    ///
    /// Not a zkEVM verification: this engine holds no verification keys. It answers whether the
    /// bytes are the artifact Ethproofs serves for that payload and system, which is as much as a
    /// non-verifying engine can say, and enough to keep a consumer's reject path reachable.
    async fn verifies(
        &self,
        block_hash: ExecutionBlockHash,
        proof_type: ProofType,
        bytes: &[u8],
    ) -> bool {
        if self.config.reject_all {
            return false;
        }
        if self.config.source == Source::Synthetic {
            return bytes == self.synthesise(block_hash, proof_type).as_slice();
        }
        if self.config.source == Source::Fixture {
            return self
                .fixtures
                .iter()
                .any(|proof| proof.proof_type == proof_type && proof.bytes == bytes);
        }

        if let Some(held) = self.served.lock().peek(&block_hash) {
            return held
                .iter()
                .any(|proof| proof.proof_type == proof_type && proof.bytes == bytes);
        }

        // A consumer's engine is asked about payloads it never served. Fetch them once, under the
        // same budget as the queue, and answer from that.
        if !self.budget.lock().take() {
            return false;
        }
        match ethproofs::fetch_by_hash(&self.http, block_hash, self.config.max_proofs_per_payload)
            .await
        {
            Ok(proofs) => {
                let verified = proofs
                    .iter()
                    .any(|proof| proof.proof_type == proof_type && proof.bytes == bytes);
                if !proofs.is_empty() {
                    self.served.lock().put(block_hash, proofs);
                }
                verified
            }
            Err(e) => {
                println!("ethproofs error verifying {block_hash:?}: {e}");
                false
            }
        }
    }

    fn synthesise(&self, block_hash: ExecutionBlockHash, proof_type: ProofType) -> Vec<u8> {
        let mut seed = Sha256::new();
        seed.update(SYNTHETIC_DOMAIN);
        seed.update(block_hash.into_root().as_slice());
        seed.update([proof_type]);
        let mut block = seed.finalize();

        let mut out = Vec::with_capacity(self.config.proof_size);
        while out.len() < self.config.proof_size {
            out.extend_from_slice(&block);
            block = Sha256::digest(block);
        }
        out.truncate(self.config.proof_size);
        out
    }
}

#[derive(Deserialize)]
struct ProofsQuery {
    beacon_block_root: String,
    block_hash: String,
    parent_hash: String,
    /// Signing domain, supplied by the caller so this engine needs no chain configuration.
    domain: String,
}

/// `GET /v1/execution_proofs`
///
/// An SSZ list of `SignedExecutionProof`, empty for an engine with no key, and empty until
/// Ethproofs has the payload.
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

    let (Some(beacon_root), Some(block_hash), Some(parent_hash), Some(domain)) = (
        parse_root(&query.beacon_block_root),
        parse_root(&query.block_hash),
        parse_root(&query.parent_hash),
        parse_root(&query.domain),
    ) else {
        return (StatusCode::BAD_REQUEST, Vec::new());
    };
    let block_hash = ExecutionBlockHash::from_root(block_hash);

    let proofs = engine
        .proofs_for(block_hash)
        .await
        .into_iter()
        .map(|(proof_type, bytes)| {
            let message = ExecutionProof {
                beacon_root,
                zk_proof: ZkevmProof {
                    proof_data: ProofData::new(bytes).expect("proof exceeds MAX_PROOF_SIZE"),
                    proof_type,
                    public_inputs: PublicInput {
                        block_hash,
                        parent_hash: ExecutionBlockHash::from_root(parent_hash),
                    },
                },
                validator_index: prover.validator_index,
            };
            let signing_root = SigningData {
                object_root: message.tree_hash_root(),
                domain,
            }
            .tree_hash_root();

            SignedExecutionProof {
                message,
                signature: prover.secret_key.sign(signing_root),
            }
        })
        .collect::<Vec<_>>();

    if !proofs.is_empty() {
        println!(
            "serving {} proofs for {block_hash:?} (beacon_root={beacon_root:?})",
            proofs.len()
        );
    }

    (StatusCode::OK, proofs.as_ssz_bytes())
}

#[derive(Deserialize)]
struct VerifyQuery {
    block_hash: String,
    proof_type: ProofType,
    #[allow(dead_code)]
    parent_hash: Option<String>,
    #[allow(dead_code)]
    beacon_block_root: Option<String>,
}

/// `POST /v1/execution_proof_verifications`
async fn verify(
    State(engine): State<Engine>,
    Query(query): Query<VerifyQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let valid = match parse_root(&query.block_hash) {
        Some(block_hash) => {
            engine
                .verifies(
                    ExecutionBlockHash::from_root(block_hash),
                    query.proof_type,
                    body.as_ref(),
                )
                .await
        }
        None => false,
    };

    println!(
        "verify block_hash={} type={} bytes={} -> {}",
        query.block_hash,
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

/// A 32 byte hex root, with or without the `0x`.
fn parse_root(root: &str) -> Option<Hash256> {
    let bytes = hex::decode(root.trim_start_matches("0x").to_lowercase()).ok()?;
    (bytes.len() == 32).then(|| Hash256::from_slice(&bytes))
}

fn load_key(config: &Config) -> Option<SecretKey> {
    if let Some(hex_key) = &config.secret_key {
        let bytes = hex::decode(hex_key.trim_start_matches("0x")).expect("secret key is not hex");
        return Some(SecretKey::deserialize(&bytes).expect("secret key is not a BLS key"));
    }

    let keystore_path = config.keystore.as_ref()?;
    let password_file = config
        .keystore_password_file
        .as_ref()
        .expect("--keystore requires --keystore-password-file");
    let keystore =
        eth2_keystore::Keystore::from_json_file(keystore_path).expect("cannot read keystore");
    let password = std::fs::read_to_string(password_file).expect("cannot read password file");
    Some(
        keystore
            .decrypt_keypair(password.trim_end().as_bytes())
            .expect("cannot decrypt keystore")
            .sk,
    )
}

#[tokio::main]
async fn main() {
    let config = Config::parse();
    let listen_address = config.listen_address;
    let source = config.source;
    let prover = load_key(&config).map(|secret_key| {
        Arc::new(Prover {
            secret_key,
            validator_index: config.validator_index,
        })
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("cannot build http client");

    let fixtures = match source {
        Source::Fixture => Arc::new(
            ethproofs::fetch_by_number(&http, config.fixture_block, config.max_proofs_per_payload)
                .await
                .expect("cannot fetch fixture proofs"),
        ),
        Source::Live | Source::Synthetic => Arc::new(vec![]),
    };

    let engine = Engine {
        served: Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(config.cache_payloads.max(1)).expect("non-zero"),
        ))),
        pending: Arc::new(Mutex::new(HashMap::new())),
        budget: Arc::new(Mutex::new(Budget {
            tokens: config.requests_per_minute,
            per_minute: config.requests_per_minute,
            refilled_at: Instant::now(),
        })),
        prover,
        http,
        fixtures,
        config: Arc::new(config),
    };

    if source == Source::Live {
        let queue_engine = engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(QUEUE_TICK).await;
                queue_engine.poll_queue().await;
            }
        });
    }

    let seeds = engine.prover.is_some();
    let app = Router::new()
        .route("/v1/execution_proofs", get(get_proofs))
        .route("/v1/execution_proof_verifications", post(verify))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .expect("cannot bind");
    println!(
        "proof seeder on {listen_address} (source={}, seeds={seeds})",
        match source {
            Source::Live => "live",
            Source::Fixture => "fixture",
            Source::Synthetic => "synthetic",
        }
    );
    axum::serve(listener, app).await.expect("server failed");
}
