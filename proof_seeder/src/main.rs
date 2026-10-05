//! A relay that signs EIP-8025 execution proofs and submits them to a beacon node.
//!
//! A proving service knows one thing about a proof: which execution block it is of. Submitting it
//! to the network takes a beacon block root, a fork's signing domain and a validator key, none of
//! which a prover should have to hold. This relay holds all three:
//!
//! - `POST /proofs?block_hash=..&proof_type=..` takes raw proof bytes, and that is the whole
//!   integration. The prover decides when; nothing here or in the beacon node drives the timing.
//! - `POST /v1/execution_proof_verifications` is the proof-engine route a consuming beacon node
//!   calls, served from the same artifacts.
//!
//! It can also fetch from Ethproofs itself, for seeding a network nobody is submitting to yet.
//!
//! Signed proofs go to `POST /eth/v1/beacon/pool/execution_proofs` on the beacon node, which
//! verifies and gossips them. Every proof carries this relay's validator index, whoever proved it.

mod ethproofs;

use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use bls::SecretKey;
use clap::{Parser, ValueEnum};
use eth2::{BeaconNodeHttpClient, Timeouts, types::BlockId};
use ethproofs::FetchedProof;
use lru::LruCache;
use parking_lot::Mutex;
use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tree_hash::TreeHash;
use types::execution::{
    ExecutionProof, ProofData, ProofType, PublicInput, SignedExecutionProof, ZkevmProof,
};
use types::{
    ChainSpec, ConfigAndPreset, Domain, EthSpec, ExecutionBlockHash, GnosisEthSpec, Hash256,
    MainnetEthSpec, MinimalEthSpec, SigningData, Slot,
};

/// Domain separator, so synthetic proofs can never be confused with anything real.
const SYNTHETIC_DOMAIN: &[u8] = b"EIP8025-SYNTHETIC-PROOF";

/// How often the chain is read and the Ethproofs queue examined.
const TICK: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Source {
    /// Only relay what is submitted to `POST /proofs`.
    None,
    /// Also fetch from Ethproofs, for the payload in question. For a network whose execution
    /// blocks are mainnet blocks.
    Live,
    /// Also serve the proofs of one pinned mainnet block, for every payload. For a devnet, whose
    /// payloads Ethproofs has never seen.
    Fixture,
    /// Also serve bytes expanded from the payload hash. No network, and two relays agree.
    Synthetic,
}

#[derive(Parser)]
#[command(name = "proof_seeder", about = "EIP-8025 execution proof relay")]
struct Config {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8025")]
    listen_address: SocketAddr,
    /// Beacon node to read the chain from and submit proofs to.
    #[arg(long, default_value = "http://127.0.0.1:5052")]
    beacon_node: String,
    /// Where proofs come from, besides what is submitted.
    #[arg(long, value_enum, default_value_t = Source::Live)]
    source: Source,
    /// Mainnet block whose proofs are served for every payload, in fixture mode.
    #[arg(long, default_value_t = 25_778_500)]
    fixture_block: u64,
    /// EIP-2335 keystore holding the key to sign proofs with.
    #[arg(long, requires = "keystore_password_file")]
    keystore: Option<String>,
    /// File holding the password for `--keystore`.
    #[arg(long)]
    keystore_password_file: Option<String>,
    /// Hex BLS key instead of a keystore. For devnets.
    #[arg(long)]
    secret_key: Option<String>,
    /// Index of the validator whose key signs proofs. Must be in the registry, or the beacon node
    /// rejects the proofs.
    #[arg(long, default_value_t = 0)]
    validator_index: u64,
    /// Size in bytes of a synthetic proof.
    #[arg(long, default_value_t = 1024)]
    proof_size: usize,
    /// Answer `INVALID` to every verification, to exercise a consumer's reject path.
    #[arg(long)]
    reject_all: bool,
    /// Proofs to submit per payload.
    #[arg(long, default_value_t = 4)]
    max_proofs_per_payload: usize,
    /// Payloads to track. Each can hold several megabytes of proofs.
    #[arg(long, default_value_t = 64)]
    cache_payloads: usize,
    /// Ethproofs requests a minute. Their quota is ten.
    #[arg(long, default_value_t = 8)]
    requests_per_minute: u32,
    /// How long to wait before asking Ethproofs about a payload. Nothing is proven sooner.
    #[arg(long, default_value_t = 5)]
    first_poll_after_minutes: u64,
    /// How long to keep asking Ethproofs about a payload before giving up on it.
    #[arg(long, default_value_t = 45)]
    give_up_after_minutes: u64,
}

struct Prover {
    secret_key: SecretKey,
    validator_index: u64,
}

/// Where a payload sits on the chain, which is what a block hash alone cannot say.
#[derive(Clone, Copy)]
struct Payload {
    beacon_root: Hash256,
    parent_hash: ExecutionBlockHash,
    slot: Slot,
}

/// A payload whose proofs Ethproofs does not have yet.
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
        if self.refilled_at.elapsed() >= Duration::from_secs(60) {
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

struct Relay<E: EthSpec> {
    config: Config,
    spec: ChainSpec,
    genesis_validators_root: Hash256,
    prover: Option<Prover>,
    beacon_node: BeaconNodeHttpClient,
    http: reqwest::Client,
    /// Payloads this relay can sign a proof of, by execution block hash.
    payloads: Mutex<LruCache<ExecutionBlockHash, Payload>>,
    /// Proofs held per payload, which is also what the verify route checks against.
    held: Mutex<LruCache<ExecutionBlockHash, Vec<FetchedProof>>>,
    /// Proofs already submitted, so a payload is not seeded twice.
    submitted: Mutex<LruCache<(ExecutionBlockHash, ProofType), ()>>,
    /// Payloads waiting on Ethproofs.
    pending: Mutex<HashMap<ExecutionBlockHash, Pending>>,
    budget: Mutex<Budget>,
    /// Proofs of the pinned block, in fixture mode.
    fixtures: Vec<FetchedProof>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Relay<E> {
    /// Read the chain forward, so a block hash can be turned into something signable.
    async fn track_payloads(&self, last_seen: &mut Slot) {
        let head = match self
            .beacon_node
            .get_beacon_blocks_ssz::<E>(BlockId::Head, &self.spec)
            .await
        {
            Ok(Some(head)) => head,
            Ok(None) => return,
            Err(e) => {
                println!("cannot read head from the beacon node: {e:?}");
                return;
            }
        };

        let head_slot = head.slot();
        let window = self.config.cache_payloads as u64;
        let from = last_seen
            .as_u64()
            .saturating_add(1)
            .max(head_slot.as_u64().saturating_sub(window));

        for slot in (from..=head_slot.as_u64()).map(Slot::new) {
            let block = if slot == head_slot {
                Some(head.clone())
            } else {
                match self
                    .beacon_node
                    .get_beacon_blocks_ssz::<E>(BlockId::Slot(slot), &self.spec)
                    .await
                {
                    Ok(block) => block,
                    Err(e) => {
                        println!("cannot read slot {slot} from the beacon node: {e:?}");
                        continue;
                    }
                }
            };
            // A skipped slot, or a fork with no payload bid to read a block hash from.
            let Some(block) = block else { continue };
            let Ok(bid) = block.message().body().signed_execution_payload_bid() else {
                continue;
            };

            self.payloads.lock().put(
                bid.message.block_hash,
                Payload {
                    beacon_root: block.canonical_root(),
                    parent_hash: bid.message.parent_block_hash,
                    slot,
                },
            );
        }

        *last_seen = head_slot;
    }

    /// Sign proofs of `block_hash` and submit them to the beacon node.
    async fn seed(
        &self,
        block_hash: ExecutionBlockHash,
        proofs: Vec<(ProofType, Vec<u8>)>,
    ) -> Result<usize, String> {
        let Some(prover) = &self.prover else {
            return Err("this relay holds no key".to_string());
        };
        let Some(payload) = self.payloads.lock().get(&block_hash).copied() else {
            return Err(format!("no payload known for {block_hash:?}"));
        };

        let fork_name = self.spec.fork_name_at_slot::<E>(payload.slot);
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            self.genesis_validators_root,
        );

        let mut signed = vec![];
        for (proof_type, bytes) in proofs {
            if self.submitted.lock().contains(&(block_hash, proof_type)) {
                continue;
            }
            let Ok(proof_data) = ProofData::new(bytes) else {
                return Err(format!(
                    "proof of {block_hash:?} type {proof_type} exceeds MAX_PROOF_SIZE"
                ));
            };

            let message = ExecutionProof {
                beacon_root: payload.beacon_root,
                zk_proof: ZkevmProof {
                    proof_data,
                    proof_type,
                    public_inputs: PublicInput {
                        block_hash,
                        parent_hash: payload.parent_hash,
                    },
                },
                validator_index: prover.validator_index,
            };
            let signing_root = SigningData {
                object_root: message.tree_hash_root(),
                domain,
            }
            .tree_hash_root();

            signed.push(SignedExecutionProof {
                message,
                signature: prover.secret_key.sign(signing_root),
            });
        }

        if signed.is_empty() {
            return Ok(0);
        }

        let proof_types = signed
            .iter()
            .map(|proof| proof.message.zk_proof.proof_type)
            .collect::<Vec<_>>();
        match self
            .beacon_node
            .post_beacon_pool_execution_proofs(&signed)
            .await
        {
            Ok(()) => {
                println!(
                    "submitted {} proofs of {block_hash:?} (slot {}, types {proof_types:?})",
                    signed.len(),
                    payload.slot
                );
                let mut submitted = self.submitted.lock();
                for proof_type in proof_types {
                    submitted.put((block_hash, proof_type), ());
                }
                Ok(signed.len())
            }
            Err(e) => Err(format!(
                "beacon node rejected proofs of {block_hash:?}: {e:?}"
            )),
        }
    }

    /// The proof systems this relay has a proof of this payload from.
    fn proof_types_for(&self, block_hash: ExecutionBlockHash) -> Vec<ProofType> {
        match self.config.source {
            Source::None => vec![],
            Source::Synthetic => (0..self.config.max_proofs_per_payload)
                .map(|proof_type| proof_type as ProofType)
                .collect(),
            Source::Fixture => self.fixtures.iter().map(|proof| proof.proof_type).collect(),
            Source::Live => self
                .held
                .lock()
                .peek(&block_hash)
                .map(|held| held.iter().map(|proof| proof.proof_type).collect())
                .unwrap_or_default(),
        }
    }

    fn proof_bytes_for(
        &self,
        block_hash: ExecutionBlockHash,
        proof_type: ProofType,
    ) -> Option<Vec<u8>> {
        match self.config.source {
            Source::None => None,
            Source::Synthetic => Some(self.synthesise(block_hash, proof_type)),
            Source::Fixture => self
                .fixtures
                .iter()
                .find(|proof| proof.proof_type == proof_type)
                .map(|proof| proof.bytes.clone()),
            Source::Live => self.held.lock().peek(&block_hash).and_then(|held| {
                held.iter()
                    .find(|proof| proof.proof_type == proof_type)
                    .map(|proof| proof.bytes.clone())
            }),
        }
    }

    /// Seed every tracked payload this relay already has proofs for.
    async fn seed_tracked_payloads(&self) {
        let block_hashes = self
            .payloads
            .lock()
            .iter()
            .map(|(block_hash, _)| *block_hash)
            .collect::<Vec<_>>();

        for block_hash in block_hashes {
            let proof_types = self
                .proof_types_for(block_hash)
                .into_iter()
                .filter(|proof_type| !self.submitted.lock().contains(&(block_hash, *proof_type)))
                .collect::<Vec<_>>();

            let proofs = proof_types
                .into_iter()
                .filter_map(|proof_type| {
                    self.proof_bytes_for(block_hash, proof_type)
                        .map(|bytes| (proof_type, bytes))
                })
                .collect::<Vec<_>>();

            if !proofs.is_empty() {
                if let Err(e) = self.seed(block_hash, proofs).await {
                    println!("{e}");
                }
            }
        }
    }

    /// Ask Ethproofs about tracked payloads that nobody has proven yet.
    async fn poll_ethproofs(&self) {
        let give_up = Duration::from_secs(self.config.give_up_after_minutes.saturating_mul(60));
        let first_poll =
            Duration::from_secs(self.config.first_poll_after_minutes.saturating_mul(60));
        let now = Instant::now();

        let untried = self
            .payloads
            .lock()
            .iter()
            .map(|(block_hash, _)| *block_hash)
            .filter(|block_hash| !self.held.lock().contains(block_hash))
            .collect::<Vec<_>>();

        let mut due = vec![];
        {
            let mut pending = self.pending.lock();
            for block_hash in untried {
                pending.entry(block_hash).or_insert_with(|| Pending {
                    first_seen: now,
                    next_poll: now + first_poll,
                    attempts: 0,
                });
            }
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
                // A block nobody has proven in ten minutes will not be proven in ten seconds.
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
                    self.held.lock().put(block_hash, proofs);
                }
                Err(e) => println!("ethproofs error for {block_hash:?}: {e}"),
            }
        }
    }

    /// Whether `bytes` are a proof of `block_hash` from `proof_type`.
    ///
    /// Not a zkEVM verification: this relay holds no verification keys. It answers whether the
    /// bytes are an artifact it holds for that payload and system, which is as much as a
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

        if let Some(held) = self.held.lock().peek(&block_hash) {
            return held
                .iter()
                .any(|proof| proof.proof_type == proof_type && proof.bytes == bytes);
        }

        // A consuming node asks about payloads this relay never seeded. Fetch them once, under the
        // same budget as the queue, and answer from that.
        if self.config.source == Source::None || !self.budget.lock().take() {
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
                    self.held.lock().put(block_hash, proofs);
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
struct ProofQuery {
    block_hash: String,
    proof_type: ProofType,
}

/// `POST /proofs?block_hash=..&proof_type=..`, body the raw proof.
///
/// What a proving service calls, on whatever schedule it likes.
async fn submit_proof<E: EthSpec>(
    State(relay): State<Arc<Relay<E>>>,
    Query(query): Query<ProofQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let Some(block_hash) = parse_root(&query.block_hash).map(ExecutionBlockHash::from_root) else {
        return (
            StatusCode::BAD_REQUEST,
            "block_hash is not a 32 byte hex root".to_string(),
        );
    };
    if relay.prover.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "this relay holds no key".to_string(),
        );
    }
    if !relay.payloads.lock().contains(&block_hash) {
        return (
            StatusCode::NOT_FOUND,
            "no payload with that block hash on the chain this relay follows".to_string(),
        );
    }

    println!(
        "offered proof of {block_hash:?} type {} ({} bytes)",
        query.proof_type,
        body.len()
    );
    match relay
        .seed(block_hash, vec![(query.proof_type, body.to_vec())])
        .await
    {
        Ok(_) => (StatusCode::ACCEPTED, String::new()),
        Err(e) => {
            println!("{e}");
            (StatusCode::BAD_GATEWAY, e)
        }
    }
}

#[derive(Deserialize)]
struct VerifyQuery {
    block_hash: String,
    proof_type: ProofType,
}

/// `POST /v1/execution_proof_verifications`, the proof-engine route a consuming node calls.
async fn verify<E: EthSpec>(
    State(relay): State<Arc<Relay<E>>>,
    Query(query): Query<VerifyQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let valid = match parse_root(&query.block_hash) {
        Some(block_hash) => {
            relay
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

async fn run<E: EthSpec>(
    config: Config,
    chain_config: types::Config,
    beacon_node: BeaconNodeHttpClient,
) {
    let spec = ChainSpec::from_config::<E>(&chain_config)
        .expect("beacon node spec does not match its own preset");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("cannot build http client");

    let genesis_validators_root = loop {
        match beacon_node.get_beacon_genesis().await {
            Ok(response) => break response.data.genesis_validators_root,
            Err(e) => {
                println!("waiting for genesis from the beacon node: {e:?}");
                tokio::time::sleep(TICK).await;
            }
        }
    };

    let fixtures = match config.source {
        Source::Fixture => {
            ethproofs::fetch_by_number(&http, config.fixture_block, config.max_proofs_per_payload)
                .await
                .expect("cannot fetch fixture proofs")
        }
        Source::Live | Source::Synthetic | Source::None => vec![],
    };

    let cache_size = NonZeroUsize::new(config.cache_payloads.max(1)).expect("non-zero");
    let listen_address = config.listen_address;
    let source = config.source;
    let relay = Arc::new(Relay::<E> {
        prover: load_key(&config).map(|secret_key| Prover {
            secret_key,
            validator_index: config.validator_index,
        }),
        payloads: Mutex::new(LruCache::new(cache_size)),
        held: Mutex::new(LruCache::new(cache_size)),
        submitted: Mutex::new(LruCache::new(
            cache_size
                .checked_mul(NonZeroUsize::new(8).expect("non-zero"))
                .expect("non-zero"),
        )),
        pending: Mutex::new(HashMap::new()),
        budget: Mutex::new(Budget {
            tokens: config.requests_per_minute,
            per_minute: config.requests_per_minute,
            refilled_at: Instant::now(),
        }),
        fixtures,
        beacon_node,
        genesis_validators_root,
        spec,
        http,
        config,
        _phantom: PhantomData,
    });

    let seeder = relay.clone();
    tokio::spawn(async move {
        let mut last_seen = Slot::new(0);
        loop {
            seeder.track_payloads(&mut last_seen).await;
            match source {
                Source::Live => seeder.poll_ethproofs().await,
                Source::Fixture | Source::Synthetic | Source::None => {}
            }
            seeder.seed_tracked_payloads().await;
            tokio::time::sleep(TICK).await;
        }
    });

    let signs = relay.prover.is_some();
    let app = Router::new()
        .route("/proofs", post(submit_proof))
        .route("/v1/execution_proof_verifications", post(verify))
        .with_state(relay);

    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .expect("cannot bind");
    println!(
        "proof relay on {listen_address} (source={}, signs={signs})",
        match source {
            Source::None => "none",
            Source::Live => "live",
            Source::Fixture => "fixture",
            Source::Synthetic => "synthetic",
        }
    );
    axum::serve(listener, app).await.expect("server failed");
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    let beacon_node = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(&config.beacon_node).expect("beacon node url is not a url"),
        Timeouts::set_all(Duration::from_secs(12)),
    );
    // Taken from the beacon node, so this relay cannot disagree with it about the network. A
    // relay outlives its node's restarts, so it waits rather than exiting.
    let chain_config = loop {
        match beacon_node.get_config_spec::<ConfigAndPreset>().await {
            Ok(response) => break response.data.config().clone(),
            Err(e) => {
                println!("waiting for the beacon node: {e:?}");
                tokio::time::sleep(TICK).await;
            }
        }
    };

    // The preset decides the spec constants, which decide how a block decodes.
    match chain_config.preset_base.as_str() {
        "mainnet" => run::<MainnetEthSpec>(config, chain_config, beacon_node).await,
        "minimal" => run::<MinimalEthSpec>(config, chain_config, beacon_node).await,
        "gnosis" => run::<GnosisEthSpec>(config, chain_config, beacon_node).await,
        preset => panic!("unsupported preset {preset}"),
    }
}
