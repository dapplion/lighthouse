//! Signs EIP-8025 execution proofs and submits them to a beacon node.
//!
//! A proving service holds no validator key and speaks no SSZ. It posts a proof and the facts that
//! identify what the proof is of:
//!
//! ```text
//! POST /proofs?beacon_root=..&slot=..&block_hash=..&parent_hash=..&proof_type=..
//! ```
//!
//! and this signs an `ExecutionProof` over those and submits it to
//! `POST /eth/v1/beacon/pool/execution_proofs`, which verifies and gossips it.
//!
//! The prover supplies the chain facts rather than this resolving them, so there is nothing to
//! cache, follow or expire here: the only state is the signing key. Whoever proved it, every proof
//! carries this relay's validator index, and nothing here checks a proof — running it for a proving
//! service means vouching for that service.

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use bls::SecretKey;
use clap::Parser;
use eth2::{BeaconNodeHttpClient, Timeouts};
use serde::Deserialize;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tree_hash::TreeHash;
use types::execution::{
    ExecutionProof, MAX_PROOF_SIZE, ProofData, ProofType, PublicInput, SignedExecutionProof,
    ZkevmProof,
};
use types::{
    ChainSpec, ConfigAndPreset, Domain, EthSpec, ExecutionBlockHash, GnosisEthSpec, Hash256,
    MainnetEthSpec, MinimalEthSpec, SigningData, Slot,
};

/// How long to wait between attempts to reach the beacon node at startup.
const RETRY: Duration = Duration::from_secs(4);

#[derive(Parser)]
#[command(
    name = "proof_seeder",
    about = "Sign EIP-8025 execution proofs and submit them"
)]
struct Config {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8025")]
    listen_address: SocketAddr,
    /// Beacon node to submit proofs to.
    #[arg(long, default_value = "http://127.0.0.1:5052")]
    beacon_node: String,
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
}

struct Relay<E: EthSpec> {
    spec: ChainSpec,
    genesis_validators_root: Hash256,
    secret_key: SecretKey,
    validator_index: u64,
    beacon_node: BeaconNodeHttpClient,
    _phantom: PhantomData<E>,
}

/// What a prover says a proof is of.
#[derive(Deserialize)]
struct ProofQuery {
    /// Beacon block the proof vouches for.
    beacon_root: String,
    /// Slot of that block, which fixes the fork and so the signing domain.
    slot: u64,
    block_hash: String,
    parent_hash: String,
    proof_type: ProofType,
}

impl<E: EthSpec> Relay<E> {
    fn sign(
        &self,
        query: &ProofQuery,
        proof_data: ProofData,
    ) -> Result<SignedExecutionProof, String> {
        let (Some(beacon_root), Some(block_hash), Some(parent_hash)) = (
            parse_root(&query.beacon_root),
            parse_root(&query.block_hash).map(ExecutionBlockHash::from_root),
            parse_root(&query.parent_hash).map(ExecutionBlockHash::from_root),
        ) else {
            return Err("beacon_root, block_hash and parent_hash must be 32 byte hex".to_string());
        };

        let fork_name = self.spec.fork_name_at_slot::<E>(Slot::new(query.slot));
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            self.genesis_validators_root,
        );

        let message = ExecutionProof {
            beacon_root,
            zk_proof: ZkevmProof {
                proof_data,
                proof_type: query.proof_type,
                public_inputs: PublicInput {
                    block_hash,
                    parent_hash,
                },
            },
            validator_index: self.validator_index,
        };
        let signing_root = SigningData {
            object_root: message.tree_hash_root(),
            domain,
        }
        .tree_hash_root();

        Ok(SignedExecutionProof {
            message,
            signature: self.secret_key.sign(signing_root),
        })
    }
}

/// `POST /proofs`, body the raw proof.
async fn submit_proof<E: EthSpec>(
    State(relay): State<Arc<Relay<E>>>,
    Query(query): Query<ProofQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let Ok(proof_data) = ProofData::new(body.to_vec()) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("proof is longer than {MAX_PROOF_SIZE} bytes"),
        );
    };

    let signed = match relay.sign(&query, proof_data) {
        Ok(signed) => signed,
        Err(e) => return (StatusCode::BAD_REQUEST, e),
    };

    match relay
        .beacon_node
        .post_beacon_pool_execution_proofs(vec![signed])
        .await
    {
        Ok(()) => {
            println!(
                "submitted proof of {} type {} ({} bytes)",
                query.block_hash,
                query.proof_type,
                body.len()
            );
            (StatusCode::ACCEPTED, String::new())
        }
        Err(e) => {
            let reason = format!("beacon node rejected the proof: {e:?}");
            println!("{reason}");
            (StatusCode::BAD_GATEWAY, reason)
        }
    }
}

/// A 32 byte hex root, with or without the `0x`.
fn parse_root(root: &str) -> Option<Hash256> {
    let bytes = hex::decode(root.trim_start_matches("0x").to_lowercase()).ok()?;
    (bytes.len() == 32).then(|| Hash256::from_slice(&bytes))
}

fn load_key(config: &Config) -> SecretKey {
    if let Some(hex_key) = &config.secret_key {
        let bytes = hex::decode(hex_key.trim_start_matches("0x")).expect("secret key is not hex");
        return SecretKey::deserialize(&bytes).expect("secret key is not a BLS key");
    }

    let keystore_path = config
        .keystore
        .as_ref()
        .expect("either --keystore or --secret-key is required");
    let password_file = config
        .keystore_password_file
        .as_ref()
        .expect("--keystore requires --keystore-password-file");
    let keystore =
        eth2_keystore::Keystore::from_json_file(keystore_path).expect("cannot read keystore");
    let password = std::fs::read_to_string(password_file).expect("cannot read password file");
    keystore
        .decrypt_keypair(password.trim_end().as_bytes())
        .expect("cannot decrypt keystore")
        .sk
}

async fn serve<E: EthSpec>(
    config: Config,
    chain_config: types::Config,
    beacon_node: BeaconNodeHttpClient,
    genesis_validators_root: Hash256,
) {
    let spec = ChainSpec::from_config::<E>(&chain_config)
        .expect("beacon node spec does not match its own preset");

    let listen_address = config.listen_address;
    let relay = Arc::new(Relay::<E> {
        secret_key: load_key(&config),
        validator_index: config.validator_index,
        beacon_node,
        genesis_validators_root,
        spec,
        _phantom: PhantomData,
    });

    let app = Router::new()
        .route("/proofs", post(submit_proof))
        // A real proof runs to a couple of megabytes, over axum's default.
        .layer(DefaultBodyLimit::max(MAX_PROOF_SIZE.saturating_add(1024)))
        .with_state(relay);

    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .expect("cannot bind");
    println!("proof relay on {listen_address}");
    axum::serve(listener, app).await.expect("server failed");
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    let beacon_node = BeaconNodeHttpClient::new(
        sensitive_url::SensitiveUrl::parse(&config.beacon_node)
            .expect("beacon node url is not a url"),
        Timeouts::set_all(Duration::from_secs(12)),
    );

    // Taken from the beacon node, so this relay cannot disagree with it about the network. It
    // outlives the node's restarts, so it waits rather than exiting.
    let chain_config = loop {
        match beacon_node.get_config_spec::<ConfigAndPreset>().await {
            Ok(response) => break response.data.config().clone(),
            Err(e) => {
                println!("waiting for the beacon node: {e:?}");
                tokio::time::sleep(RETRY).await;
            }
        }
    };
    let genesis_validators_root = loop {
        match beacon_node.get_beacon_genesis().await {
            Ok(response) => break response.data.genesis_validators_root,
            Err(e) => {
                println!("waiting for genesis from the beacon node: {e:?}");
                tokio::time::sleep(RETRY).await;
            }
        }
    };

    // The preset decides the spec constants, which decide the fork at a slot.
    match chain_config.preset_base.as_str() {
        "mainnet" => {
            serve::<MainnetEthSpec>(config, chain_config, beacon_node, genesis_validators_root)
                .await
        }
        "minimal" => {
            serve::<MinimalEthSpec>(config, chain_config, beacon_node, genesis_validators_root)
                .await
        }
        "gnosis" => {
            serve::<GnosisEthSpec>(config, chain_config, beacon_node, genesis_validators_root).await
        }
        preset => panic!("unsupported preset {preset}"),
    }
}
