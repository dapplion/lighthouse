//! Brings Ethproofs proofs to a proof relay.
//!
//! Ethproofs proves mainnet execution blocks. A Gloas payload commits its execution block hash in
//! the bid, so this follows the beacon chain to learn which beacon block committed which execution
//! block, asks Ethproofs for proofs of the blocks it has seen, and posts each one to a relay's
//! `POST /proofs` — the same route a proving service uses, so this gets no privileged path.
//!
//! Ethproofs has no feed, so this emulates one: a payload nobody has proven yet is polled on a
//! backoff under a request budget until its proofs appear or it ages out. The first proofs for a
//! block land about five minutes after it, so seeding is always retroactive.

mod ethproofs;

use clap::Parser;
use eth2::{BeaconNodeHttpClient, Timeouts, types::BlockId};
use ethproofs::FetchedProof;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use types::{
    ChainSpec, ConfigAndPreset, EthSpec, ExecutionBlockHash, GnosisEthSpec, Hash256,
    MainnetEthSpec, MinimalEthSpec, Slot,
};

/// How often the chain is read and the poll queue examined.
const TICK: Duration = Duration::from_secs(4);

#[derive(Parser)]
#[command(
    name = "ethproofs_bridge",
    about = "Post Ethproofs proofs to a proof relay"
)]
struct Config {
    /// Relay to post proofs to.
    #[arg(long, default_value = "http://127.0.0.1:8025")]
    relay: String,
    /// Beacon node to read the chain from.
    #[arg(long, default_value = "http://127.0.0.1:5052")]
    beacon_node: String,
    /// Proofs to post per payload.
    #[arg(long, default_value_t = 4)]
    max_proofs_per_payload: usize,
    /// Payloads to track, and the slot window read at startup.
    #[arg(long, default_value_t = 64)]
    window: usize,
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

/// A payload this bridge is working on: where it sits on the chain, what Ethproofs has said about
/// it so far, and what has already gone to the relay.
struct Tracked {
    beacon_root: Hash256,
    parent_hash: ExecutionBlockHash,
    slot: Slot,
    posted: Vec<types::execution::ProofType>,
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

struct Bridge<E: EthSpec> {
    config: Config,
    spec: ChainSpec,
    beacon_node: BeaconNodeHttpClient,
    http: reqwest::Client,
    /// Payloads in the window, by execution block hash. One entry per payload holds everything
    /// known about it, so a payload leaving the window takes its schedule with it.
    tracked: LruCache<ExecutionBlockHash, Tracked>,
    budget: Budget,
    cursor: Slot,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> Bridge<E> {
    /// Read the chain forward, learning which beacon block committed which execution block.
    ///
    /// Returns how many payloads this pass added, which is the only sign the bridge is following
    /// anything until Ethproofs has something to give.
    async fn track_payloads(&mut self) -> usize {
        let head = match self
            .beacon_node
            .get_beacon_blocks_ssz::<E>(BlockId::Head, &self.spec)
            .await
        {
            Ok(Some(head)) => head,
            Ok(None) => return 0,
            Err(e) => {
                println!("cannot read head from the beacon node: {e:?}");
                return 0;
            }
        };

        let head_slot = head.slot();
        let window = self.config.window as u64;
        let from = self
            .cursor
            .as_u64()
            .saturating_add(1)
            .max(head_slot.as_u64().saturating_sub(window));

        let mut added = 0;
        let mut read_through = from.saturating_sub(1);
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
                        // Leave the cursor behind this slot so the next pass retries it.
                        break;
                    }
                }
            };
            read_through = slot.as_u64();
            // A skipped slot, or a fork with no payload bid to read an execution block hash from.
            let Some(block) = block else { continue };
            let Ok(bid) = block.message().body().signed_execution_payload_bid() else {
                continue;
            };

            let now = Instant::now();
            let first_poll =
                Duration::from_secs(self.config.first_poll_after_minutes.saturating_mul(60));
            if self.tracked.contains(&bid.message.block_hash) {
                continue;
            }
            self.tracked.put(
                bid.message.block_hash,
                Tracked {
                    beacon_root: block.canonical_root(),
                    parent_hash: bid.message.parent_block_hash,
                    slot,
                    posted: vec![],
                    first_seen: now,
                    next_poll: now + first_poll,
                    attempts: 0,
                },
            );
            added += 1;
        }

        self.cursor = Slot::new(read_through);
        added
    }

    /// Ask Ethproofs about the payloads that are due, and post what comes back.
    async fn poll_and_post(&mut self) {
        let give_up = Duration::from_secs(self.config.give_up_after_minutes.saturating_mul(60));
        let now = Instant::now();

        let mut due = vec![];
        for (block_hash, state) in self.tracked.iter_mut() {
            if state.first_seen.elapsed() > give_up {
                continue;
            }
            if state.posted.len() >= self.config.max_proofs_per_payload || state.next_poll > now {
                continue;
            }
            if !self.budget.take() {
                break;
            }
            state.attempts += 1;
            // A block nobody has proven in ten minutes will not be proven in ten seconds.
            state.next_poll = now + Duration::from_secs(60 * state.attempts.min(5) as u64);
            due.push(*block_hash);
        }

        for block_hash in due {
            let proofs = match ethproofs::fetch_by_hash(
                &self.http,
                block_hash,
                self.config.max_proofs_per_payload,
            )
            .await
            {
                Ok(proofs) => proofs,
                Err(e) => {
                    println!("ethproofs error for {block_hash:?}: {e}");
                    continue;
                }
            };
            if proofs.is_empty() {
                continue;
            }

            for proof in proofs {
                let Some(state) = self.tracked.peek(&block_hash) else {
                    continue;
                };
                if state.posted.contains(&proof.proof_type) {
                    continue;
                }
                let (beacon_root, parent_hash, slot) =
                    (state.beacon_root, state.parent_hash, state.slot);

                match self
                    .post(block_hash, beacon_root, parent_hash, slot, &proof)
                    .await
                {
                    Ok(()) => {
                        println!(
                            "posted {} proof of {block_hash:?} (slot {slot}, type {}, {} bytes)",
                            proof.team,
                            proof.proof_type,
                            proof.bytes.len()
                        );
                        if let Some(state) = self.tracked.get_mut(&block_hash) {
                            state.posted.push(proof.proof_type);
                        }
                    }
                    Err(e) => println!("relay refused a proof of {block_hash:?}: {e}"),
                }
            }
        }
    }

    async fn post(
        &self,
        block_hash: ExecutionBlockHash,
        beacon_root: Hash256,
        parent_hash: ExecutionBlockHash,
        slot: Slot,
        proof: &FetchedProof,
    ) -> Result<(), String> {
        let response = self
            .http
            .post(format!(
                "{}/proofs",
                self.config.relay.trim_end_matches('/')
            ))
            .query(&[
                ("beacon_root", format!("{beacon_root:?}")),
                ("slot", slot.as_u64().to_string()),
                ("block_hash", format!("{block_hash:?}")),
                ("parent_hash", format!("{parent_hash:?}")),
                ("proof_type", proof.proof_type.to_string()),
            ])
            .header("content-type", "application/octet-stream")
            .body(proof.bytes.clone())
            .send()
            .await
            .map_err(|e| format!("cannot reach the relay: {e}"))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        Err(format!(
            "{status}: {}",
            response.text().await.unwrap_or_default()
        ))
    }
}

async fn run<E: EthSpec>(
    config: Config,
    chain_config: types::Config,
    beacon_node: BeaconNodeHttpClient,
) {
    let spec = ChainSpec::from_config::<E>(&chain_config)
        .expect("beacon node spec does not match its own preset");
    let window = NonZeroUsize::new(config.window.max(1)).expect("non-zero");

    let mut bridge = Bridge::<E> {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("cannot build http client"),
        tracked: LruCache::new(window),
        budget: Budget {
            tokens: config.requests_per_minute,
            per_minute: config.requests_per_minute,
            refilled_at: Instant::now(),
        },
        cursor: Slot::new(0),
        beacon_node,
        spec,
        config,
        _phantom: std::marker::PhantomData,
    };

    println!(
        "ethproofs bridge posting to {}",
        bridge.config.relay.trim_end_matches('/')
    );
    loop {
        let added = bridge.track_payloads().await;
        if added > 0 {
            println!(
                "tracking {added} more payloads, through slot {} ({} in the window)",
                bridge.cursor,
                bridge.tracked.len()
            );
        }
        bridge.poll_and_post().await;
        tokio::time::sleep(TICK).await;
    }
}

#[tokio::main]
async fn main() {
    let config = Config::parse();

    let beacon_node = BeaconNodeHttpClient::new(
        sensitive_url::SensitiveUrl::parse(&config.beacon_node)
            .expect("beacon node url is not a url"),
        Timeouts::set_all(Duration::from_secs(12)),
    );

    // Taken from the beacon node, so this bridge cannot disagree with it about the network. It
    // outlives the node's restarts, so it waits rather than exiting.
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
