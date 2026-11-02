//! Realistic fork choice persistence benchmark.
//!
//! Builds a disk-backed harness chain, inflates the proto-array vote vector to a network-sized
//! validator count, then measures:
//!
//! 1. The breakdown of `persist_fork_choice` (snapshot, SSZ encode by field, zstd, DB write).
//! 2. The real `persist_fork_choice()` call end to end.
//! 3. How long a fork choice writer waits when it contends with a persist.
//! 4. The lookahead `recompute_head_at_slot` at an epoch boundary where finality advances, which
//!    is the run block production waits on.
//!
//! Run with:
//!   FC_BENCH_VOTES=1200000 cargo bench -p beacon_chain --bench fork_choice_persist

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use beacon_chain::chain_config::FastConfirmationMode;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType, test_spec,
};
use beacon_chain::{ChainConfig, WhenSlotSkipped};
use bls::Keypair;
use ssz::Encode;
use store::database::interface::BeaconNodeBackend;
use store::{DBColumn, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::{EthSpec, Hash256, Slot, Spec};

type E = Spec;
type Harness = BeaconChainHarness<DiskHarnessType<E>>;

const HARNESS_VALIDATORS: usize = 64;
const ITERATIONS: usize = 15;

fn get_store(db_path: &TempDir) -> Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>> {
    let spec = Arc::new(test_spec::<E>());
    HotColdDB::open(
        &db_path.path().join("hot_db"),
        &db_path.path().join("cold_db"),
        &db_path.path().join("blobs_db"),
        |_, _, _| Ok(()),
        StoreConfig::default(),
        spec,
    )
    .expect("disk store should initialize")
}

/// Deterministic per-validator pseudo-random value, standing in for the committee shuffle.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Give every validator a vote from the last epoch at a shuffled slot, pointing at the canonical
/// block at that slot. About 3% of validators are offline and keep an empty vote.
fn inflate_votes(harness: &Harness, votes: usize) {
    let chain = &harness.chain;
    let head_slot = chain.head_snapshot().beacon_block.slot();
    let slots_per_epoch = E::slots_per_epoch();
    let roots: Vec<(Slot, Hash256)> = (0..slots_per_epoch)
        .map(|i| {
            let slot = head_slot.saturating_sub(i);
            let root = chain
                .block_root_at_slot(slot, WhenSlotSkipped::Prev)
                .unwrap()
                .unwrap();
            (slot, root)
        })
        .collect();

    let mut fork_choice = chain.canonical_head.fork_choice_write_lock();
    let proto_array = fork_choice.proto_array_mut();
    for validator_index in HARNESS_VALIDATORS..votes {
        let random = splitmix64(validator_index as u64);
        if random % 100 < 3 {
            continue;
        }
        let (slot, root) = roots[(random >> 32) as usize % roots.len()];
        proto_array
            .process_attestation(validator_index, root, slot, true)
            .unwrap();
    }
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn max(samples: &[Duration]) -> Duration {
    samples.iter().copied().max().unwrap_or_default()
}

fn ms(d: Duration) -> String {
    format!("{:>8.1}ms", d.as_secs_f64() * 1000.0)
}

fn row(name: &str, samples: Vec<Duration>) {
    let worst = max(&samples);
    println!(
        "{name:<44} median {}   max {}",
        ms(median(samples)),
        ms(worst)
    );
}

fn time<T>(f: impl FnOnce() -> T) -> (Duration, T) {
    let start = Instant::now();
    let out = f();
    (start.elapsed(), out)
}

fn breakdown(harness: &Harness) {
    let chain = &harness.chain;
    let store_config = chain.store.get_config();

    let mut snapshot = vec![];
    let mut encode_votes = vec![];
    let mut encode_nodes = vec![];
    let mut encode_indices = vec![];
    let mut encode_all = vec![];
    let mut compress = vec![];
    let mut write = vec![];
    let mut drop_snapshot = vec![];
    let mut encode_proto_array = vec![];
    let mut encode_fork_choice = vec![];
    let mut memcpy = vec![];
    let mut sizes = (0, 0, 0, 0, 0);

    for _ in 0..ITERATIONS {
        let (d, (fc, store)) = time(|| {
            let fork_choice = chain.canonical_head.fork_choice_read_lock();
            (
                fork_choice.to_persisted(),
                fork_choice.fc_store().to_persisted(),
            )
        });
        snapshot.push(d);

        let container = &fc.proto_array;
        let (d, votes) = time(|| container.votes.as_ssz_bytes());
        encode_votes.push(d);
        let (d, nodes) = time(|| container.nodes.as_ssz_bytes());
        encode_nodes.push(d);
        let (d, indices) = time(|| container.indices.as_ssz_bytes());
        encode_indices.push(d);
        let (d, _) = time(|| black_box(container.as_ssz_bytes()));
        encode_proto_array.push(d);
        let (d, _) = time(|| black_box(fc.as_ssz_bytes()));
        encode_fork_choice.push(d);

        // Same field order and shape as `beacon_chain::PersistedForkChoiceV29`.
        let (d, bytes) = time(|| {
            let mut buf = Vec::new();
            let mut encoder =
                ssz::SszEncoder::container(&mut buf, 2 * ssz::BYTES_PER_LENGTH_OFFSET);
            encoder.append(&fc);
            encoder.append(&store);
            encoder.finalize();
            buf
        });
        encode_all.push(d);

        // Memory bandwidth baseline: one fresh copy of the SSZ payload.
        let (d, _) = time(|| black_box(bytes.clone()));
        memcpy.push(d);

        let (d, compressed) = time(|| store_config.compress_bytes(&bytes).unwrap());
        compress.push(d);

        sizes = (
            votes.len(),
            nodes.len(),
            indices.len(),
            bytes.len(),
            compressed.len(),
        );

        let (d, ()) = time(|| {
            chain
                .store
                .hot_db
                .do_atomically(vec![KeyValueStoreOp::PutKeyValue(
                    DBColumn::ForkChoice,
                    Hash256::repeat_byte(0xbe).as_slice().to_vec(),
                    compressed,
                )])
                .unwrap()
        });
        write.push(d);

        let (d, ()) = time(|| drop(black_box((fc, store, votes, nodes, indices, bytes))));
        drop_snapshot.push(d);
    }

    let mb = |n: usize| n as f64 / 1_000_000.0;
    println!(
        "payload: votes {:.1}MB, nodes {:.2}MB ({} nodes), indices {:.2}MB, total SSZ {:.1}MB, zstd {:.1}MB",
        mb(sizes.0),
        mb(sizes.1),
        chain
            .canonical_head
            .fork_choice_read_lock()
            .proto_array()
            .len(),
        mb(sizes.2),
        mb(sizes.3),
        mb(sizes.4),
    );
    println!();
    row("snapshot (to_persisted, under read lock)", snapshot);
    row("  encode votes", encode_votes);
    row("  encode nodes", encode_nodes);
    row("  encode indices", encode_indices);
    row(
        "  encode proto_array SszContainer (1 level)",
        encode_proto_array,
    );
    row(
        "  encode fork_choice::Persisted (2 levels)",
        encode_fork_choice,
    );
    row("encode full container (3 levels, as prod)", encode_all);
    row("  baseline: one memcpy of the SSZ bytes", memcpy);
    row("zstd compress", compress);
    row("db write", write);
    row("drop snapshot + buffers", drop_snapshot);
}

fn end_to_end(harness: &Harness) {
    let chain = &harness.chain;
    let samples = (0..ITERATIONS)
        .map(|_| time(|| chain.persist_fork_choice().unwrap()).0)
        .collect();
    row("persist_fork_choice() end to end", samples);
    let samples = (0..ITERATIONS)
        .map(|_| time(|| black_box(chain.persist_fork_choice_in_batch().unwrap())).0)
        .collect();
    row("  persist_fork_choice_in_batch (no write)", samples);
}

/// A writer that takes the fork choice write lock every millisecond, like attestation batches and
/// block imports do, while the main thread persists.
fn contention(harness: &Harness) {
    let chain = harness.chain.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let stop = stop.clone();
        let chain = chain.clone();
        std::thread::spawn(move || {
            let mut waits = vec![];
            while !stop.load(Ordering::Relaxed) {
                let (d, guard) = time(|| chain.canonical_head.fork_choice_write_lock());
                drop(guard);
                waits.push(d);
                std::thread::sleep(Duration::from_millis(1));
            }
            waits
        })
    };

    std::thread::sleep(Duration::from_millis(50));
    let persists = (0..ITERATIONS)
        .map(|_| {
            let d = time(|| chain.persist_fork_choice().unwrap()).0;
            std::thread::sleep(Duration::from_millis(20));
            d
        })
        .collect();
    stop.store(true, Ordering::Relaxed);
    let waits = writer.join().unwrap();

    row("persist_fork_choice() with a contending writer", persists);
    let mut sorted = waits.clone();
    sorted.sort();
    println!(
        "{:<44} p50 {}   p99 {}   max {}   ({} acquisitions)",
        "  writer wait for write lock",
        ms(sorted[sorted.len() / 2]),
        ms(sorted[sorted.len() * 99 / 100]),
        ms(max(&waits)),
        waits.len(),
    );
}

/// The state advance timer's lookahead run at slot -0.5s, on an epoch boundary where finality
/// advances, so `after_finalization` (and its persist) runs inside it.
async fn lookahead_at_epoch_boundary(harness: &Harness, votes: usize, epochs: usize) {
    let chain = &harness.chain;
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let mut with_finality = vec![];
    let mut without_finality = vec![];

    for _ in 0..epochs {
        // Fill up to the last slot of the epoch.
        let head_slot = chain.head_snapshot().beacon_block.slot().as_usize();
        let to_epoch_end = slots_per_epoch - 1 - head_slot % slots_per_epoch;
        let blocks = if to_epoch_end == 0 {
            slots_per_epoch
        } else {
            to_epoch_end
        };
        harness.advance_slot();
        harness
            .extend_chain(
                blocks,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        inflate_votes(harness, votes);

        let next_slot = chain.head_snapshot().beacon_block.slot() + 1;
        let finalized_before = chain.head().finalized_checkpoint();
        let start = Instant::now();
        chain.recompute_head_at_slot(next_slot).await;
        let d = start.elapsed();
        if chain.head().finalized_checkpoint() != finalized_before {
            with_finality.push(d);
        } else {
            without_finality.push(d);
        }
    }

    if !with_finality.is_empty() {
        row("lookahead recompute_head, finality advanced", with_finality);
    }
    if !without_finality.is_empty() {
        row("lookahead recompute_head, no finality", without_finality);
    }
}

fn main() {
    let votes: usize = std::env::var("FC_BENCH_VOTES")
        .ok()
        .map(|v| v.parse().expect("FC_BENCH_VOTES must be a number"))
        .unwrap_or(1_200_000);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let keypairs: Vec<Keypair> =
        types::test_utils::generate_deterministic_keypairs(HARNESS_VALIDATORS);
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .chain_config(ChainConfig {
            fast_confirmation: FastConfirmationMode::Enabled,
            ..ChainConfig::default()
        })
        .keypairs(keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();
    harness.advance_slot();

    runtime.block_on(async {
        // Reach finality so the proto-array has a realistic window of nodes.
        harness
            .extend_chain(
                5 * E::slots_per_epoch() as usize - 1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
    });
    inflate_votes(&harness, votes);
    // Apply the votes so `current_*` is populated, as it is after the epoch's head runs.
    runtime.block_on(harness.chain.recompute_head_at_current_slot());

    println!("votes: {votes}, iterations: {ITERATIONS}");
    breakdown(&harness);
    println!();
    end_to_end(&harness);
    contention(&harness);
    println!();
    runtime.block_on(lookahead_at_epoch_boundary(&harness, votes, 6));
}
