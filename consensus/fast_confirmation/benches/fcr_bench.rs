//! Benchmarks for the Fast Confirmation Rule (FCR).
//!
//! Measures performance of the core FCR algorithms at various validator set sizes
//! using a synthetic linear chain built via `ProtoArrayForkChoice`.
//!
//! All benchmarks run on `MainnetEthSpec` (32 slots/epoch). The chain spans two epochs so the
//! FCR state machine has a real epoch boundary to act on, and `get_latest_confirmed` is measured
//! at both an epoch-boundary slot and a mid-epoch slot (see `bench_get_latest_confirmed`).

use std::collections::BTreeSet;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fast_confirmation::{BalanceSourceData, CheckpointAndBalance, FastConfirmationRule};
use fixed_bytes::FixedBytesExtended;
use proto_array::core::{ProtoArray, VoteTracker};
use proto_array::{Block, ExecutionStatus, JustifiedBalances, ProtoArrayForkChoice};
use types::*;

type E = MainnetEthSpec;

const GWEI_PER_ETH: u64 = 1_000_000_000;
const BALANCE: u64 = 32 * GWEI_PER_ETH;

/// Last block in the chain (epoch 1 for MainnetEthSpec). The chain is linear: slots 0..=HEAD_SLOT.
const HEAD_SLOT: u64 = 63;
/// Epoch-1 boundary block; the FCR's current-epoch observed-justified checkpoint points here.
const OBSERVED_JUSTIFIED_SLOT: u64 = 32;
/// Recent already-confirmed block (epoch 1), so `get_latest_confirmed` runs the full precompute
/// path (`get_block_epoch(confirmed) + 1 >= current_epoch`) instead of reverting to finalized.
const CONFIRMED_SLOT: u64 = 40;

/// `current_slot` at the start of epoch 2: drives the epoch-boundary branches of
/// `get_latest_confirmed` (`is_confirmed_chain_safe`, restart-from-justified).
const EPOCH_BOUNDARY_SLOT: u64 = 64;
/// `current_slot` mid epoch 2: drives the FFG sweep (`will_no_conflicting_checkpoint_be_justified`
/// → `get_current_target_score`), which the epoch-boundary slot short-circuits.
const MID_EPOCH_SLOT: u64 = 66;

/// Deterministic block root for a given slot (linear chain): slot `s` → `s + 1`.
fn block_root_at(slot: u64) -> Hash256 {
    Hash256::from_low_u64_be(slot + 1)
}

/// All data needed to run an FCR benchmark iteration.
struct BenchData {
    proto_array: ProtoArray,
    votes: Vec<VoteTracker>,
    balance_source: BalanceSourceData,
    fcr: FastConfirmationRule,
    head_root: Hash256,
    finalized_checkpoint: Checkpoint,
    unrealized_justified_checkpoint: Checkpoint,
    equivocating_indices: BTreeSet<u64>,
    block_roots: Vec<Hash256>,
}

/// Build a synthetic two-epoch linear chain with `num_validators` voting for scattered recent
/// blocks, and an FCR seeded so `get_latest_confirmed` exercises the full per-slot work.
///
/// Chain layout (MainnetEthSpec, 32 slots/epoch):
///   genesis(slot 0) → block_1(slot 1) → ... → block_63(slot 63), head = slot 63 (epoch 1)
///   finalized = justified = genesis; current-epoch observed-justified = epoch-1 boundary (slot 32)
///   confirmed = slot 40 (epoch 1). FCR is evaluated at current slots in epoch 2.
fn build_chain(num_validators: usize) -> BenchData {
    let spec = E::default_spec();
    let slots_per_epoch = E::slots_per_epoch();
    let genesis_root = block_root_at(0);

    let genesis_checkpoint = Checkpoint {
        epoch: Epoch::new(0),
        root: genesis_root,
    };
    let observed_justified_checkpoint = Checkpoint {
        epoch: Epoch::new(1),
        root: block_root_at(OBSERVED_JUSTIFIED_SLOT),
    };
    let finalized_checkpoint = genesis_checkpoint;
    let justified_checkpoint = genesis_checkpoint;

    let shuffling_id = AttestationShufflingId::from_components(Epoch::new(0), genesis_root);

    let mut fc = ProtoArrayForkChoice::new::<E>(
        Slot::new(0),    // current_slot
        Slot::new(0),    // finalized_block_slot
        Hash256::zero(), // finalized_block_state_root
        justified_checkpoint,
        finalized_checkpoint,
        shuffling_id.clone(),
        shuffling_id.clone(),
        ExecutionStatus::irrelevant(),
        None, // execution_payload_parent_hash
        None, // execution_payload_block_hash
        0,    // proposer_index
        &spec,
    )
    .expect("create fork choice");

    let mut block_roots = vec![genesis_root];

    for slot_u in 1..=HEAD_SLOT {
        let slot = Slot::new(slot_u);
        let epoch = slot.epoch(slots_per_epoch);
        let root = block_root_at(slot_u);
        let parent_root = block_roots[(slot_u - 1) as usize];
        // Target is the block at the first slot of this block's epoch.
        let target_root = block_root_at(epoch.as_u64() * slots_per_epoch);
        // Epoch-0 blocks have nothing justified beyond genesis; epoch-1 blocks see the epoch-1
        // boundary as unrealized-justified, matching the FCR's observed-justified checkpoint.
        let unrealized_justified_checkpoint = if epoch == Epoch::new(0) {
            genesis_checkpoint
        } else {
            observed_justified_checkpoint
        };

        let block = Block {
            slot,
            root,
            parent_root: Some(parent_root),
            state_root: Hash256::zero(),
            target_root,
            current_epoch_shuffling_id: shuffling_id.clone(),
            next_epoch_shuffling_id: shuffling_id.clone(),
            justified_checkpoint,
            finalized_checkpoint,
            execution_status: ExecutionStatus::irrelevant(),
            unrealized_justified_checkpoint: Some(unrealized_justified_checkpoint),
            unrealized_finalized_checkpoint: Some(finalized_checkpoint),
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
            proposer_index: Some(0),
            payload_received: false,
        };

        fc.process_block::<E>(block, slot, &spec, Duration::from_secs(0))
            .expect("process block");

        block_roots.push(root);
    }

    let head_root = block_root_at(HEAD_SLOT);

    // Model mainnet: each validator last attested in a different recent slot, so validators vote
    // for different recent block roots, scattered by validator index. This defeats a single-entry
    // vote-root cache (the realistic case), unlike an all-vote-for-head trivial best case.
    let voteable = &block_roots[1..]; // non-genesis blocks
    for val_idx in 0..num_validators {
        let voted = voteable[val_idx % voteable.len()];
        fc.process_attestation(val_idx, voted, Slot::new(0), false)
            .expect("process attestation");
    }

    // Materialize votes: find_head swaps next_root → current_root in VoteTrackers.
    let balances = JustifiedBalances::from_effective_balances(vec![BALANCE; num_validators])
        .expect("justified balances");

    fc.find_head::<E>(
        justified_checkpoint,
        finalized_checkpoint,
        &balances,
        Hash256::zero(), // no proposer boost
        &BTreeSet::new(),
        Slot::new(EPOCH_BOUNDARY_SLOT),
        &spec,
    )
    .expect("find head");

    let proto_array = fc.core_proto_array().clone();
    let votes = fc.votes().to_vec();

    let total_active_balance = BALANCE.saturating_mul(num_validators as u64);
    let balance_source = BalanceSourceData {
        dependent_root: observed_justified_checkpoint.root,
        total_active_balance,
        effective_balances: vec![BALANCE; num_validators],
        slashed: vec![false; num_validators],
    };

    // Build FCR state. `new` builds head assignments/balances from the state; the bench overwrites
    // balances and the slot-tracking variables below, so a small committee-cache-ready state
    // suffices (its assignments aren't on the O(V) cost path).
    let mut seed_state = BeaconState::<E>::new(0, Default::default(), &spec);
    for _ in 0..E::slots_per_epoch() {
        seed_state
            .validators_mut()
            .push(Validator {
                effective_balance: spec.max_effective_balance,
                activation_epoch: Epoch::new(0),
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            })
            .expect("push validator");
        seed_state
            .balances_mut()
            .push(spec.max_effective_balance)
            .expect("push balance");
    }
    for relative_epoch in [
        RelativeEpoch::Previous,
        RelativeEpoch::Current,
        RelativeEpoch::Next,
    ] {
        seed_state
            .build_committee_cache(relative_epoch, &spec)
            .expect("committee cache");
    }
    let mut fcr = FastConfirmationRule::new(finalized_checkpoint, &seed_state, 25, 40)
        .expect("fcr initialization");
    fcr.previous_slot_head = head_root;
    fcr.current_slot_head = head_root;
    fcr.confirmed_root = block_root_at(CONFIRMED_SLOT);
    fcr.test_set_head_balance_source(balance_source.clone());
    fcr.current_epoch_observed_justified =
        CheckpointAndBalance::new(observed_justified_checkpoint, balance_source.clone());
    fcr.previous_epoch_observed_justified =
        CheckpointAndBalance::new(genesis_checkpoint, balance_source.clone());

    BenchData {
        proto_array,
        votes,
        balance_source,
        fcr,
        head_root,
        finalized_checkpoint,
        unrealized_justified_checkpoint: observed_justified_checkpoint,
        equivocating_indices: BTreeSet::new(),
        block_roots,
    }
}

const VALIDATOR_SET_SIZES: [usize; 5] = [64, 16_000, 100_000, 500_000, 1_000_000];

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// FFG scoring function: counts target checkpoint support. This is the epoch-boundary FFG sweep
/// (`get_current_target_score`); its cost is O(V) regardless of the current slot.
fn bench_get_current_target_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_current_target_score");

    for &n in &VALIDATOR_SET_SIZES {
        let data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_current_target_score::<E>(
                    data.head_root,
                    Slot::new(EPOCH_BOUNDARY_SLOT),
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// Batch precomputation of attestation scores for the full chain. Runs on every FCR tick; its
/// cost is O(V × depth) regardless of the current slot.
fn bench_precompute_chain_scores(c: &mut Criterion) {
    let mut group = c.benchmark_group("precompute_chain_scores");

    for &n in &VALIDATOR_SET_SIZES {
        let data = build_chain(n);
        let genesis_root = data.block_roots[0];
        // `block_roots[1..]` is exactly `get_ancestor_roots(head, genesis)` for this linear chain.
        let terminal_slot = data
            .proto_array
            .block_slot(genesis_root)
            .expect("genesis in proto array");

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                fast_confirmation::optimizations::precompute_chain_attestation_scores(
                    &data.proto_array,
                    &data.block_roots[1..],
                    terminal_slot,
                    &data.balance_source,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// Full confirmation algorithm (the complete production code path), measured at both an
/// epoch-boundary current slot and a mid-epoch current slot. The boundary slot drives
/// `is_confirmed_chain_safe`/restart-from-justified while short-circuiting the FFG sweep; the
/// mid-epoch slot drives the FFG sweep instead. Both run the O(V × depth) precompute.
fn bench_get_latest_confirmed(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_latest_confirmed");

    for &n in &VALIDATOR_SET_SIZES {
        let data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        for (slot_context, current_slot) in [
            ("epoch_boundary", EPOCH_BOUNDARY_SLOT),
            ("mid_epoch", MID_EPOCH_SLOT),
        ] {
            group.bench_with_input(BenchmarkId::new(slot_context, n), &n, |b, _| {
                b.iter(|| {
                    data.fcr.get_latest_confirmed::<E>(
                        data.head_root,
                        &data.finalized_checkpoint,
                        &data.unrealized_justified_checkpoint,
                        Slot::new(current_slot),
                        &data.proto_array,
                        &data.votes,
                        &data.equivocating_indices,
                    )
                })
            });
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_get_current_target_score,
    bench_precompute_chain_scores,
    bench_get_latest_confirmed,
);
criterion_main!(benches);
