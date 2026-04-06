//! Benchmarks for MemoryTracker::track_item on BeaconState.
//!
//! Measures the cost of a single tree walk over states at mainnet scale.

use criterion::{Criterion, criterion_group, criterion_main};
use fixed_bytes::FixedBytesExtended;
use milhouse::mem::MemoryTracker;
use milhouse::{List, Vector};
use ssz_types::BitVector;
use std::hint::black_box;
use std::sync::Arc;
use types::state::*;
use types::*;

type E = MainnetEthSpec;

/// Build a mainnet-scale Altair state with `n` validators.
///
/// Uses dummy values — no real keypairs needed. The tree structure and memory layout
/// are identical to a real state, which is all that matters for MemoryTracker benchmarks.
fn make_mainnet_state(n: usize) -> BeaconState<E> {
    let validator = Validator {
        pubkey: bls::PublicKeyBytes::empty(),
        withdrawal_credentials: Hash256::ZERO,
        effective_balance: 32_000_000_000,
        slashed: false,
        activation_eligibility_epoch: Epoch::new(0),
        activation_epoch: Epoch::new(0),
        exit_epoch: Epoch::new(u64::MAX),
        withdrawable_epoch: Epoch::new(u64::MAX),
    };
    let validators = List::new(vec![validator; n]).unwrap();
    let balances = List::new(vec![32_000_000_000u64; n]).unwrap();
    let inactivity_scores = List::new(vec![0u64; n]).unwrap();
    let participation = List::new(vec![ParticipationFlags::default(); n]).unwrap();
    let default_committee_cache = Arc::new(CommitteeCache::default());
    let sync_committee = Arc::new(SyncCommittee::temporary());

    BeaconState::Altair(BeaconStateAltair {
        genesis_time: 0,
        genesis_validators_root: Hash256::ZERO,
        slot: Slot::new(0),
        fork: Fork::default(),
        latest_block_header: BeaconBlockHeader::empty(),
        block_roots: Vector::default(),
        state_roots: Vector::default(),
        historical_roots: List::default(),
        eth1_data: Eth1Data::default(),
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators,
        balances,
        randao_mixes: Vector::default(),
        slashings: Vector::default(),
        previous_epoch_participation: participation.clone(),
        current_epoch_participation: participation,
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: Checkpoint::default(),
        current_justified_checkpoint: Checkpoint::default(),
        finalized_checkpoint: Checkpoint::default(),
        inactivity_scores,
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        total_active_balance: None,
        progressive_balances_cache: ProgressiveBalancesCache::default(),
        committee_caches: [
            default_committee_cache.clone(),
            default_committee_cache.clone(),
            default_committee_cache,
        ],
        pubkey_cache: PubkeyCache::default(),
        exit_cache: ExitCache::default(),
        slashings_cache: SlashingsCache::default(),
        epoch_cache: EpochCache::default(),
        approx_owned_bytes: ApproxOwnedBytesList::default(),
    })
}

fn bench_track_mainnet(c: &mut Criterion) {
    let mut group = c.benchmark_group("mainnet_track_item");
    group.sample_size(10);

    for n in [1_000_000, 2_000_000] {
        eprintln!("Building state with {n} validators...");
        let state = make_mainnet_state(n);

        // Single full walk — the cost of measuring one state from scratch.
        group.bench_function(format!("full_walk_{n}"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                let stats = tracker.track_item(&state);
                black_box(stats.total_size);
            });
        });
    }

    group.finish();
}

fn bench_pre_post_mainnet(c: &mut Criterion) {
    let mut group = c.benchmark_group("mainnet_pre_post_delta");
    group.sample_size(10);

    for n in [1_000_000, 2_000_000] {
        eprintln!("Building pre/post states with {n} validators...");
        let pre = make_mainnet_state(n);

        // Simulate a mid-epoch slot: 1 balance change, a few roots, participation.
        let mut post = pre.clone();
        *post.balances_mut().get_mut(0).unwrap() += 1;
        *post.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x01);
        *post.block_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x02);
        *post.randao_mixes_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x03);
        for i in 0..128 {
            post.current_epoch_participation_mut()
                .unwrap()
                .get_mut(i)
                .unwrap()
                .add_flag(0)
                .unwrap();
        }
        post.apply_pending_mutations().unwrap();

        // The proposed approach: track pre (expensive), then track post (cheap delta).
        group.bench_function(format!("slot_transition_{n}"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                tracker.track_item(&pre);
                let pre_total = tracker.total_size();
                tracker.track_item(&post);
                let post_total = tracker.total_size();
                black_box(post_total - pre_total);
            });
        });

        // Simulate epoch boundary: all balances + inactivity dirty.
        let mut post_epoch = pre.clone();
        for i in 0..n {
            *post_epoch.balances_mut().get_mut(i).unwrap() += 1;
        }
        for i in 0..n {
            *post_epoch
                .inactivity_scores_mut()
                .unwrap()
                .get_mut(i)
                .unwrap() += 1;
        }
        *post_epoch.previous_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        *post_epoch.current_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        post_epoch.apply_pending_mutations().unwrap();

        group.bench_function(format!("epoch_transition_{n}"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                tracker.track_item(&pre);
                let pre_total = tracker.total_size();
                tracker.track_item(&post_epoch);
                let post_total = tracker.total_size();
                black_box(post_total - pre_total);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_track_mainnet, bench_pre_post_mainnet,);
criterion_main!(benches);
