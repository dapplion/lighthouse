//! Benchmarks for state memory measurement approaches.
//!
//! Compares cow_bytes (pairwise tree walk) vs MemoryTracker at mainnet scale.

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

fn make_state(n: usize) -> BeaconState<E> {
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
    let default_cc = Arc::new(CommitteeCache::default());
    let sync = Arc::new(SyncCommittee::temporary());

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
        current_sync_committee: sync.clone(),
        next_sync_committee: sync,
        total_active_balance: None,
        progressive_balances_cache: ProgressiveBalancesCache::default(),
        committee_caches: [default_cc.clone(), default_cc.clone(), default_cc],
        pubkey_cache: PubkeyCache::default(),
        exit_cache: ExitCache::default(),
        slashings_cache: SlashingsCache::default(),
        epoch_cache: EpochCache::default(),
        approx_owned_bytes: ApproxOwnedBytesList::default(),
    })
}

fn make_slot_transition(base: &BeaconState<E>, n: usize) -> BeaconState<E> {
    let mut post = base.clone();
    // 1 proposer reward + 128 participation + roots + randao
    *post.balances_mut().get_mut(0).unwrap() += 1;
    *post.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x01);
    *post.block_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x02);
    *post.randao_mixes_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x03);
    for i in 0..128.min(n) {
        post.current_epoch_participation_mut()
            .unwrap()
            .get_mut(i)
            .unwrap()
            .add_flag(0)
            .unwrap();
    }
    post.apply_pending_mutations().unwrap();
    post
}

fn make_epoch_transition(base: &BeaconState<E>, n: usize) -> BeaconState<E> {
    let mut post = base.clone();
    // All balances + inactivity + participation replaced
    for i in 0..n {
        *post.balances_mut().get_mut(i).unwrap() += 1;
    }
    for i in 0..n {
        *post.inactivity_scores_mut().unwrap().get_mut(i).unwrap() += 1;
    }
    *post.previous_epoch_participation_mut().unwrap() =
        List::new(vec![ParticipationFlags::default(); n]).unwrap();
    *post.current_epoch_participation_mut().unwrap() =
        List::new(vec![ParticipationFlags::default(); n]).unwrap();
    post.apply_pending_mutations().unwrap();
    post
}

fn bench_cow_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("cow_bytes");
    group.sample_size(10);

    for n in [1_000_000, 2_000_000] {
        eprintln!("Building states with {n} validators...");
        let base = make_state(n);

        // Slot transition: few dirty nodes.
        let post_slot = make_slot_transition(&base, n);
        group.bench_function(format!("slot_transition_{n}"), |b| {
            b.iter(|| black_box(cow_bytes_between(&base, &post_slot)));
        });

        // Epoch transition: many dirty nodes.
        let post_epoch = make_epoch_transition(&base, n);
        group.bench_function(format!("epoch_transition_{n}"), |b| {
            b.iter(|| black_box(cow_bytes_between(&base, &post_epoch)));
        });

        // Total tree bytes (for initial finalized state).
        group.bench_function(format!("total_tree_bytes_{n}"), |b| {
            b.iter(|| black_box(total_state_tree_bytes(&base)));
        });
    }

    group.finish();
}

fn bench_tracker_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracker_comparison");
    group.sample_size(10);

    // Compare cow_bytes vs MemoryTracker at 1M validators.
    let n = 1_000_000;
    eprintln!("Building tracker comparison states ({n} validators)...");
    let base = make_state(n);
    let post_slot = make_slot_transition(&base, n);

    group.bench_function("cow_bytes_slot_1M", |b| {
        b.iter(|| black_box(cow_bytes_between(&base, &post_slot)));
    });

    group.bench_function("tracker_slot_1M", |b| {
        b.iter(|| {
            let mut tracker = MemoryTracker::default();
            tracker.track_item(&base);
            let pre = tracker.total_size();
            tracker.track_item(&post_slot);
            black_box(tracker.total_size() - pre);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_cow_bytes, bench_tracker_comparison);
criterion_main!(benches);
