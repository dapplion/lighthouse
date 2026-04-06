//! Benchmarks for MemoryTracker::track_item on BeaconState.
//!
//! Measures the cost of a single tree walk over states of varying validator counts.

use criterion::{Criterion, criterion_group, criterion_main};
use milhouse::mem::MemoryTracker;
use state_processing::per_slot_processing;
use std::hint::black_box;
use types::{ChainSpec, Epoch, EthSpec, Hash256, MinimalEthSpec};

type E = MinimalEthSpec;

fn make_state(n_validators: usize, advance_slots: u64) -> types::BeaconState<E> {
    let mut spec = ChainSpec::minimal();
    spec.altair_fork_epoch = Some(Epoch::new(0));

    let keypairs = types::test_utils::generate_deterministic_keypairs(n_validators);
    let mut state = genesis::interop_genesis_state::<E>(
        &keypairs,
        1_567_552_690,
        Hash256::repeat_byte(0x42),
        None,
        &spec,
    )
    .unwrap();
    state.build_caches(&spec).unwrap();

    for _ in 0..advance_slots {
        per_slot_processing(&mut state, None, &spec).unwrap();
    }
    state.apply_pending_mutations().unwrap();
    state
}

fn bench_track_single_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("track_item_single_state");

    for n in [64, 256, 1024, 4096] {
        let state = make_state(n, 0);
        group.bench_function(format!("genesis_{n}_validators"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                let stats = tracker.track_item(&state);
                black_box(stats.total_size);
            });
        });
    }

    group.finish();
}

fn bench_track_differential(c: &mut Criterion) {
    let mut group = c.benchmark_group("track_item_differential");
    let spec = {
        let mut s = ChainSpec::minimal();
        s.altair_fork_epoch = Some(Epoch::new(0));
        s
    };

    for n in [64, 256, 1024] {
        let base = make_state(n, 0);
        let slots_per_epoch = E::slots_per_epoch();

        // State advanced to epoch boundary (many dirty fields).
        let mut epoch_state = base.clone();
        for _ in 0..slots_per_epoch {
            per_slot_processing(&mut epoch_state, None, &spec).unwrap();
        }
        epoch_state.apply_pending_mutations().unwrap();

        group.bench_function(format!("epoch_boundary_{n}_validators"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                tracker.track_item(&base);
                let stats = tracker.track_item(&epoch_state);
                black_box(stats.differential_size);
            });
        });

        // State advanced 1 slot (few dirty fields).
        let mut slot_state = base.clone();
        per_slot_processing(&mut slot_state, None, &spec).unwrap();
        slot_state.apply_pending_mutations().unwrap();

        group.bench_function(format!("mid_epoch_{n}_validators"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                tracker.track_item(&base);
                let stats = tracker.track_item(&slot_state);
                black_box(stats.differential_size);
            });
        });
    }

    group.finish();
}

fn bench_pre_then_post(c: &mut Criterion) {
    let mut group = c.benchmark_group("pre_then_post_delta");
    let spec = {
        let mut s = ChainSpec::minimal();
        s.altair_fork_epoch = Some(Epoch::new(0));
        s
    };

    for n in [64, 256, 1024] {
        let pre = make_state(n, 0);

        // Process one slot.
        let mut post = pre.clone();
        per_slot_processing(&mut post, None, &spec).unwrap();
        post.apply_pending_mutations().unwrap();

        group.bench_function(format!("slot_transition_{n}_validators"), |b| {
            b.iter(|| {
                // This is the proposed approach: track pre, track post, delta = diff.
                let mut tracker = MemoryTracker::default();
                tracker.track_item(&pre);
                let pre_total = tracker.total_size();
                tracker.track_item(&post);
                let post_total = tracker.total_size();
                black_box(post_total - pre_total);
            });
        });

        // Epoch boundary transition.
        let slots_per_epoch = E::slots_per_epoch();
        let mut pre_epoch = make_state(n, slots_per_epoch - 1);
        pre_epoch.build_caches(&spec).unwrap();
        let mut post_epoch = pre_epoch.clone();
        per_slot_processing(&mut post_epoch, None, &spec).unwrap();
        post_epoch.apply_pending_mutations().unwrap();

        group.bench_function(format!("epoch_transition_{n}_validators"), |b| {
            b.iter(|| {
                let mut tracker = MemoryTracker::default();
                tracker.track_item(&pre_epoch);
                let pre_total = tracker.total_size();
                tracker.track_item(&post_epoch);
                let post_total = tracker.total_size();
                black_box(post_total - pre_total);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_track_single_state,
    bench_track_differential,
    bench_pre_then_post,
);
criterion_main!(benches);
