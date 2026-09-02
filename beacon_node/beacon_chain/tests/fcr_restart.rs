#![cfg(not(debug_assertions))]

//! The Fast Confirmation Rule (FCR) `confirmed_root` must not move backwards across a beacon node
//! restart. It is published as the `fast_confirmation` event and as the engine `safeBlockHash`, so
//! a node that rewinds it on every boot rewinds an EL's `safe` tag with it.
//!
//! The restart here is a real one: the chain is persisted to a disk store and then rebuilt with
//! `BeaconChainBuilder::resume_from_db`, which is the production boot path, so the resumed chain's
//! FCR state comes entirely from the database. No part of the rule itself is persisted —
//! `CanonicalHead::new` rebuilds it from the checkpoint fork choice was restored with.
//!
//! Seeding that rebuild from `finalized_checkpoint` used to drop the confirmed root by ~2 epochs
//! and leave it there: the advance path in `get_latest_confirmed` is gated on
//! `get_block_epoch(confirmed_root) + 1 >= current_epoch`, which the finalized root cannot satisfy,
//! so the only way back was the "restart the confirmation chain" branch at the first slot of an
//! epoch — one epoch later, or two when the epoch containing the restart failed to justify.

use beacon_chain::{
    BeaconChain, BeaconChainTypes, ChainConfig,
    chain_config::FastConfirmationMode,
    test_utils::{BeaconChainHarness, DiskHarnessType, test_spec},
};
use bls::Keypair;
use std::sync::{Arc, LazyLock};
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::{ChainSpec, EthSpec, Hash256, MinimalEthSpec, Slot};

type E = MinimalEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;

const VALIDATOR_COUNT: usize = 64;
/// Slots built before the restart is considered. Enough for the chain to be justifying and
/// finalizing, and for FCR to have reached its steady state.
const WARMUP_SLOTS: u64 = 5 * 8;
/// Slots observed after the restart (`MinimalEthSpec` has 8 slots per epoch).
const SLOTS_AFTER_RESTART: u64 = 3 * 8;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn chain_config() -> ChainConfig {
    ChainConfig {
        fast_confirmation: FastConfirmationMode::Enabled,
        ..ChainConfig::default()
    }
}

fn get_store(
    db_path: &TempDir,
    spec: ChainSpec,
) -> Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>> {
    HotColdDB::open(
        &db_path.path().join("chain_db"),
        &db_path.path().join("freezer_db"),
        &db_path.path().join("blobs_db"),
        |_, _, _| Ok(()),
        StoreConfig {
            prune_payloads: false,
            ..StoreConfig::default()
        },
        spec.into(),
    )
    .expect("disk store should initialize")
}

fn fresh_harness(store: Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>>) -> TestHarness {
    let harness = TestHarness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec())
        .fresh_disk_store(store)
        .mock_execution_layer()
        .chain_config(chain_config())
        .build();
    harness.advance_slot();
    harness
}

/// Shut the node down and boot it again from the same database, the way an operator restart does.
///
/// The returned harness is built by `resume_from_db`, so its chain — and therefore its FCR state —
/// comes entirely from the database. The old harness is kept alive by the caller only because it
/// owns the mock execution engine the new chain talks to; nothing drives it any more.
fn restart_harness(
    store: Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>>,
    old: &TestHarness,
) -> TestHarness {
    old.chain
        .persist_fork_choice()
        .expect("should persist fork choice");
    old.chain
        .persist_op_pool()
        .expect("should persist the op pool");

    let slot_clock = old.chain.slot_clock.clone();
    let execution_layer = old.chain.execution_layer.clone();

    TestHarness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec())
        .resumed_disk_store(store)
        .testing_slot_clock(slot_clock)
        .execution_layer(execution_layer)
        .chain_config(chain_config())
        .build()
}

struct Sample {
    current_slot: Slot,
    head_slot: Slot,
    confirmed_slot: Slot,
    confirmed_root: Hash256,
    finalized_root: Hash256,
}

impl Sample {
    fn delay(&self) -> u64 {
        self.current_slot
            .as_u64()
            .saturating_sub(self.confirmed_slot.as_u64())
    }
}

fn sample<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Sample {
    let cached_head = chain.canonical_head.cached_head();
    let confirmed_root = chain
        .canonical_head
        .fast_confirmation
        .as_ref()
        .expect("FCR enabled")
        .lock()
        .confirmed_root;
    let confirmed_slot = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&confirmed_root)
        .expect("confirmed block in fork choice")
        .slot;
    Sample {
        current_slot: chain.slot().unwrap(),
        head_slot: cached_head.head_slot(),
        confirmed_slot,
        confirmed_root,
        finalized_root: cached_head.finalized_checkpoint().root,
    }
}

/// One slot, in the order a running node does it: the slot tick fires `recompute_head` first (so
/// FCR's once-per-slot update sees only what arrived in earlier slots), then the block and its
/// attestations land and the head is recomputed again.
/// The key property: a restart must not walk the confirmed root backwards.
///
/// `confirmed_root` is monotonic along the canonical chain — that is the whole point of confirming
/// a block, and both the `fast_confirmation` event and the engine `safeBlockHash` publish it.
fn assert_confirmed_root_did_not_regress(before: &Sample, after: &Sample) {
    assert!(
        after.confirmed_slot >= before.confirmed_slot,
        "the confirmed root went backwards across the restart: it was slot {} before and is \
         slot {} after",
        before.confirmed_slot,
        after.confirmed_slot
    );
    // Standing still at the same slot must mean the very same block, not a same-height sibling.
    if after.confirmed_slot == before.confirmed_slot {
        assert_eq!(
            after.confirmed_root, before.confirmed_root,
            "the confirmed root changed to a different block at the same slot {}",
            before.confirmed_slot
        );
    }
}

/// The confirmed root never goes backwards over a run of samples either, so a restart cannot be
/// papered over by recovering a slot later.
fn assert_confirmed_root_never_regresses(first: &Sample, timeline: &[Sample]) {
    let mut previous = first;
    for sample in timeline {
        assert!(
            sample.confirmed_slot >= previous.confirmed_slot,
            "the confirmed root went backwards at slot {}: was slot {}, now slot {}",
            sample.current_slot,
            previous.confirmed_slot,
            sample.confirmed_slot
        );
        if sample.confirmed_slot == previous.confirmed_slot {
            assert_eq!(
                sample.confirmed_root, previous.confirmed_root,
                "the confirmed root changed to a different block at the same slot {}",
                previous.confirmed_slot
            );
        }
        previous = sample;
    }
}

async fn build_slot(harness: &TestHarness) {
    build_slot_attested_by(harness, None).await
}

/// As `build_slot`, but only `attesters` attest. `None` means every validator.
async fn build_slot_attested_by(harness: &TestHarness, attesters: Option<&[usize]>) {
    harness.advance_slot();
    harness.chain.recompute_head_at_current_slot().await;
    match attesters {
        None => harness.extend_slots(1).await,
        Some(attesters) => {
            harness
                .extend_slots_some_validators(1, attesters.to_vec())
                .await
        }
    };
    harness.chain.recompute_head_at_current_slot().await;
}

/// Build a chain to a steady state, restart the node at `restart_slot_in_epoch`, and check the
/// confirmed root across and after the restart.
async fn restart_at_slot_in_epoch(restart_slot_in_epoch: u64) {
    let db_path = tempdir().expect("temp dir");
    let store = get_store(&db_path, test_spec::<E>());
    let harness = fresh_harness(store.clone());

    for _ in 0..WARMUP_SLOTS {
        build_slot(&harness).await;
    }
    // Advance to the requested position within an epoch before restarting.
    while harness.chain.slot().unwrap().as_u64() % E::slots_per_epoch() != restart_slot_in_epoch {
        build_slot(&harness).await;
    }

    let before = sample(&harness.chain);
    assert!(
        before.delay() <= 1,
        "chain should be in a steady state before the restart, delay was {} \
         (current slot {}, confirmed slot {})",
        before.delay(),
        before.current_slot,
        before.confirmed_slot
    );

    let old_harness = harness;
    let harness = restart_harness(store, &old_harness);
    harness.chain.recompute_head_at_current_slot().await;

    // THE KEY PROPERTY. A block, once confirmed, stays confirmed: rebooting the node must not
    // announce an older confirmed root than the one it announced a slot earlier.
    let after = sample(&harness.chain);
    assert_confirmed_root_did_not_regress(&before, &after);

    let mut timeline = Vec::new();
    for _ in 0..SLOTS_AFTER_RESTART {
        build_slot(&harness).await;
        timeline.push(sample(&harness.chain));
    }

    println!(
        "=== restart at slot_in_epoch {} ({} slots per epoch) ===",
        restart_slot_in_epoch,
        E::slots_per_epoch()
    );
    println!(
        "before restart:  current_slot={} head_slot={} confirmed_slot={} delay={}",
        before.current_slot,
        before.head_slot,
        before.confirmed_slot,
        before.delay()
    );
    println!(
        "after restart:   current_slot={} confirmed_slot={} delay={}",
        after.current_slot,
        after.confirmed_slot,
        after.delay()
    );
    for s in &timeline {
        println!(
            "  slot {:>3} (epoch {:>2}, slot_in_epoch {}) head={:>3} confirmed={:>3} delay={:>3}{}",
            s.current_slot,
            s.current_slot.epoch(E::slots_per_epoch()),
            s.current_slot.as_u64() % E::slots_per_epoch(),
            s.head_slot,
            s.confirmed_slot,
            s.delay(),
            if s.confirmed_root == s.finalized_root {
                "  <- at finalized"
            } else {
                ""
            }
        );
    }

    assert_confirmed_root_never_regresses(&after, &timeline);
    assert!(
        after.delay() <= 1,
        "the restart should not cost any confirmation delay, delay was {}",
        after.delay()
    );
    assert!(
        timeline.iter().all(|s| s.delay() <= 1),
        "the chain should stay at its steady-state confirmation delay after the restart"
    );

    drop(old_harness);
}

/// A restart in the middle of an epoch.
#[tokio::test]
async fn confirmed_root_survives_a_restart_mid_epoch() {
    restart_at_slot_in_epoch(4).await;
}

/// Restarting on the first slot of an epoch. This used to be the worst case: the epoch-boundary
/// rotation runs on this very slot, but over freshly seeded state it is a no-op, so recovery had to
/// wait a further full epoch.
#[tokio::test]
async fn confirmed_root_survives_a_restart_on_an_epoch_boundary() {
    restart_at_slot_in_epoch(0).await;
}

/// Restarting on the last slot of an epoch.
#[tokio::test]
async fn confirmed_root_survives_a_restart_at_the_end_of_an_epoch() {
    restart_at_slot_in_epoch(E::slots_per_epoch() - 1).await;
}

/// The devnet case, where recovery used to miss the first epoch boundary entirely and cost two.
///
/// The rotation at the first slot of an epoch installs
/// `previous_epoch_greatest_unrealized_checkpoint`, which FCR snapshots at the *last slot of the
/// previous epoch*. If that epoch has not been unrealized-justified by then, the rotation installs
/// a checkpoint whose block is two epochs back and the restart branch's
/// `observed_justified_block_slot.epoch + 1 == current_epoch` fails, so a confirmed root that
/// depends on that branch is stuck for another whole epoch.
///
/// Here the epoch containing the restart is driven with no attestations at all, so it cannot be
/// justified under any fork's weighting; participation is restored for the following epoch.
#[tokio::test]
async fn confirmed_root_survives_a_restart_when_the_restart_epoch_does_not_justify() {
    let restart_slot_in_epoch = 4;
    let db_path = tempdir().expect("temp dir");
    let store = get_store(&db_path, test_spec::<E>());
    let harness = fresh_harness(store.clone());

    for _ in 0..WARMUP_SLOTS {
        build_slot(&harness).await;
    }
    while harness.chain.slot().unwrap().as_u64() % E::slots_per_epoch() != restart_slot_in_epoch {
        build_slot(&harness).await;
    }

    let before = sample(&harness.chain);
    assert!(
        before.delay() <= 1,
        "chain should be in a steady state before the restart, delay was {}",
        before.delay()
    );

    let old_harness = harness;
    let harness = restart_harness(store, &old_harness);
    harness.chain.recompute_head_at_current_slot().await;

    let after = sample(&harness.chain);
    assert_confirmed_root_did_not_regress(&before, &after);

    // No attesters at all, so the restart epoch's target cannot reach the 2/3 justification
    // threshold. A partial set would work too, but the fraction that keeps an epoch unjustified
    // depends on the fork's attestation weighting, and this does not.
    let no_attesters: Vec<usize> = vec![];
    let restart_epoch = after.current_slot.epoch(E::slots_per_epoch());
    let mut timeline = Vec::new();

    for _ in 0..SLOTS_AFTER_RESTART {
        // No participation for the rest of the restart epoch, full participation afterwards.
        let in_restart_epoch =
            harness.chain.slot().unwrap().epoch(E::slots_per_epoch()) == restart_epoch;
        let attesters = in_restart_epoch.then_some(no_attesters.as_slice());
        build_slot_attested_by(&harness, attesters).await;
        timeline.push(sample(&harness.chain));
    }

    println!(
        "=== restart at slot_in_epoch {}, restart epoch left unjustified ===",
        restart_slot_in_epoch
    );
    println!(
        "before restart:  current_slot={} confirmed_slot={} delay={}",
        before.current_slot,
        before.confirmed_slot,
        before.delay()
    );
    println!(
        "after restart:   current_slot={} confirmed_slot={} delay={}",
        after.current_slot,
        after.confirmed_slot,
        after.delay()
    );
    for s in &timeline {
        println!(
            "  slot {:>3} (epoch {:>2}, slot_in_epoch {}) head={:>3} confirmed={:>3} delay={:>3}{}",
            s.current_slot,
            s.current_slot.epoch(E::slots_per_epoch()),
            s.current_slot.as_u64() % E::slots_per_epoch(),
            s.head_slot,
            s.confirmed_slot,
            s.delay(),
            if s.confirmed_root == s.finalized_root {
                "  <- pinned to finalized"
            } else {
                ""
            }
        );
    }

    // Note that the timeline is *not* monotonic here, and should not be: an epoch with no
    // attestations cannot be re-confirmed, so `is_confirmed_chain_safe` fails at the next epoch
    // boundary and the confirmed root drops to finalized. That revert is the spec's safety
    // behaviour and has nothing to do with the restart — see the control test below, which
    // reproduces it with no restart at all. What matters here is that the restart itself cost
    // nothing, and that confirmation returns once participation does.
    let last = timeline.last().expect("timeline is not empty");
    assert!(
        last.delay() <= 1,
        "confirmation should be back to its steady-state delay once participation returns, \
         delay was {}",
        last.delay()
    );

    drop(old_harness);
}

/// Control for `confirmed_root_survives_a_restart_when_the_restart_epoch_does_not_justify`: an
/// epoch with no attestations walks the confirmed root back to the finalized root at the next
/// epoch boundary on its own, with no restart involved. That revert is
/// `is_confirmed_chain_safe` refusing to re-confirm a chain nobody voted for, and it is why the
/// unjustified-epoch scenario above cannot assert a monotonic timeline.
#[tokio::test]
async fn an_unattested_epoch_reverts_the_confirmed_root_without_any_restart() {
    let db_path = tempdir().expect("temp dir");
    let store = get_store(&db_path, test_spec::<E>());
    let harness = fresh_harness(store);

    for _ in 0..WARMUP_SLOTS {
        build_slot(&harness).await;
    }
    while harness.chain.slot().unwrap().as_u64() % E::slots_per_epoch() != 4 {
        build_slot(&harness).await;
    }

    let before = sample(&harness.chain);
    assert!(
        before.delay() <= 1,
        "chain should be in a steady state first, delay was {}",
        before.delay()
    );

    let no_attesters: Vec<usize> = vec![];
    let quiet_epoch = before.current_slot.epoch(E::slots_per_epoch());
    let mut timeline = Vec::new();
    for _ in 0..E::slots_per_epoch() {
        let in_quiet_epoch =
            harness.chain.slot().unwrap().epoch(E::slots_per_epoch()) == quiet_epoch;
        build_slot_attested_by(&harness, in_quiet_epoch.then_some(no_attesters.as_slice())).await;
        timeline.push(sample(&harness.chain));
    }

    println!("=== an unattested epoch, no restart ===");
    for s in &timeline {
        println!(
            "  slot {:>3} (slot_in_epoch {}) confirmed={:>3} delay={:>3}{}",
            s.current_slot,
            s.current_slot.as_u64() % E::slots_per_epoch(),
            s.confirmed_slot,
            s.delay(),
            if s.confirmed_root == s.finalized_root {
                "  <- at finalized"
            } else {
                ""
            }
        );
    }

    let reverted = timeline
        .iter()
        .find(|s| s.confirmed_root == s.finalized_root)
        .expect("an unattested epoch should send the confirmed root back to finalized");
    assert!(
        reverted.confirmed_slot < before.confirmed_slot,
        "the revert should move the confirmed root backwards"
    );
    assert_eq!(
        reverted.current_slot.as_u64() % E::slots_per_epoch(),
        0,
        "the revert happens at the epoch boundary, where the chain is re-confirmed"
    );
}
