#![cfg(not(debug_assertions))]

//! Reproduction of the Fast Confirmation Rule (FCR) `confirmed_root` regression across a beacon
//! node restart.
//!
//! The restart here is a real one: the chain is persisted to a disk store and then rebuilt with
//! `BeaconChainBuilder::resume_from_db`, which is the production boot path. That path runs
//! `CanonicalHead::new`, which rebuilds the rule from `finalized_checkpoint` — no part of the FCR
//! state is persisted, so a restart replaces a `confirmed_root` that was tracking the head with the
//! finalized root.
//!
//! From there the advance path in `get_latest_confirmed` is gated on
//! `get_block_epoch(confirmed_root) + 1 >= current_epoch`, which the finalized root cannot satisfy,
//! so the only way back is the "restart the confirmation chain" branch at the first slot of an
//! epoch.

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
/// The key property: a restart makes the confirmed root go backwards.
///
/// `confirmed_root` is supposed to be monotonic along the canonical chain — that is the whole point
/// of confirming a block, and it is what the `fast_confirmation` event and the engine
/// `safeBlockHash` both publish. Returns how many slots of confirmed chain the restart threw away.
fn assert_confirmed_root_regressed(before: &Sample, after: &Sample) -> u64 {
    assert!(
        after.confirmed_slot < before.confirmed_slot,
        "the confirmed root must go backwards across a restart: it was slot {} before and is \
         slot {} after",
        before.confirmed_slot,
        after.confirmed_slot
    );
    assert_eq!(
        after.confirmed_root, after.finalized_root,
        "the restart drops the confirmed root all the way back to the finalized root"
    );
    let regression = before.confirmed_slot.as_u64() - after.confirmed_slot.as_u64();
    assert!(
        regression >= E::slots_per_epoch(),
        "the restart should throw away at least a whole epoch of confirmed chain, threw away {} \
         slots",
        regression
    );
    regression
}

/// The regression persists: the confirmed root stays behind its pre-restart value until an epoch
/// boundary, since the "restart the confirmation chain" branch is the only way back and it only
/// runs at the first slot of an epoch. Returns how many slots that took.
fn assert_regression_lasts_until_an_epoch_boundary(
    restart_slot: Slot,
    recovered_at: Option<Slot>,
) -> u64 {
    let recovered_at = recovered_at
        .expect("the confirmed root should eventually get back to where it was before the restart");
    assert!(
        recovered_at > restart_slot,
        "the confirmed root cannot recover on the restart slot itself"
    );
    assert_eq!(
        recovered_at.as_u64() % E::slots_per_epoch(),
        0,
        "the confirmed root can only recover at the first slot of an epoch, recovered at slot {}",
        recovered_at
    );
    recovered_at.as_u64() - restart_slot.as_u64()
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

/// Build a chain, restart the node at `restart_slot_in_epoch`, and report what the confirmed root
/// does afterwards.
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

    // THE REGRESSION. The confirmed root is meant to be monotonic: a block, once confirmed, stays
    // confirmed. A restart breaks that — the announced confirmed root moves backwards.
    let after = sample(&harness.chain);
    let regression = assert_confirmed_root_regressed(&before, &after);

    let restart_slot = after.current_slot;
    let mut recovered_at = None;
    let mut timeline = Vec::new();

    for _ in 0..SLOTS_AFTER_RESTART {
        build_slot(&harness).await;
        let s = sample(&harness.chain);
        if recovered_at.is_none() && s.confirmed_slot >= before.confirmed_slot {
            recovered_at = Some(s.current_slot);
        }
        timeline.push(s);
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
        "after restart:   current_slot={} confirmed_slot={} delay={} (regressed {} slots)",
        after.current_slot,
        after.confirmed_slot,
        after.delay(),
        regression
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

    // The regression is not transient: it lasts until the next epoch boundary, because that is
    // where the only recovery path lives.
    let regressed_for = assert_regression_lasts_until_an_epoch_boundary(restart_slot, recovered_at);
    println!(
        "confirmed root regressed {} slots and stayed behind its pre-restart value for {} slots",
        regression, regressed_for
    );
    assert_eq!(
        regressed_for,
        E::slots_per_epoch() - restart_slot_in_epoch,
        "the regression should last exactly until the next epoch boundary"
    );

    drop(old_harness);
}

/// A restart in the middle of an epoch: the confirmed root falls back to the finalized root and
/// stays there until an epoch boundary.
#[tokio::test]
async fn confirmed_root_regresses_across_a_restart_mid_epoch() {
    restart_at_slot_in_epoch(4).await;
}

/// Restarting on the first slot of an epoch costs a whole epoch, because
/// `previous_epoch_greatest_unrealized_checkpoint` is only written at the *last* slot of an epoch,
/// so the rotation that runs on this very slot is a no-op over freshly seeded state.
#[tokio::test]
async fn confirmed_root_regresses_across_a_restart_on_an_epoch_boundary() {
    restart_at_slot_in_epoch(0).await;
}

/// Restarting on the last slot of an epoch is the best case: the boundary is one slot away.
#[tokio::test]
async fn confirmed_root_regresses_across_a_restart_at_the_end_of_an_epoch() {
    restart_at_slot_in_epoch(E::slots_per_epoch() - 1).await;
}

/// The devnet case: recovery misses the first epoch boundary entirely and costs two.
///
/// The rotation at the first slot of an epoch installs
/// `previous_epoch_greatest_unrealized_checkpoint`, which FCR snapshots at the *last slot of the
/// previous epoch*. If that epoch has not been unrealized-justified by then, the rotation installs
/// a checkpoint whose block is two epochs back, the restart branch's
/// `observed_justified_block_slot.epoch + 1 == current_epoch` fails, and the confirmed root stays
/// pinned to the finalized root for another whole epoch.
///
/// Here the epoch containing the restart is driven with no attestations at all, so it cannot be
/// justified under any fork's weighting; participation is restored for the following epoch.
#[tokio::test]
async fn recovery_slips_a_second_epoch_when_the_restart_epoch_does_not_justify() {
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
    let regression = assert_confirmed_root_regressed(&before, &after);

    // No attesters at all, so the restart epoch's target cannot reach the 2/3 justification
    // threshold. A partial set would work too, but the fraction that keeps an epoch unjustified
    // depends on the fork's attestation weighting, and this does not.
    let no_attesters: Vec<usize> = vec![];
    let restart_slot = after.current_slot;
    let restart_epoch = restart_slot.epoch(E::slots_per_epoch());
    let mut recovered_at = None;
    let mut timeline = Vec::new();

    for _ in 0..SLOTS_AFTER_RESTART {
        // No participation for the rest of the restart epoch, full participation afterwards.
        let in_restart_epoch =
            harness.chain.slot().unwrap().epoch(E::slots_per_epoch()) == restart_epoch;
        let attesters = in_restart_epoch.then_some(no_attesters.as_slice());
        build_slot_attested_by(&harness, attesters).await;
        let s = sample(&harness.chain);
        if recovered_at.is_none() && s.confirmed_slot >= before.confirmed_slot {
            recovered_at = Some(s.current_slot);
        }
        timeline.push(s);
    }

    println!(
        "=== restart at slot_in_epoch {}, restart epoch is left unjustified ===",
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

    let regressed_for = assert_regression_lasts_until_an_epoch_boundary(restart_slot, recovered_at);
    let rest_of_restart_epoch = E::slots_per_epoch() - restart_slot_in_epoch;
    println!(
        "confirmed root regressed {} slots and stayed behind its pre-restart value for {} slots \
         ({} epoch boundaries missed)",
        regression,
        regressed_for,
        (regressed_for - rest_of_restart_epoch) / E::slots_per_epoch()
    );
    assert!(
        regressed_for > rest_of_restart_epoch,
        "the regression should have outlasted the first epoch boundary after the restart, but \
         ended after {} slots",
        regressed_for
    );

    drop(old_harness);
}
