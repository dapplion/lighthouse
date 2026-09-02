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
use eth2::types::SignedBlockContentsTuple;
use std::sync::{Arc, LazyLock};
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::{
    BeaconState, ChainSpec, EthSpec, Hash256, MinimalEthSpec, SignedExecutionPayloadEnvelope, Slot,
};

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

#[derive(Clone, Copy)]
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
/// The key property: the confirmed root the node announces after a restart is the same block it
/// announced before the restart.
///
/// `confirmed_root` is monotonic along the canonical chain — that is the whole point of confirming
/// a block, and both the `fast_confirmation` event and the engine `safeBlockHash` publish it. The
/// chain does not move while the node is down, so re-running FCR on the restored database must
/// arrive at exactly the same block.
fn assert_same_confirmed_root(before: &Sample, after: &Sample) {
    assert_eq!(
        after.confirmed_root, before.confirmed_root,
        "the confirmed root changed across the restart: block {:?} at slot {} before, block {:?} \
         at slot {} after",
        before.confirmed_root, before.confirmed_slot, after.confirmed_root, after.confirmed_slot
    );
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

    // Run FCR and capture the confirmed root the node is announcing.
    harness.chain.recompute_head_at_current_slot().await;
    let before = sample(&harness.chain);
    assert!(
        before.delay() <= 1,
        "chain should be in a steady state before the restart, delay was {} \
         (current slot {}, confirmed slot {})",
        before.delay(),
        before.current_slot,
        before.confirmed_slot
    );

    // Stop the node and start it again from the database.
    let old_harness = harness;
    let harness = restart_harness(store, &old_harness);

    // Re-run FCR and capture the confirmed root again.
    harness.chain.recompute_head_at_current_slot().await;
    let after = sample(&harness.chain);

    assert_same_confirmed_root(&before, &after);

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

    // Stop the node, start it again from the database, and re-run FCR.
    let old_harness = harness;
    let harness = restart_harness(store, &old_harness);
    harness.chain.recompute_head_at_current_slot().await;

    let after = sample(&harness.chain);
    assert_same_confirmed_root(&before, &after);

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

// ------------------------------------------------------------------------------------------------
// Differential rig.
//
// A control node that never restarts and a node under test are fed exactly the same blocks,
// attestations and slot clock. The control proposes; the node imports. A regression of the node's
// confirmed root is *caused by the restart* only if the control did not regress as well — the
// reverts the spec mandates (a chain that can no longer be re-confirmed) hit both nodes alike.
// ------------------------------------------------------------------------------------------------

/// Which validators attest in a slot.
#[derive(Clone, Copy, PartialEq)]
enum Participation {
    All,
    Half,
    Nobody,
}

impl Participation {
    fn validators(self) -> Vec<usize> {
        match self {
            Participation::All => (0..VALIDATOR_COUNT).collect(),
            Participation::Half => (0..VALIDATOR_COUNT / 2).collect(),
            Participation::Nobody => vec![],
        }
    }
}

/// A block the control proposed, with everything the node needs to import it later: under Gloas
/// the execution payload arrives separately as an envelope, verified against the post-state.
struct ProducedBlock {
    slot: Slot,
    root: Hash256,
    contents: SignedBlockContentsTuple<E>,
    envelope: Option<SignedExecutionPayloadEnvelope<E>>,
    post_state: BeaconState<E>,
    block_state_root: Hash256,
}

struct Pair {
    control: TestHarness,
    /// `None` while the node is down.
    node: Option<TestHarness>,
    node_store: Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>>,
    _control_db: TempDir,
    _node_db: TempDir,
    /// Every block the control proposed, in order. On boot the node re-imports the ones after
    /// its head, which covers both downtime and a crash that lost fork choice progress.
    blocks: Vec<ProducedBlock>,
    /// The highest confirmed slot the node has announced so far.
    high_water: Slot,
    log: Vec<String>,
}

fn build_node(
    store: Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>>,
    control: &TestHarness,
    fresh: bool,
) -> TestHarness {
    let builder = TestHarness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec());
    let builder = if fresh {
        builder.fresh_disk_store(store)
    } else {
        builder.resumed_disk_store(store)
    };
    builder
        .testing_slot_clock(control.chain.slot_clock.clone())
        .execution_layer(control.chain.execution_layer.clone())
        .chain_config(chain_config())
        .build()
}

impl Pair {
    fn new() -> Self {
        let control_db = tempdir().expect("temp dir");
        let control = fresh_harness(get_store(&control_db, test_spec::<E>()));
        let node_db = tempdir().expect("temp dir");
        let node_store = get_store(&node_db, test_spec::<E>());
        let node = build_node(node_store.clone(), &control, true);
        Self {
            control,
            node: Some(node),
            node_store,
            _control_db: control_db,
            _node_db: node_db,
            blocks: Vec::new(),
            high_water: Slot::new(0),
            log: Vec::new(),
        }
    }

    fn node(&self) -> &TestHarness {
        self.node.as_ref().expect("node is up")
    }

    fn slot(&self) -> Slot {
        self.control.chain.slot().unwrap()
    }

    fn slot_in_epoch(&self) -> u64 {
        self.slot().as_u64() % E::slots_per_epoch()
    }

    /// One slot for both nodes: tick, then (unless the chain is stalled) the control proposes,
    /// the node imports, `participation` attests, and both recompute their head.
    async fn step(&mut self, participation: Participation, propose: bool) {
        self.control.advance_slot();
        let slot = self.slot();
        self.control.chain.recompute_head_at_current_slot().await;
        if let Some(node) = &self.node {
            node.chain.recompute_head_at_current_slot().await;
        }
        self.observe("tick");
        if !propose {
            return;
        }

        let state = self.control.get_current_state();
        let (contents, envelope, mut post_state) =
            self.control.make_block_with_envelope(state, slot).await;
        let root = contents.0.canonical_root();
        let block_state_root = contents.0.state_root();
        let block_hash = self
            .control
            .process_block(slot, root, contents.clone())
            .await
            .expect("control imports its own block");
        if let Some(envelope) = &envelope {
            self.control
                .process_envelope(root, envelope.clone(), &post_state, block_state_root)
                .await;
        }
        let produced = ProducedBlock {
            slot,
            root,
            contents,
            envelope,
            post_state: post_state.clone(),
            block_state_root,
        };
        if let Some(node) = &self.node {
            Self::import(node, &produced).await;
        }
        self.blocks.push(produced);

        let validators = participation.validators();
        if !validators.is_empty() {
            let state_root = post_state.canonical_root().unwrap();
            let attestations = self.control.make_attestations(
                &validators,
                &post_state,
                state_root,
                block_hash,
                slot,
            );
            if let Some(node) = &self.node {
                node.process_attestations(attestations.clone(), &post_state);
            }
            self.control.process_attestations(attestations, &post_state);
        }

        self.control.chain.recompute_head_at_current_slot().await;
        if let Some(node) = &self.node {
            node.chain.recompute_head_at_current_slot().await;
        }
        self.observe("slot");
    }

    /// Import a block the control produced, envelope included, without touching the shared clock.
    async fn import(node: &TestHarness, block: &ProducedBlock) {
        node.process_block_result(block.contents.clone())
            .await
            .expect("node imports the block");
        if let Some(envelope) = &block.envelope {
            node.process_envelope(
                block.root,
                envelope.clone(),
                &block.post_state,
                block.block_state_root,
            )
            .await;
        }
    }

    async fn steps(&mut self, n: u64, participation: Participation) {
        for _ in 0..n {
            self.step(participation, true).await;
        }
    }

    /// Advance to the requested position within an epoch.
    async fn advance_to_slot_in_epoch(&mut self, slot_in_epoch: u64) {
        while self.slot_in_epoch() != slot_in_epoch {
            self.step(Participation::All, true).await;
        }
    }

    /// Bring both nodes to a steady state and check they agree.
    async fn warm_up(&mut self) {
        self.steps(WARMUP_SLOTS, Participation::All).await;
        let a = sample(&self.control.chain);
        let b = sample(&self.node().chain);
        assert!(
            a.delay() <= 1 && b.delay() <= 1,
            "both nodes should be at steady state, delays {} and {}",
            a.delay(),
            b.delay()
        );
        assert_eq!(
            a.confirmed_root, b.confirmed_root,
            "identical inputs should give identical confirmed roots"
        );
    }

    /// Stop the node. A graceful stop persists like a real shutdown would; a crash persists
    /// nothing beyond what the chain wrote on its own (fork choice at epoch transitions).
    fn stop_node(&mut self, graceful: bool) {
        let node = self.node.take().expect("node is up");
        if graceful {
            node.chain
                .persist_fork_choice()
                .expect("should persist fork choice");
            node.chain
                .persist_op_pool()
                .expect("should persist the op pool");
            drop(node);
        } else {
            // `BeaconChain` persists fork choice when dropped, which a crash does not get to do.
            std::mem::forget(node);
        }
        self.log.push(format!(
            "slot {:>3}: node stopped ({})",
            self.slot(),
            if graceful { "graceful" } else { "crash" }
        ));
    }

    /// Boot the node from its database. The first FCR run happens before any catch-up, exactly
    /// as on a real boot; every block after the node's head is then imported one by one, as sync
    /// would do.
    async fn boot_node(&mut self) {
        let node = build_node(self.node_store.clone(), &self.control, false);
        self.node = Some(node);
        self.node().chain.recompute_head_at_current_slot().await;
        self.observe("boot");
        let head_slot = self.node().chain.canonical_head.cached_head().head_slot();
        let to_replay: Vec<usize> = (0..self.blocks.len())
            .filter(|i| self.blocks[*i].slot > head_slot)
            .collect();
        for i in to_replay {
            Self::import(self.node(), &self.blocks[i]).await;
            self.observe("catch-up");
        }
    }

    /// The FCR tracking variables, for the log: (previous, current) observed-justified epochs, the
    /// greatest-unrealized epoch, and the slot of the last per-slot update.
    fn tracking<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> String {
        let fcr = chain
            .canonical_head
            .fast_confirmation
            .as_ref()
            .expect("FCR enabled")
            .lock();
        format!(
            "obs=({},{}) gu={} upd={}",
            fcr.previous_epoch_observed_justified.checkpoint().epoch,
            fcr.current_epoch_observed_justified.checkpoint().epoch,
            fcr.previous_epoch_greatest_unrealized_checkpoint.epoch,
            fcr.last_update_slot()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into())
        )
    }

    /// Record both nodes' confirmed roots and check the differential invariant.
    fn observe(&mut self, phase: &str) {
        let Some(node) = &self.node else {
            return;
        };
        let a = sample(&self.control.chain);
        let b = sample(&node.chain);
        let floor = std::cmp::min(self.high_water, a.confirmed_slot);
        self.log.push(format!(
            "slot {:>3} {:<8} control confirmed={:>3} [{}]  node head={:>3} confirmed={:>3} delay={:>3} [{}]{}",
            a.current_slot,
            phase,
            a.confirmed_slot,
            Self::tracking(&self.control.chain),
            b.head_slot,
            b.confirmed_slot,
            b.delay(),
            Self::tracking(&node.chain),
            if b.confirmed_slot < floor {
                "  <== UNCONFIRMATION"
            } else {
                ""
            }
        ));
        assert!(
            b.confirmed_slot >= floor,
            "restart-caused unconfirmation at slot {} ({}): the node announced confirmed slot {} \
             after having announced {}, while the control, which never restarted, is at {}\n{}",
            a.current_slot,
            phase,
            b.confirmed_slot,
            self.high_water,
            a.confirmed_slot,
            self.log.join("\n")
        );
        self.high_water = std::cmp::max(self.high_water, b.confirmed_slot);
    }

    fn assert_converged(&self) {
        let a = sample(&self.control.chain);
        let b = sample(&self.node().chain);
        assert_eq!(
            a.confirmed_root,
            b.confirmed_root,
            "the node should have converged on the control's confirmed root\n{}",
            self.log.join("\n")
        );
    }

    fn print_log(&self, title: &str) {
        println!("=== {} ===", title);
        for line in &self.log {
            println!("  {}", line);
        }
    }
}

struct Scenario {
    name: &'static str,
    restart_slot_in_epoch: u64,
    /// Slots with no blocks before the restart, both nodes up.
    stall_before: u64,
    /// Slots the node is down for.
    downtime: u64,
    /// Whether the chain keeps going while the node is down.
    chain_continues: bool,
    graceful: bool,
    /// Participation for the first epoch after the node is back.
    participation_after: Participation,
    restarts: u64,
}

impl Scenario {
    fn instant(name: &'static str, restart_slot_in_epoch: u64) -> Self {
        Self {
            name,
            restart_slot_in_epoch,
            stall_before: 0,
            downtime: 0,
            chain_continues: true,
            graceful: true,
            participation_after: Participation::All,
            restarts: 1,
        }
    }

    async fn run(self) {
        let mut pair = Pair::new();
        pair.warm_up().await;
        pair.advance_to_slot_in_epoch(self.restart_slot_in_epoch)
            .await;
        for _ in 0..self.stall_before {
            pair.step(Participation::All, false).await;
        }
        for _ in 0..self.restarts {
            pair.stop_node(self.graceful);
            for _ in 0..self.downtime {
                pair.step(Participation::All, self.chain_continues).await;
            }
            pair.boot_node().await;
        }
        pair.steps(E::slots_per_epoch(), self.participation_after)
            .await;
        pair.steps(E::slots_per_epoch(), Participation::All).await;
        pair.print_log(self.name);
        pair.assert_converged();
    }
}

#[tokio::test]
async fn differential_instant_restart_at_epoch_start() {
    Scenario::instant("instant restart, slot_in_epoch 0", 0)
        .run()
        .await;
}

#[tokio::test]
async fn differential_instant_restart_mid_epoch() {
    Scenario::instant("instant restart, slot_in_epoch 4", 4)
        .run()
        .await;
}

#[tokio::test]
async fn differential_instant_restart_at_epoch_end() {
    Scenario::instant("instant restart, slot_in_epoch 7", 7)
        .run()
        .await;
}

#[tokio::test]
async fn differential_one_slot_of_downtime() {
    Scenario {
        downtime: 1,
        ..Scenario::instant("1 slot down, chain continues", 4)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_three_slots_of_downtime() {
    Scenario {
        downtime: 3,
        ..Scenario::instant("3 slots down, chain continues", 2)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_downtime_across_an_epoch_boundary() {
    // Stops at slot_in_epoch 6, boots at slot_in_epoch 2 of the next epoch: the confirmed block
    // is still inside the previous epoch when the node comes back.
    Scenario {
        downtime: 4,
        ..Scenario::instant("4 slots down across an epoch boundary", 6)
    }
    .run()
    .await;
}

/// Known gap. The confirmed block is two epochs old when the node comes back, so the spec's
/// `epoch_too_old` revert to finalized is mandatory on the first run, and from there the node is
/// in the same position as a fresh checkpoint-sync node until the next epoch boundary. The
/// announcement itself could only be avoided by not running FCR until sync has caught up, which
/// needs sync status the chain does not have.
#[ignore = "the confirmed block is past the epoch_too_old window at boot; needs an FCR gate on sync status"]
#[tokio::test]
async fn differential_downtime_of_more_than_an_epoch() {
    // Boots with a confirmed block two epochs old, past the `epoch_too_old` window.
    Scenario {
        downtime: E::slots_per_epoch() + 4,
        ..Scenario::instant("12 slots down, confirmed block two epochs old at boot", 4)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_downtime_while_the_chain_is_stalled() {
    Scenario {
        downtime: 3,
        chain_continues: false,
        ..Scenario::instant("3 slots down, chain stalled meanwhile", 4)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_restart_during_a_chain_stall() {
    Scenario {
        stall_before: 3,
        downtime: 1,
        ..Scenario::instant("3 empty slots, then restart", 2)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_restart_then_nobody_attests() {
    Scenario {
        downtime: 1,
        participation_after: Participation::Nobody,
        ..Scenario::instant("restart, then an epoch nobody attests", 4)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_restart_then_half_participation() {
    Scenario {
        downtime: 1,
        participation_after: Participation::Half,
        ..Scenario::instant("restart, then an epoch at half participation", 4)
    }
    .run()
    .await;
}

#[tokio::test]
async fn differential_two_restarts_in_a_row() {
    Scenario {
        downtime: 1,
        restarts: 2,
        ..Scenario::instant("two restarts, 1 slot down each", 4)
    }
    .run()
    .await;
}

/// Known gap. A crash loses everything since the last epoch-transition persist, so the node boots
/// with fork choice and the confirmed root it had then, and re-syncs the rest. Closing it needs
/// the FCR state persisted every slot and applied lazily once the confirmed block is back in fork
/// choice, since it may be ahead of the persisted fork choice.
#[ignore = "boots from the last epoch-transition persist; needs per-slot FCR persistence applied lazily after sync"]
#[tokio::test]
async fn differential_crash_instead_of_graceful_shutdown() {
    Scenario {
        downtime: 1,
        graceful: false,
        ..Scenario::instant("crash, 1 slot down", 4)
    }
    .run()
    .await;
}
