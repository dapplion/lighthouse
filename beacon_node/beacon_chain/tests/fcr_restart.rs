#![cfg(not(debug_assertions))]

//! The Fast Confirmation Rule's `confirmed_root` must not move backwards across a restart.
//!
//! Oracle: a harness node that never restarts is fed the same blocks, attestations and clock as
//! the node under test. The node may only regress when the harness does, which excludes the
//! reverts the spec mandates. Restarts go through `BeaconChainBuilder::resume_from_db`.

use beacon_chain::{
    BeaconChain, BeaconChainTypes, ChainConfig,
    chain_config::FastConfirmationMode,
    persisted_fast_confirmation::{FAST_CONFIRMATION_DB_KEY, PersistedFastConfirmation},
    test_utils::{BeaconChainHarness, DiskHarnessType, test_spec},
};
use bls::Keypair;
use eth2::types::SignedBlockContentsTuple;
use std::sync::{Arc, LazyLock};
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::{BeaconState, EthSpec, Hash256, MinimalEthSpec, SignedExecutionPayloadEnvelope, Slot};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<DiskHarnessType<E>>;
type Store = Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>>;

const VALIDATOR_COUNT: usize = 64;
const WARMUP_SLOTS: u64 = 40;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn store(db: &TempDir) -> Store {
    HotColdDB::open(
        &db.path().join("chain_db"),
        &db.path().join("freezer_db"),
        &db.path().join("blobs_db"),
        |_, _, _| Ok(()),
        StoreConfig {
            prune_payloads: false,
            ..StoreConfig::default()
        },
        test_spec::<E>().into(),
    )
    .unwrap()
}

fn config(fcr: bool, reset_payload_statuses: bool) -> ChainConfig {
    ChainConfig {
        fast_confirmation: if fcr {
            FastConfirmationMode::Enabled
        } else {
            FastConfirmationMode::Disabled
        },
        always_reset_payload_statuses: reset_payload_statuses,
        ..ChainConfig::default()
    }
}

/// The harness owns the mock execution layer and the clock; the node shares both.
fn harness(store: Store) -> Harness {
    let harness = Harness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec())
        .fresh_disk_store(store)
        .mock_execution_layer()
        .chain_config(config(true, false))
        .build();
    harness.advance_slot();
    harness
}

fn node(store: Store, harness: &Harness, fresh: bool, fcr: bool, reset: bool) -> Harness {
    let builder = Harness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec());
    let builder = if fresh {
        builder.fresh_disk_store(store)
    } else {
        builder.resumed_disk_store(store)
    };
    builder
        .testing_slot_clock(harness.chain.slot_clock.clone())
        .execution_layer(harness.chain.execution_layer.clone())
        .chain_config(config(fcr, reset))
        .build()
}

fn validators(n: usize) -> Vec<usize> {
    (0..n).collect()
}

fn confirmed<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Option<(Hash256, Slot)> {
    let root = chain
        .canonical_head
        .fast_confirmation
        .as_ref()?
        .lock()
        .confirmed_root;
    let slot = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&root)
        .unwrap()
        .slot;
    Some((root, slot))
}

struct Produced {
    slot: Slot,
    root: Hash256,
    contents: SignedBlockContentsTuple<E>,
    envelope: Option<SignedExecutionPayloadEnvelope<E>>,
    post_state: BeaconState<E>,
}

struct Rig {
    harness: Harness,
    node: Option<Harness>,
    node_store: Store,
    _dbs: (TempDir, TempDir),
    blocks: Vec<Produced>,
    /// Confirmed root and slot at the moment the node was stopped.
    stopped: Option<(Hash256, Slot)>,
    /// Highest confirmed slot the node has announced.
    high_water: Slot,
    log: Vec<String>,
}

impl Rig {
    fn new() -> Self {
        let (harness_db, node_db) = (tempdir().unwrap(), tempdir().unwrap());
        let harness = harness(store(&harness_db));
        let node_store = store(&node_db);
        let node = node(node_store.clone(), &harness, true, true, false);
        Self {
            harness,
            node: Some(node),
            node_store,
            _dbs: (harness_db, node_db),
            blocks: vec![],
            stopped: None,
            high_water: Slot::new(0),
            log: vec![],
        }
    }

    fn node(&self) -> &Harness {
        self.node.as_ref().unwrap()
    }

    fn slot(&self) -> Slot {
        self.harness.chain.slot().unwrap()
    }

    /// One slot: tick both nodes, then (unless stalled) the harness proposes, the node imports,
    /// `attesters` attest, both recompute the head.
    async fn step(&mut self, attesters: &[usize], propose: bool) {
        self.harness.advance_slot();
        let slot = self.slot();
        self.recompute("tick").await;
        if !propose {
            return;
        }

        let state = self.harness.get_current_state();
        let (contents, envelope, mut post_state) =
            self.harness.make_block_with_envelope(state, slot).await;
        let root = contents.0.canonical_root();
        let block_hash = self
            .harness
            .process_block(slot, root, contents.clone())
            .await
            .unwrap();
        if let Some(envelope) = &envelope {
            let state_root = contents.0.state_root();
            self.harness
                .process_envelope(root, envelope.clone(), &post_state, state_root)
                .await;
        }
        let produced = Produced {
            slot,
            root,
            contents,
            envelope,
            post_state: post_state.clone(),
        };
        if let Some(node) = &self.node {
            Self::import(node, &produced).await;
        }
        self.blocks.push(produced);

        if !attesters.is_empty() {
            let state_root = post_state.canonical_root().unwrap();
            let attestations = self.harness.make_attestations(
                attesters,
                &post_state,
                state_root,
                block_hash,
                slot,
            );
            if let Some(node) = &self.node {
                node.process_attestations(attestations.clone(), &post_state);
            }
            self.harness.process_attestations(attestations, &post_state);
        }
        self.recompute("slot").await;
    }

    async fn import(node: &Harness, block: &Produced) {
        node.process_block_result(block.contents.clone())
            .await
            .unwrap();
        if let Some(envelope) = &block.envelope {
            let state_root = block.contents.0.state_root();
            node.process_envelope(block.root, envelope.clone(), &block.post_state, state_root)
                .await;
        }
    }

    async fn recompute(&mut self, phase: &str) {
        self.harness.chain.recompute_head_at_current_slot().await;
        if let Some(node) = &self.node {
            node.chain.recompute_head_at_current_slot().await;
        }
        self.observe(phase);
    }

    async fn steps(&mut self, n: u64, attesters: &[usize]) {
        for _ in 0..n {
            self.step(attesters, true).await;
        }
    }

    /// A graceful stop persists like a real shutdown; a crash persists nothing beyond the
    /// chain's own epoch-transition writes (`BeaconChain::drop` would persist, so leak it).
    fn stop(&mut self, graceful: bool) {
        let node = self.node.take().unwrap();
        self.stopped = confirmed(&node.chain);
        if graceful {
            node.chain.persist_fork_choice().unwrap();
            node.chain.persist_op_pool().unwrap();
        } else {
            std::mem::forget(node);
        }
        self.log.push(format!("slot {:>3} stopped", self.slot()));
    }

    /// Boot from the database, run FCR once before any catch-up (as a real boot does), then
    /// import every block after the node's head, as sync would.
    async fn boot(&mut self) {
        self.node = Some(node(
            self.node_store.clone(),
            &self.harness,
            false,
            true,
            false,
        ));
        self.node().chain.recompute_head_at_current_slot().await;
        if let Some((root, slot)) = self.stopped
            && slot == self.slot()
        {
            let (now, _) = confirmed(&self.node().chain).unwrap();
            assert_eq!(now, root, "same slot, same block");
        }
        self.observe("boot");
        let head = self.node().chain.canonical_head.cached_head().head_slot();
        for i in 0..self.blocks.len() {
            if self.blocks[i].slot > head {
                Self::import(self.node(), &self.blocks[i]).await;
                self.observe("catch-up");
            }
        }
    }

    /// The invariant: the node never announces a confirmed slot below its own high-water mark
    /// unless the harness is below it too, and both roots are on the same branch.
    fn observe(&mut self, phase: &str) {
        let Some(node) = &self.node else { return };
        let Some((mine_root, mine)) = confirmed(&node.chain) else {
            return;
        };
        let (harness_root, harness) = confirmed(&self.harness.chain).unwrap();
        let (ancestor, descendant) = if mine <= harness {
            (mine_root, harness_root)
        } else {
            (harness_root, mine_root)
        };
        assert!(
            self.harness
                .chain
                .canonical_head
                .fork_choice_read_lock()
                .is_descendant(ancestor, descendant),
            "confirmed roots on different branches at slot {}",
            self.slot()
        );
        let floor = self.high_water.min(harness);
        let head = node.chain.canonical_head.cached_head().head_slot();
        self.log.push(format!(
            "slot {:>3} {phase:<8} harness={harness:>3} node head={head:>3} confirmed={mine:>3}",
            self.slot()
        ));
        assert!(
            mine >= floor,
            "restart-caused unconfirmation ({phase}): node at {mine}, was {}, harness at {harness}\n{}",
            self.high_water,
            self.log.join("\n")
        );
        // Once caught up the node has at most the harness's votes, so it can never be ahead.
        let harness_head = self.harness.chain.canonical_head.cached_head().head_slot();
        assert!(
            head < harness_head || mine <= harness,
            "over-confirmation ({phase}): node at {mine}, harness at {harness}\n{}",
            self.log.join("\n")
        );
        self.high_water = self.high_water.max(mine);
    }
}

struct Scenario {
    /// Slot within the epoch at which the node stops.
    at: u64,
    /// Empty slots before the stop, both nodes up.
    stall_before: u64,
    /// Slots the node is down.
    down: u64,
    /// Whether the harness keeps proposing while the node is down.
    chain_continues: bool,
    /// Attesters while the node is down.
    attesters_down: usize,
    graceful: bool,
    /// Attesters for the first epoch after the node is back.
    attesters_after: usize,
    restarts: u64,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            at: 4,
            stall_before: 0,
            down: 0,
            chain_continues: true,
            attesters_down: VALIDATOR_COUNT,
            graceful: true,
            attesters_after: VALIDATOR_COUNT,
            restarts: 1,
        }
    }
}

impl Scenario {
    fn at(mut self, slot_in_epoch: u64) -> Self {
        self.at = slot_in_epoch;
        self
    }
    fn down(mut self, slots: u64) -> Self {
        self.down = slots;
        self
    }
    fn stall_before(mut self, slots: u64) -> Self {
        self.stall_before = slots;
        self
    }
    fn chain_stalled(mut self) -> Self {
        self.chain_continues = false;
        self
    }
    fn attesters_down(mut self, n: usize) -> Self {
        self.attesters_down = n;
        self
    }
    fn crash(mut self) -> Self {
        self.graceful = false;
        self
    }
    fn attesters_after(mut self, n: usize) -> Self {
        self.attesters_after = n;
        self
    }
    fn restarts(mut self, n: u64) -> Self {
        self.restarts = n;
        self
    }

    async fn run(self) {
        let all = validators(VALIDATOR_COUNT);
        let epoch = E::slots_per_epoch();
        let mut rig = Rig::new();
        rig.steps(WARMUP_SLOTS, &all).await;
        while rig.slot().as_u64() % epoch != self.at {
            rig.step(&all, true).await;
        }
        for _ in 0..self.stall_before {
            rig.step(&all, false).await;
        }
        for _ in 0..self.restarts {
            rig.stop(self.graceful);
            let down = validators(self.attesters_down);
            for _ in 0..self.down {
                rig.step(&down, self.chain_continues).await;
            }
            rig.boot().await;
        }
        rig.steps(epoch, &validators(self.attesters_after)).await;
        rig.steps(epoch, &all).await;
        assert_eq!(
            confirmed(&rig.harness.chain),
            confirmed(&rig.node().chain),
            "node did not converge on the harness\n{}",
            rig.log.join("\n")
        );
    }
}

#[tokio::test]
async fn instant_restart_at_epoch_start() {
    Scenario::default().at(0).run().await;
}

#[tokio::test]
async fn instant_restart_mid_epoch() {
    Scenario::default().run().await;
}

/// The votes queued in the epoch's last slot are lost with `PersistedForkChoiceV29`, and the
/// boundary re-confirmation runs before the next block brings them back.
#[ignore = "needs queued attestations persisted across the restart"]
#[tokio::test]
async fn instant_restart_at_epoch_end() {
    Scenario::default().at(7).run().await;
}

#[tokio::test]
async fn one_slot_of_downtime() {
    Scenario::default().down(1).run().await;
}

#[tokio::test]
async fn three_slots_of_downtime() {
    Scenario::default().at(2).down(3).run().await;
}

#[tokio::test]
async fn downtime_across_an_epoch_boundary() {
    Scenario::default().at(6).down(4).run().await;
}

/// The confirmed block is past the `epoch_too_old` window at boot; the revert is mandatory.
#[ignore = "needs an FCR gate on sync status"]
#[tokio::test]
async fn downtime_of_more_than_an_epoch() {
    Scenario::default().down(12).run().await;
}

/// The harness re-confirms at the boundary and reverts; the node slept through that boundary and
/// must run the same check when it comes back rather than keep a root the votes no longer carry.
#[tokio::test]
async fn downtime_across_an_epoch_boundary_while_participation_drops() {
    Scenario::default()
        .at(2)
        .down(8)
        .attesters_down(0)
        .run()
        .await;
}

#[tokio::test]
async fn downtime_while_the_chain_is_stalled() {
    Scenario::default().down(3).chain_stalled().run().await;
}

#[tokio::test]
async fn restart_during_a_chain_stall() {
    Scenario::default()
        .at(2)
        .stall_before(3)
        .down(1)
        .run()
        .await;
}

#[tokio::test]
async fn restart_then_nobody_attests() {
    Scenario::default().down(1).attesters_after(0).run().await;
}

#[tokio::test]
async fn restart_then_half_participation() {
    Scenario::default()
        .down(1)
        .attesters_after(VALIDATOR_COUNT / 2)
        .run()
        .await;
}

#[tokio::test]
async fn two_restarts_in_a_row() {
    Scenario::default().down(1).restarts(2).run().await;
}

/// Boots from the last epoch-transition persist, with the confirmed root it had then.
#[ignore = "needs per-slot FCR persistence applied lazily after sync"]
#[tokio::test]
async fn crash_instead_of_graceful_shutdown() {
    Scenario::default().down(1).crash().run().await;
}

/// With FCR disabled the next fork choice persist deletes the item, so enabling FCR again later
/// seeds afresh instead of restoring stale state.
#[tokio::test]
async fn disabling_fcr_clears_the_persisted_state() {
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let persisted = |rig: &Rig| {
        rig.node_store
            .get_item::<PersistedFastConfirmation>(&FAST_CONFIRMATION_DB_KEY)
            .unwrap()
    };
    assert!(persisted(&rig).is_some());
    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        false,
        false,
    ));
    rig.steps(E::slots_per_epoch(), &all).await;
    rig.stop(true);
    assert!(persisted(&rig).is_none());
}

/// A `--reset-payload-statuses` boot marks every pre-Gloas block optimistic. The persisted state
/// is restored regardless: as for a running node, nothing optimistic gets confirmed and the
/// epoch-start reconfirmation reverts an optimistic chain.
#[tokio::test]
async fn a_payload_status_reset_keeps_the_persisted_root() {
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let (stopped, _) = rig.stopped.unwrap();
    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        true,
        true,
    ));
    let (root, _) = confirmed(&rig.node().chain).unwrap();
    assert_eq!(root, stopped);
}
