#![cfg(not(debug_assertions))]

//! The Fast Confirmation Rule's `confirmed_root` must not move backwards across a restart.
//!
//! Oracle: a control node that never restarts is fed the same blocks, attestations and clock as
//! the node under test. The node may only regress when the control does, which excludes the
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

/// The control owns the mock execution layer and the clock; the node shares both.
fn control(store: Store) -> Harness {
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

fn node(store: Store, control: &Harness, fresh: bool, fcr: bool, reset: bool) -> Harness {
    let builder = Harness::builder(MinimalEthSpec)
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
    control: Harness,
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
        let (control_db, node_db) = (tempdir().unwrap(), tempdir().unwrap());
        let control = control(store(&control_db));
        let node_store = store(&node_db);
        let node = node(node_store.clone(), &control, true, true, false);
        Self {
            control,
            node: Some(node),
            node_store,
            _dbs: (control_db, node_db),
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
        self.control.chain.slot().unwrap()
    }

    /// One slot: tick both nodes, then (unless stalled) the control proposes, the node imports,
    /// `attesters` attest, both recompute the head.
    async fn step(&mut self, attesters: &[usize], propose: bool) {
        self.control.advance_slot();
        let slot = self.slot();
        self.recompute("tick").await;
        if !propose {
            return;
        }

        let state = self.control.get_current_state();
        let (contents, envelope, mut post_state) =
            self.control.make_block_with_envelope(state, slot).await;
        let root = contents.0.canonical_root();
        let block_hash = self
            .control
            .process_block(slot, root, contents.clone())
            .await
            .unwrap();
        if let Some(envelope) = &envelope {
            let state_root = contents.0.state_root();
            self.control
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
            let attestations = self.control.make_attestations(
                attesters,
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
        self.control.chain.recompute_head_at_current_slot().await;
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
            &self.control,
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
    /// unless the control is below it too, and both roots are on the same branch.
    fn observe(&mut self, phase: &str) {
        let Some(node) = &self.node else { return };
        let Some((mine_root, mine)) = confirmed(&node.chain) else {
            return;
        };
        let (control_root, control) = confirmed(&self.control.chain).unwrap();
        let (ancestor, descendant) = if mine <= control {
            (mine_root, control_root)
        } else {
            (control_root, mine_root)
        };
        assert!(
            self.control
                .chain
                .canonical_head
                .fork_choice_read_lock()
                .is_descendant(ancestor, descendant),
            "confirmed roots on different branches at slot {}",
            self.slot()
        );
        let floor = self.high_water.min(control);
        let head = node.chain.canonical_head.cached_head().head_slot();
        self.log.push(format!(
            "slot {:>3} {phase:<8} control={control:>3} node head={head:>3} confirmed={mine:>3}",
            self.slot()
        ));
        assert!(
            mine >= floor,
            "restart-caused unconfirmation ({phase}): node at {mine}, was {}, control at {control}\n{}",
            self.high_water,
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
    /// Whether the control keeps proposing while the node is down.
    chain_continues: bool,
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
            for _ in 0..self.down {
                rig.step(&all, self.chain_continues).await;
            }
            rig.boot().await;
        }
        rig.steps(epoch, &validators(self.attesters_after)).await;
        rig.steps(epoch, &all).await;
        assert_eq!(
            confirmed(&rig.control.chain),
            confirmed(&rig.node().chain),
            "node did not converge on the control\n{}",
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
        &rig.control,
        false,
        false,
        false,
    ));
    rig.steps(E::slots_per_epoch(), &all).await;
    rig.stop(true);
    assert!(persisted(&rig).is_none());
}

/// `--reset-payload-statuses` marks every pre-Gloas block optimistic at boot (Gloas payload
/// statuses are left alone). A confirmed root must be `VALID` like any block FCR confirms, so an
/// optimistic persisted root is refused and the rule is seeded from the justified checkpoint.
#[tokio::test]
async fn a_payload_status_reset_refuses_an_optimistic_persisted_root() {
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let (stopped, _) = rig.stopped.unwrap();
    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.control,
        false,
        true,
        true,
    ));
    let chain = &rig.node().chain;
    let optimistic = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&stopped)
        .unwrap()
        .execution_status
        .is_optimistic_or_invalid();
    let justified = chain
        .canonical_head
        .cached_head()
        .justified_checkpoint()
        .root;
    let (root, _) = confirmed(chain).unwrap();
    assert_eq!(root, if optimistic { justified } else { stopped });
}
