//! Differential test: Lighthouse's rule and the ported `fast_confirmation_core`
//! must reach the same verdict on the same chain.
//!
//! The unit tests inside `fast_confirmation` cover the arithmetic. This covers
//! the state machine: a real `ProtoArray`, real vote trackers, and
//! `get_latest_confirmed` run twice over the same inputs. It is the evidence
//! that the port is faithful in behaviour and not merely in shape.

use std::collections::BTreeSet;
use std::time::Duration;

use ethereum_hashing::hash_fixed;
use fast_confirmation::adapter::{Assignments, ProtoArrayStore, VoteTrackers};
use fast_confirmation::{
    BalanceSourceData, BalanceSourceKey, CheckpointAndBalance, FastConfirmationRule,
};
use fast_confirmation_core as core_rule;
use fixed_bytes::FixedBytesExtended;
use proto_array::core::{ProtoArray, VoteTracker};
use proto_array::{Block, ExecutionStatus, JustifiedBalances, ProtoArrayForkChoice};
use types::*;

type E = MainnetEthSpec;

const GWEI_PER_ETH: u64 = 1_000_000_000;
const BALANCE: u64 = 32 * GWEI_PER_ETH;
const CHAIN_TIP_SLOT: u64 = 69;
const OBSERVED_JUSTIFIED_SLOT: u64 = 32;
const NUM_VALIDATORS: usize = 2_048;

fn block_root_at(slot: u64) -> Hash256 {
    let mut preimage = [0u8; 16];
    preimage[..8].copy_from_slice(b"fcr-root");
    preimage[8..].copy_from_slice(&(slot + 1).to_le_bytes());
    Hash256::from_slice(&hash_fixed(&preimage))
}

struct Fixture {
    proto_array: ProtoArray,
    votes: Vec<VoteTracker>,
    balance_source: BalanceSourceData,
    lh: FastConfirmationRule,
    core: core_rule::rule::FastConfirmationRule<Assignments>,
    finalized_checkpoint: Checkpoint,
    observed_justified_checkpoint: Checkpoint,
    genesis_checkpoint: Checkpoint,
}

fn core_balances(b: &BalanceSourceData) -> core_rule::rule::BalanceSourceData {
    core_rule::rule::BalanceSourceData {
        total_active_balance: b.total_active_balance,
        effective_balances: b.effective_balances.clone(),
        slashed: b.slashed.clone(),
    }
}

/// Build one chain and two rules seeded to the same state.
fn fixture(gap_slot: Option<u64>) -> Fixture {
    let spec = E::default_spec();
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
        Slot::new(0),
        Slot::new(0),
        Hash256::zero(),
        justified_checkpoint,
        finalized_checkpoint,
        shuffling_id.clone(),
        shuffling_id.clone(),
        ExecutionStatus::irrelevant(),
        None,
        None,
        0,
        &spec,
    )
    .expect("create fork choice");

    let mut block_roots = vec![genesis_root];
    for slot_u in 1..=CHAIN_TIP_SLOT {
        if Some(slot_u) == gap_slot {
            block_roots.push(block_roots[(slot_u - 1) as usize]);
            continue;
        }
        let slot = Slot::new(slot_u);
        let epoch = slot.epoch(E::slots_per_epoch());
        let root = block_root_at(slot_u);
        let parent_root = block_roots[(slot_u - 1) as usize];
        let target_root = block_root_at(epoch.as_u64() * E::slots_per_epoch());
        let unrealized_justified_checkpoint = if epoch == Epoch::new(0) {
            genesis_checkpoint
        } else {
            observed_justified_checkpoint
        };

        fc.process_block::<E>(
            Block {
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
            },
            slot,
            &spec,
            Duration::from_secs(0),
        )
        .expect("process block");
        block_roots.push(root);
    }

    // Model a healthy network: the overwhelming majority attest to the canonical
    // head, so support actually clears the safety threshold and the confirmation
    // decision is exercised. (The benchmark deliberately scatters votes instead,
    // to defeat caching -- that is the right choice for measuring cost and the
    // wrong one for testing the verdict, because nothing ever confirms.)
    let tip_root = block_roots[CHAIN_TIP_SLOT as usize];
    let voteable = &block_roots[1..];
    for val_idx in 0..NUM_VALIDATORS {
        let voted = if val_idx % 20 == 0 {
            voteable[val_idx % voteable.len()]
        } else {
            tip_root
        };
        fc.process_attestation(val_idx, voted, Slot::new(0), false)
            .expect("process attestation");
    }

    let balances = JustifiedBalances::from_effective_balances(vec![BALANCE; NUM_VALIDATORS])
        .expect("justified balances");
    fc.find_head::<E>(
        justified_checkpoint,
        finalized_checkpoint,
        &balances,
        Hash256::zero(),
        &BTreeSet::new(),
        Slot::new(CHAIN_TIP_SLOT),
        &spec,
    )
    .expect("find head");

    let balance_source = BalanceSourceData {
        key: BalanceSourceKey::NoSlashings {
            epoch_boundary_root: observed_justified_checkpoint.root,
            epoch: Slot::new(CHAIN_TIP_SLOT).epoch(E::slots_per_epoch()),
        },
        total_active_balance: BALANCE.saturating_mul(NUM_VALIDATORS as u64),
        effective_balances: vec![BALANCE; NUM_VALIDATORS],
        slashed: vec![false; NUM_VALIDATORS],
    };

    let mut seed_state = BeaconState::<E>::new(0, Default::default(), &spec);
    for _ in 0..E::slots_per_epoch() as usize {
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
    seed_state
        .build_all_committee_caches(&spec)
        .expect("committee caches");
    let seed_assignments =
        SlotAssignments::new(&seed_state, &spec, None).expect("slot assignments");

    let mut lh = FastConfirmationRule::new(
        finalized_checkpoint.root,
        &seed_state,
        seed_assignments.clone(),
        finalized_checkpoint,
        &seed_state,
        25,
        40,
    )
    .expect("lh fcr");
    lh.test_set_head_balance_source(balance_source.clone());

    let core = core_rule::rule::FastConfirmationRule::new(
        fast_confirmation::adapter::checkpoint(&finalized_checkpoint),
        fast_confirmation::adapter::root(finalized_checkpoint.root),
        25,
        40,
        Assignments(seed_assignments),
        core_balances(&balance_source),
        E::slots_per_epoch(),
    );

    Fixture {
        proto_array: fc.core_proto_array().clone(),
        votes: fc.votes().to_vec(),
        balance_source,
        lh,
        core,
        finalized_checkpoint,
        observed_justified_checkpoint,
        genesis_checkpoint,
    }
}

impl Fixture {
    /// Point both rules at the same chain position.
    fn apply(&mut self, head_slot: u64, confirmed_slot: u64) {
        let head_root = block_root_at(head_slot);
        let confirmed_root = block_root_at(confirmed_slot);

        self.lh.previous_slot_head = head_root;
        self.lh.current_slot_head = head_root;
        self.lh.confirmed_root = confirmed_root;
        self.lh.current_epoch_observed_justified = CheckpointAndBalance::new(
            self.observed_justified_checkpoint,
            self.balance_source.clone(),
        );
        self.lh.previous_epoch_observed_justified =
            CheckpointAndBalance::new(self.genesis_checkpoint, self.balance_source.clone());

        let cb = core_balances(&self.balance_source);
        self.core.previous_slot_head = fast_confirmation::adapter::root(head_root);
        self.core.current_slot_head = fast_confirmation::adapter::root(head_root);
        self.core.confirmed_root = fast_confirmation::adapter::root(confirmed_root);
        self.core.current_epoch_observed_justified = core_rule::rule::CheckpointAndBalance::new(
            fast_confirmation::adapter::checkpoint(&self.observed_justified_checkpoint),
            cb.clone(),
        );
        self.core.previous_epoch_observed_justified = core_rule::rule::CheckpointAndBalance::new(
            fast_confirmation::adapter::checkpoint(&self.genesis_checkpoint),
            cb,
        );
    }

    /// Run both implementations and require the same answer.
    fn assert_same(&self, head_slot: u64, current_slot: u64, label: &str) {
        let head_root = block_root_at(head_slot);
        let equivocating = BTreeSet::new();

        let lh = self.lh.get_latest_confirmed::<E>(
            head_root,
            &self.finalized_checkpoint,
            &self.observed_justified_checkpoint,
            Slot::new(current_slot),
            &self.proto_array,
            &self.votes,
            &equivocating,
        );

        let store = ProtoArrayStore {
            proto_array: &self.proto_array,
        };
        let core = self.core.get_latest_confirmed(
            fast_confirmation::adapter::root(head_root),
            &fast_confirmation::adapter::checkpoint(&self.finalized_checkpoint),
            &fast_confirmation::adapter::checkpoint(&self.observed_justified_checkpoint),
            core_rule::Slot::new(current_slot),
            &store,
            &VoteTrackers(&self.votes),
            &equivocating,
        );

        match (lh, core) {
            (Ok(l), Ok(c)) => assert_eq!(
                l,
                fast_confirmation::adapter::hash(c),
                "{label}: confirmed root differs between implementations"
            ),
            (Err(_), Err(_)) => {
                // Both refused. The error taxonomies differ by design; agreeing
                // on "no confirmation" is the behaviour under test.
            }
            (l, c) => panic!(
                "{label}: one implementation errored and the other did not: lh={l:?} core={c:?}"
            ),
        }
    }
}

/// The realistic spectrum the benchmark measures, asserted for agreement.
#[test]
fn implementations_agree_across_chain_positions() {
    let mut f = fixture(None);
    for (name, head_slot, current_slot, confirmed_slot) in [
        ("steady_mid_epoch", 69u64, 70u64, 66u64),
        ("epoch_first_slot", 63, 64, 40),
        ("epoch_catch_up", 65, 66, 40),
        ("missed_epoch_start", 63, 68, 40),
    ] {
        f.apply(head_slot, confirmed_slot);
        f.assert_same(head_slot, current_slot, name);
    }
}

/// A missed slot is where the empty-slot support discount fires, and where an
/// off-by-one between the two ancestor walks would show up.
#[test]
fn implementations_agree_across_a_missed_slot() {
    let mut f = fixture(Some(60));
    for (name, head_slot, current_slot, confirmed_slot) in [
        ("after_gap", 61u64, 62u64, 56u64),
        ("spanning_gap", 62, 63, 58),
        ("gap_then_epoch", 63, 66, 40),
    ] {
        f.apply(head_slot, confirmed_slot);
        f.assert_same(head_slot, current_slot, name);
    }
}

/// The confirmed root lagging far behind forces the revert-to-finalized path,
/// the branch most likely to diverge because it is the least exercised.
#[test]
fn implementations_agree_on_revert_to_finalized() {
    let mut f = fixture(None);
    for (name, head_slot, current_slot, confirmed_slot) in [
        ("confirmed_two_epochs_back", 69u64, 70u64, 5u64),
        ("confirmed_at_genesis", 69, 70, 0),
    ] {
        f.apply(head_slot, confirmed_slot);
        f.assert_same(head_slot, current_slot, name);
    }
}
