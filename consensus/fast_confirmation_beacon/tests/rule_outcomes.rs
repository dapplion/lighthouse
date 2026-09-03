//! Behaviour of `get_latest_confirmed` over a real `ProtoArray`, pinned.
//!
//! Lighthouse now delegates the rule to `fast_confirmation_core`, so running
//! both and comparing them would compare the code to itself. The expectations
//! below were instead recorded from Lighthouse's own implementation *before*
//! the delegation, over the same fixtures, and assert that routing through the
//! core did not change a single verdict.
//!
//! Each case is `(head slot, current slot, confirmed-in slot) -> confirmed-out
//! slot`. They were chosen to cover the branches that decide the outcome:
//! steady state, the epoch boundary, a missed slot, and revert-to-finalized.

use std::collections::BTreeSet;
use std::time::Duration;

use ethereum_hashing::hash_fixed;
use fast_confirmation_beacon::{
    BalanceSourceData, CheckpointAndBalance, FastConfirmationRule, adapter,
};
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
    finalized_checkpoint: Checkpoint,
    observed_justified_checkpoint: Checkpoint,
    genesis_checkpoint: Checkpoint,
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
        epoch: adapter::epoch(Slot::new(CHAIN_TIP_SLOT).epoch(E::slots_per_epoch())),
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

    Fixture {
        proto_array: fc.core_proto_array().clone(),
        votes: fc.votes().to_vec(),
        balance_source,
        lh,
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

        self.lh.inner.previous_slot_head = adapter::root(head_root);
        self.lh.inner.current_slot_head = adapter::root(head_root);
        self.lh.inner.confirmed_root = adapter::root(confirmed_root);
        self.lh.inner.current_epoch_observed_justified = CheckpointAndBalance::new(
            adapter::checkpoint(&self.observed_justified_checkpoint),
            self.balance_source.clone(),
        );
        self.lh.inner.previous_epoch_observed_justified = CheckpointAndBalance::new(
            adapter::checkpoint(&self.genesis_checkpoint),
            self.balance_source.clone(),
        );
    }

    /// Run the rule and require the recorded verdict.
    fn assert_confirms(&self, head_slot: u64, current_slot: u64, expected_slot: u64, label: &str) {
        let confirmed = self
            .lh
            .get_latest_confirmed::<E>(
                block_root_at(head_slot),
                &self.finalized_checkpoint,
                &self.observed_justified_checkpoint,
                Slot::new(current_slot),
                &self.proto_array,
                &self.votes,
                &BTreeSet::new(),
            )
            .unwrap_or_else(|e| panic!("{label}: rule returned an error: {e:?}"));

        assert_eq!(
            confirmed,
            block_root_at(expected_slot),
            "{label}: expected the block at slot {expected_slot}"
        );
    }
}

/// Steady state and the epoch boundary. The confirmed root advances to the head
/// or to the last block the support cleared.
#[test]
fn confirms_the_recorded_blocks_across_chain_positions() {
    let mut f = fixture(None);
    for (name, head_slot, current_slot, confirmed_slot, expected) in [
        ("steady_mid_epoch", 69u64, 70u64, 66u64, 69u64),
        ("epoch_first_slot", 63, 64, 40, 63),
        ("epoch_catch_up", 65, 66, 40, 65),
        ("missed_epoch_start", 63, 68, 40, 63),
    ] {
        f.apply(head_slot, confirmed_slot);
        f.assert_confirms(head_slot, current_slot, expected, name);
    }
}

/// A missed slot, where the empty-slot support discount applies and an
/// off-by-one in the ancestor walk would show up.
#[test]
fn confirms_the_recorded_blocks_across_a_missed_slot() {
    let mut f = fixture(Some(60));
    for (name, head_slot, current_slot, confirmed_slot, expected) in [
        ("after_gap", 61u64, 62u64, 56u64, 61u64),
        ("spanning_gap", 62, 63, 58, 62),
        ("gap_then_epoch", 63, 66, 40, 63),
    ] {
        f.apply(head_slot, confirmed_slot);
        f.assert_confirms(head_slot, current_slot, expected, name);
    }
}

/// A confirmed root left too far behind reverts to the finalized block. This is
/// the least-exercised branch and the one most likely to drift.
#[test]
fn reverts_to_finalized_when_the_confirmed_root_falls_behind() {
    let mut f = fixture(None);
    for (name, head_slot, current_slot, confirmed_slot, expected) in [
        ("confirmed_two_epochs_back", 69u64, 70u64, 5u64, 0u64),
        ("confirmed_at_genesis", 69, 70, 0, 0),
    ] {
        f.apply(head_slot, confirmed_slot);
        f.assert_confirms(head_slot, current_slot, expected, name);
    }
}
