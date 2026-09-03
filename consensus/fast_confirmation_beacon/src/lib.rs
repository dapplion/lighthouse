//! Lighthouse's side of the Fast Confirmation Rule.
//!
//! The rule itself is `fast_confirmation`, a `no_std` crate that a zkVM guest
//! compiles too. This crate owns one and feeds it: it builds the balance
//! snapshots from a `BeaconState`, lends it `ProtoArray` and the vote trackers
//! without copying them, converts the types at the boundary, and logs and
//! counts what the rule reports.

pub mod adapter;
mod balance_source;
pub mod metrics;

pub use balance_source::BalanceSourceKey;
pub use fast_confirmation::{BalanceSourceData, CheckpointAndBalance, Outcome};

use adapter::{Assignments, ProtoArrayStore, Spec, VoteTrackers};
use fast_confirmation as core_rule;
use proto_array::core::{ProtoArray, VoteTracker};
use safe_arith::ArithError;
use std::collections::BTreeSet;
use tracing::{debug, debug_span};
use types::{BeaconState, Checkpoint, Epoch, EthSpec, Hash256, Slot, SlotAssignments};

#[derive(Debug, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Error {
    NodeNotFound(Hash256),
    NodeHasNoBlockHash(Hash256),
    ParentRootNotFound(Hash256),
    UnableToObtainHeadState(String),
    UnableToObtainCheckpointState(String),
    MissingCheckpointState(Checkpoint),
    AncestorNotFound { block: Hash256, slot: Slot },
    UnrealizedJustificationNotFound(Hash256),
    CheckpointBlockNotFound { block: Hash256, epoch: Epoch },
    HeadCheckpointNotFound(Hash256),
    MissingPrecomputedScore(Hash256),
    BlockEpochNone(Hash256),
    CommitteeCacheUninitialized(String),
    BlockRootsOutOfBounds(String),
    SlashingsOutOfBounds(String),
    IndexOutOfBounds(usize),
    SlotAssignmentsError,
    ArithError(ArithError),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

impl From<core_rule::Error> for Error {
    fn from(e: core_rule::Error) -> Self {
        use adapter::{from_checkpoint as cp, hash as h};
        match e {
            core_rule::Error::NodeNotFound(r) => Error::NodeNotFound(h(r)),
            core_rule::Error::NodeHasNoBlockHash(r) => Error::NodeHasNoBlockHash(h(r)),
            core_rule::Error::ParentRootNotFound(r) => Error::ParentRootNotFound(h(r)),
            core_rule::Error::UnableToObtainHeadState(s) => Error::UnableToObtainHeadState(s),
            core_rule::Error::UnableToObtainCheckpointState(s) => {
                Error::UnableToObtainCheckpointState(s)
            }
            core_rule::Error::MissingCheckpointState(c) => Error::MissingCheckpointState(cp(c)),
            core_rule::Error::AncestorNotFound { block, slot } => Error::AncestorNotFound {
                block: h(block),
                slot: Slot::new(slot.as_u64()),
            },
            core_rule::Error::UnrealizedJustificationNotFound(r) => {
                Error::UnrealizedJustificationNotFound(h(r))
            }
            core_rule::Error::CheckpointBlockNotFound { block, epoch } => {
                Error::CheckpointBlockNotFound {
                    block: h(block),
                    epoch: Epoch::new(epoch.as_u64()),
                }
            }
            core_rule::Error::HeadCheckpointNotFound(r) => Error::HeadCheckpointNotFound(h(r)),
            core_rule::Error::MissingPrecomputedScore(r) => Error::MissingPrecomputedScore(h(r)),
            core_rule::Error::BlockEpochNone(r) => Error::BlockEpochNone(h(r)),
            core_rule::Error::CommitteeCacheUninitialized(s) => {
                Error::CommitteeCacheUninitialized(s)
            }
            core_rule::Error::BlockRootsOutOfBounds(s) => Error::BlockRootsOutOfBounds(s),
            core_rule::Error::SlashingsOutOfBounds(s) => Error::SlashingsOutOfBounds(s),
            core_rule::Error::IndexOutOfBounds(i) => Error::IndexOutOfBounds(i),
            core_rule::Error::SlotAssignmentsError(_) => Error::SlotAssignmentsError,
            core_rule::Error::ArithError(_) => Error::ArithError(ArithError::Overflow),
        }
    }
}

/// The rule, with what Lighthouse keeps beside it.
#[derive(Debug)]
pub struct FastConfirmationRule {
    pub inner: core_rule::FastConfirmationRule<Assignments>,
    /// Keys the head balance snapshot on the head's epoch boundary root -- or the
    /// head block root itself once the epoch contains a slashing -- so a reorg
    /// past the previous-epoch boundary or an intra-epoch slashing rebuilds it.
    head_balance_key: BalanceSourceKey,
}

impl FastConfirmationRule {
    /// Initialize FCR from the finalized checkpoint, seeding both observed-justified balance
    /// sources from `checkpoint_state` as the spec does. `byzantine_threshold` is clamped
    /// to [0, 25].
    pub fn new<E: EthSpec>(
        head_root: Hash256,
        head_state: &BeaconState<E>,
        slot_assignments: SlotAssignments,
        finalized_checkpoint: Checkpoint,
        checkpoint_state: &BeaconState<E>,
        byzantine_threshold: u64,
        proposer_score_boost: u64,
    ) -> Result<Self, Error> {
        let head_balance_key = BalanceSourceKey::compute(head_state, head_root)?;
        let inner = core_rule::FastConfirmationRule::new(
            balance_source::build(head_state),
            Assignments(slot_assignments),
            adapter::checkpoint(&finalized_checkpoint),
            balance_source::build(checkpoint_state),
            byzantine_threshold,
            proposer_score_boost,
        )?;
        Ok(Self {
            inner,
            head_balance_key,
        })
    }

    /// Enable spec test mode: `on_fast_confirmation` still tracks variables but
    /// does not update `confirmed_root`. Call `get_latest_confirmed` explicitly
    /// when the test needs the confirmation result.
    pub fn set_spec_test_mode(&mut self, enabled: bool) {
        self.inner.set_spec_test_mode(enabled)
    }

    /// Directly set head balances for synthetic-data benchmarks; not used in production.
    pub fn test_set_head_balance_source(&mut self, balance_source: BalanceSourceData) {
        self.inner.test_set_head_balance_source(balance_source)
    }

    /// Top-level entry point. Spec: `on_fast_confirmation(fcr_store)`.
    ///
    /// Called after head selection, while the fork-choice read lock is held.
    /// All parameters are borrowed from fork choice. The `head_state` is used to
    /// rebuild the head balance source and committee assignments; `checkpoint_state`
    /// backs the observed-justified balance source at the epoch-boundary rotation
    /// (spec: `store.checkpoint_states[checkpoint]`). Callers should obtain the
    /// required checkpoint via `checkpoint_state_needed` and may pass `None` when
    /// it returns `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn on_fast_confirmation<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
        head_state: &BeaconState<E>,
        slot_assignments: &SlotAssignments,
        checkpoint_state: Option<&BeaconState<E>>,
    ) -> Result<(), Error> {
        let _span = debug_span!("fcr_on_fast_confirmation", slot = %current_slot).entered();

        let (head_balance_source, checkpoint_balance) =
            self.prepare_balances::<E>(head_root, head_state, current_slot, checkpoint_state)?;

        let previous_confirmed = self.confirmed_root();
        let outcome = self.inner.on_fast_confirmation::<Spec<E>, _>(
            adapter::root(head_root),
            &adapter::checkpoint(finalized_checkpoint),
            &adapter::checkpoint(unrealized_justified_checkpoint),
            adapter::slot(current_slot),
            &ProtoArrayStore { proto_array },
            &VoteTrackers(votes),
            equivocating_indices,
            head_balance_source,
            Assignments(slot_assignments.clone()),
            checkpoint_balance,
        )?;
        self.report(
            outcome,
            previous_confirmed,
            self.confirmed_root(),
            finalized_checkpoint,
            current_slot,
        );
        Ok(())
    }

    /// Rebuild the head balance snapshot if its key moved, and the checkpoint
    /// snapshot if this slot rotates onto a new checkpoint. `None` means the
    /// rule keeps what it has.
    fn prepare_balances<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        head_state: &BeaconState<E>,
        current_slot: Slot,
        checkpoint_state: Option<&BeaconState<E>>,
    ) -> Result<(Option<BalanceSourceData>, Option<BalanceSourceData>), Error> {
        let head_balance_key = BalanceSourceKey::compute(head_state, head_root)?;
        let head_balance_source = (self.head_balance_key != head_balance_key).then(|| {
            let _span = debug_span!("fcr_rebuild_head_balance").entered();
            balance_source::build(head_state)
        });
        self.head_balance_key = head_balance_key;

        let checkpoint_balance = match (
            self.checkpoint_state_needed::<E>(current_slot),
            checkpoint_state,
        ) {
            (None, _) => None,
            (Some(checkpoint), None) => return Err(Error::MissingCheckpointState(checkpoint)),
            (Some(checkpoint), Some(state)) => {
                // Sanity: the supplied state must be the checkpoint's state, advanced to the
                // checkpoint's epoch.
                if state.current_epoch() != checkpoint.epoch {
                    return Err(Error::MissingCheckpointState(checkpoint));
                }
                let _span = debug_span!("fcr_rebuild_current_balance").entered();
                Some(balance_source::build(state))
            }
        };
        Ok((head_balance_source, checkpoint_balance))
    }

    /// Spec: `update_fast_confirmation_variables`, without the confirmation
    /// that follows it in `on_fast_confirmation`.
    pub fn update_fast_confirmation_variables<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        head_state: &BeaconState<E>,
        slot_assignments: &SlotAssignments,
        checkpoint_state: Option<&BeaconState<E>>,
    ) -> Result<(), Error> {
        let _span = debug_span!("fcr_update_variables", slot = %current_slot).entered();
        let (head_balance_source, checkpoint_balance) =
            self.prepare_balances::<E>(head_root, head_state, current_slot, checkpoint_state)?;
        Ok(self.inner.update_fast_confirmation_variables::<Spec<E>>(
            adapter::root(head_root),
            &adapter::checkpoint(unrealized_justified_checkpoint),
            adapter::slot(current_slot),
            head_balance_source,
            Assignments(slot_assignments.clone()),
            checkpoint_balance,
        )?)
    }

    /// Slot of the most recent per-slot FCR update (`update_fast_confirmation_variables`), used to
    /// sample per-slot metrics exactly once per slot.
    pub fn last_update_slot(&self) -> Option<Slot> {
        self.inner.last_update_slot().map(|s| Slot::new(s.as_u64()))
    }

    /// The checkpoint whose state (spec: `store.checkpoint_states[checkpoint]`) must be
    /// supplied to `on_fast_confirmation` at `current_slot`, or `None` if no state is
    /// required — either no rotation happens this slot, or the rotating checkpoint is
    /// unchanged so its existing balance snapshot is reused.
    pub fn checkpoint_state_needed<E: EthSpec>(&self, current_slot: Slot) -> Option<Checkpoint> {
        self.inner
            .checkpoint_state_needed::<Spec<E>>(adapter::slot(current_slot))
            .map(adapter::from_checkpoint)
    }

    /// Spec: get_latest_confirmed
    #[allow(clippy::too_many_arguments)]
    pub fn get_latest_confirmed<E: EthSpec>(
        &self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Hash256, Error> {
        let _span = debug_span!("fcr_get_latest_confirmed").entered();
        let (confirmed, outcome) = self.inner.get_latest_confirmed::<Spec<E>, _>(
            adapter::root(head_root),
            &adapter::checkpoint(finalized_checkpoint),
            &adapter::checkpoint(unrealized_justified_checkpoint),
            adapter::slot(current_slot),
            &ProtoArrayStore { proto_array },
            &VoteTrackers(votes),
            equivocating_indices,
        )?;
        let confirmed = adapter::hash(confirmed);
        self.report(
            outcome,
            self.confirmed_root(),
            confirmed,
            finalized_checkpoint,
            current_slot,
        );
        Ok(confirmed)
    }

    /// Spec: `get_current_target_score`.
    pub fn get_current_target_score<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        Ok(self.inner.get_current_target_score::<Spec<E>, _>(
            adapter::root(head_root),
            adapter::slot(current_slot),
            &ProtoArrayStore { proto_array },
            &VoteTrackers(votes),
            equivocating_indices,
        )?)
    }

    /// Fed into `safe_block_hash` for the EL.
    pub fn confirmed_root(&self) -> Hash256 {
        adapter::hash(self.inner.confirmed_root)
    }

    pub fn set_confirmed_root(&mut self, root: Hash256) {
        self.inner.confirmed_root = adapter::root(root);
    }

    pub fn previous_epoch_observed_justified_checkpoint(&self) -> Checkpoint {
        adapter::from_checkpoint(self.inner.previous_epoch_observed_justified.checkpoint())
    }

    pub fn current_epoch_observed_justified_checkpoint(&self) -> Checkpoint {
        adapter::from_checkpoint(self.inner.current_epoch_observed_justified.checkpoint())
    }

    pub fn previous_epoch_greatest_unrealized_checkpoint(&self) -> Checkpoint {
        adapter::from_checkpoint(self.inner.previous_epoch_greatest_unrealized_checkpoint)
    }

    pub fn previous_slot_head(&self) -> Hash256 {
        adapter::hash(self.inner.previous_slot_head)
    }

    pub fn current_slot_head(&self) -> Hash256 {
        adapter::hash(self.inner.current_slot_head)
    }

    /// What the rule reported, logged and counted as it always was.
    fn report(
        &self,
        outcome: Outcome,
        previous_confirmed: Hash256,
        confirmed: Hash256,
        finalized_checkpoint: &Checkpoint,
        current_slot: Slot,
    ) {
        if let Some(reason) = outcome.reverted_to_finalized {
            debug!(
                prev_confirmed = %previous_confirmed,
                finalized = %finalized_checkpoint.root,
                slot = %current_slot,
                reason = reason,
                "FCR reverted to finalized"
            );
            metrics::inc_counter_vec(&metrics::FCR_REVERT_TO_FINALIZED, &[reason]);
        }
        if outcome.restarted_from_justified {
            let justified = self.current_epoch_observed_justified_checkpoint();
            debug!(
                prev_confirmed = %previous_confirmed,
                justified = %justified.root,
                justified_epoch = %justified.epoch,
                "FCR restarted from observed justified"
            );
            metrics::inc_counter(&metrics::FCR_RESTART_FROM_JUSTIFIED);
        }
        if outcome.advanced {
            debug!(
                confirmed = %confirmed,
                prev = %previous_confirmed,
                "FCR advanced"
            );
            metrics::inc_counter(&metrics::FCR_ADVANCE);
        }
        if let Some((support, safety_threshold)) = outcome.unconfirmed_support
            && safety_threshold > 0
        {
            metrics::observe(
                &metrics::FCR_UNCONFIRMED_SUPPORT_RATIO,
                support as f64 / safety_threshold as f64,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test: a slashing processed mid-epoch must rebuild the head balance source
    /// even though the epoch boundary root is unchanged for the rest of the epoch (the FCR analogue
    /// of the unrealized-checkpoints bug fixed in sigp/lighthouse#9471).
    #[test]
    fn head_balance_source_rebuilt_after_intra_epoch_slashing() {
        use state_processing::{GloasVerificationContext, per_slot_processing};
        use types::MinimalEthSpec;
        type E = MinimalEthSpec;

        let spec = E::default_spec();
        let mut state: BeaconState<E> = BeaconState::new(0, Default::default(), &spec);
        for _ in 0..32 {
            let validator = types::Validator {
                effective_balance: spec.max_effective_balance,
                activation_epoch: Epoch::new(0),
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            };
            state
                .validators_mut()
                .push(validator)
                .expect("push validator");
            state
                .balances_mut()
                .push(spec.max_effective_balance)
                .expect("push balance");
        }
        state
            .build_all_committee_caches(&spec)
            .expect("committee caches");

        // Advance to a mid-epoch slot: at an epoch start the dependent root changes and would
        // rebuild the source regardless, masking the bug.
        let mid_epoch_slot = Slot::new(E::slots_per_epoch() + 4);
        while state.slot() < mid_epoch_slot {
            per_slot_processing(
                &mut state,
                None,
                GloasVerificationContext::FullVerification,
                &spec,
            )
            .expect("should advance slot");
        }
        state
            .build_all_committee_caches(&spec)
            .expect("committee caches");

        let checkpoint = Checkpoint {
            epoch: state.current_epoch(),
            root: Hash256::repeat_byte(1),
        };
        let head_root_a = Hash256::repeat_byte(2);
        let slot_assignments = SlotAssignments::new(&state, &spec, None).expect("slot assignments");
        let mut fcr = FastConfirmationRule::new::<E>(
            head_root_a,
            &state,
            slot_assignments.clone(),
            checkpoint,
            &state,
            25,
            40,
        )
        .expect("fcr initialization");

        assert!(matches!(
            fcr.head_balance_key,
            BalanceSourceKey::NoSlashings { .. }
        ));
        assert!(!fcr.inner.head_balance_source().slashed[0]);
        let pre_slashing_key = fcr.head_balance_key;

        // Simulate a slashing landing in a new head block within the same epoch (mirroring what
        // `slash_validator` does to the state).
        let effective_balance = spec.max_effective_balance;
        state.get_validator_mut(0).expect("validator 0").slashed = true;
        state
            .set_slashings(state.current_epoch(), effective_balance)
            .expect("set slashings");

        let head_root_b = Hash256::repeat_byte(3);
        fcr.update_fast_confirmation_variables::<E>(
            head_root_b,
            &checkpoint,
            state.slot(),
            &state,
            &slot_assignments,
            None,
        )
        .expect("update variables");

        // The regression assertion: the balance source must have been rebuilt.
        assert!(fcr.inner.head_balance_source().slashed[0]);
        assert_eq!(
            fcr.head_balance_key,
            BalanceSourceKey::SlashingsPresent {
                head_block_root: head_root_b
            }
        );
        assert_ne!(fcr.head_balance_key, pre_slashing_key);

        // While the epoch contains a slashing, every head change rebuilds the source.
        let head_root_c = Hash256::repeat_byte(4);
        fcr.update_fast_confirmation_variables::<E>(
            head_root_c,
            &checkpoint,
            state.slot(),
            &state,
            &slot_assignments,
            None,
        )
        .expect("update variables");
        assert_eq!(
            fcr.head_balance_key,
            BalanceSourceKey::SlashingsPresent {
                head_block_root: head_root_c
            }
        );
    }
}
