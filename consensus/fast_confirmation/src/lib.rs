//! Fast Confirmation Rule (FCR) for Ethereum consensus.
//!
//! Implements the Fast Confirmation Rule from the latest merged consensus-specs. FCR is a pure read-only
//! observer of fork-choice state that computes a `confirmed_root` — a block guaranteed
//! to remain canonical under standard assumptions (synchrony + <25% Byzantine).
//!
//! This module just reads proto_array, votes, and checkpoints via shared references and writes
//! only its own state.
//!
//! ## Spec divergences (performance optimizations)
//!
//! We diverge in several ways, all behaviorally equivalent:
//!
//! 1. **Batch score precomputation** (`precompute_chain_attestation_scores`): iterates
//!    validators once, walks each vote to the deepest canonical chain block, then builds
//!    a suffix-sum score array.
//!
//! 2. **Cached spec helpers**: `is_one_confirmed` still reads as
//!    `support > compute_safety_threshold`, but `get_attestation_score` is backed by a
//!    precomputed chain score cache. The FFG predicates compute `compute_honest_ffg_support`
//!    internally; their call sites are short-circuited, so the O(V) FFG sweep only runs near
//!    epoch boundaries (and at most a couple of times) rather than every slot.
//!
//! 3. **Vote-root balance aggregation** (`optimizations::RootBalanceMap`): before ancestor
//!    lookups, validators with the same vote root (or root+epoch) are collapsed into one
//!    balance. Real mainnet votes are scattered by validator index, so caching only the previous
//!    root thrashes; aggregation turns ~1M per-validator ancestor/checkpoint lookups into one
//!    lookup per distinct vote. This is a readability deviation from the spec loop, but is kept
//!    because the 1M-validator `get_latest_confirmed` benches improve by ~28-82%.
//!
//! 4. **Snapshot balance sources** (`BalanceSourceData`): the current/previous observed-justified
//!    sources are rebuilt only at the epoch-boundary rotation (bundled with their checkpoint in
//!    `CheckpointAndBalance`), and the head source only when its `BalanceSourceKey` changes
//!    (the epoch boundary root normally, per head block once the epoch contains a slashing) — instead
//!    of re-scanning the validator set every slot.
//!
//! The visible algorithm deliberately keeps the spec function names and control-flow shape;
//! the caches are implementation details behind those helpers.

pub mod adapter;
mod balance_source;
pub mod metrics;
pub mod optimizations;

use adapter::Assignments;
pub use balance_source::{BalanceSourceData, BalanceSourceKey};
use fast_confirmation_core as core_rule;
pub use optimizations::CheckpointAndBalance;

use proto_array::core::{ProtoArray, VoteTracker};
use safe_arith::{ArithError, SafeArith};
use std::collections::BTreeSet;
use tracing::{debug, debug_span};
use types::{BeaconState, BeaconStateError, Checkpoint, EthSpec, Hash256, Slot, SlotAssignments};

#[derive(Debug, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Error {
    NodeNotFound(Hash256),
    NodeHasNoBlockHash(Hash256),
    ParentRootNotFound(Hash256),
    UnableToObtainHeadState(String),
    UnableToObtainCheckpointState(String),
    MissingCheckpointState(Checkpoint),
    AncestorNotFound {
        block: Hash256,
        slot: Slot,
    },
    UnrealizedJustificationNotFound(Hash256),
    CheckpointBlockNotFound {
        block: Hash256,
        epoch: types::Epoch,
    },
    HeadCheckpointNotFound(Hash256),
    MissingPrecomputedScore(Hash256),
    BlockEpochNone(Hash256),
    CommitteeCacheUninitialized(String),
    BlockRootsOutOfBounds(String),
    SlashingsOutOfBounds(String),
    IndexOutOfBounds(usize),
    SlotAssignmentsError(BeaconStateError),
    ArithError(ArithError),
    /// An error the ported core raised that has no Lighthouse-side equivalent.
    CoreRule(String),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

impl From<fast_confirmation_core::ArithError> for Error {
    fn from(_: fast_confirmation_core::ArithError) -> Self {
        Error::ArithError(ArithError::Overflow)
    }
}

/// The Fast Confirmation Rule state
#[derive(Debug)]
pub struct FastConfirmationRule {
    // === Output ===
    /// Fed into `safe_block_hash` for the EL.
    pub confirmed_root: Hash256,

    // === Tracking state (spec's 6 new store fields) ===
    /// Spec `previous_epoch_observed_justified_checkpoint` with its `get_previous_balance_source`
    /// snapshot; used to re-confirm.
    pub previous_epoch_observed_justified: CheckpointAndBalance,
    /// Spec `current_epoch_observed_justified_checkpoint` with its `get_current_balance_source`
    /// snapshot; used to advance.
    pub current_epoch_observed_justified: CheckpointAndBalance,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Hash256,
    pub current_slot_head: Hash256,

    // === Config ===
    pub byzantine_threshold: u64,
    /// Proposer score boost percentage from ChainSpec (e.g. 40 for mainnet).
    proposer_score_boost: u64,

    // === Committee data from head state ===
    /// Per-validator committee slot assignments across the last 3 epochs.
    /// Used by `get_block_support_between_slots` and `compute_adversarial_weight`.
    slot_assignments: Assignments,

    // === FFG data from the head state ===
    /// Built from the spec's `get_pulled_up_head_state`. Keyed (via `BalanceSourceData.key`)
    /// on the head's epoch boundary root — or the head block root itself once the epoch contains a
    /// slashing — so a reorg past the previous-epoch boundary or an intra-epoch slashing
    /// rebuilds it.
    head_balance_source: BalanceSourceData,

    // === Internal bookkeeping ===
    /// The last slot at which `update_fast_confirmation_variables` ran.
    /// Prevents double-rotation when `recompute_head` runs multiple times per slot.
    /// `None` means no update has occurred yet (avoids using Slot(0) as sentinel,
    /// since slot 0 is a real slot with real committee assignments).
    last_update_slot: Option<Slot>,

    /// When `true`, `on_fast_confirmation` updates tracking variables but skips
    /// the `get_latest_confirmed` call. The spec test runner runs FCR implicitly
    /// at the start of each slot; the Lighthouse test harness mirrors that by
    /// calling `get_latest_confirmed` explicitly per check, so the auto-run is
    /// disabled here. Always `false` in production.
    spec_test_mode: bool,
}

impl FastConfirmationRule {
    /// Maximum valid value for `byzantine_threshold` (25%).
    const MAX_BYZANTINE_THRESHOLD: u64 = 25;

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
        let byzantine_threshold = byzantine_threshold.min(Self::MAX_BYZANTINE_THRESHOLD);
        // Sanity: the supplied state must be the checkpoint's state, advanced to the
        // checkpoint's epoch.
        if checkpoint_state.current_epoch() != finalized_checkpoint.epoch {
            return Err(Error::MissingCheckpointState(finalized_checkpoint));
        }
        let checkpoint_balance =
            BalanceSourceData::new(checkpoint_state, finalized_checkpoint.root)?;
        Ok(Self {
            confirmed_root: finalized_checkpoint.root,
            previous_epoch_observed_justified: CheckpointAndBalance::new(
                finalized_checkpoint,
                checkpoint_balance.clone(),
            ),
            current_epoch_observed_justified: CheckpointAndBalance::new(
                finalized_checkpoint,
                checkpoint_balance,
            ),
            previous_epoch_greatest_unrealized_checkpoint: finalized_checkpoint,
            previous_slot_head: finalized_checkpoint.root,
            current_slot_head: finalized_checkpoint.root,
            byzantine_threshold,
            proposer_score_boost,
            slot_assignments: Assignments(slot_assignments),
            head_balance_source: BalanceSourceData::new(head_state, head_root)?,
            last_update_slot: None,
            spec_test_mode: false,
        })
    }

    /// Enable spec test mode: `on_fast_confirmation` still tracks variables but
    /// does not update `confirmed_root`. Call `get_latest_confirmed` explicitly
    /// when the test needs the confirmation result.
    pub fn set_spec_test_mode(&mut self, enabled: bool) {
        self.spec_test_mode = enabled;
    }

    /// Directly set head balances for synthetic-data benchmarks; not used in production.
    pub fn test_set_head_balance_source(&mut self, balance_source: BalanceSourceData) {
        self.head_balance_source = balance_source;
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

        self.update_fast_confirmation_variables::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
            head_state,
            slot_assignments,
            checkpoint_state,
        )?;

        if !self.spec_test_mode {
            let _span = debug_span!("fcr_get_latest_confirmed").entered();
            self.confirmed_root = self.get_latest_confirmed::<E>(
                head_root,
                finalized_checkpoint,
                unrealized_justified_checkpoint,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )?;
        }

        Ok(())
    }

    /// Slot of the most recent per-slot FCR update (`update_fast_confirmation_variables`), used to
    /// sample per-slot metrics exactly once per slot.
    pub fn last_update_slot(&self) -> Option<Slot> {
        self.last_update_slot
    }

    /// True iff `update_fast_confirmation_variables` will rotate the observed-justified
    /// checkpoint pairs when run at `current_slot` (once per slot, at the first slot of an
    /// epoch).
    fn will_rotate<E: EthSpec>(&self, current_slot: Slot) -> bool {
        self.last_update_slot.is_none_or(|s| current_slot > s)
            && is_start_slot_at_epoch::<E>(current_slot)
    }

    /// The checkpoint whose state (spec: `store.checkpoint_states[checkpoint]`) must be
    /// supplied to `on_fast_confirmation` at `current_slot`, or `None` if no state is
    /// required — either no rotation happens this slot, or the rotating checkpoint is
    /// unchanged so its existing balance snapshot is reused.
    pub fn checkpoint_state_needed<E: EthSpec>(&self, current_slot: Slot) -> Option<Checkpoint> {
        (self.will_rotate::<E>(current_slot)
            && self.previous_epoch_greatest_unrealized_checkpoint
                != self.current_epoch_observed_justified.checkpoint())
        .then_some(self.previous_epoch_greatest_unrealized_checkpoint)
    }

    /// Spec: `update_fast_confirmation_variables`.
    fn update_fast_confirmation_variables<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        head_state: &BeaconState<E>,
        slot_assignments: &SlotAssignments,
        checkpoint_state: Option<&BeaconState<E>>,
    ) -> Result<(), Error> {
        let _span = debug_span!("fcr_update_variables", slot = %current_slot).entered();

        self.slot_assignments = Assignments(slot_assignments.clone());

        let head_balance_key = BalanceSourceKey::compute(head_state, head_root)?;
        if self.head_balance_source.key != head_balance_key {
            let _span = debug_span!("fcr_rebuild_head_balance").entered();
            self.head_balance_source = BalanceSourceData::new(head_state, head_root)?;
        }

        // Spec: update_fast_confirmation_variables must be called at most once per slot.
        if self.last_update_slot.is_none_or(|s| current_slot > s) {
            // Rotate the slot heads unconditionally, once per slot (spec).
            self.previous_slot_head = self.current_slot_head;
            self.current_slot_head = head_root;

            // At last slot of epoch: snapshot greatest unrealized justified.
            if is_start_slot_at_epoch::<E>(current_slot.safe_add(1)?) {
                self.previous_epoch_greatest_unrealized_checkpoint =
                    *unrealized_justified_checkpoint;
            }

            // At first slot of epoch: rotate the (checkpoint, balances) pairs. `previous` takes
            // `current`'s snapshot (spec-equal, no O(V) re-derive); `current` is rebuilt in one
            // step so the pair stays coherent, with balances from the new checkpoint's state
            // (spec: `store.checkpoint_states[checkpoint]`) evaluated at the checkpoint's epoch.
            // The first conjunct of `will_rotate` is always true inside the once-per-slot guard.
            if self.will_rotate::<E>(current_slot) {
                let new_current_cp = self.previous_epoch_greatest_unrealized_checkpoint;
                let new_current =
                    if new_current_cp == self.current_epoch_observed_justified.checkpoint() {
                        // Same checkpoint keys the same `checkpoint_states` entry — reuse the snapshot.
                        self.current_epoch_observed_justified.clone()
                    } else {
                        let checkpoint_state = checkpoint_state
                            .ok_or(Error::MissingCheckpointState(new_current_cp))?;
                        // Sanity: the supplied state must be the checkpoint's state, advanced to the
                        // checkpoint's epoch.
                        if checkpoint_state.current_epoch() != new_current_cp.epoch {
                            return Err(Error::MissingCheckpointState(new_current_cp));
                        }
                        CheckpointAndBalance::new(new_current_cp, {
                            let _span = debug_span!("fcr_rebuild_current_balance").entered();
                            BalanceSourceData::new(checkpoint_state, new_current_cp.root)?
                        })
                    };
                self.previous_epoch_observed_justified =
                    std::mem::replace(&mut self.current_epoch_observed_justified, new_current);
            }

            self.last_update_slot = Some(current_slot);
        }

        Ok(())
    }

    /// Spec: get_latest_confirmed
    #[allow(clippy::too_many_arguments)]
    /// Spec: `get_latest_confirmed`.
    ///
    /// The rule itself lives in `fast_confirmation_core`, which the zkVM guest
    /// compiles too. This lends it Lighthouse's state rather than copying it:
    /// the balance snapshots are per-validator vectors, so a per-call copy would
    /// cost tens of megabytes at mainnet size.
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
        let store = adapter::ProtoArrayStore { proto_array };
        let previous_confirmed = self.confirmed_root;
        let (confirmed, outcome) = self.core_view::<E>().get_latest_confirmed_with_outcome(
            adapter::root(head_root),
            &adapter::checkpoint(finalized_checkpoint),
            &adapter::checkpoint(unrealized_justified_checkpoint),
            adapter::slot(current_slot),
            &store,
            &adapter::VoteTrackers(votes),
            equivocating_indices,
        )?;
        let confirmed = adapter::hash(confirmed);

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
            debug!(
                justified_epoch = %self.current_epoch_observed_justified.checkpoint().epoch,
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
        let store = adapter::ProtoArrayStore { proto_array };
        Ok(self.core_view::<E>().get_current_target_score(
            adapter::root(head_root),
            adapter::slot(current_slot),
            &store,
            &adapter::VoteTrackers(votes),
            equivocating_indices,
        )?)
    }

    /// Lend this state to the core rule. Only the 32-byte roots are copied.
    fn core_view<E: EthSpec>(
        &self,
    ) -> core_rule::rule::RuleView<'_, adapter::Assignments, BalanceSourceData> {
        core_rule::rule::RuleView {
            confirmed_root: adapter::root(self.confirmed_root),
            previous_epoch_observed_justified: core_rule::rule::CheckpointAndBalanceRef::new(
                adapter::checkpoint(&self.previous_epoch_observed_justified.checkpoint()),
                self.previous_epoch_observed_justified.balances(),
            ),
            current_epoch_observed_justified: core_rule::rule::CheckpointAndBalanceRef::new(
                adapter::checkpoint(&self.current_epoch_observed_justified.checkpoint()),
                self.current_epoch_observed_justified.balances(),
            ),
            previous_slot_head: adapter::root(self.previous_slot_head),
            byzantine_threshold: self.byzantine_threshold,
            proposer_score_boost: self.proposer_score_boost,
            slot_assignments: &self.slot_assignments,
            head_balance_source: &self.head_balance_source,
            slots_per_epoch: E::slots_per_epoch(),
        }
    }
}

/// Spec: `is_start_slot_at_epoch`.
fn is_start_slot_at_epoch<E: EthSpec>(slot: Slot) -> bool {
    slot.as_u64().is_multiple_of(E::slots_per_epoch())
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Epoch, MainnetEthSpec};

    type E = MainnetEthSpec;

    #[test]
    fn test_is_start_slot_at_epoch() {
        assert!(is_start_slot_at_epoch::<E>(Slot::new(0)));
        assert!(is_start_slot_at_epoch::<E>(Slot::new(32)));
        assert!(!is_start_slot_at_epoch::<E>(Slot::new(1)));
        assert!(!is_start_slot_at_epoch::<E>(Slot::new(31)));
    }

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
            fcr.head_balance_source.key,
            BalanceSourceKey::NoSlashings { .. }
        ));
        assert!(!fcr.head_balance_source.slashed[0]);
        let pre_slashing_key = fcr.head_balance_source.key;

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
        assert!(fcr.head_balance_source.slashed[0]);
        assert_eq!(
            fcr.head_balance_source.key,
            BalanceSourceKey::SlashingsPresent {
                head_block_root: head_root_b
            }
        );
        assert_ne!(fcr.head_balance_source.key, pre_slashing_key);

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
            fcr.head_balance_source.key,
            BalanceSourceKey::SlashingsPresent {
                head_block_root: head_root_c
            }
        );
    }
}
