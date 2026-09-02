//! The fast confirmation rule, ported from `fast_confirmation` with the bodies
//! left as close to the originals as the `no_std` constraints allow.
//!
//! Three substitutions were needed and they are the only ones:
//!
//! - `E: EthSpec` becomes a `slots_per_epoch` field. The rule reads exactly one
//!   thing off the spec, and threading a generic for it forced `types` into
//!   every signature.
//! - `&ProtoArray` becomes `&S: ForkChoiceStore`. The free functions below keep
//!   Lighthouse's argument order -- `get_block_slot(root, store)` -- so the call
//!   sites in the ported bodies are unchanged text.
//! - `tracing` and `metrics` are dropped. They are host observability, and a
//!   circuit has nowhere to send them.
//!
//! Everything else -- the revert conditions, the two confirmation loops, the FFG
//! guards, the discount -- is the same code. It is meant to be read side by side
//! with the original, and anything that is not a literal transcription is
//! commented as such.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cell::OnceCell;

use crate::primitives::{Checkpoint, Epoch, Root, Slot, Votes};
use crate::store::{self, ForkChoiceStore};
use crate::{Arith, Error, Result};

// ---------------------------------------------------------------------------
// Free functions, in Lighthouse's argument order so the bodies port verbatim
// ---------------------------------------------------------------------------

fn get_block_slot<S: ForkChoiceStore>(root: Root, store: &S) -> Result<Slot> {
    store.block_slot(root)
}

fn parent_root<S: ForkChoiceStore>(root: Root, store: &S) -> Result<Root> {
    store.parent_root(root)
}

fn is_optimistic_or_invalid<S: ForkChoiceStore>(root: Root, store: &S) -> Result<bool> {
    store::is_optimistic_or_invalid(store, root)
}

fn is_ancestor<S: ForkChoiceStore>(
    block_root: Root,
    ancestor_root: Root,
    store: &S,
) -> Result<bool> {
    store::is_ancestor(store, block_root, ancestor_root)
}

fn get_ancestor<S: ForkChoiceStore>(block_root: Root, slot: Slot, store: &S) -> Result<Root> {
    store::get_ancestor(store, block_root, slot)
}

fn get_ancestor_roots<S: ForkChoiceStore>(
    block_root: Root,
    terminal_root: Root,
    store: &S,
) -> Result<Vec<Root>> {
    store::get_ancestor_roots(store, block_root, terminal_root)
}

fn unrealized_justification_of<S: ForkChoiceStore>(root: Root, store: &S) -> Result<Checkpoint> {
    store.unrealized_justified_checkpoint(root)
}

/// Spec: `get_block_epoch`.
fn get_block_epoch<S: ForkChoiceStore>(
    root: Root,
    store: &S,
    slots_per_epoch: u64,
) -> Result<Epoch> {
    Ok(get_block_slot(root, store)?.epoch(slots_per_epoch))
}

fn get_voting_source_epoch<S: ForkChoiceStore>(
    root: Root,
    current_slot: Slot,
    store: &S,
    slots_per_epoch: u64,
) -> Result<Epoch> {
    store::get_voting_source_epoch(store, root, current_slot, slots_per_epoch)
}

fn get_checkpoint_for_block<S: ForkChoiceStore>(
    block_root: Root,
    epoch: Epoch,
    store: &S,
    slots_per_epoch: u64,
) -> Option<Checkpoint> {
    store::get_checkpoint_for_block(store, block_root, epoch, slots_per_epoch)
}

fn get_current_target<S: ForkChoiceStore>(
    head_root: Root,
    current_slot: Slot,
    store: &S,
    slots_per_epoch: u64,
) -> Result<Checkpoint> {
    store::get_current_target(store, head_root, current_slot, slots_per_epoch)
}

/// Spec: `is_start_slot_at_epoch`.
fn is_start_slot_at_epoch(slot: Slot, slots_per_epoch: u64) -> bool {
    slot.as_u64().is_multiple_of(slots_per_epoch)
}

/// Spec: `compute_start_slot_at_epoch`.
fn compute_start_slot_at_epoch_spe(epoch: Epoch, slots_per_epoch: u64) -> Slot {
    epoch.start_slot(slots_per_epoch)
}

// ---------------------------------------------------------------------------
// What the caller supplies
// ---------------------------------------------------------------------------

/// `fast_confirmation::balance_source::BalanceSourceData`, less the constructor
/// that reads a `BeaconState` -- that stays host-side, because a circuit gets
/// these from a committee proof instead.
#[derive(Clone, Debug, Default)]
pub struct BalanceSourceData {
    pub total_active_balance: u64,
    pub effective_balances: Vec<u64>,
    pub slashed: Vec<bool>,
}

/// The balance snapshot the rule reads, as an interface.
///
/// Lighthouse carries an extra cache key on its own snapshot type and the guest
/// carries none, so neither can be the other. Both answer these five questions,
/// which is all the rule ever asks -- so the rule is written once against this
/// and each host lends it the data it already holds.
pub trait Balances {
    fn total_active_balance(&self) -> u64;
    fn balance(&self, index: usize) -> u64;
    fn is_slashed(&self, index: usize) -> bool;
    fn unslashed_and_active_indices(&self) -> impl Iterator<Item = (usize, u64)> + '_;
    fn active_indices(&self) -> impl Iterator<Item = usize> + '_;
}

impl Balances for BalanceSourceData {
    fn total_active_balance(&self) -> u64 {
        self.total_active_balance
    }
    fn balance(&self, index: usize) -> u64 {
        BalanceSourceData::balance(self, index)
    }
    fn is_slashed(&self, index: usize) -> bool {
        BalanceSourceData::is_slashed(self, index)
    }
    fn unslashed_and_active_indices(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        BalanceSourceData::unslashed_and_active_indices(self)
    }
    fn active_indices(&self) -> impl Iterator<Item = usize> + '_ {
        BalanceSourceData::active_indices(self)
    }
}

impl BalanceSourceData {
    pub fn balance(&self, index: usize) -> u64 {
        self.effective_balances.get(index).copied().unwrap_or(0)
    }

    pub fn is_slashed(&self, index: usize) -> bool {
        self.slashed.get(index).copied().unwrap_or(false)
    }

    /// Indices with a non-zero balance that are not slashed, which is what the
    /// spec means by an active unslashed validator.
    pub fn unslashed_and_active_indices(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.effective_balances
            .iter()
            .enumerate()
            .filter(|(i, balance)| **balance > 0 && !self.is_slashed(*i))
            .map(|(i, balance)| (i, *balance))
    }

    pub fn active_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.effective_balances
            .iter()
            .enumerate()
            .filter(|(_, balance)| **balance > 0)
            .map(|(i, _)| i)
    }
}

/// A checkpoint and the balances observed alongside it.
#[derive(Clone, Debug, Default)]
pub struct CheckpointAndBalance {
    checkpoint: Checkpoint,
    balances: BalanceSourceData,
}

impl CheckpointAndBalance {
    pub fn new(checkpoint: Checkpoint, balances: BalanceSourceData) -> Self {
        Self {
            checkpoint,
            balances,
        }
    }
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }
    pub fn balances(&self) -> &BalanceSourceData {
        &self.balances
    }
}

/// Which slots a validator attests in. `types::SlotAssignments` in Lighthouse;
/// a circuit answers it from the committee proof.
pub trait SlotAssignments {
    fn is_in_range(&self, validator_index: usize, start_slot: Slot, end_slot: Slot)
    -> Result<bool>;
}

/// Precomputed per-block attestation scores. Lighthouse builds this once per
/// chain to avoid a validator pass per candidate block; the trait keeps that
/// optimisation available to a circuit that has its own way of producing them.
pub trait AttestationScores {
    fn get_attestation_score(&self, block_root: Root) -> Option<u64>;
}

/// Spec: `get_attestation_score`.
fn get_attestation_score<A: AttestationScores>(
    block_root: Root,
    attestation_scores: &A,
) -> Result<u64> {
    attestation_scores
        .get_attestation_score(block_root)
        .ok_or(Error::MissingPrecomputedScore(block_root))
}

/// Memoises the honest FFG support for one evaluation, as the original does.
#[derive(Default)]
pub struct HonestFfgSupportCache {
    support: OnceCell<u64>,
}

impl HonestFfgSupportCache {
    pub fn new() -> Self {
        Self {
            support: OnceCell::new(),
        }
    }

    fn get_or_compute<F: FnOnce() -> Result<u64>>(&self, f: F) -> Result<u64> {
        if let Some(v) = self.support.get() {
            return Ok(*v);
        }
        let v = f()?;
        let _ = self.support.set(v);
        Ok(v)
    }
}

/// Spec: `get_attestation_score`, precomputed for a whole chain.
///
/// Port of `optimizations::precompute_chain_attestation_scores`. One pass over
/// the votes instead of one per candidate block: each vote is projected onto the
/// nearest chain position at or below it, then the positions are suffix-summed,
/// so a block's score is every vote for it or any descendant of it.
pub struct ChainAttestationScores {
    scores: crate::rootmap::RootMap<Root>,
}

impl ChainAttestationScores {
    pub fn for_chain<S: ForkChoiceStore, V: Votes + ?Sized, B: Balances>(
        store: &S,
        chain: &[Root],
        terminal_slot: Slot,
        balance_source: &B,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Self> {
        // Position of each chain member, oldest first.
        let mut position = crate::rootmap::RootMap::<Root>::new();
        for (i, root) in chain.iter().enumerate() {
            position.insert(*root, i as u64);
        }

        // Spec: `aggregate_vote_balances`. A vote for the zero root is no vote,
        // and an equivocator's is discounted -- the same two skips as upstream.
        let mut balance_by_root = crate::rootmap::RootMap::<Root>::new();
        // Walking the active set rather than the vote list fuses the balance
        // and slashed lookups into one step and skips reading a vote that
        // could not have counted.
        for (val_idx, balance) in balance_source.unslashed_and_active_indices() {
            if equivocating_indices.contains(&(val_idx as u64)) {
                continue;
            }
            let Some(vote) = votes.get(val_idx) else {
                continue;
            };
            let vote_root = vote.current_root();
            if vote_root == crate::primitives::ZERO_ROOT {
                continue;
            }
            balance_by_root.add(vote_root, balance)?;
        }

        let mut score_at_position = alloc::vec![0u64; chain.len()];
        for (vote_root, balance) in balance_by_root.iter() {
            // Project the vote onto the chain: walk towards the root until a
            // chain member is reached, or the walk drops past the terminal.
            let mut root = vote_root;
            let pos = loop {
                if let Some(p) = position.get(&root) {
                    break Some(p as usize);
                }
                let Ok((slot, parent)) = store.slot_and_parent(root) else {
                    break None;
                };
                if slot <= terminal_slot {
                    break None;
                }
                match parent {
                    Some(parent) => root = parent,
                    None => break None,
                }
            };
            let Some(pos) = pos else { continue };
            let score = score_at_position
                .get_mut(pos)
                .ok_or(Error::IndexOutOfBounds(pos))?;
            *score = score.safe_add(balance)?;
        }

        let mut scores = crate::rootmap::RootMap::<Root>::new();
        let mut running = 0u64;
        for i in (0..chain.len()).rev() {
            running = running.safe_add(score_at_position[i])?;
            scores.insert(chain[i], running);
        }
        Ok(Self { scores })
    }
}

impl AttestationScores for ChainAttestationScores {
    fn get_attestation_score(&self, block_root: Root) -> Option<u64> {
        self.scores.get(&block_root)
    }
}

/// Rich outcome of `is_one_confirmed`, kept so a host can still report why a
/// block fell short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    Confirmed,
    NotConfirmed(Unconfirmed),
}

/// Why a block failed `is_one_confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unconfirmed {
    /// The block's execution status is optimistic or invalid.
    Optimistic,
    /// Attestation support did not exceed the safety threshold.
    BelowThreshold { support: u64, safety_threshold: u64 },
}

impl Confirmation {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Confirmation::Confirmed)
    }
}

/// The Fast Confirmation Rule state.
///
/// `slot_assignments` is a type parameter rather than a concrete
/// `types::SlotAssignments`: Lighthouse reads it from a `BeaconState` cache, a
/// circuit from a committee proof, and neither should have to know about the
/// other.
#[derive(Debug)]
pub struct FastConfirmationRule<A> {
    pub confirmed_root: Root,
    pub previous_epoch_observed_justified: CheckpointAndBalance,
    pub current_epoch_observed_justified: CheckpointAndBalance,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Root,
    pub current_slot_head: Root,
    pub byzantine_threshold: u64,
    pub(crate) proposer_score_boost: u64,
    pub(crate) slot_assignments: A,
    pub(crate) head_balance_source: BalanceSourceData,
    pub(crate) last_update_slot: Option<Slot>,
    pub(crate) spec_test_mode: bool,
    /// The one value the rule reads off the chain spec. Lighthouse threads this
    /// as `E: EthSpec`, which pulls `types` into every signature.
    pub(crate) slots_per_epoch: u64,
}

/// What the rule did, beyond the root it returned.
///
/// The core cannot emit Lighthouse's metrics or logs -- it has no allocator to
/// format with and no registry to write to -- but it is the only place that
/// knows which branch fired. So it reports, and the host decides what to say.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Why the rule fell back to the finalized root, if it did.
    pub reverted_to_finalized: Option<&'static str>,
    /// The chain restarted from the current-epoch observed-justified checkpoint.
    pub restarted_from_justified: bool,
    /// The confirmed root moved forward.
    pub advanced: bool,
    /// `(support, safety_threshold)` of the block that blocked re-confirmation.
    pub unconfirmed_support: Option<(u64, u64)>,
}

/// A checkpoint paired with a *borrowed* balance snapshot.
///
/// Mirrors [`CheckpointAndBalance`]'s accessors so the rule bodies read the
/// same whether the state is owned or borrowed.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointAndBalanceRef<'a, B> {
    checkpoint: Checkpoint,
    balances: &'a B,
}

impl<'a, B> CheckpointAndBalanceRef<'a, B> {
    pub fn new(checkpoint: Checkpoint, balances: &'a B) -> Self {
        Self {
            checkpoint,
            balances,
        }
    }

    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    pub fn balances(&self) -> &'a B {
        self.balances
    }
}

/// The rule's state, borrowed rather than owned.
///
/// Every read-only part of the rule is implemented against this, so a host that
/// already holds the state in its own types can evaluate the rule without
/// copying it. The balance snapshots are per-validator vectors -- tens of
/// megabytes at mainnet size -- so a per-evaluation copy is not affordable, and
/// the roots are 32 bytes and simply copied.
#[derive(Debug, Clone, Copy)]
pub struct RuleView<'a, A, B> {
    pub confirmed_root: Root,
    pub previous_epoch_observed_justified: CheckpointAndBalanceRef<'a, B>,
    pub current_epoch_observed_justified: CheckpointAndBalanceRef<'a, B>,
    pub previous_slot_head: Root,
    pub byzantine_threshold: u64,
    pub proposer_score_boost: u64,
    pub slot_assignments: &'a A,
    pub head_balance_source: &'a B,
    pub slots_per_epoch: u64,
}

impl<'a, A, B> RuleView<'a, A, B> {
    pub(crate) fn get_previous_balance_source(&self) -> &'a B {
        self.previous_epoch_observed_justified.balances()
    }

    pub(crate) fn get_current_balance_source(&self) -> &'a B {
        self.current_epoch_observed_justified.balances()
    }
}

impl<A: SlotAssignments> FastConfirmationRule<A> {
    pub const MAX_BYZANTINE_THRESHOLD: u64 = 25;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        finalized_checkpoint: Checkpoint,
        head_root: Root,
        byzantine_threshold: u64,
        proposer_score_boost: u64,
        slot_assignments: A,
        head_balance_source: BalanceSourceData,
        slots_per_epoch: u64,
    ) -> Self {
        let byzantine_threshold = byzantine_threshold.min(Self::MAX_BYZANTINE_THRESHOLD);
        Self {
            confirmed_root: finalized_checkpoint.root,
            previous_epoch_observed_justified: CheckpointAndBalance::new(
                finalized_checkpoint,
                head_balance_source.clone(),
            ),
            current_epoch_observed_justified: CheckpointAndBalance::new(
                finalized_checkpoint,
                head_balance_source.clone(),
            ),
            previous_epoch_greatest_unrealized_checkpoint: finalized_checkpoint,
            previous_slot_head: head_root,
            current_slot_head: head_root,
            byzantine_threshold,
            proposer_score_boost,
            slot_assignments,
            head_balance_source,
            last_update_slot: None,
            spec_test_mode: false,
            slots_per_epoch,
        }
    }

    pub fn set_spec_test_mode(&mut self, enabled: bool) {
        self.spec_test_mode = enabled;
    }

    pub fn last_update_slot(&self) -> Option<Slot> {
        self.last_update_slot
    }

    /// Spec: `on_fast_confirmation`.
    ///
    /// **Adapted, not transcribed.** Lighthouse takes `&BeaconState` here and
    /// derives balances from it. A `BeaconState` cannot cross into `no_std`, and
    /// a circuit does not have one -- it has a committee proof. So the caller
    /// derives `BalanceSourceData` and passes it in. `checkpoint_balances`
    /// carries the epoch alongside, because the original checks
    /// `checkpoint_state.current_epoch() == new_current_cp.epoch` and that check
    /// is load-bearing.
    #[allow(clippy::too_many_arguments)]
    pub fn on_fast_confirmation<S: ForkChoiceStore, V: Votes + ?Sized>(
        &mut self,
        head_root: Root,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
        head_balance_source: BalanceSourceData,
        slot_assignments: A,
        checkpoint_balances: Option<(Epoch, BalanceSourceData)>,
    ) -> Result<()> {
        self.update_fast_confirmation_variables(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
            head_balance_source,
            slot_assignments,
            checkpoint_balances,
        )?;

        if !self.spec_test_mode {
            self.confirmed_root = self.view().get_latest_confirmed(
                head_root,
                finalized_checkpoint,
                unrealized_justified_checkpoint,
                current_slot,
                store,
                votes,
                equivocating_indices,
            )?;
        }

        Ok(())
    }

    /// True iff `update_fast_confirmation_variables` will rotate the observed-justified
    /// checkpoint pairs when run at `current_slot` (once per slot, at the first slot of an
    /// epoch).
    fn will_rotate(&self, current_slot: Slot) -> bool {
        self.last_update_slot.is_none_or(|s| current_slot > s)
            && is_start_slot_at_epoch(current_slot, self.slots_per_epoch)
    }

    /// The checkpoint whose state (spec: `store.checkpoint_states[checkpoint]`) must be
    /// supplied to `on_fast_confirmation` at `current_slot`, or `None` if no state is
    /// required — either no rotation happens this slot, or the rotating checkpoint is
    /// unchanged so its existing balance snapshot is reused.
    pub fn checkpoint_state_needed(&self, current_slot: Slot) -> Option<Checkpoint> {
        (self.will_rotate(current_slot)
            && self.previous_epoch_greatest_unrealized_checkpoint
                != self.current_epoch_observed_justified.checkpoint())
        .then_some(self.previous_epoch_greatest_unrealized_checkpoint)
    }

    /// Spec: the variable rotation `on_fast_confirmation` performs before
    /// evaluating. **Adapted** for the same reason as its caller: the balance
    /// sources arrive derived.
    fn update_fast_confirmation_variables(
        &mut self,
        head_root: Root,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        head_balance_source: BalanceSourceData,
        slot_assignments: A,
        checkpoint_balances: Option<(Epoch, BalanceSourceData)>,
    ) -> Result<()> {
        self.slot_assignments = slot_assignments;
        // Lighthouse skips the rebuild when `BalanceSourceKey` is unchanged.
        // That key is a hash of state fields, so the caller -- which has the
        // state -- is the only one that can compute it. It decides.
        self.head_balance_source = head_balance_source;

        if self.last_update_slot.is_none_or(|s| current_slot > s) {
            self.previous_slot_head = self.current_slot_head;
            self.current_slot_head = head_root;

            if is_start_slot_at_epoch(current_slot.safe_add(1u64)?, self.slots_per_epoch) {
                self.previous_epoch_greatest_unrealized_checkpoint =
                    *unrealized_justified_checkpoint;
            }

            if self.will_rotate(current_slot) {
                let new_current_cp = self.previous_epoch_greatest_unrealized_checkpoint;
                let new_current =
                    if new_current_cp == self.current_epoch_observed_justified.checkpoint() {
                        self.current_epoch_observed_justified.clone()
                    } else {
                        let (epoch, balances) = checkpoint_balances
                            .ok_or(Error::MissingCheckpointState(new_current_cp))?;
                        if epoch != new_current_cp.epoch {
                            return Err(Error::MissingCheckpointState(new_current_cp));
                        }
                        CheckpointAndBalance::new(new_current_cp, balances)
                    };
                self.previous_epoch_observed_justified =
                    core::mem::replace(&mut self.current_epoch_observed_justified, new_current);
            }
            self.last_update_slot = Some(current_slot);
        }

        Ok(())
    }

    /// Spec: `get_latest_confirmed`. Evaluated against a borrowed view of this
    /// state, which is where the rule actually lives.
    #[allow(clippy::too_many_arguments)]
    pub fn get_latest_confirmed<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Root> {
        self.view().get_latest_confirmed(
            head_root,
            finalized_checkpoint,
            unrealized_justified_checkpoint,
            current_slot,
            store,
            votes,
            equivocating_indices,
        )
    }

    /// Spec: `get_current_target_score`.
    pub fn get_current_target_score<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        self.view().get_current_target_score(
            head_root,
            current_slot,
            store,
            votes,
            equivocating_indices,
        )
    }

    /// Borrow the state so the read-only rule can run against it.
    pub fn view(&self) -> RuleView<'_, A, BalanceSourceData> {
        RuleView {
            confirmed_root: self.confirmed_root,
            previous_epoch_observed_justified: CheckpointAndBalanceRef::new(
                self.previous_epoch_observed_justified.checkpoint(),
                self.previous_epoch_observed_justified.balances(),
            ),
            current_epoch_observed_justified: CheckpointAndBalanceRef::new(
                self.current_epoch_observed_justified.checkpoint(),
                self.current_epoch_observed_justified.balances(),
            ),
            previous_slot_head: self.previous_slot_head,
            byzantine_threshold: self.byzantine_threshold,
            proposer_score_boost: self.proposer_score_boost,
            slot_assignments: &self.slot_assignments,
            head_balance_source: &self.head_balance_source,
            slots_per_epoch: self.slots_per_epoch,
        }
    }
}

impl<A: SlotAssignments, B: Balances> RuleView<'_, A, B> {
    #[allow(clippy::too_many_arguments)]
    pub fn get_latest_confirmed<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Root> {
        self.get_latest_confirmed_with_outcome(
            head_root,
            finalized_checkpoint,
            unrealized_justified_checkpoint,
            current_slot,
            store,
            votes,
            equivocating_indices,
        )
        .map(|(root, _)| root)
    }

    /// [`Self::get_latest_confirmed`], also reporting which branch fired so the
    /// host can record it.
    #[allow(clippy::too_many_arguments)]
    pub fn get_latest_confirmed_with_outcome<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<(Root, Outcome)> {
        let mut outcome = Outcome::default();
        let current_epoch = current_slot.epoch(self.slots_per_epoch);
        let is_epoch_start = is_start_slot_at_epoch(current_slot, self.slots_per_epoch);
        let mut confirmed_root = self.confirmed_root;

        let confirmed_block_epoch_result =
            get_block_epoch(confirmed_root, store, self.slots_per_epoch);

        // Revert to finalized block if either of the following is true:
        let should_revert_to_finalized_reason = if confirmed_block_epoch_result
            .as_ref()
            .map_or(true, |block_epoch| {
                block_epoch.saturating_add(1u64) < current_epoch
            }) {
            if confirmed_block_epoch_result.is_err() {
                // We have an additional revert case not present in the spec: the `confirmed_root`
                // could have been pruned from fork choice. This needs to be a recoverable failure
                // (a revert) rather than a hard error.
                Some("confirmed_block_pruned")
            } else {
                // 1) the latest confirmed block's epoch is older than the previous epoch,
                Some("epoch_too_old")
            }
        } else if !is_ancestor(head_root, confirmed_root, store)? {
            // 2) the latest confirmed block does not belong to the canonical chain,
            Some("not_ancestor")
        } else if is_epoch_start
            && let Some(chain_unsafe_reason) = self.is_confirmed_chain_safe(
                // 3) the confirmed chain starting from the current epoch observed justified
                //    checkpoint cannot be re-confirmed at the start of the current epoch.
                confirmed_root,
                current_slot,
                store,
                votes,
                equivocating_indices,
                &mut outcome,
            )?
        {
            Some(chain_unsafe_reason)
        } else {
            None
        };
        // Lighthouse logs `reason` here; the core returns the root and lets the
        // host decide what to say about it.
        if let Some(reason) = should_revert_to_finalized_reason {
            outcome.reverted_to_finalized = Some(reason);
            confirmed_root = finalized_checkpoint.root;
        }

        // Restart the confirmation chain if each of the following conditions are true:
        // 1) it is the start of the current epoch,
        let observed_justified_block_slot = get_block_slot(
            self.current_epoch_observed_justified.checkpoint().root,
            store,
        )?;
        // 2) epoch of fcr_store.current_epoch_observed_justified_checkpoint.root equals to the previous epoch,
        let is_observed_justified_block_epoch_ok = observed_justified_block_slot
            .epoch(self.slots_per_epoch)
            .safe_add(1u64)?
            == current_epoch;
        // 3) fcr_store.current_epoch_observed_justified_checkpoint equals to unrealized justification of the head,
        let is_head_unrealized_justified_ok = self.current_epoch_observed_justified.checkpoint()
            == unrealized_justification_of(head_root, store)?;
        // 4) confirmed block is older than the block of fcr_store.current_epoch_observed_justified_checkpoint.
        let is_confirmed_block_stale =
            get_block_slot(confirmed_root, store)? < observed_justified_block_slot;
        if is_epoch_start
            && is_observed_justified_block_epoch_ok
            && is_head_unrealized_justified_ok
            && is_confirmed_block_stale
        {
            outcome.restarted_from_justified = true;
            confirmed_root = self.current_epoch_observed_justified.checkpoint().root;
        }

        // Attempt to further advance the latest confirmed block
        if get_block_epoch(confirmed_root, store, self.slots_per_epoch)?.safe_add(1u64)?
            >= current_epoch
        {
            let advanced = self.find_latest_confirmed_descendant(
                confirmed_root,
                head_root,
                unrealized_justified_checkpoint,
                current_slot,
                store,
                votes,
                equivocating_indices,
            )?;
            outcome.advanced = advanced != confirmed_root;
            confirmed_root = advanced;
        }

        Ok((confirmed_root, outcome))
    }

    /// Spec: find_latest_confirmed_descendant
    ///
    /// DIVERGENCE: `is_one_confirmed` below is backed by an attestation-score cache instead of
    /// recomputing `get_attestation_score` per block. The control-flow shape follows the spec.
    #[allow(clippy::too_many_arguments)]
    fn find_latest_confirmed_descendant<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        latest_confirmed_root: Root,
        head_root: Root,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Root> {
        let current_epoch = current_slot.epoch(self.slots_per_epoch);
        let mut confirmed_root = latest_confirmed_root;

        // Precompute attestation scores for the whole chain (confirmed → head) in one O(V × depth)
        // pass; both loops below read per-block scores from it instead of recomputing per block.
        let attestation_scores = {
            let chain = get_ancestor_roots(head_root, latest_confirmed_root, store)?;
            let terminal_slot = get_block_slot(latest_confirmed_root, store)?;
            ChainAttestationScores::for_chain(
                store,
                &chain,
                terminal_slot,
                self.get_current_balance_source(),
                votes,
                equivocating_indices,
            )?
        };

        // Shared across both FFG predicates so the O(V) honest-support sweep runs at most once.
        let honest_ffg_support = HonestFfgSupportCache::new();

        if get_block_epoch(confirmed_root, store, self.slots_per_epoch)?.safe_add(1u64)?
            == current_epoch
            && get_voting_source_epoch(
                self.previous_slot_head,
                current_slot,
                store,
                self.slots_per_epoch,
            )?
            .safe_add(2u64)?
                >= current_epoch
            && (is_start_slot_at_epoch(current_slot, self.slots_per_epoch)
                || (self.will_no_conflicting_checkpoint_be_justified(
                    head_root,
                    unrealized_justified_checkpoint,
                    current_slot,
                    store,
                    votes,
                    equivocating_indices,
                    &honest_ffg_support,
                )? && (unrealized_justification_of(self.previous_slot_head, store)?
                    .epoch
                    .safe_add(1u64)?
                    >= current_epoch
                    || unrealized_justification_of(head_root, store)?
                        .epoch
                        .safe_add(1u64)?
                        >= current_epoch)))
        {
            let canonical_roots = get_ancestor_roots(head_root, confirmed_root, store)?;

            for block_root in &canonical_roots {
                let block_epoch = get_block_epoch(*block_root, store, self.slots_per_epoch)?;

                if block_epoch == current_epoch {
                    break;
                }

                if !is_ancestor(self.previous_slot_head, *block_root, store)? {
                    break;
                }

                if !self
                    .is_one_confirmed(
                        self.get_current_balance_source(),
                        *block_root,
                        &attestation_scores,
                        current_slot,
                        store,
                        votes,
                        equivocating_indices,
                    )?
                    .is_confirmed()
                {
                    break;
                }
                confirmed_root = *block_root;
            }
        }

        if is_start_slot_at_epoch(current_slot, self.slots_per_epoch)
            || unrealized_justification_of(head_root, store)?
                .epoch
                .safe_add(1u64)?
                >= current_epoch
        {
            let canonical_roots = get_ancestor_roots(head_root, confirmed_root, store)?;

            let mut tentative_confirmed_root = confirmed_root;

            for block_root in &canonical_roots {
                let block_epoch = get_block_epoch(*block_root, store, self.slots_per_epoch)?;
                let tentative_epoch =
                    get_block_epoch(tentative_confirmed_root, store, self.slots_per_epoch)?;

                if block_epoch > tentative_epoch
                    && !self.will_current_target_be_justified(
                        head_root,
                        current_slot,
                        store,
                        votes,
                        equivocating_indices,
                        &honest_ffg_support,
                    )?
                {
                    break;
                }

                if !self
                    .is_one_confirmed(
                        self.get_current_balance_source(),
                        *block_root,
                        &attestation_scores,
                        current_slot,
                        store,
                        votes,
                        equivocating_indices,
                    )?
                    .is_confirmed()
                {
                    break;
                }
                tentative_confirmed_root = *block_root;
            }

            if get_block_epoch(tentative_confirmed_root, store, self.slots_per_epoch)?
                == current_epoch
                || (get_voting_source_epoch(
                    tentative_confirmed_root,
                    current_slot,
                    store,
                    self.slots_per_epoch,
                )?
                .safe_add(2u64)?
                    >= current_epoch
                    && (is_start_slot_at_epoch(current_slot, self.slots_per_epoch)
                        || self.will_no_conflicting_checkpoint_be_justified(
                            head_root,
                            unrealized_justified_checkpoint,
                            current_slot,
                            store,
                            votes,
                            equivocating_indices,
                            &honest_ffg_support,
                        )?))
            {
                confirmed_root = tentative_confirmed_root;
            }
        }

        Ok(confirmed_root)
    }

    /// Spec: is_confirmed_chain_safe
    ///
    /// DIVERGENCE: Same optimization as find_latest_confirmed_descendant —
    /// precomputes scores once and uses `is_one_confirmed_with_score`.
    ///
    /// `Ok(None)` = the confirmed chain is safe (re-confirmable). `Ok(Some(reason))` = it
    /// isn't, with `reason` naming which check failed (surfaced as the revert metric label).
    #[allow(clippy::too_many_arguments)]
    fn is_confirmed_chain_safe<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        confirmed_root: Root,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
        outcome: &mut Outcome,
    ) -> Result<Option<&'static str>> {
        if get_checkpoint_for_block(
            confirmed_root,
            self.current_epoch_observed_justified.checkpoint().epoch,
            store,
            self.slots_per_epoch,
        )
        .is_none_or(|checkpoint| checkpoint != self.current_epoch_observed_justified.checkpoint())
        {
            return Ok(Some("off_justified_chain"));
        }

        let current_epoch = current_slot.epoch(self.slots_per_epoch);
        let start_root_exclusive = if self
            .current_epoch_observed_justified
            .checkpoint()
            .epoch
            .safe_add(1u64)?
            >= current_epoch
        {
            self.current_epoch_observed_justified.checkpoint().root
        } else {
            // Limit reconfirmation to the first block of the previous epoch.
            // If successful, reconfirmation of ancestors is implied.
            let ancestor_at_previous_epoch_start = get_ancestor(
                confirmed_root,
                compute_start_slot_at_epoch_spe(
                    current_epoch.safe_sub(1u64)?,
                    self.slots_per_epoch,
                ),
                store,
            )?;
            if get_block_epoch(
                ancestor_at_previous_epoch_start,
                store,
                self.slots_per_epoch,
            )?
            .safe_add(1u64)?
                == current_epoch
            {
                // The parent of the first block of the previous epoch.
                parent_root(ancestor_at_previous_epoch_start, store)?
            } else {
                // The last block of the epoch before the previous one.
                ancestor_at_previous_epoch_start
            }
        };

        let chain_roots = get_ancestor_roots(confirmed_root, start_root_exclusive, store)?;
        let terminal_slot = get_block_slot(start_root_exclusive, store)?;
        let attestation_scores = ChainAttestationScores::for_chain(
            store,
            &chain_roots,
            terminal_slot,
            self.get_previous_balance_source(),
            votes,
            equivocating_indices,
        )?;

        for root in &chain_roots {
            if let Confirmation::NotConfirmed(unconfirmed) = self.is_one_confirmed(
                self.get_previous_balance_source(),
                *root,
                &attestation_scores,
                current_slot,
                store,
                votes,
                equivocating_indices,
            )? {
                // `root` is not confirmed; surface why for the revert metric.
                match unconfirmed {
                    // Lighthouse reports `support` and `safety_threshold` to a
                    // metric here. The core has nowhere to send them, so it
                    // returns the reason and the host reads the numbers off the
                    // `Confirmation` it already has.
                    Unconfirmed::BelowThreshold {
                        support,
                        safety_threshold,
                    } => {
                        outcome.unconfirmed_support = Some((support, safety_threshold));
                        return Ok(Some("unconfirmed_below_threshold"));
                    }
                    Unconfirmed::Optimistic => {
                        return Ok(Some("unconfirmed_optimistic"));
                    }
                }
            }
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // LMD-GHOST helpers
    // -----------------------------------------------------------------------

    /// Spec: `get_block_support_between_slots`.
    fn get_block_support_between_slots<V: Votes + ?Sized>(
        &self,
        balance_source: &B,
        block_root: Root,
        start_slot: Slot,
        end_slot: Slot,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        // Spec: sum effective balance of validators that:
        // - Are assigned to attest in a committee in the `range(start_slot, end_slot + 1)`
        // - Are active in `balance_source` tracked here as `balance > 0`
        // - Are not slashed in `balance_source` tracked here as `slashed == false`
        // - Do not belong to the `store.equivocating_indices` set
        // - Their vote is for exactly `block_root`
        //
        // The conditions are pure predicates, so the order they are tested in
        // does not change the sum -- but it does change the cost. Committee
        // assignment is the selective one: a range of a slot or two out of an
        // epoch admits a small fraction of the set, so it is tested first and
        // the vote is only read for validators that survive it.
        let mut score = 0u64;
        for (val_idx, balance) in balance_source.unslashed_and_active_indices() {
            if balance == 0
                || !self
                    .slot_assignments
                    .is_in_range(val_idx, start_slot, end_slot)
                    .map_err(|_| Error::SlotAssignmentsError)?
                || equivocating_indices.contains(&(val_idx as u64))
            {
                continue;
            }
            let Some(vote) = votes.get(val_idx) else {
                continue;
            };
            if vote.current_root() == block_root {
                score = score.safe_add(balance)?;
            }
        }
        Ok(score)
    }

    /// Spec: `compute_proposer_score(balance_source)`.
    /// Uses `(committee_weight * proposer_score_boost) // 100` (multiply-first) to match
    /// the spec and avoid precision loss from divide-first ordering.
    fn compute_proposer_score(&self, balance_source: &B) -> Result<u64> {
        Ok(crate::compute_proposer_score(
            balance_source.total_active_balance(),
            self.slots_per_epoch,
            self.proposer_score_boost,
        )?)
    }

    /// Spec: `compute_empty_slot_support_discount`.
    fn compute_empty_slot_support_discount<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        balance_source: &B,
        block_root: Root,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        // Lighthouse holds `ProtoNode`s here; the core has accessors, so the
        // same two facts are read directly. Identical logic.
        let block_slot = get_block_slot(block_root, store)?;
        let parent_block_root = parent_root(block_root, store)?;
        let parent_block_slot = get_block_slot(parent_block_root, store)?;

        if parent_block_slot.safe_add(1u64)? == block_slot {
            return Ok(0);
        }

        let parent_support_in_empty_slots = self.get_block_support_between_slots(
            balance_source,
            parent_block_root,
            parent_block_slot.safe_add(1u64)?,
            block_slot.safe_sub(1u64)?,
            votes,
            equivocating_indices,
        )?;

        let adversarial_weight = self.compute_adversarial_weight(
            balance_source,
            parent_block_slot.safe_add(1u64)?,
            block_slot.safe_sub(1u64)?,
            equivocating_indices,
        )?;

        if parent_support_in_empty_slots > adversarial_weight {
            Ok(parent_support_in_empty_slots.safe_sub(adversarial_weight)?)
        } else {
            Ok(0)
        }
    }

    /// Spec: `get_support_discount`.
    fn get_support_discount<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        balance_source: &B,
        block_root: Root,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        self.compute_empty_slot_support_discount(
            balance_source,
            block_root,
            store,
            votes,
            equivocating_indices,
        )
    }

    /// Spec: `compute_safety_threshold`.
    fn compute_safety_threshold<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        balance_source: &B,
        block_root: Root,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        let parent_root = parent_root(block_root, store)?;
        let parent_slot = get_block_slot(parent_root, store)?;

        let total_active_balance = balance_source.total_active_balance();
        let proposer_score = self.compute_proposer_score(balance_source)?;
        let maximum_support = crate::estimate_committee_weight_between_slots(
            total_active_balance,
            (parent_slot.safe_add(1u64)?).as_u64(),
            (current_slot.safe_sub(1u64)?).as_u64(),
            self.slots_per_epoch,
        )?;
        let support_discount = self.get_support_discount(
            balance_source,
            block_root,
            store,
            votes,
            equivocating_indices,
        )?;
        let adversarial_weight = self.get_adversarial_weight(
            balance_source,
            block_root,
            current_slot,
            store,
            equivocating_indices,
        )?;

        Ok(crate::safety_threshold(
            maximum_support,
            proposer_score,
            adversarial_weight,
            support_discount,
        )?)
    }

    /// Spec: `get_adversarial_weight`.
    fn get_adversarial_weight<S: ForkChoiceStore>(
        &self,
        balance_source: &B,
        block_root: Root,
        current_slot: Slot,
        store: &S,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        let block_slot = get_block_slot(block_root, store)?;
        let parent_root = parent_root(block_root, store)?;
        let block_epoch = get_block_epoch(block_root, store, self.slots_per_epoch)?;

        if block_epoch > get_block_epoch(parent_root, store, self.slots_per_epoch)? {
            self.compute_adversarial_weight(
                balance_source,
                compute_start_slot_at_epoch_spe(block_epoch, self.slots_per_epoch),
                current_slot.safe_sub(1u64)?,
                equivocating_indices,
            )
        } else {
            self.compute_adversarial_weight(
                balance_source,
                block_slot,
                current_slot.safe_sub(1u64)?,
                equivocating_indices,
            )
        }
    }

    /// Spec: `compute_adversarial_weight`.
    fn compute_adversarial_weight(
        &self,
        balance_source: &B,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        let total_active_balance = balance_source.total_active_balance();
        let maximum_weight = crate::estimate_committee_weight_between_slots(
            total_active_balance,
            (start_slot).as_u64(),
            (end_slot).as_u64(),
            self.slots_per_epoch,
        )?;
        let max_adversarial_weight =
            crate::max_adversarial_weight(maximum_weight, self.byzantine_threshold)?;

        let equivocation_score = self.get_equivocation_score(
            balance_source,
            start_slot,
            end_slot,
            equivocating_indices,
        )?;

        Ok(crate::adversarial_weight(
            max_adversarial_weight,
            equivocation_score,
        ))
    }

    /// Spec: `get_equivocation_score`.
    /// Equivalent to the spec's `active_equivocating_indices`, but tests committee membership
    /// with precomputed head assignments instead of materializing all committee participants.
    fn get_equivocation_score(
        &self,
        balance_source: &B,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        let mut score = 0u64;
        // Spec: Sum the effective balance of validators that:
        // - Belong to the `store.equivocating_indices` set
        // - Are assigned to attest in a committee in the `range(start_slot, end_slot + 1)`
        // - Are active in `balance_source` tracked here as `balance > 0`
        for &idx in equivocating_indices {
            let idx = idx as usize;
            if self
                .slot_assignments
                .is_in_range(idx, start_slot, end_slot)
                .map_err(|_| Error::SlotAssignmentsError)?
            {
                score = score.safe_add(balance_source.balance(idx))?;
            }
        }
        Ok(score)
    }

    // -----------------------------------------------------------------------
    // FFG helpers
    // -----------------------------------------------------------------------

    /// Spec: `will_no_conflicting_checkpoint_be_justified`.
    #[allow(clippy::too_many_arguments)]
    fn will_no_conflicting_checkpoint_be_justified<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
        honest_ffg_support: &HonestFfgSupportCache,
    ) -> Result<bool> {
        if get_current_target(head_root, current_slot, store, self.slots_per_epoch)?
            == *unrealized_justified_checkpoint
        {
            return Ok(true);
        }

        let total_active_balance = self.head_balance_source.total_active_balance();
        let honest_ffg = honest_ffg_support.get_or_compute(|| {
            self.compute_honest_ffg_support(
                head_root,
                current_slot,
                store,
                votes,
                equivocating_indices,
            )
        })?;
        Ok(honest_ffg.safe_mul(3)? > total_active_balance)
    }

    /// Spec: `will_current_target_be_justified`.
    fn will_current_target_be_justified<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
        honest_ffg_support: &HonestFfgSupportCache,
    ) -> Result<bool> {
        let total_active_balance = self.head_balance_source.total_active_balance();
        let honest_ffg = honest_ffg_support.get_or_compute(|| {
            self.compute_honest_ffg_support(
                head_root,
                current_slot,
                store,
                votes,
                equivocating_indices,
            )
        })?;
        Ok(honest_ffg.safe_mul(3)? >= total_active_balance.safe_mul(2)?)
    }

    /// Spec: `get_current_target_score` — estimates FFG support for the current-epoch target.
    ///
    /// Sums the balance of validators whose latest-message checkpoint (resolved from the vote
    /// root at the vote's epoch) matches the current target. Votes are epoch-filtered and
    /// aggregated by `(root, epoch)`, so each checkpoint lookup runs once per distinct vote
    /// rather than once per validator.
    pub fn get_current_target_score<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        let target = get_current_target(head_root, current_slot, store, self.slots_per_epoch)?;

        // Aggregate balances by (vote root, vote epoch): most validators share a small set of
        // latest-message checkpoints, so each O(depth) checkpoint lookup runs once per distinct
        // key rather than once per validator.
        let mut balance_by_vote_checkpoint = crate::rootmap::RootMap::<(Root, Epoch)>::new();

        // Spec: sum the effective balance of validators that:
        // - Are active the current epoch
        // - Are not slashed in the current epoch
        // - Don't belong in the equivocating_indices set
        // - Have a vote for the current target
        let mut score = 0u64;

        for (val_idx, balance) in self.head_balance_source.unslashed_and_active_indices() {
            let Some(vote) = votes.get(val_idx) else {
                continue;
            };
            let vote_root = vote.current_root();
            // Spec: get_latest_message_epoch(latest_messages[i]).
            let vote_epoch = vote.current_slot().epoch(self.slots_per_epoch);
            // A zero root means the validator has no latest message.
            if vote_root != crate::primitives::ZERO_ROOT
                && vote_epoch == target.epoch
                && !equivocating_indices.contains(&(val_idx as u64))
            {
                balance_by_vote_checkpoint.add((vote_root, vote_epoch), balance)?;
            }
        }

        for ((vote_root, vote_epoch), balance) in balance_by_vote_checkpoint.iter() {
            // Spec: get_checkpoint_for_block(store, latest_messages[i].root,
            //        get_latest_message_epoch(latest_messages[i])).
            if get_checkpoint_for_block(vote_root, vote_epoch, store, self.slots_per_epoch)
                == Some(target)
            {
                score = score.safe_add(balance)?;
            }
        }
        Ok(score)
    }

    /// Spec: `compute_honest_ffg_support_for_current_target`.
    fn compute_honest_ffg_support<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        head_root: Root,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64> {
        let current_epoch = current_slot.epoch(self.slots_per_epoch);
        let balance_source = &self.head_balance_source;
        let total_active_balance = balance_source.total_active_balance();

        let ffg_support_for_checkpoint = self.get_current_target_score(
            head_root,
            current_slot,
            store,
            votes,
            equivocating_indices,
        )?;

        let ffg_weight_till_now = crate::estimate_committee_weight_between_slots(
            total_active_balance,
            compute_start_slot_at_epoch_spe(current_epoch, self.slots_per_epoch).as_u64(),
            current_slot.safe_sub(1u64)?.as_u64(),
            self.slots_per_epoch,
        )?;

        let remaining_ffg_weight = total_active_balance.safe_sub(ffg_weight_till_now)?;
        let remaining_honest_ffg_weight = remaining_ffg_weight
            .safe_div(100)?
            .safe_mul(100u64.safe_sub(self.byzantine_threshold)?)?;

        // Compute potential adversarial weight (accounts for slashed validators).
        let adversarial_weight = self.compute_adversarial_weight(
            balance_source,
            compute_start_slot_at_epoch_spe(current_epoch, self.slots_per_epoch),
            current_slot.safe_sub(1u64)?,
            equivocating_indices,
        )?;
        let min_honest_ffg_support = ffg_support_for_checkpoint.safe_sub(core::cmp::min(
            adversarial_weight,
            ffg_support_for_checkpoint,
        ))?;

        Ok(min_honest_ffg_support.safe_add(remaining_honest_ffg_weight)?)
    }

    /// Spec: `is_one_confirmed`.
    #[allow(clippy::too_many_arguments)]
    fn is_one_confirmed<S: ForkChoiceStore, V: Votes + ?Sized>(
        &self,
        balance_source: &B,
        block_root: Root,
        attestation_scores: &impl AttestationScores,
        current_slot: Slot,
        store: &S,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Confirmation> {
        // Spec MUST: not confirmed if the block's execution status is not VALID.
        if is_optimistic_or_invalid(block_root, store)? {
            return Ok(Confirmation::NotConfirmed(Unconfirmed::Optimistic));
        }
        let support = get_attestation_score(block_root, attestation_scores)?;
        let safety_threshold = self.compute_safety_threshold(
            balance_source,
            block_root,
            current_slot,
            store,
            votes,
            equivocating_indices,
        )?;
        if support > safety_threshold {
            Ok(Confirmation::Confirmed)
        } else {
            Ok(Confirmation::NotConfirmed(Unconfirmed::BelowThreshold {
                support,
                safety_threshold,
            }))
        }
    }
}
