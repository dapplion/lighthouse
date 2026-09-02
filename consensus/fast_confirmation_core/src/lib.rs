//! The fast confirmation rule, minus the store.
//!
//! Everything here is a pure function of scalars. There is no `ProtoArray`, no
//! `BeaconState`, no allocation and no `std`, so the same code runs inside
//! Lighthouse's fork choice and inside a zkVM guest that has neither.
//!
//! The split is not arbitrary. The rule has two halves and only one of them is
//! about walking a chain:
//!
//! - **deciding what a vote is worth, and what bar it has to clear** — the
//!   estimator, the proposer score, the adversarial budget, the threshold, and
//!   the predicate that says whether one validator's balance counts. All of it
//!   is integer arithmetic over quantities a caller already holds.
//! - **finding those quantities** — ancestry, unrealized justification,
//!   execution status, latest votes. That is inherently a store walk, a
//!   different job in each consumer, and it is deliberately not here.
//!
//! Two implementations of the first half is how a prover and a client come to
//! disagree about what "confirmed" means without either being obviously wrong.
//! One implementation makes that impossible rather than unlikely.
//!
//! Spec: `consensus-specs` fast confirmation rule, and arXiv:2405.00549.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Checked arithmetic overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArithError;

pub mod primitives;
pub mod rule;
pub mod store;

pub use primitives::{Checkpoint, Epoch, ExecutionStatus, Root, Slot, Vote, Votes, ZERO_ROOT};

/// Why the rule could not reach an answer. Mirrors `fast_confirmation::Error`,
/// less the variants that only a `ProtoArray` can raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NodeNotFound(Root),
    ParentRootNotFound(Root),
    AncestorNotFound {
        block: Root,
    },
    UnrealizedJustificationNotFound(Root),
    HeadCheckpointNotFound(Root),
    CheckpointBlockNotFound {
        block: Root,
        epoch: Epoch,
    },
    MissingPrecomputedScore(Root),
    MissingCheckpointState(Checkpoint),
    SlotAssignmentsError,
    IndexOutOfBounds(usize),
    /// An ancestor walk ran past any plausible chain length, so the tree it was
    /// given has a cycle.
    WalkTooLong,
    Arith(ArithError),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::Arith(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// The pure-arithmetic helpers below cannot fail by walking a chain, so they
/// carry the narrow error. `From<ArithError> for Error` lifts them into the
/// rule's wider `Result` at each `?`.
pub type ArithResult<T> = core::result::Result<T, ArithError>;

/// Checked arithmetic, named as `safe_arith::SafeArith` names it so both
/// consumers read the same. That crate is not `no_std`, which is the only
/// reason this exists.
pub(crate) trait Arith: Sized {
    fn safe_add(self, other: Self) -> ArithResult<Self>;
    fn safe_sub(self, other: Self) -> ArithResult<Self>;
    fn safe_mul(self, other: Self) -> ArithResult<Self>;
    fn safe_div(self, other: Self) -> ArithResult<Self>;
    fn safe_rem(self, other: Self) -> ArithResult<Self>;
}

impl Arith for u64 {
    fn safe_add(self, other: Self) -> ArithResult<Self> {
        self.checked_add(other).ok_or(ArithError)
    }
    fn safe_sub(self, other: Self) -> ArithResult<Self> {
        self.checked_sub(other).ok_or(ArithError)
    }
    fn safe_mul(self, other: Self) -> ArithResult<Self> {
        self.checked_mul(other).ok_or(ArithError)
    }
    fn safe_div(self, other: Self) -> ArithResult<Self> {
        self.checked_div(other).ok_or(ArithError)
    }
    fn safe_rem(self, other: Self) -> ArithResult<Self> {
        self.checked_rem(other).ok_or(ArithError)
    }
}

/// Spec: `COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR`, in per-mille.
pub const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// Spec: `is_full_validator_set_covered`.
///
/// True when `[start_slot, end_slot]` contains a whole epoch, in which case the
/// committees in it are the whole validator set and no estimate is needed.
pub fn is_full_validator_set_covered(
    slots_per_epoch: u64,
    start_slot: u64,
    end_slot: u64,
) -> ArithResult<bool> {
    let start_full_epoch = start_slot
        .safe_add(slots_per_epoch.safe_sub(1)?)?
        .safe_div(slots_per_epoch)?;
    let end_full_epoch = end_slot.safe_add(1)?.safe_div(slots_per_epoch)?;
    Ok(start_full_epoch < end_full_epoch)
}

/// Spec: `adjust_committee_weight_estimate_to_ensure_safety`.
///
/// Ceiling division, deliberately. The function exists to over-estimate
/// committee weight; flooring would under-estimate and weaken the threshold.
pub fn adjust_committee_weight_estimate_to_ensure_safety(estimate: u64) -> ArithResult<u64> {
    estimate
        .div_ceil(1000)
        .safe_mul(1000u64.safe_add(COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR)?)
}

/// Spec: `estimate_committee_weight_between_slots`.
///
/// **Reads no committee.** It is a function of the total active balance and a
/// slot range, which is exactly why an unproven committee assignment does not
/// move it — and therefore why a prover who picks the partition picks its own
/// denominator unless the assignment is proven elsewhere.
pub fn estimate_committee_weight_between_slots(
    total_active_balance: u64,
    start_slot: u64,
    end_slot: u64,
    slots_per_epoch: u64,
) -> ArithResult<u64> {
    if start_slot > end_slot {
        return Ok(0);
    }
    if is_full_validator_set_covered(slots_per_epoch, start_slot, end_slot)? {
        return Ok(total_active_balance);
    }

    let spe = slots_per_epoch;
    let start_epoch = start_slot.safe_div(spe)?;
    let end_epoch = end_slot.safe_div(spe)?;

    if start_epoch == end_epoch {
        let num_slots = end_slot.safe_sub(start_slot)?.safe_add(1)?;
        return total_active_balance.safe_div(spe)?.safe_mul(num_slots);
    }

    // Crosses an epoch boundary without covering a whole epoch: pro-rata.
    let slots_since_start_epoch = start_slot.safe_rem(spe)?;
    let num_slots_in_start_epoch = spe.safe_sub(slots_since_start_epoch)?;

    let slots_since_end_epoch = end_slot.safe_rem(spe)?;
    let num_slots_in_end_epoch = slots_since_end_epoch.safe_add(1)?;
    let remaining_slots_in_end_epoch = spe.safe_sub(num_slots_in_end_epoch)?;

    let start_epoch_weight = total_active_balance
        .safe_div(spe)?
        .safe_mul(num_slots_in_start_epoch)?;
    let end_epoch_weight = total_active_balance
        .safe_div(spe)?
        .safe_mul(num_slots_in_end_epoch)?;

    let start_epoch_weight_pro_rated = start_epoch_weight
        .safe_div(spe)?
        .safe_mul(remaining_slots_in_end_epoch)?;

    adjust_committee_weight_estimate_to_ensure_safety(
        start_epoch_weight_pro_rated.safe_add(end_epoch_weight)?,
    )
}

/// Spec: `compute_proposer_score(balance_source)`.
///
/// Multiply-first, to match the spec and avoid the precision loss of dividing
/// the committee weight before applying the boost.
pub fn compute_proposer_score(
    total_active_balance: u64,
    slots_per_epoch: u64,
    proposer_score_boost: u64,
) -> ArithResult<u64> {
    total_active_balance
        .safe_div(slots_per_epoch)?
        .safe_mul(proposer_score_boost)?
        .safe_div(100)
}

/// The adversary's budget over a window, before equivocating stake is credited
/// back. Spec: the `max_adversarial_weight` term of `compute_adversarial_weight`.
pub fn max_adversarial_weight(maximum_weight: u64, byzantine_threshold: u64) -> ArithResult<u64> {
    maximum_weight.safe_div(100)?.safe_mul(byzantine_threshold)
}

/// Spec: the tail of `compute_adversarial_weight`. Equivocating stake is already
/// counted against the adversary, so it is not budgeted twice; the term
/// saturates at zero rather than wrapping.
pub fn adversarial_weight(max_adversarial_weight: u64, equivocation_score: u64) -> u64 {
    max_adversarial_weight.saturating_sub(equivocation_score)
}

/// Spec: the safety threshold,
/// `(maximum_support + proposer_score + 2 * adversarial_weight - support_discount) / 2`.
///
/// Saturates at zero when the discount exceeds the numerator, as the reference
/// implementation does.
pub fn safety_threshold(
    maximum_support: u64,
    proposer_score: u64,
    adversarial_weight: u64,
    support_discount: u64,
) -> ArithResult<u64> {
    let numerator = maximum_support
        .safe_add(proposer_score)?
        .safe_add(adversarial_weight.safe_mul(2)?)?;
    if support_discount < numerator {
        numerator.safe_sub(support_discount)?.safe_div(2)
    } else {
        Ok(0)
    }
}

/// Whether one validator's effective balance counts toward a block's support.
///
/// Spec: the loop body of `get_block_support_between_slots`. Every condition the
/// specification puts on a counted vote is here, and there are five of them —
/// which is the point of extracting it. A consumer that reimplements this by
/// hand tends to keep the two that are easy to see.
///
/// `in_committee_range` is "assigned to attest in a committee in
/// `range(start_slot, end_slot + 1)`", which each consumer answers its own way:
/// Lighthouse from precomputed slot assignments, a circuit from a committee
/// proof. Everything else is a fact about the validator.
#[allow(clippy::fn_params_excessive_bools)]
pub fn counts_toward_support(
    effective_balance: u64,
    slashed: bool,
    equivocating: bool,
    in_committee_range: bool,
    vote_matches_block: bool,
) -> bool {
    effective_balance > 0 && !slashed && !equivocating && in_committee_range && vote_matches_block
}

/// Spec: `is_one_confirmed`, once support and threshold are known.
///
/// A block whose execution payload is optimistic or invalid is never confirmed;
/// that is a store fact, so the caller supplies it.
pub fn is_one_confirmed(optimistic_or_invalid: bool, support: u64, safety_threshold: u64) -> bool {
    !optimistic_or_invalid && support > safety_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    const SPE: u64 = 32;

    #[test]
    fn full_set_coverage_matches_the_spec_boundaries() {
        assert!(is_full_validator_set_covered(SPE, 0, 31).unwrap());
        assert!(is_full_validator_set_covered(SPE, 0, 32).unwrap());
        assert!(!is_full_validator_set_covered(SPE, 0, 0).unwrap());
        assert!(!is_full_validator_set_covered(SPE, 1, 31).unwrap());
    }

    #[test]
    fn one_slot_is_one_committee_and_a_full_epoch_is_everything() {
        let total = 32_000_000_000u64;
        assert_eq!(
            estimate_committee_weight_between_slots(total, 0, 0, SPE).unwrap(),
            1_000_000_000
        );
        assert_eq!(
            estimate_committee_weight_between_slots(total, 0, 31, SPE).unwrap(),
            total
        );
    }

    #[test]
    fn an_empty_range_weighs_nothing() {
        assert_eq!(
            estimate_committee_weight_between_slots(32_000_000_000, 10, 5, SPE).unwrap(),
            0
        );
    }

    /// The pro-rata branch can exceed the total active balance by design — the
    /// adjustment factor over-estimates on purpose — so "just use `T`" is not
    /// the conservative simplification it looks like.
    #[test]
    fn the_cross_epoch_branch_can_exceed_the_total() {
        let total = 32_000_000_000u64;
        let w = estimate_committee_weight_between_slots(total, 31, 32, SPE).unwrap();
        assert!(w > 0);
        assert_ne!(w, total.safe_div(SPE).unwrap().safe_mul(2).unwrap());
    }

    #[test]
    fn the_threshold_saturates_rather_than_wrapping() {
        assert_eq!(safety_threshold(10, 0, 0, 1_000).unwrap(), 0);
        assert_eq!(safety_threshold(100, 20, 10, 0).unwrap(), 70);
    }

    /// Moved from `fast_confirmation` with the function. Ceiling division is the
    /// whole point: flooring would under-estimate committee weight and weaken
    /// the threshold, and 999 must not round to nothing.
    #[test]
    fn the_adjustment_factor_rounds_up() {
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1000).unwrap(),
            1005
        );
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(999).unwrap(),
            1005
        );
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1500).unwrap(),
            2010
        );
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(0).unwrap(),
            0
        );
    }

    #[test]
    fn every_condition_can_veto_a_vote() {
        assert!(counts_toward_support(32, false, false, true, true));
        assert!(!counts_toward_support(0, false, false, true, true));
        assert!(!counts_toward_support(32, true, false, true, true));
        assert!(!counts_toward_support(32, false, true, true, true));
        assert!(!counts_toward_support(32, false, false, false, true));
        assert!(!counts_toward_support(32, false, false, true, false));
    }
}
