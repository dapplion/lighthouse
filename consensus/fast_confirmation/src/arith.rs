//! The rule's arithmetic as free functions, for a caller that has the numbers
//! but no `FastConfirmationRule` -- a zkVM guest proving one slot's threshold.
//! The rule's own methods call these, so there is one copy of each formula.

use crate::primitives::{ArithError, SafeArith};

/// Spec: `compute_proposer_score`. Multiply first, as the spec does, so no
/// precision is lost to the division.
pub fn compute_proposer_score(
    total_active_balance: u64,
    slots_per_epoch: u64,
    proposer_score_boost: u64,
) -> Result<u64, ArithError> {
    let committee_weight = total_active_balance.safe_div(slots_per_epoch)?;
    committee_weight
        .safe_mul(proposer_score_boost)?
        .safe_div(100)
}

/// Spec: `get_adversarial_weight`, the budget before equivocations are removed.
/// Divides first, as Lighthouse does.
pub fn max_adversarial_weight(
    maximum_weight: u64,
    byzantine_threshold: u64,
) -> Result<u64, ArithError> {
    maximum_weight.safe_div(100)?.safe_mul(byzantine_threshold)
}

/// Spec: `get_adversarial_weight`, less the equivocators already caught.
pub fn adversarial_weight(max_adversarial_weight: u64, equivocation_score: u64) -> u64 {
    max_adversarial_weight.saturating_sub(equivocation_score)
}

/// Spec: `compute_safety_threshold`:
/// `(maximum_support + proposer_score + 2 * adversarial_weight - support_discount) / 2`.
pub fn safety_threshold(
    maximum_support: u64,
    proposer_score: u64,
    adversarial_weight: u64,
    support_discount: u64,
) -> Result<u64, ArithError> {
    maximum_support
        .safe_add(proposer_score)?
        .safe_add(adversarial_weight.safe_mul(2)?)?
        .saturating_sub(support_discount)
        .safe_div(2)
}

/// Whether one validator's balance counts towards a block's support: active,
/// unslashed, not equivocating, in a committee of the window, and voting for
/// exactly that block.
pub fn counts_toward_support(
    balance: u64,
    slashed: bool,
    equivocating: bool,
    in_committee_range: bool,
    votes_for_block: bool,
) -> bool {
    balance > 0 && !slashed && !equivocating && in_committee_range && votes_for_block
}

/// Spec: `is_one_confirmed`.
pub fn is_one_confirmed(optimistic_or_invalid: bool, support: u64, safety_threshold: u64) -> bool {
    !optimistic_or_invalid && support > safety_threshold
}
