//! Per-checkpoint snapshot of validator balances used by the Fast Confirmation Rule.

use tracing::{debug, debug_span};
use types::{BeaconState, Checkpoint, Epoch, EthSpec};

/// Snapshot of a checkpoint state's balances and committee assignments.
///
/// FCR needs two of these simultaneously: one for new confirmations (current epoch
/// observed justified) and one for reconfirmation at epoch boundaries (previous).
#[derive(Clone, Debug)]
pub struct BalanceSourceData {
    pub checkpoint: Checkpoint,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// True if the validator has been slashed. Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

impl BalanceSourceData {
    /// Assemble a `BalanceSourceData` from already-computed parts.
    pub(crate) fn from_parts(
        checkpoint: Checkpoint,
        effective_balances: Vec<u64>,
        total_active_balance: u64,
        slashed: Vec<bool>,
    ) -> Self {
        debug!(
            validators = effective_balances.len(),
            active_balance = total_active_balance,
            epoch = %checkpoint.epoch,
            "FCR balance source built"
        );
        Self {
            checkpoint,
            total_active_balance,
            effective_balances,
            slashed,
        }
    }

    /// Build a balance source for a single `epoch`, anchored to `checkpoint`, in one pass over the
    /// validator set. Effective balance is counted for active validators regardless of slashed
    /// status (matching the spec's `get_total_active_balance`); `slashed` is recorded separately
    /// for the slashed-filtering used by `get_block_support_between_slots`. The total uses a
    /// saturating add — it is a sum of effective balances and cannot realistically overflow `u64`.
    pub(crate) fn for_epoch<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        checkpoint: Checkpoint,
    ) -> Self {
        let _span = debug_span!("fcr_build_balance_source", epoch = %epoch).entered();

        let validators = state.validators();
        let mut effective_balances = Vec::with_capacity(validators.len());
        let mut slashed = Vec::with_capacity(validators.len());
        let mut total_active_balance = 0u64;

        for validator in validators.iter() {
            slashed.push(validator.slashed);
            if validator.is_active_at(epoch) {
                effective_balances.push(validator.effective_balance);
                total_active_balance =
                    total_active_balance.saturating_add(validator.effective_balance);
            } else {
                effective_balances.push(0);
            }
        }

        Self::from_parts(
            checkpoint,
            effective_balances,
            total_active_balance,
            slashed,
        )
    }

    pub(crate) fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
    }

    pub(crate) fn active_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.effective_balances
            .iter()
            .enumerate()
            .filter_map(|(i, balance)| (*balance > 0).then_some(i))
    }

    pub(crate) fn unslashed_and_active_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.effective_balances
            .iter()
            .enumerate()
            .filter_map(|(i, balance)| {
                (*balance > 0 && !self.slashed.get(i).copied().unwrap_or(false)).then_some(i)
            })
    }

    /// Return balance only if the validator is not slashed.
    /// Spec: `get_block_support_between_slots` excludes slashed validators.
    pub(crate) fn unslashed_balance(&self, val_idx: usize) -> u64 {
        if self.slashed.get(val_idx).copied().unwrap_or(false) {
            0
        } else {
            self.balance(val_idx)
        }
    }
}
