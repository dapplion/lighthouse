//! Validator-balance snapshot used by the Fast Confirmation Rule.

use crate::primitives::Epoch;
use alloc::vec::Vec;

/// Snapshot of a validator set's effective balances for one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSourceData {
    /// The epoch the snapshot was taken at.
    pub epoch: Epoch,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

impl BalanceSourceData {
    #[inline]
    pub fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
    }

    #[inline]
    pub fn unslashed_and_active_indices(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.effective_balances
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, balance)| {
                (balance > 0 && !self.slashed.get(i).copied().unwrap_or(false))
                    .then_some((i, balance))
            })
    }

    /// Return balance only if the validator is not slashed.
    /// Spec: `get_block_support_between_slots` excludes slashed validators.
    #[inline]
    pub fn unslashed_balance(&self, val_idx: usize) -> u64 {
        if self.slashed.get(val_idx).copied().unwrap_or(false) {
            0
        } else {
            self.balance(val_idx)
        }
    }
}
