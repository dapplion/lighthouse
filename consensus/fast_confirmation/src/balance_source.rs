//! Validator-balance snapshot used by the Fast Confirmation Rule.

use crate::Error;
use types::{BeaconState, Epoch, EthSpec, Hash256};

/// Cache key identifying the validator-set view a [`BalanceSourceData`] was built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceSourceKey {
    /// No slashings have been processed in the epoch (`state.slashings[epoch % E] == 0`): the
    /// epoch's dependent root (block at the last slot of the previous epoch) pins the effective
    /// balances, activation set and slashed flags for the whole epoch.
    NoSlashings { epoch_boundary_root: Hash256 },
    /// At least one slashing has been processed in the epoch. Slashings flip `Validator.slashed`
    /// mid-epoch without moving the dependent root, so the snapshot is keyed on its own block
    /// root instead and every head change rebuilds it for the rest of the epoch (cf. the
    /// unrealized-checkpoints fix in sigp/lighthouse#9471). A further slashing can only arrive
    /// via a new block, so the block root also distinguishes different slashing sets.
    SlashingsPresent { head_block_root: Hash256 },
}

impl BalanceSourceKey {
    /// `block_root` is the root of the block the snapshot's `state` descends from (the head
    /// root for the head source; the checkpoint root for checkpoint sources).
    pub(crate) fn compute<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        block_root: Hash256,
    ) -> Result<Self, Error> {
        let epoch_slashings = state
            .get_slashings(epoch)
            .map_err(|e| Error::SlashingsOutOfBounds(format!("slashings lookup: {e:?}")))?;
        if epoch_slashings > 0 {
            Ok(Self::SlashingsPresent {
                head_block_root: block_root,
            })
        } else {
            Ok(Self::NoSlashings {
                epoch_boundary_root: crate::dependent_root::<E>(state, epoch)?,
            })
        }
    }
}

/// Snapshot of a validator set's effective balances for one epoch.
///
/// The [`BalanceSourceKey`] fixes this snapshot — two chains sharing it have the same view — and
/// is used as the cache key.
#[derive(Clone, Debug)]
pub struct BalanceSourceData {
    pub key: BalanceSourceKey,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

impl BalanceSourceData {
    /// Build a balance source for a single `epoch` in one pass over the validator set, tagged with
    /// its [`BalanceSourceKey`] (computed from `state`, `epoch` and `block_root`). Effective
    /// balance is counted for active validators regardless of slashed status (matching the spec's
    /// `get_total_active_balance`); `slashed` is recorded separately for the slashed-filtering
    /// used by `get_block_support_between_slots`. The total uses a saturating add — it is a sum
    /// of effective balances and cannot realistically overflow.
    pub(crate) fn for_epoch<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        block_root: Hash256,
    ) -> Result<Self, Error> {
        let key = BalanceSourceKey::compute(state, epoch, block_root)?;
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

        Ok(Self {
            key,
            total_active_balance,
            effective_balances,
            slashed,
        })
    }

    pub(crate) fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
    }

    pub(crate) fn unslashed_and_active_indices(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
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
    pub(crate) fn unslashed_balance(&self, val_idx: usize) -> u64 {
        if self.slashed.get(val_idx).copied().unwrap_or(false) {
            0
        } else {
            self.balance(val_idx)
        }
    }
}
