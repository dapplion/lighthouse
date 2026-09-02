//! Validator-balance snapshot used by the Fast Confirmation Rule, built from a
//! `BeaconState`.

use crate::Error;
use crate::adapter;
use fast_confirmation::BalanceSourceData;
use safe_arith::SafeArith;
use types::{BeaconState, Epoch, EthSpec, Hash256};

/// Cache key identifying the validator-set view a `BalanceSourceData` was built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceSourceKey {
    /// No slashings have been processed in the `epoch` (`state.slashings[epoch % E] == 0`): the
    /// epoch's boundary root (block at the last slot of the previous epoch) pins the effective
    /// balances, activation set and slashed flags for the whole epoch.
    NoSlashings {
        epoch_boundary_root: Hash256,
        epoch: Epoch,
    },
    /// At least one slashing has been processed in the epoch. Slashings flip `Validator.slashed`
    /// mid-epoch without moving the epoch boundary root, so the snapshot is keyed on its own block
    /// root instead and every head change rebuilds it for the rest of the epoch.
    SlashingsPresent { head_block_root: Hash256 },
}

impl BalanceSourceKey {
    /// Create a key for a specific `block_root` and its state.
    pub(crate) fn compute<E: EthSpec>(
        state: &BeaconState<E>,
        block_root: Hash256,
    ) -> Result<Self, Error> {
        let epoch = state.current_epoch();
        let epoch_slashings = state
            .get_slashings(epoch)
            .map_err(|e| Error::SlashingsOutOfBounds(format!("slashings lookup: {e:?}")))?;
        if epoch_slashings > 0 {
            Ok(Self::SlashingsPresent {
                head_block_root: block_root,
            })
        } else {
            Ok(Self::NoSlashings {
                epoch_boundary_root: get_epoch_boundary_root::<E>(state)?,
                epoch,
            })
        }
    }
}

/// Create a balance source for `state` at its current epoch.
///
/// The state must be pulled up to the desired epoch prior to calling this function.
pub(crate) fn build<E: EthSpec>(state: &BeaconState<E>) -> BalanceSourceData {
    let current_epoch = state.current_epoch();
    let validators = state.validators();
    let mut effective_balances = Vec::with_capacity(validators.len());
    let mut slashed = Vec::with_capacity(validators.len());
    let mut total_active_balance = 0u64;

    for validator in validators.iter() {
        slashed.push(validator.slashed);
        if validator.is_active_at(current_epoch) {
            effective_balances.push(validator.effective_balance);
            total_active_balance = total_active_balance.saturating_add(validator.effective_balance);
        } else {
            effective_balances.push(0);
        }
    }

    BalanceSourceData {
        epoch: adapter::epoch(current_epoch),
        total_active_balance,
        effective_balances,
        slashed,
    }
}

/// Block root at the last slot of the previous epoch.
///
/// Used to identify the balance source fields of the `validator` registry in the absence of
/// slashings.
fn get_epoch_boundary_root<E: EthSpec>(state: &BeaconState<E>) -> Result<Hash256, Error> {
    if state.current_epoch() == 0 {
        return Ok(Hash256::ZERO);
    }
    let slot = state
        .current_epoch()
        .start_slot(E::slots_per_epoch())
        .safe_sub(1)?;
    Ok(*state
        .get_block_root(slot)
        .map_err(|e| Error::BlockRootsOutOfBounds(format!("{e:?}")))?)
}
