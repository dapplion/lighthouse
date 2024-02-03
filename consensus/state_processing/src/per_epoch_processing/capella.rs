use super::altair::inactivity_updates::process_inactivity_updates;
use super::altair::justification_and_finalization::process_justification_and_finalization;
use super::altair::participation_cache::ParticipationCache;
use super::altair::participation_flag_updates::process_participation_flag_updates;
use super::altair::rewards_and_penalties::process_rewards_and_penalties;
use super::altair::sync_committee_updates::process_sync_committee_updates;
use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
use safe_arith::SafeArith;
use types::{BeaconState, BeaconStateDeneb, BeaconStateError, ChainSpec, EthSpec, RelativeEpoch};

use crate::common::update_progressive_balances_cache::{
    initialize_progressive_balances_cache, update_progressive_balances_on_epoch_transition,
};
pub use historical_summaries_update::process_historical_summaries_update;

mod historical_summaries_update;

pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary<T>, Error> {
    // Ensure the committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.build_committee_cache(RelativeEpoch::Next, spec)?;

    // Pre-compute participating indices and total balances.
    let participation_cache = ParticipationCache::new(state, spec)?;
    let sync_committee = state.current_sync_committee()?.clone();
    initialize_progressive_balances_cache(state, Some(&participation_cache), spec)?;

    // Justification and finalization.
    let justification_and_finalization_state =
        process_justification_and_finalization(state, &participation_cache)?;
    justification_and_finalization_state.apply_changes_to_state(state);

    process_inactivity_updates(state, &participation_cache, spec)?;

    // Rewards and Penalties.
    process_rewards_and_penalties(state, &participation_cache, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(
        state,
        participation_cache.current_epoch_total_active_balance(),
        spec,
    )?;

    // Reset eth1 data votes.
    process_eth1_data_reset(state)?;

    process_pending_balance_deposits(state, spec)?;
    process_pending_consolidations(state, spec)?;

    // Update effective balances with hysteresis (lag).
    process_effective_balance_updates(state, Some(&participation_cache), spec)?;

    // Reset slashings
    process_slashings_reset(state)?;

    // Set randao mix
    process_randao_mixes_reset(state)?;

    // Set historical summaries accumulator
    process_historical_summaries_update(state)?;

    // Rotate current/previous epoch participation
    process_participation_flag_updates(state)?;

    process_sync_committee_updates(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches(spec)?;

    update_progressive_balances_on_epoch_transition(state, spec)?;

    Ok(EpochProcessingSummary::Altair {
        participation_cache,
        sync_committee,
    })
}

pub fn process_pending_balance_deposits<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let activation_exit_churn_limit = state.get_activation_exit_churn_limit(spec)?;

    if let BeaconState::Deneb(BeaconStateDeneb {
        ref mut deposit_balance_to_consume,
        ref mut pending_balance_deposits,
        ref mut balances,
        ..
    }) = state
    {
        deposit_balance_to_consume.safe_add_assign(activation_exit_churn_limit)?;
        let mut next_pending_deposit_index = 0;
        for pending_balance_deposit in pending_balance_deposits.iter() {
            if *deposit_balance_to_consume < pending_balance_deposit.amount {
                break;
            }

            deposit_balance_to_consume.safe_sub_assign(pending_balance_deposit.amount)?;

            let index = pending_balance_deposit.index as usize;
            balances
                .get_mut(index)
                .ok_or(BeaconStateError::BalancesOutOfBounds(index))?
                .safe_add_assign(pending_balance_deposit.amount)?;

            next_pending_deposit_index.safe_add_assign(1)?;
        }

        // TODO(maxeb), converting to vec to have something while SSZ api supports pop
        let mut pending_balance_deposits_vec = pending_balance_deposits.to_vec();
        pending_balance_deposits_vec.drain(0..next_pending_deposit_index);
        *pending_balance_deposits = pending_balance_deposits_vec.into();
    }

    Ok(())
}

pub fn process_pending_consolidations<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch();

    if let BeaconState::Deneb(BeaconStateDeneb {
        ref mut pending_consolidations,
        ref mut balances,
        ref validators,
        ..
    }) = state
    {
        let mut next_pending_consolidation = 0;

        for pending_consolidation in pending_consolidations.iter() {
            let source_index = pending_consolidation.source_index as usize;
            let source_validator = validators
                .get(source_index)
                .ok_or(BeaconStateError::UnknownValidator(source_index))?;
            if source_validator.withdrawable_epoch > current_epoch {
                break;
            }

            if !source_validator.slashed {
                // Move active balance to target. Excess balance will be withdrawn.
                // Inlined get_active_balance function
                let active_balance_ceil = if source_validator.has_eth1_withdrawal_credential(spec) {
                    spec.min_activation_balance
                } else {
                    spec.max_effective_balance(types::ForkName::Deneb)
                };
                let balance_source = balances
                    .get_mut(source_index)
                    .ok_or(BeaconStateError::BalancesOutOfBounds(source_index))?;
                let target_index = pending_consolidation.target_index as usize;
                let active_balance = std::cmp::min(*balance_source, active_balance_ceil);
                balance_source.safe_sub_assign(active_balance)?;
                let balance_target = balances
                    .get_mut(target_index)
                    .ok_or(BeaconStateError::BalancesOutOfBounds(source_index))?;
                balance_target.safe_add_assign(active_balance)?;
            }

            next_pending_consolidation.safe_add_assign(1)?;
        }

        // TODO(maxeb), converting to vec to have something while SSZ api supports pop
        let mut pending_consolidations_vec = pending_consolidations.to_vec();
        pending_consolidations_vec.drain(0..next_pending_consolidation);
        *pending_consolidations = pending_consolidations_vec.into();
    }

    Ok(())
}
