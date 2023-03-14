use super::altair::inactivity_updates::process_inactivity_updates;
use super::altair::justification_and_finalization::process_justification_and_finalization;
use super::altair::participation_cache::ParticipationCache;
use super::altair::participation_flag_updates::process_participation_flag_updates;
use super::altair::rewards_and_penalties::process_rewards_and_penalties;
use super::altair::sync_committee_updates::process_sync_committee_updates;
use super::{process_registry_updates, process_slashings, EpochProcessingSummary, Error};
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    errors::EpochProcessingError,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
use safe_arith::SafeArith;
use types::{BeaconState, BeaconStateCapella, ChainSpec, Epoch, EthSpec, ForkName, RelativeEpoch};

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

    process_whisk_updates(state, spec)?;

    // Rotate the epoch caches to suit the epoch transition.
    state.advance_caches(spec)?;

    update_progressive_balances_on_epoch_transition(state, spec)?;

    Ok(EpochProcessingSummary::Altair {
        participation_cache,
        sync_committee,
    })
}

fn process_whisk_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    if next_epoch.safe_rem(T::whisk_epochs_per_shuffling_phase())? == 0 {
        select_whisk_trackers(state, next_epoch, spec)?;
    }
    Ok(())
}

fn select_whisk_trackers<T: EthSpec>(
    state: &mut BeaconState<T>,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    // TODO: If after whisk
    match state.fork_name(spec) {
        Ok(ForkName::Capella) => {}
        _ => return Ok(()),
    }

    let whisk_proposer_indices = state.compute_whisk_proposer_indices(epoch, spec)?;
    let whisk_candidate_indices = state.compute_whisk_candidate_indices(epoch, spec)?;

    // TODO: @sproul expects automation of this match on superstruct
    let (whisk_proposer_trackers, whisk_candidate_trackers, whisk_validator_trackers) = match state
    {
        BeaconState::Capella(BeaconStateCapella {
            ref mut whisk_proposer_trackers,
            ref mut whisk_candidate_trackers,
            ref whisk_validator_trackers,
            ..
        }) => (
            whisk_proposer_trackers,
            whisk_candidate_trackers,
            whisk_validator_trackers,
        ),
        _ => return Ok(()),
    };

    // Select proposer trackers from candidate trackers
    for (index, tracker) in whisk_proposer_indices
        .iter()
        .zip(&mut whisk_proposer_trackers.iter_mut())
    {
        *tracker = whisk_candidate_trackers
            .get(*index)
            .ok_or(EpochProcessingError::WhiskIndexOutOfBounds)?
            .clone();
    }

    // Select candidate trackers from active validator trackers
    for (index, tracker) in whisk_candidate_indices
        .iter()
        .zip(&mut whisk_candidate_trackers.iter_mut())
    {
        *tracker = whisk_validator_trackers
            .get(*index)
            .ok_or(EpochProcessingError::WhiskIndexOutOfBounds)?
            .clone();
    }

    Ok(())
}
