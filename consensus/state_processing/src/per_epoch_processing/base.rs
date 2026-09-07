use super::{EpochProcessingSummary, Error, process_registry_updates, process_slashings};
use crate::epoch_cache::initialize_epoch_cache;
use crate::per_epoch_processing::{
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
pub use justification_and_finalization::process_justification_and_finalization;
pub use participation_record_updates::process_participation_record_updates;
pub use rewards_and_penalties::process_rewards_and_penalties;
use types::{BeaconState, BeaconStateError, ChainSpec, EthSpec, RelativeEpoch, Shufflings};
pub use validator_statuses::{TotalBalances, ValidatorStatus, ValidatorStatuses};

pub mod justification_and_finalization;
pub mod participation_record_updates;
pub mod rewards_and_penalties;
pub mod validator_statuses;

pub fn process_epoch<E: EthSpec>(
    state: &mut BeaconState<E>,
    shufflings: Option<&mut Shufflings>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary<E>, Error> {
    // Phase0 rewards read attestation committees, so shufflings are mandatory here.
    let shufflings = shufflings.ok_or(BeaconStateError::ShufflingsNotProvided)?;
    shufflings.check_matches(state)?;

    state.build_active_totals_cache(spec)?;
    initialize_epoch_cache(state, spec)?;

    // Load the struct we use to assign validators into sets based on their participation.
    //
    // E.g., attestation in the previous epoch, attested to the head, etc.
    let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
    validator_statuses.process_attestations(state, shufflings)?;

    // Justification and finalization.
    let justification_and_finalization_state =
        process_justification_and_finalization(state, &validator_statuses.total_balances, spec)?;
    justification_and_finalization_state.apply_changes_to_state(state);

    // Rewards and Penalties.
    process_rewards_and_penalties(state, &validator_statuses, spec)?;

    // Registry Updates.
    process_registry_updates(state, spec)?;

    // Slashings.
    process_slashings(
        state,
        validator_statuses.total_balances.current_epoch(),
        spec,
    )?;

    // Reset eth1 data votes.
    process_eth1_data_reset(state)?;

    // Update effective balances with hysteresis (lag).
    process_effective_balance_updates(state, spec)?;

    // Reset slashings
    process_slashings_reset(state)?;

    // Set randao mix
    process_randao_mixes_reset(state)?;

    // Set historical root accumulator
    process_historical_roots_update(state)?;

    // Rotate current/previous epoch attestations
    process_participation_record_updates(state)?;

    // Rotate the shufflings to suit the epoch transition. `advance` rejects a cache that is not
    // initialized for the incoming next epoch.
    let lookahead_epoch = RelativeEpoch::Next.into_epoch(state.next_epoch()?);
    let next_shuffling = state.initialize_committee_cache_for_lookahead(lookahead_epoch, spec)?;
    shufflings.advance(next_shuffling)?;

    Ok(EpochProcessingSummary::Base {
        total_balances: validator_statuses.total_balances,
        statuses: validator_statuses.statuses,
    })
}
