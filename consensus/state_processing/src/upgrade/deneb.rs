use std::mem;
use types::{
    BeaconState, BeaconStateDeneb, BeaconStateError as Error, ChainSpec, EthSpec, Fork,
    RelativeEpoch,
};

/// Transform a `Capella` state into an `Deneb` state.
pub fn upgrade_to_deneb<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let earliest_exit_epoch = pre_state
        .validators()
        .iter()
        .map(|v| v.exit_epoch.as_u64())
        .filter(|exit_epoch| *exit_epoch != spec.far_future_epoch.as_u64())
        .max()
        .unwrap_or(0);

    // Needs to build total active balance cache
    pre_state.build_committee_cache(RelativeEpoch::Current, spec)?;
    let exit_balance_to_consume = pre_state.get_activation_exit_churn_limit(spec)?;

    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_capella_mut()?;

    let previous_fork_version = pre.fork.current_version;

    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let post = BeaconState::Deneb(BeaconStateDeneb {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: previous_fork_version,
            current_version: spec.deneb_fork_version,
            epoch,
        },
        // History
        latest_block_header: pre.latest_block_header.clone(),
        block_roots: pre.block_roots.clone(),
        state_roots: pre.state_roots.clone(),
        historical_roots: mem::take(&mut pre.historical_roots),
        // Eth1
        eth1_data: pre.eth1_data.clone(),
        eth1_data_votes: mem::take(&mut pre.eth1_data_votes),
        eth1_deposit_index: pre.eth1_deposit_index,
        // Registry
        validators: mem::take(&mut pre.validators),
        balances: mem::take(&mut pre.balances),
        // Randomness
        randao_mixes: pre.randao_mixes.clone(),
        // Slashings
        slashings: pre.slashings.clone(),
        // `Participation
        previous_epoch_participation: mem::take(&mut pre.previous_epoch_participation),
        current_epoch_participation: mem::take(&mut pre.current_epoch_participation),
        // Finality
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        // Inactivity
        inactivity_scores: mem::take(&mut pre.inactivity_scores),
        // Sync committees
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        // Execution
        latest_execution_payload_header: pre.latest_execution_payload_header.upgrade_to_deneb(),
        // Capella
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
        // MaxEB
        deposit_balance_to_consume: 0u64.into(),
        pending_balance_deposits: <_>::default(),
        earliest_exit_epoch: earliest_exit_epoch.into(),
        exit_balance_to_consume,
        // Caches
        total_active_balance: pre.total_active_balance,
        progressive_balances_cache: mem::take(&mut pre.progressive_balances_cache),
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        tree_hash_cache: mem::take(&mut pre.tree_hash_cache),
    });

    *pre_state = post;

    Ok(())
}
