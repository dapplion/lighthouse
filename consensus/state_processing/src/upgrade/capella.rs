use bls::PublicKeyBytes;
use curdleproofs_whisk::{compute_initial_tracker, deserialize_fr, Fr};
use ethereum_hashing::hash;
use ssz_types::{FixedVector, VariableList};
use std::mem;
use types::{
    BeaconState, BeaconStateCapella, BeaconStateError as Error, ChainSpec, EthSpec, Fork, Validator,
};

/// Transform a `Merge` state into an `Capella` state.
pub fn upgrade_to_capella<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = pre_state.current_epoch();

    // Initialize all validators with predictable commitments
    let mut whisk_validator_trackers = VariableList::empty();
    let mut whisk_validator_k_commitments = VariableList::empty();
    for validator in pre_state.validators().iter() {
        let k = compute_initial_whisk_k(validator);
        let (k_commitment, tracker) =
            compute_initial_tracker(&k).map_err(|e| Error::WhiskInvalid(e.to_string()))?;
        whisk_validator_trackers.push(tracker)?;
        whisk_validator_k_commitments.push(k_commitment)?;
    }

    // Select proposers and candidates
    // Do a candidate selection followed by a proposer selection so that we have proposers for the upcoming day
    // Use an old epoch when selecting candidates so that we don't get the same seed as in the next candidate selection
    let mut whisk_candidate_trackers = Vec::with_capacity(E::whisk_candidate_trackers_count());
    let mut whisk_proposer_trackers = Vec::with_capacity(E::whisk_proposer_trackers_count());
    let whisk_proposer_indices = pre_state.compute_whisk_proposer_indices(epoch, spec)?;
    // TODO WHISK: per spec, should use an epoch in the past but compute_whisk_candidate_indices only supports
    // current epoch.
    let whisk_candidate_indices_prev_epoch =
        pre_state.compute_whisk_candidate_indices(epoch, spec)?;
    let whisk_candidate_proposer = pre_state.compute_whisk_candidate_indices(epoch, spec)?;
    // Select candidate trackers from active validator trackers
    for candidate_index in whisk_candidate_indices_prev_epoch.iter() {
        whisk_candidate_trackers.push(
            whisk_validator_trackers
                .get(*candidate_index)
                .ok_or(Error::WhiskIndexOutOfBounds)?
                .clone(),
        );
    }
    // Select proposer trackers
    for proposer_index in whisk_proposer_indices.iter() {
        let candidate_index = whisk_candidate_proposer
            .get(*proposer_index)
            .ok_or(Error::WhiskIndexOutOfBounds)?;
        whisk_proposer_trackers.push(
            whisk_validator_trackers
                .get(*candidate_index)
                .ok_or(Error::WhiskIndexOutOfBounds)?
                .clone(),
        );
    }

    let pre = pre_state.as_merge_mut()?;

    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let post = BeaconState::Capella(BeaconStateCapella {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.capella_fork_version,
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
        latest_execution_payload_header: pre.latest_execution_payload_header.upgrade_to_capella(),
        // Capella
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: VariableList::default(),
        // Whisk
        whisk_candidate_trackers: FixedVector::from(whisk_candidate_trackers),
        whisk_proposer_trackers: FixedVector::from(whisk_proposer_trackers),
        whisk_validator_trackers,
        whisk_validator_k_commitments,
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

// TODO: move utils to somewhere

/// Compute the initial deterministic whisk k secret for validator with `pubkey`
pub fn compute_initial_whisk_k(validator: &Validator) -> Fr {
    compute_initial_whisk_k_from_pubkey(&validator.pubkey)
}

pub fn compute_initial_whisk_k_from_pubkey(pubkey: &PublicKeyBytes) -> Fr {
    deserialize_fr(&hash(pubkey.as_serialized()))
}
