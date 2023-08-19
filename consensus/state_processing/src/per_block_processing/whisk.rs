use bls::Signature;
use curdleproofs_whisk::{
    is_g1_generator, is_matching_tracker, is_valid_whisk_tracker_proof, BLSG1Point,
    TrackerProofBytes, WhiskShuffleProofBytes, WhiskTracker, TRACKER_PROOF_SIZE, WHISK,
    WHISK_SHUFFLE_PROOF_SIZE,
};
use ethereum_hashing::hash;
use int_to_bytes::int_to_bytes8;
use safe_arith::SafeArith;
use ssz::Encode;
use types::{
    AbstractExecPayload, BeaconBlockBodyRef, BeaconBlockRef, BeaconState, BeaconStateCapella,
    BeaconStateError, ChainSpec, Epoch, EthSpec, WhiskShuffleProof, WhiskTrackerProof,
};

use crate::{upgrade::capella::compute_initial_whisk_k, BlockProcessingError};

use super::errors::{BlockOperationError, HeaderInvalid};

pub fn process_whisk_registration<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    block: BeaconBlockRef<T, Payload>,
) -> Result<(), BlockProcessingError> {
    if let (
        Ok(whisk_registration_proof),
        Ok(whisk_tracker),
        Ok(whisk_k_commitment),
        BeaconState::Capella(BeaconStateCapella {
            ref mut whisk_validator_trackers,
            ref mut whisk_validator_k_commitments,
            ..
        }),
    ) = (
        block.body().whisk_registration_proof(),
        block.body().whisk_tracker(),
        block.body().whisk_k_commitment(),
        state,
    ) {
        // TODO: This function needs access to mut fields + a method state.is_k_commitment_unique()
        // A better way to do this?
        let proposer = block.proposer_index() as usize;
        let proposer_tracker = &whisk_validator_trackers
            .get(proposer)
            .ok_or(BlockProcessingError::ProposerOutOfBounds)?;

        if is_g1_generator(&proposer_tracker.r_g) {
            // First whisk proposal
            block_verify!(
                !is_g1_generator(&whisk_tracker.r_g),
                BlockProcessingError::InvalidWhisk("r_g not g1 generator".to_string())
            );
            block_verify!(
                is_k_commitment_unique(whisk_validator_k_commitments, whisk_k_commitment),
                BlockProcessingError::InvalidWhisk("k_commitment not unique".to_string())
            );
            block_verify!(
                is_valid_whisk_tracker_proof(
                    whisk_tracker,
                    whisk_k_commitment,
                    &ssz_tracker_proof_to_crypto_tracker_proof::<T>(whisk_registration_proof),
                )
                .unwrap_or(false),
                BlockProcessingError::InvalidWhisk("invalid registration proof".to_string())
            );

            *whisk_validator_k_commitments
                .get_mut(proposer)
                .ok_or(BlockProcessingError::ProposerOutOfBounds)? = whisk_k_commitment.clone();
            *whisk_validator_trackers
                .get_mut(proposer)
                .ok_or(BlockProcessingError::ProposerOutOfBounds)? = whisk_tracker.clone();
        } else {
            block_verify!(
                whisk_registration_proof == &WhiskTrackerProof::<T>::default(),
                BlockProcessingError::InvalidWhisk(
                    "expected default registration proof".to_string()
                )
            );
            block_verify!(
                whisk_tracker == &WhiskTracker::default(),
                BlockProcessingError::InvalidWhisk(format!(
                    "expected default registration tracker: {:?}",
                    whisk_tracker
                ))
            );
            block_verify!(
                whisk_k_commitment == &BLSG1Point::default(),
                BlockProcessingError::InvalidWhisk(format!(
                    "expected default registration commitment: {:?}",
                    whisk_tracker
                ))
            );
        }
    }

    Ok(())
}

pub fn ssz_tracker_proof_to_crypto_tracker_proof<T: EthSpec>(
    tracker_proof: &WhiskTrackerProof<T>,
) -> TrackerProofBytes {
    let vec: Vec<u8> = tracker_proof.as_ssz_bytes();
    let mut arr = [0; TRACKER_PROOF_SIZE];
    arr.copy_from_slice(&vec);
    arr
}

fn ssz_shuffle_proof_to_crypto_shuffle_proof<T: EthSpec>(
    shuffle_proof: &WhiskShuffleProof<T>,
) -> WhiskShuffleProofBytes {
    let vec: Vec<u8> = shuffle_proof.as_ssz_bytes();
    let mut arr = [0; WHISK_SHUFFLE_PROOF_SIZE];
    arr.copy_from_slice(&vec);
    arr
}

pub fn is_k_commitment_unique(
    whisk_validator_k_commitments: &[BLSG1Point],
    k_commitment: &BLSG1Point,
) -> bool {
    for whisk_k_commitment in whisk_validator_k_commitments {
        if whisk_k_commitment == k_commitment {
            return false;
        }
    }
    true
}

/// Given a `randao_reveal` return the list of indices that got shuffled from the entire candidate set
pub fn get_shuffle_indices<T: EthSpec>(randao_reveal: &Signature) -> Vec<usize> {
    let randao_reveal = randao_reveal.as_ssz_bytes();
    let mut shuffle_indices: Vec<usize> = Vec::with_capacity(T::whisk_validators_per_shuffle());

    for i in 0..T::whisk_validators_per_shuffle() as u64 {
        let mut pre_image = randao_reveal.clone();
        pre_image.append(&mut int_to_bytes8(i));
        // TODO: from_be_bytes truncates the output correctly?
        // TODO: big or little endian?.
        #[allow(clippy::expect_used)]
        #[allow(clippy::arithmetic_side_effects)]
        let shuffle_index = usize::from_be_bytes(
            hash(&pre_image)
                .get(0..8)
                .expect("hash is 32 bytes")
                .try_into()
                .expect("first 8 bytes of signature should always convert to fixed array"),
        )
        .wrapping_rem(T::whisk_candidate_trackers_count());
        shuffle_indices.push(shuffle_index);
    }

    shuffle_indices
}

pub fn process_shuffled_trackers<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    body: BeaconBlockBodyRef<T, Payload>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let current_epoch = state.current_epoch();

    // Check shuffle proof
    if let (
        Ok(whisk_candidate_trackers),
        Ok(whisk_post_shuffle_trackers),
        Ok(whisk_shuffle_proof),
    ) = (
        state.whisk_candidate_trackers_mut(),
        body.whisk_post_shuffle_trackers(),
        body.whisk_shuffle_proof(),
    ) {
        // Actual count of shuffled trackers is `ELL - N_BLINDERS`. See:
        // https://github.com/dapplion/curdleproofs/blob/641c5692f285c3f3672c53022f52a1b199f0b338/src/lib.rs#L32-L33
        let post_shuffle_trackers: Vec<WhiskTracker> =
            whisk_post_shuffle_trackers.iter().cloned().collect();

        if !should_shuffle_trackers(current_epoch, spec) {
            // Require zero-ed trackers during cooldown
            let zero_tracker = WhiskTracker::default();
            block_verify!(
                post_shuffle_trackers
                    .iter()
                    .all(|tracker| tracker == &zero_tracker),
                BlockProcessingError::InvalidWhisk("changed trackers during cooldown".to_string())
            );
        } else {
            // Given a `randao_reveal` return the list of indices that got shuffled from the entire candidate set
            let shuffle_indices = get_shuffle_indices::<T>(body.randao_reveal());
            let mut pre_shuffle_trackers: Vec<WhiskTracker> = vec![];
            for i in shuffle_indices.iter() {
                pre_shuffle_trackers.push(
                    whisk_candidate_trackers
                        .get(*i)
                        .ok_or(BlockProcessingError::ShuffleIndexOutOfBounds)?
                        .clone(),
                );
            }

            // Require shuffled trackers during shuffle
            block_verify!(
                WHISK
                    .is_valid_whisk_shuffle_proof(
                        pre_shuffle_trackers.as_ref(),
                        post_shuffle_trackers.as_ref(),
                        &ssz_shuffle_proof_to_crypto_shuffle_proof::<T>(whisk_shuffle_proof),
                    )
                    .is_ok(),
                BlockProcessingError::InvalidWhisk("invalid shuffle proof".to_string())
            );

            // Shuffle candidate trackers
            for (tracker, index) in post_shuffle_trackers.into_iter().zip(shuffle_indices) {
                *whisk_candidate_trackers
                    .get_mut(index)
                    .ok_or(BlockProcessingError::ShuffleIndexOutOfBounds)? = tracker;
            }
        }
    }

    Ok(())
}

/// Return true if at `epoch` validator should shuffle candidate trackers
#[allow(clippy::arithmetic_side_effects)]
pub fn should_shuffle_trackers(epoch: Epoch, spec: &ChainSpec) -> bool {
    // (clippy::arithmetic_side_effects) Will never divide by zero
    epoch % spec.whisk_epochs_per_shuffling_phase + spec.whisk_proposer_selection_gap + 1
        < spec.whisk_epochs_per_shuffling_phase
}

pub fn verify_whisk_opening_proof<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &BeaconState<T>,
    block: BeaconBlockRef<T, Payload>,
) -> Result<(), BlockOperationError<HeaderInvalid>> {
    let proposer_index = block.proposer_index();
    let whisk_opening_proof = block.body().whisk_opening_proof()?;
    let whisk_proposer_trackers = state.whisk_proposer_trackers()?;
    let whisk_validator_k_commitments = state.whisk_validator_k_commitments()?;

    // process_whisk_opening_proof
    #[allow(clippy::expect_used)]
    let tracker = whisk_proposer_trackers
        .get(
            // Use block so gossip validation can use a not dialed forward
            block
                .slot()
                .as_usize()
                .safe_rem(T::whisk_proposer_trackers_count())
                .expect("whisk_proposer_tracker_count is never 0"),
        )
        .expect("arr[x mod arr.len] always in bounds");

    // Proposal against tracker created with deterministic k
    if whisk_opening_proof == &WhiskTrackerProof::<T>::default() {
        let validator = state.get_validator(proposer_index as usize)?;
        let initial_k = compute_initial_whisk_k(validator);

        verify!(
            tracker
                .try_into()
                .map(|tracker| is_matching_tracker(&tracker, &initial_k))
                .unwrap_or(false),
            HeaderInvalid::InitialWhiskProposerMismatch
        );
    } else {
        let k_commitment = &whisk_validator_k_commitments
            .get(proposer_index as usize)
            .ok_or(BeaconStateError::UnknownValidator(proposer_index as usize))?;
        let whisk_opening_proof =
            ssz_tracker_proof_to_crypto_tracker_proof::<T>(whisk_opening_proof);

        verify!(
            is_valid_whisk_tracker_proof(tracker, k_commitment, &whisk_opening_proof)
                .unwrap_or(false),
            HeaderInvalid::ProposerProofInvalid
        )
    }

    Ok(())
}
