use crate::consensus_context::ConsensusContext;
use crate::upgrade::capella::compute_initial_whisk_k;
use curdleproofs_whisk::{
    is_g1_generator, is_matching_tracker, is_valid_whisk_tracker_proof, BLSG1Point,
    TrackerProofBytes, WhiskShuffleProofBytes, TRACKER_PROOF_SIZE, WHISK, WHISK_SHUFFLE_ELL,
    WHISK_SHUFFLE_PROOF_SIZE,
};
use errors::{BlockOperationError, BlockProcessingError, HeaderInvalid};
use ethereum_hashing::hash;
use int_to_bytes::int_to_bytes8;
use rayon::prelude::*;
use safe_arith::{ArithError, SafeArith};
use signature_sets::{block_proposal_signature_set, get_pubkey_from_state, randao_signature_set};
use ssz::Encode;
use std::borrow::Cow;
use tree_hash::TreeHash;
use types::*;

pub use self::verify_attester_slashing::{
    get_slashable_indices, get_slashable_indices_modular, verify_attester_slashing,
};
pub use self::verify_proposer_slashing::verify_proposer_slashing;
pub use altair::sync_committee::process_sync_aggregate;
pub use block_signature_verifier::{BlockSignatureVerifier, ParallelSignatureSets};
pub use is_valid_indexed_attestation::is_valid_indexed_attestation;
pub use process_operations::process_operations;
pub use verify_attestation::{
    verify_attestation_for_block_inclusion, verify_attestation_for_state,
};
pub use verify_bls_to_execution_change::verify_bls_to_execution_change;
pub use verify_deposit::{
    get_existing_validator_index, verify_deposit_merkle_proof, verify_deposit_signature,
};
pub use verify_exit::verify_exit;

pub mod altair;
pub mod block_signature_verifier;
pub mod errors;
mod is_valid_indexed_attestation;
pub mod process_operations;
pub mod signature_sets;
pub mod tests;
mod verify_attestation;
mod verify_attester_slashing;
mod verify_bls_to_execution_change;
mod verify_deposit;
mod verify_exit;
mod verify_proposer_slashing;

use crate::common::decrease_balance;
use crate::StateProcessingStrategy;

use crate::common::update_progressive_balances_cache::{
    initialize_progressive_balances_cache, update_progressive_balances_metrics,
};
#[cfg(feature = "arbitrary-fuzz")]
use arbitrary::Arbitrary;

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum BlockSignatureStrategy {
    /// Do not validate any signature. Use with caution.
    NoVerification,
    /// Validate each signature individually, as its object is being processed.
    VerifyIndividual,
    /// Validate only the randao reveal signature.
    VerifyRandao,
    /// Verify all signatures in bulk at the beginning of block processing.
    VerifyBulk,
}

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifySignatures {
    /// Validate all signatures encountered.
    True,
    /// Do not validate any signature. Use with caution.
    False,
}

impl VerifySignatures {
    pub fn is_true(self) -> bool {
        self == VerifySignatures::True
    }
}

/// Control verification of the latest block header.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifyBlockRoot {
    True,
    False,
}

/// Updates the state for a new block, whilst validating that the block is valid, optionally
/// checking the block proposer signature.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// If `block_root` is `Some`, this root is used for verification of the proposer's signature. If it
/// is `None` the signing root is computed from scratch. This parameter only exists to avoid
/// re-calculating the root when it is already known. Note `block_root` should be equal to the
/// tree hash root of the block, NOT the signing root of the block. This function takes
/// care of mixing in the domain.
pub fn per_block_processing<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    signed_block: &SignedBeaconBlock<T, Payload>,
    block_signature_strategy: BlockSignatureStrategy,
    state_processing_strategy: StateProcessingStrategy,
    verify_block_root: VerifyBlockRoot,
    ctxt: &mut ConsensusContext<T>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let block = signed_block.message();

    // Verify that the `SignedBeaconBlock` instantiation matches the fork at `signed_block.slot()`.
    signed_block
        .fork_name(spec)
        .map_err(BlockProcessingError::InconsistentBlockFork)?;

    // Verify that the `BeaconState` instantiation matches the fork at `state.slot()`.
    state
        .fork_name(spec)
        .map_err(BlockProcessingError::InconsistentStateFork)?;

    initialize_progressive_balances_cache(state, None, spec)?;

    let verify_signatures = match block_signature_strategy {
        BlockSignatureStrategy::VerifyBulk => {
            // Verify all signatures in the block at once.
            block_verify!(
                BlockSignatureVerifier::verify_entire_block(
                    state,
                    |i| get_pubkey_from_state(state, i),
                    |pk_bytes| pk_bytes.decompress().ok().map(Cow::Owned),
                    signed_block,
                    ctxt,
                    spec
                )
                .is_ok(),
                BlockProcessingError::BulkSignatureVerificationFailed
            );
            VerifySignatures::False
        }
        BlockSignatureStrategy::VerifyIndividual => VerifySignatures::True,
        BlockSignatureStrategy::NoVerification => VerifySignatures::False,
        BlockSignatureStrategy::VerifyRandao => VerifySignatures::False,
    };

    let proposer_index = process_block_header(state, block, verify_block_root, ctxt, spec)?;

    if verify_signatures.is_true() {
        verify_block_signature(state, signed_block, ctxt, spec)?;
    }

    let verify_randao = if let BlockSignatureStrategy::VerifyRandao = block_signature_strategy {
        VerifySignatures::True
    } else {
        verify_signatures
    };
    // Ensure the current and previous epoch caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

    // The call to the `process_execution_payload` must happen before the call to the
    // `process_randao` as the former depends on the `randao_mix` computed with the reveal of the
    // previous block.
    if is_execution_enabled(state, block.body()) {
        let payload = block.body().execution_payload()?;
        if state_processing_strategy == StateProcessingStrategy::Accurate {
            process_withdrawals::<T, Payload>(state, payload, spec)?;
        }
        process_execution_payload::<T, Payload>(state, payload, spec)?;
    }

    process_randao(state, block, verify_randao, ctxt, spec)?;
    process_eth1_data(state, block.body().eth1_data())?;
    process_operations(state, block, verify_signatures, ctxt, spec)?;

    if let Ok(sync_aggregate) = block.body().sync_aggregate() {
        process_sync_aggregate(
            state,
            sync_aggregate,
            proposer_index,
            verify_signatures,
            spec,
        )?;
    }

    if is_progressive_balances_enabled(state) {
        update_progressive_balances_metrics(state.progressive_balances_cache())?;
    }

    process_shuffled_trackers(state, block.body())?;
    process_whisk_registration(state, block)?;

    Ok(())
}

fn process_whisk_registration<T: EthSpec, Payload: AbstractExecPayload<T>>(
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

fn process_shuffled_trackers<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    body: BeaconBlockBodyRef<T, Payload>,
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

        // Actual count of shuffled trackers is `ELL - N_BLINDERS`. See:
        // https://github.com/dapplion/curdleproofs/blob/641c5692f285c3f3672c53022f52a1b199f0b338/src/lib.rs#L32-L33
        let post_shuffle_trackers: Vec<WhiskTracker> = whisk_post_shuffle_trackers
            .iter()
            .take(WHISK_SHUFFLE_ELL)
            .cloned()
            .collect();

        if !should_shuffle_trackers::<T>(current_epoch) {
            // Require unchanged trackers during cooldown
            block_verify!(
                pre_shuffle_trackers == post_shuffle_trackers,
                BlockProcessingError::InvalidWhisk("changed trackers during cooldown".to_string())
            );
        } else {
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
        }

        // Shuffle candidate trackers
        for (tracker, index) in post_shuffle_trackers.into_iter().zip(shuffle_indices) {
            *whisk_candidate_trackers
                .get_mut(index)
                .ok_or(BlockProcessingError::ShuffleIndexOutOfBounds)? = tracker;
        }
    }

    Ok(())
}

/// Return true if at `epoch` validator should shuffle candidate trackers
#[allow(clippy::arithmetic_side_effects)]
pub fn should_shuffle_trackers<T: EthSpec>(epoch: Epoch) -> bool {
    // (clippy::arithmetic_side_effects) Will never divide by zero
    epoch % T::whisk_epochs_per_shuffling_phase() + T::whisk_proposer_selection_gap() + 1
        < T::whisk_epochs_per_shuffling_phase()
}

/// Processes the block header, returning the proposer index.
pub fn process_block_header<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    block: BeaconBlockRef<T, Payload>,
    verify_block_root: VerifyBlockRoot,
    ctxt: &mut ConsensusContext<T>,
    spec: &ChainSpec,
) -> Result<u64, BlockOperationError<HeaderInvalid>> {
    let block_header = block.temporary_block_header();

    // Verify that the slots match
    verify!(
        block_header.slot == state.slot(),
        HeaderInvalid::StateSlotMismatch
    );

    // Verify that the block is newer than the latest block header
    verify!(
        block_header.slot > state.latest_block_header().slot,
        HeaderInvalid::OlderThanLatestBlockHeader {
            block_slot: block_header.slot,
            latest_block_header_slot: state.latest_block_header().slot,
        }
    );

    // Verify that proposer index is the correct index
    let proposer_index = block_header.proposer_index;

    if let (
        Ok(whisk_opening_proof),
        Ok(whisk_proposer_trackers),
        Ok(whisk_validator_k_commitments),
    ) = (
        block.body().whisk_opening_proof(),
        state.whisk_proposer_trackers(),
        state.whisk_validator_k_commitments(),
    ) {
        // process_whisk_opening_proof
        #[allow(clippy::expect_used)]
        let tracker = whisk_proposer_trackers
            .get(
                state
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
    } else {
        let state_proposer_index = ctxt.get_proposer_index(state, spec)?;
        verify!(
            proposer_index == state_proposer_index,
            HeaderInvalid::ProposerIndexMismatch {
                block_proposer_index: proposer_index,
                state_proposer_index,
            }
        );
    }

    if verify_block_root == VerifyBlockRoot::True {
        let expected_previous_block_root = state.latest_block_header().tree_hash_root();
        verify!(
            block_header.parent_root == expected_previous_block_root,
            HeaderInvalid::ParentBlockRootMismatch {
                state: expected_previous_block_root,
                block: block_header.parent_root,
            }
        );
    }

    *state.latest_block_header_mut() = block_header;

    // Verify proposer is not slashed
    verify!(
        !state.get_validator(proposer_index as usize)?.slashed,
        HeaderInvalid::ProposerSlashed(proposer_index)
    );

    Ok(proposer_index)
}

/// Verifies the signature of a block.
///
/// Spec v0.12.1
pub fn verify_block_signature<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &BeaconState<T>,
    block: &SignedBeaconBlock<T, Payload>,
    ctxt: &mut ConsensusContext<T>,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<HeaderInvalid>> {
    let block_root = Some(ctxt.get_current_block_root(block)?);
    verify!(
        block_proposal_signature_set(
            state,
            |i| get_pubkey_from_state(state, i),
            block,
            block_root,
            spec
        )?
        .verify(),
        HeaderInvalid::ProposalSignatureInvalid
    );

    Ok(())
}

/// Verifies the `randao_reveal` against the block's proposer pubkey and updates
/// `state.latest_randao_mixes`.
pub fn process_randao<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    block: BeaconBlockRef<'_, T, Payload>,
    verify_signatures: VerifySignatures,
    _ctxt: &mut ConsensusContext<T>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if verify_signatures.is_true() {
        // Verify RANDAO reveal signature.
        block_verify!(
            randao_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                block,
                // TODO Whisk: proposer index correctness is checked in the paths I'm aware of. Is
                // process_randao ever called with unchecked proposer index?
                block.proposer_index(),
                spec
            )?
            .verify(),
            BlockProcessingError::RandaoSignatureInvalid
        );
    }

    // Update the current epoch RANDAO mix.
    state.update_randao_mix(state.current_epoch(), block.body().randao_reveal())?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
pub fn process_eth1_data<T: EthSpec>(
    state: &mut BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<(), Error> {
    if let Some(new_eth1_data) = get_new_eth1_data(state, eth1_data)? {
        *state.eth1_data_mut() = new_eth1_data;
    }

    state.eth1_data_votes_mut().push(eth1_data.clone())?;

    Ok(())
}

/// Returns `Ok(Some(eth1_data))` if adding the given `eth1_data` to `state.eth1_data_votes` would
/// result in a change to `state.eth1_data`.
pub fn get_new_eth1_data<T: EthSpec>(
    state: &BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<Option<Eth1Data>, ArithError> {
    let num_votes = state
        .eth1_data_votes()
        .iter()
        .filter(|vote| *vote == eth1_data)
        .count();

    // The +1 is to account for the `eth1_data` supplied to the function.
    if num_votes.safe_add(1)?.safe_mul(2)? > T::SlotsPerEth1VotingPeriod::to_usize() {
        Ok(Some(eth1_data.clone()))
    } else {
        Ok(None)
    }
}

/// Performs *partial* verification of the `payload`.
///
/// The verification is partial, since the execution payload is not verified against an execution
/// engine. That is expected to be performed by an upstream function.
///
/// ## Specification
///
/// Contains a partial set of checks from the `process_execution_payload` function:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/beacon-chain.md#process_execution_payload
pub fn partially_verify_execution_payload<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &BeaconState<T>,
    block_slot: Slot,
    payload: Payload::Ref<'_>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if is_merge_transition_complete(state) {
        block_verify!(
            payload.parent_hash() == state.latest_execution_payload_header()?.block_hash(),
            BlockProcessingError::ExecutionHashChainIncontiguous {
                expected: state.latest_execution_payload_header()?.block_hash(),
                found: payload.parent_hash(),
            }
        );
    }
    block_verify!(
        payload.prev_randao() == *state.get_randao_mix(state.current_epoch())?,
        BlockProcessingError::ExecutionRandaoMismatch {
            expected: *state.get_randao_mix(state.current_epoch())?,
            found: payload.prev_randao(),
        }
    );

    let timestamp = compute_timestamp_at_slot(state, block_slot, spec)?;
    block_verify!(
        payload.timestamp() == timestamp,
        BlockProcessingError::ExecutionInvalidTimestamp {
            expected: timestamp,
            found: payload.timestamp(),
        }
    );

    Ok(())
}

/// Calls `partially_verify_execution_payload` and then updates the payload header in the `state`.
///
/// ## Specification
///
/// Partially equivalent to the `process_execution_payload` function:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/beacon-chain.md#process_execution_payload
pub fn process_execution_payload<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    payload: Payload::Ref<'_>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    partially_verify_execution_payload::<T, Payload>(state, state.slot(), payload, spec)?;

    match state.latest_execution_payload_header_mut()? {
        ExecutionPayloadHeaderRefMut::Merge(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Merge(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
        ExecutionPayloadHeaderRefMut::Capella(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Capella(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
    }

    Ok(())
}

/// These functions will definitely be called before the merge. Their entire purpose is to check if
/// the merge has happened or if we're on the transition block. Thus we don't want to propagate
/// errors from the `BeaconState` being an earlier variant than `BeaconStateMerge` as we'd have to
/// repeaetedly write code to treat these errors as false.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_merge_transition_complete
pub fn is_merge_transition_complete<T: EthSpec>(state: &BeaconState<T>) -> bool {
    // We must check defaultness against the payload header with 0x0 roots, as that's what's meant
    // by `ExecutionPayloadHeader()` in the spec.
    state
        .latest_execution_payload_header()
        .map(|header| !header.is_default_with_zero_roots())
        .unwrap_or(false)
}
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_merge_transition_block
pub fn is_merge_transition_block<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &BeaconState<T>,
    body: BeaconBlockBodyRef<T, Payload>,
) -> bool {
    // For execution payloads in blocks (which may be headers) we must check defaultness against
    // the payload with `transactions_root` equal to the tree hash of the empty list.
    body.execution_payload()
        .map(|payload| {
            !is_merge_transition_complete(state) && !payload.is_default_with_empty_roots()
        })
        .unwrap_or(false)
}
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_execution_enabled
pub fn is_execution_enabled<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &BeaconState<T>,
    body: BeaconBlockBodyRef<T, Payload>,
) -> bool {
    is_merge_transition_block(state, body) || is_merge_transition_complete(state)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
pub fn compute_timestamp_at_slot<T: EthSpec>(
    state: &BeaconState<T>,
    block_slot: Slot,
    spec: &ChainSpec,
) -> Result<u64, ArithError> {
    let slots_since_genesis = block_slot.as_u64().safe_sub(spec.genesis_slot.as_u64())?;
    slots_since_genesis
        .safe_mul(spec.seconds_per_slot)
        .and_then(|since_genesis| state.genesis_time().safe_add(since_genesis))
}

/// Compute the next batch of withdrawals which should be included in a block.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#new-get_expected_withdrawals
pub fn get_expected_withdrawals<T: EthSpec>(
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> Result<Withdrawals<T>, BlockProcessingError> {
    let epoch = state.current_epoch();
    let mut withdrawal_index = state.next_withdrawal_index()?;
    let mut validator_index = state.next_withdrawal_validator_index()?;
    let mut withdrawals = vec![];

    let bound = std::cmp::min(
        state.validators().len() as u64,
        spec.max_validators_per_withdrawals_sweep,
    );
    for _ in 0..bound {
        let validator = state.get_validator(validator_index as usize)?;
        let balance = *state.balances().get(validator_index as usize).ok_or(
            BeaconStateError::BalancesOutOfBounds(validator_index as usize),
        )?;
        if validator.is_fully_withdrawable_at(balance, epoch, spec) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_eth1_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        } else if validator.is_partially_withdrawable_validator(balance, spec) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_eth1_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance.safe_sub(spec.max_effective_balance)?,
            });
            withdrawal_index.safe_add_assign(1)?;
        }
        if withdrawals.len() == T::max_withdrawals_per_payload() {
            break;
        }
        validator_index = validator_index
            .safe_add(1)?
            .safe_rem(state.validators().len() as u64)?;
    }

    Ok(withdrawals.into())
}

/// Apply withdrawals to the state.
pub fn process_withdrawals<T: EthSpec, Payload: AbstractExecPayload<T>>(
    state: &mut BeaconState<T>,
    payload: Payload::Ref<'_>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    match state {
        BeaconState::Merge(_) => Ok(()),
        BeaconState::Capella(_) => {
            let expected_withdrawals = get_expected_withdrawals(state, spec)?;
            let expected_root = expected_withdrawals.tree_hash_root();
            let withdrawals_root = payload.withdrawals_root()?;

            if expected_root != withdrawals_root {
                return Err(BlockProcessingError::WithdrawalsRootMismatch {
                    expected: expected_root,
                    found: withdrawals_root,
                });
            }

            for withdrawal in expected_withdrawals.iter() {
                decrease_balance(
                    state,
                    withdrawal.validator_index as usize,
                    withdrawal.amount,
                )?;
            }

            // Update the next withdrawal index if this block contained withdrawals
            if let Some(latest_withdrawal) = expected_withdrawals.last() {
                *state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;

                // Update the next validator index to start the next withdrawal sweep
                if expected_withdrawals.len() == T::max_withdrawals_per_payload() {
                    // Next sweep starts after the latest withdrawal's validator index
                    let next_validator_index = latest_withdrawal
                        .validator_index
                        .safe_add(1)?
                        .safe_rem(state.validators().len() as u64)?;
                    *state.next_withdrawal_validator_index_mut()? = next_validator_index;
                }
            }

            // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
            if expected_withdrawals.len() != T::max_withdrawals_per_payload() {
                let next_validator_index = state
                    .next_withdrawal_validator_index()?
                    .safe_add(spec.max_validators_per_withdrawals_sweep)?
                    .safe_rem(state.validators().len() as u64)?;
                *state.next_withdrawal_validator_index_mut()? = next_validator_index;
            }

            Ok(())
        }
        // these shouldn't even be encountered but they're here for completeness
        BeaconState::Base(_) | BeaconState::Altair(_) => Ok(()),
    }
}
