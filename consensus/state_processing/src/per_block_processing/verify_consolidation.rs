use super::errors::{BlockOperationError, ConsolidationInvalid};
use crate::{
    per_block_processing::{signature_sets::get_pubkey_from_state, VerifySignatures},
    signature_sets::consolidation_signature_set,
};
use types::*;

pub fn verify_consolidation<T: EthSpec>(
    state: &mut BeaconState<T>,
    signed_consolidation: &SignedConsolidation,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<ConsolidationInvalid>> {
    let current_epoch = state.current_epoch();

    let consolidation = &signed_consolidation.message;
    let target_index = consolidation.target_index as usize;
    let source_index = consolidation.source_index as usize;
    let target_validator = state.validators().get(target_index).ok_or_else(|| {
        BlockOperationError::invalid(ConsolidationInvalid::ValidatorUnknown(target_index))
    })?;
    let source_validator = state.validators().get(source_index).ok_or_else(|| {
        BlockOperationError::invalid(ConsolidationInvalid::ValidatorUnknown(source_index))
    })?;

    // Verify the source and the target are active
    verify!(
        source_validator.is_exited_at(current_epoch),
        ConsolidationInvalid::SourceInactive
    );
    verify!(
        target_validator.is_exited_at(current_epoch),
        ConsolidationInvalid::TargetInactive
    );
    // Verify exits for source and target have not been initiated
    verify!(
        source_validator.exit_epoch == spec.far_future_epoch,
        ConsolidationInvalid::SourceExited
    );
    verify!(
        target_validator.exit_epoch == spec.far_future_epoch,
        ConsolidationInvalid::TargetExited
    );
    // Consolidations must specify an epoch when they become valid; they are not valid before then
    verify!(
        current_epoch >= consolidation.epoch,
        ConsolidationInvalid::TooEarly
    );

    // Verify the source and the target have Execution layer withdrawal credentials
    verify!(
        source_validator.has_eth1_or_compounding_withdrawal_credential(spec),
        ConsolidationInvalid::SourceNoEth1Credentials
    );
    verify!(
        target_validator.has_eth1_or_compounding_withdrawal_credential(spec),
        ConsolidationInvalid::TargetNoEth1Credentials
    );
    // Verify the same withdrawal address
    verify!(
        source_validator.withdrawal_credentials[1..]
            == target_validator.withdrawal_credentials[1..],
        ConsolidationInvalid::NotSameCredentials
    );

    // Verify consolidation is signed by the source and the target
    if verify_signatures.is_true() {
        verify!(
            consolidation_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                signed_consolidation,
                spec
            )?
            .verify(),
            ConsolidationInvalid::BadSignature
        );
    }

    Ok(())
}
