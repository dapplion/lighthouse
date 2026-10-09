use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::ExecutionProofsByRangeRequest;
use std::sync::Arc;
use types::{ProofType, SignedExecutionProofEnvelope};

/// Accumulates results of an `execution_proofs_by_range` request.
///
/// A proof names a beacon block root and carries no slot, so a response cannot be checked against
/// the requested slot range: the proof type is the only part of the request a response can be
/// validated against. Completion works as in `execution_proofs_by_root`.
pub struct ExecutionProofsByRangeRequestItems {
    proof_types: Vec<ProofType>,
    items: Vec<Arc<SignedExecutionProofEnvelope>>,
}

impl ExecutionProofsByRangeRequestItems {
    pub fn new(request: &ExecutionProofsByRangeRequest) -> Self {
        Self {
            proof_types: request.proof_types.clone(),
            items: vec![],
        }
    }
}

impl ActiveRequestItems for ExecutionProofsByRangeRequestItems {
    type Item = Arc<SignedExecutionProofEnvelope>;

    fn add(&mut self, proof: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = proof.beacon_block_root();
        let proof_type = proof.proof_type();

        if !self.proof_types.contains(&proof_type) {
            return Err(LookupVerifyError::UnrequestedIndex(proof_type as u64));
        }

        if self
            .items
            .iter()
            .any(|item| item.beacon_block_root() == block_root && item.proof_type() == proof_type)
        {
            return Err(LookupVerifyError::DuplicatedProof(block_root, proof_type));
        }

        self.items.push(proof);

        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
