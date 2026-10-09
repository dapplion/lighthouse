use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::ExecutionProofsByRootRequest;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use types::{Hash256, ProofType, SignedExecutionProofEnvelope};

/// Accumulates results of an `execution_proofs_by_root` request.
///
/// A block commits to nothing about its proofs, so a peer that holds fewer than we asked for is
/// not misbehaving. Items are therefore only returned on stream termination.
pub struct ExecutionProofsByRootRequestItems {
    requested: HashMap<Hash256, HashSet<ProofType>>,
    items: Vec<Arc<SignedExecutionProofEnvelope>>,
}

impl ExecutionProofsByRootRequestItems {
    pub fn new(request: &ExecutionProofsByRootRequest) -> Self {
        let mut requested: HashMap<Hash256, HashSet<ProofType>> = HashMap::new();
        for proof_id in request.proof_ids.iter() {
            requested
                .entry(proof_id.block_root)
                .or_default()
                .extend(proof_id.proof_types.iter().copied());
        }

        Self {
            requested,
            items: vec![],
        }
    }
}

impl ActiveRequestItems for ExecutionProofsByRootRequestItems {
    type Item = Arc<SignedExecutionProofEnvelope>;

    fn add(&mut self, proof: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = proof.beacon_block_root();
        let proof_type = proof.proof_type();

        match self.requested.get(&block_root) {
            None => return Err(LookupVerifyError::UnrequestedBlockRoot(block_root)),
            Some(proof_types) if !proof_types.contains(&proof_type) => {
                return Err(LookupVerifyError::UnrequestedIndex(proof_type as u64));
            }
            Some(_) => {}
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
