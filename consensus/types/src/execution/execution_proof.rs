use crate::{ForkName, Hash256, SignedRoot};
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::sync::Arc;
use tree_hash_derive::TreeHash;

/// Maximum size of `proof_data` in bytes (EIP-8025 `MAX_PROOF_SIZE`).
pub const MAX_PROOF_SIZE: usize = 4_194_304;

/// Proof types a single payload can be proven by (EIP-8025 `MAX_EXECUTION_PROOFS_PER_PAYLOAD`).
///
/// Used only to bound req/resp response counts. Which types a node serves is local
/// configuration.
pub const MAX_EXECUTION_PROOFS_PER_PAYLOAD: u64 = 4;

/// SSZ bound for `proof_data`.
pub type MaxProofSize = typenum::U4194304;

/// Spec type `ProofData`.
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Spec type `ProofType`.
pub type ProofType = u8;

/// Spec constant `STATELESS_INPUT_SCHEMA_ID`: Amsterdam fork (`0x15`), schema revision (`0x01`).
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Spec type `PublicInput`.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
pub struct PublicInput {
    pub new_payload_request_root: Hash256,
    pub successful_validation: bool,
    #[serde(with = "serde_utils::quoted_u64")]
    pub chain_id: u64,
    pub schema_id: u16,
}

/// Spec type `ExecutionProof`.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

/// Spec type `ExecutionProofEnvelope`.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProofEnvelope {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub beacon_block_root: Hash256,
}

impl SignedRoot for ExecutionProofEnvelope {}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedExecutionProofEnvelope {
    pub message: ExecutionProofEnvelope,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub signature: Signature,
}

impl SignedExecutionProofEnvelope {
    pub fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }

    pub fn proof_type(&self) -> ProofType {
        self.message.proof_type
    }

    /// Returns the minimum SSZ-encoded size (`proof_data` empty).
    pub fn min_size() -> usize {
        Self {
            message: ExecutionProofEnvelope {
                proof_data: ProofData::empty(),
                proof_type: 0,
                beacon_block_root: Hash256::ZERO,
            },
            validator_index: 0,
            signature: Signature::empty(),
        }
        .as_ssz_bytes()
        .len()
    }

    /// Returns the maximum SSZ-encoded size.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        // `proof_data` is the only variable-length field.
        Self::min_size() + MAX_PROOF_SIZE
    }
}

/// A block's verified execution proofs, at most one per `ProofType`.
pub type ExecutionProofEnvelopeList = Vec<Arc<SignedExecutionProofEnvelope>>;

/// Bound on the `proof_types` filter of a req/resp request: every distinct `ProofType`.
///
/// The set of types a node serves is local configuration rather than a spec constant, so the
/// `u8` domain is the only bound that cannot go stale.
pub type MaxProofTypes = typenum::U256;

/// Names the proof types wanted for one beacon block in an `ExecutionProofsByRoot` request.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct ExecutionProofsByRootIdentifier {
    pub block_root: Hash256,
    pub proof_types: VariableList<ProofType, MaxProofTypes>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedExecutionProofEnvelope);
}
