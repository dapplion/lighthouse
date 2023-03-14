use crate::*;
use serde::{Deserialize, Serialize};

/// A proposer preparation, created when a validator prepares the beacon node for potential proposers
/// by supplying information required when proposing blocks for the given validators.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ProposerPreparationData {
    /// The validators index.
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    /// The fee-recipient address.
    pub fee_recipient: Address,
}

/// A proposer preparation, created when a validator prepares the beacon node for potential proposers
/// by supplying information required when proposing blocks for the given validators.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Copy)]
pub struct WhiskProposerPreparationData {
    /// The validators index.
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    /// Slot validator will propose
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_slot: u64,
    /// Shuffling decision root at which validator is known to be a proposer
    pub whisk_shuffling_decision_root: WhiskProposerShufflingRoot,
}

/// Whisk shuffling root is the root of the last block before the first epoch of a shuffling round.
/// This different type ensures that a pre-whisk shuffling root is not mixed with this one.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct WhiskProposerShufflingRoot(pub Hash256);
