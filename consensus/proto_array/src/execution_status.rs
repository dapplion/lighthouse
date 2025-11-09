use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::fmt;
use types::ExecutionBlockHash;

/// Represents the verification status of an execution payload.
#[derive(Clone, Copy, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[ssz(enum_behaviour = "union")]
pub enum ExecutionStatus {
    /// An EL has determined that the payload is valid.
    Valid(ExecutionBlockHash),
    /// An EL has determined that the payload is invalid.
    Invalid(ExecutionBlockHash),
    /// An EL has not yet verified the execution payload.
    Optimistic(ExecutionBlockHash),
    /// The block is either prior to the merge fork, or after the merge fork but before the terminal
    /// PoW block has been found.
    ///
    /// # Note:
    ///
    /// This `bool` only exists to satisfy our SSZ implementation which requires all variants
    /// to have a value. It can be set to anything.
    Irrelevant(bool),
}

impl ExecutionStatus {
    pub fn is_execution_enabled(&self) -> bool {
        !matches!(self, ExecutionStatus::Irrelevant(_))
    }

    pub fn irrelevant() -> Self {
        ExecutionStatus::Irrelevant(false)
    }

    pub fn block_hash(&self) -> Option<ExecutionBlockHash> {
        match self {
            ExecutionStatus::Valid(hash)
            | ExecutionStatus::Invalid(hash)
            | ExecutionStatus::Optimistic(hash) => Some(*hash),
            ExecutionStatus::Irrelevant(_) => None,
        }
    }

    /// Returns `true` if the block:
    ///
    /// - Has a valid payload, OR
    /// - Does not have execution enabled.
    ///
    /// Whenever this function returns `true`, the block is *fully valid*.
    pub fn is_valid_or_irrelevant(&self) -> bool {
        matches!(
            self,
            ExecutionStatus::Valid(_) | ExecutionStatus::Irrelevant(_)
        )
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has a valid payload
    ///
    /// This function will return `false` for any block from a slot prior to the Bellatrix fork.
    /// This means that some blocks that are perfectly valid will still receive a `false` response.
    /// See `Self::is_valid_or_irrelevant` for a function that will always return `true` given any
    /// perfectly valid block.
    pub fn is_valid_and_post_bellatrix(&self) -> bool {
        matches!(self, ExecutionStatus::Valid(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has a payload that has not yet been verified by an EL.
    pub fn is_strictly_optimistic(&self) -> bool {
        matches!(self, ExecutionStatus::Optimistic(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    ///     - Has a payload that has not yet been verified by an EL, OR.
    ///     - Has a payload that has been deemed invalid by an EL.
    pub fn is_optimistic_or_invalid(&self) -> bool {
        matches!(
            self,
            ExecutionStatus::Optimistic(_) | ExecutionStatus::Invalid(_)
        )
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has an invalid payload.
    pub fn is_invalid(&self) -> bool {
        matches!(self, ExecutionStatus::Invalid(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Does not have execution enabled (before or after Bellatrix fork)
    pub fn is_irrelevant(&self) -> bool {
        matches!(self, ExecutionStatus::Irrelevant(_))
    }
}

impl fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionStatus::Valid(_) => write!(f, "valid"),
            ExecutionStatus::Invalid(_) => write!(f, "invalid"),
            ExecutionStatus::Optimistic(_) => write!(f, "optimistic"),
            ExecutionStatus::Irrelevant(_) => write!(f, "irrelevant"),
        }
    }
}
