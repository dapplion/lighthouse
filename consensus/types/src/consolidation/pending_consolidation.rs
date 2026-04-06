use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use milhouse::mem::MemorySize;

use crate::{fork::ForkName, test_utils::TestRandom};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
pub struct PendingConsolidation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub source_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_index: u64,
}

impl MemorySize for PendingConsolidation {
    fn self_pointer(&self) -> usize {
        self as *const _ as usize
    }

    fn subtrees(&self) -> Vec<&dyn MemorySize> {
        vec![]
    }

    fn intrinsic_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PendingConsolidation);
}
