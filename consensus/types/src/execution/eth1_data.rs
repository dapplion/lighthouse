use context_deserialize::context_deserialize;
use milhouse::mem::MemorySize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use crate::{core::Hash256, fork::ForkName, test_utils::TestRandom};

/// Contains data obtained from the Eth1 chain.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    PartialEq,
    Clone,
    Default,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
#[context_deserialize(ForkName)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: Hash256,
}

impl MemorySize for Eth1Data {
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

    ssz_and_tree_hash_tests!(Eth1Data);
}
