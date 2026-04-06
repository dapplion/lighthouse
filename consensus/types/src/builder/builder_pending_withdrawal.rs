use crate::test_utils::TestRandom;
use crate::{Address, ForkName};
use context_deserialize::context_deserialize;
use milhouse::mem::MemorySize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Default,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[context_deserialize(ForkName)]
pub struct BuilderPendingWithdrawal {
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
}

impl MemorySize for BuilderPendingWithdrawal {
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

    ssz_and_tree_hash_tests!(BuilderPendingWithdrawal);
}
