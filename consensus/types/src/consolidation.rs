use crate::{test_utils::TestRandom, Epoch, SignedRoot};
use bls::Signature;

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct Consolidation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub source_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_index: u64,
    pub epoch: Epoch,
}

impl SignedRoot for Consolidation {}

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct SignedConsolidation {
    pub message: Consolidation,
    pub signature: Signature,
}

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct PendingConsolidation {
    pub source_index: u64,
    pub target_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedConsolidation);
}
