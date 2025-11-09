use crate::proto_array::ProposerBoost;
use crate::{
    Error, JustifiedBalances,
    proto_array::{ElasticList, ProtoArray, ProtoNodeV17, VoteTracker},
};
use ssz::{Encode, four_byte_option_impl};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use superstruct::superstruct;
use types::{Checkpoint, Hash256};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

pub type SszContainer = SszContainerV28;

#[superstruct(
    variants(V17, V28),
    variant_attributes(derive(Encode, Decode, Clone)),
    no_enum
)]
pub struct SszContainer {
    pub votes: Vec<VoteTracker>,
    #[superstruct(only(V17))]
    pub balances: Vec<u64>,
    pub prune_threshold: usize,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub nodes: Vec<ProtoNodeV17>,
    pub indices: Vec<(Hash256, usize)>,
    pub previous_proposer_boost: ProposerBoost,
}

impl From<&ProtoArray> for SszContainer {
    fn from(from: &ProtoArray) -> Self {
        Self {
            votes: from.votes.0.clone(),
            prune_threshold: from.prune_threshold,
            justified_checkpoint: from.justified_checkpoint,
            finalized_checkpoint: from.finalized_checkpoint,
            nodes: from.nodes.clone(),
            indices: from.indices.iter().map(|(k, v)| (*k, *v)).collect(),
            previous_proposer_boost: from.previous_proposer_boost,
        }
    }
}

impl TryFrom<(SszContainer, JustifiedBalances)> for ProtoArray {
    type Error = Error;

    fn try_from((from, balances): (SszContainer, JustifiedBalances)) -> Result<Self, Error> {
        Ok(ProtoArray {
            prune_threshold: from.prune_threshold,
            justified_checkpoint: from.justified_checkpoint,
            finalized_checkpoint: from.finalized_checkpoint,
            nodes: from.nodes,
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
            previous_proposer_boost: from.previous_proposer_boost,
            votes: ElasticList(from.votes),
            balances,
        })
    }
}

// Convert V17 to V28 by dropping balances.
impl From<SszContainerV17> for SszContainerV28 {
    fn from(v17: SszContainerV17) -> Self {
        Self {
            votes: v17.votes,
            prune_threshold: v17.prune_threshold,
            justified_checkpoint: v17.justified_checkpoint,
            finalized_checkpoint: v17.finalized_checkpoint,
            nodes: v17.nodes,
            indices: v17.indices,
            previous_proposer_boost: v17.previous_proposer_boost,
        }
    }
}

// Convert V28 to V17 by re-adding balances.
impl From<(SszContainerV28, JustifiedBalances)> for SszContainerV17 {
    fn from((v28, balances): (SszContainerV28, JustifiedBalances)) -> Self {
        Self {
            votes: v28.votes,
            balances: balances.effective_balances.clone(),
            prune_threshold: v28.prune_threshold,
            justified_checkpoint: v28.justified_checkpoint,
            finalized_checkpoint: v28.finalized_checkpoint,
            nodes: v28.nodes,
            indices: v28.indices,
            previous_proposer_boost: v28.previous_proposer_boost,
        }
    }
}
