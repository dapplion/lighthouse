use crate::proto_array::ProposerBoost;
use crate::{
    Error, JustifiedBalances,
    proto_array::{InclusionListSatisfaction, ProtoArray, ProtoNode, ProtoNodeV17},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker, VoteTrackerV28},
};
use ssz::{Encode, four_byte_option_impl};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use superstruct::superstruct;
use types::{Checkpoint, Hash256};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

pub type SszContainer = SszContainerV33;

#[superstruct(
    variants(V28, V29, V33),
    variant_attributes(derive(Encode, Decode, Clone)),
    no_enum
)]
pub struct SszContainer {
    #[superstruct(only(V28))]
    pub votes_v28: Vec<VoteTrackerV28>,
    #[superstruct(only(V29, V33))]
    pub votes: Vec<VoteTracker>,
    pub prune_threshold: usize,
    // Deprecated, remove in a future schema migration
    #[superstruct(only(V28))]
    justified_checkpoint: Checkpoint,
    // Deprecated, remove in a future schema migration
    #[superstruct(only(V28))]
    finalized_checkpoint: Checkpoint,
    #[superstruct(only(V28))]
    pub nodes: Vec<ProtoNodeV17>,
    #[superstruct(only(V29, V33))]
    pub nodes: Vec<ProtoNode>,
    pub indices: Vec<(Hash256, usize)>,
    /// The `inclusion_list_satisfaction` of each node in `nodes`, which the node itself does not
    /// encode. Pre-Gloas nodes have the default.
    #[superstruct(only(V33))]
    pub inclusion_list_satisfaction: Vec<InclusionListSatisfaction>,
    #[superstruct(only(V28))]
    pub previous_proposer_boost: ProposerBoost,
}

impl SszContainerV33 {
    pub fn from_proto_array(from: &ProtoArrayForkChoice) -> Self {
        let proto_array = &from.proto_array;

        Self {
            votes: from.votes.0.clone(),
            prune_threshold: proto_array.prune_threshold,
            nodes: proto_array.nodes.clone(),
            indices: proto_array.indices.iter().map(|(k, v)| (*k, *v)).collect(),
            inclusion_list_satisfaction: proto_array
                .nodes
                .iter()
                .map(|node| node.inclusion_list_satisfaction().unwrap_or_default())
                .collect(),
        }
    }
}

impl TryFrom<(SszContainerV33, JustifiedBalances)> for ProtoArrayForkChoice {
    type Error = Error;

    fn try_from((from, balances): (SszContainerV33, JustifiedBalances)) -> Result<Self, Error> {
        if from.inclusion_list_satisfaction.len() != from.nodes.len() {
            return Err(Error::InvalidInclusionListSatisfactionLength {
                nodes: from.nodes.len(),
                inclusion_list_satisfaction: from.inclusion_list_satisfaction.len(),
            });
        }
        let mut nodes = from.nodes;
        for (node, inclusion_list_satisfaction) in
            nodes.iter_mut().zip(from.inclusion_list_satisfaction)
        {
            if let Ok(node_inclusion_list_satisfaction) = node.inclusion_list_satisfaction_mut() {
                *node_inclusion_list_satisfaction = inclusion_list_satisfaction;
            }
        }

        let mut proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            nodes,
            indices: from.indices.into_iter().collect::<HashMap<_, _>>(),
            children: Vec::new(),
        };
        proto_array.rebuild_children_index()?;

        Ok(Self {
            proto_array,
            votes: ElasticList(from.votes),
            balances,
        })
    }
}

// Convert legacy V28 to current V29.
impl From<SszContainerV28> for SszContainerV29 {
    fn from(v28: SszContainerV28) -> Self {
        Self {
            votes: v28.votes_v28.into_iter().map(Into::into).collect(),
            prune_threshold: v28.prune_threshold,
            nodes: v28
                .nodes
                .into_iter()
                .map(|mut node| {
                    // best_child/best_descendant are no longer used (replaced by
                    // the virtual tree walk). Clear during conversion.
                    node.best_child = None;
                    node.best_descendant = None;
                    ProtoNode::V17(node)
                })
                .collect(),
            indices: v28.indices,
        }
    }
}

// Convert legacy V29 to current V33. No V29 node has recorded inclusion list satisfaction.
impl From<SszContainerV29> for SszContainerV33 {
    fn from(v29: SszContainerV29) -> Self {
        Self {
            inclusion_list_satisfaction: vec![
                InclusionListSatisfaction::Satisfied;
                v29.nodes.len()
            ],
            votes: v29.votes,
            prune_threshold: v29.prune_threshold,
            nodes: v29.nodes,
            indices: v29.indices,
        }
    }
}

// Downgrade current V33 to legacy V29 (lossy: nodes lose inclusion list satisfaction).
impl From<SszContainerV33> for SszContainerV29 {
    fn from(v33: SszContainerV33) -> Self {
        Self {
            votes: v33.votes,
            prune_threshold: v33.prune_threshold,
            nodes: v33.nodes,
            indices: v33.indices,
        }
    }
}

// Downgrade legacy V29 to legacy V28 (lossy: V29 nodes lose payload-specific fields).
impl From<SszContainerV29> for SszContainerV28 {
    fn from(v29: SszContainerV29) -> Self {
        Self {
            votes_v28: v29.votes.into_iter().map(Into::into).collect(),
            prune_threshold: v29.prune_threshold,
            // These checkpoints are not consumed in v28 paths since the upgrade from v17,
            // we can safely default the values.
            justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            nodes: v29
                .nodes
                .into_iter()
                .filter_map(|node| match node {
                    ProtoNode::V17(v17) => Some(v17),
                    ProtoNode::V29(_) => None,
                })
                .collect(),
            indices: v29.indices,
            // Proposer boost is not tracked in V29 (computed on-the-fly), so reset it.
            previous_proposer_boost: ProposerBoost::default(),
        }
    }
}
