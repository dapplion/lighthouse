use crate::proto_array::ProposerBoost;
use crate::{
    Error, ExecutionStatus, JustifiedBalances,
    proto_array::{ParentPayloadStatus, ProtoArray, ProtoNode, ProtoNodeV17, ProtoNodeV33},
    proto_array_fork_choice::{ElasticList, ProtoArrayForkChoice, VoteTracker, VoteTrackerV28},
};
use ssz::{BitVector, Encode, four_byte_option_impl};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use superstruct::superstruct;
use typenum::U512;
use types::{AttestationShufflingId, Checkpoint, ExecutionBlockHash, Hash256, Slot};

// Define a "legacy" implementation of `Option<usize>` which uses four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_usize, usize);
four_byte_option_impl!(four_byte_option_checkpoint, Checkpoint);

/// A proto node as persisted by schemas v29 to v32, only decoded and encoded by schema migrations.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
#[ssz(enum_behaviour = "union")]
#[allow(clippy::large_enum_variant)]
pub enum LegacyProtoNode {
    V17(ProtoNodeV17),
    V29(ProtoNodeV29),
}

impl LegacyProtoNode {
    pub fn weight(&self) -> u64 {
        match self {
            LegacyProtoNode::V17(node) => node.weight,
            LegacyProtoNode::V29(node) => node.weight,
        }
    }

    pub fn weight_mut(&mut self) -> &mut u64 {
        match self {
            LegacyProtoNode::V17(node) => &mut node.weight,
            LegacyProtoNode::V29(node) => &mut node.weight,
        }
    }

    pub fn parent(&self) -> Option<usize> {
        match self {
            LegacyProtoNode::V17(node) => node.parent,
            LegacyProtoNode::V29(node) => node.parent,
        }
    }
}

/// The Gloas proto node of schemas v29 to v32, without the inclusion list verdict of
/// `ProtoNodeV33`.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct ProtoNodeV29 {
    pub slot: Slot,
    pub state_root: Hash256,
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub root: Hash256,
    #[ssz(with = "four_byte_option_usize")]
    pub parent: Option<usize>,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub weight: u64,
    pub execution_status: ExecutionStatus,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    #[ssz(with = "four_byte_option_checkpoint")]
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,
    pub parent_payload_status: ParentPayloadStatus,
    pub empty_payload_weight: u64,
    pub full_payload_weight: u64,
    pub execution_payload_block_hash: ExecutionBlockHash,
    pub execution_payload_parent_hash: ExecutionBlockHash,
    pub block_timeliness_attestation_threshold: bool,
    pub block_timeliness_ptc_threshold: bool,
    pub payload_timeliness_votes: BitVector<U512>,
    pub payload_data_availability_votes: BitVector<U512>,
    pub ptc_participation: BitVector<U512>,
    pub payload_received: bool,
    pub proposer_index: u64,
    pub equivocating_attestation_score: u64,
}

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
    #[superstruct(only(V29))]
    pub nodes: Vec<LegacyProtoNode>,
    #[superstruct(only(V33))]
    pub nodes: Vec<ProtoNode>,
    pub indices: Vec<(Hash256, usize)>,
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
        }
    }
}

impl TryFrom<(SszContainerV33, JustifiedBalances)> for ProtoArrayForkChoice {
    type Error = Error;

    fn try_from((from, balances): (SszContainerV33, JustifiedBalances)) -> Result<Self, Error> {
        let mut proto_array = ProtoArray {
            prune_threshold: from.prune_threshold,
            nodes: from.nodes,
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

// Convert legacy V28 to legacy V29.
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
                    LegacyProtoNode::V17(node)
                })
                .collect(),
            indices: v28.indices,
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
                    LegacyProtoNode::V17(v17) => Some(v17),
                    LegacyProtoNode::V29(_) => None,
                })
                .collect(),
            indices: v29.indices,
            // Proposer boost is not tracked in V29 (computed on-the-fly), so reset it.
            previous_proposer_boost: ProposerBoost::default(),
        }
    }
}

// Convert legacy V29 to current V33. V29 nodes have no inclusion list verdict, so their payloads
// are recorded as satisfying the inclusion lists.
impl From<SszContainerV29> for SszContainerV33 {
    fn from(v29: SszContainerV29) -> Self {
        Self {
            votes: v29.votes,
            prune_threshold: v29.prune_threshold,
            nodes: v29
                .nodes
                .into_iter()
                .map(|node| match node {
                    LegacyProtoNode::V17(v17) => ProtoNode::V17(v17),
                    LegacyProtoNode::V29(v29) => ProtoNode::V33(v29.into()),
                })
                .collect(),
            indices: v29.indices,
        }
    }
}

// Downgrade current V33 to legacy V29 (lossy: nodes lose the inclusion list verdict).
impl From<SszContainerV33> for SszContainerV29 {
    fn from(v33: SszContainerV33) -> Self {
        Self {
            votes: v33.votes,
            prune_threshold: v33.prune_threshold,
            nodes: v33
                .nodes
                .into_iter()
                .map(|node| match node {
                    ProtoNode::V17(v17) => LegacyProtoNode::V17(v17),
                    ProtoNode::V33(v33) => LegacyProtoNode::V29(v33.into()),
                })
                .collect(),
            indices: v33.indices,
        }
    }
}

impl From<ProtoNodeV29> for ProtoNodeV33 {
    fn from(v29: ProtoNodeV29) -> Self {
        Self {
            slot: v29.slot,
            state_root: v29.state_root,
            target_root: v29.target_root,
            current_epoch_shuffling_id: v29.current_epoch_shuffling_id,
            next_epoch_shuffling_id: v29.next_epoch_shuffling_id,
            root: v29.root,
            parent: v29.parent,
            justified_checkpoint: v29.justified_checkpoint,
            finalized_checkpoint: v29.finalized_checkpoint,
            weight: v29.weight,
            execution_status: v29.execution_status,
            unrealized_justified_checkpoint: v29.unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint: v29.unrealized_finalized_checkpoint,
            parent_payload_status: v29.parent_payload_status,
            empty_payload_weight: v29.empty_payload_weight,
            full_payload_weight: v29.full_payload_weight,
            execution_payload_block_hash: v29.execution_payload_block_hash,
            execution_payload_parent_hash: v29.execution_payload_parent_hash,
            block_timeliness_attestation_threshold: v29.block_timeliness_attestation_threshold,
            block_timeliness_ptc_threshold: v29.block_timeliness_ptc_threshold,
            payload_timeliness_votes: v29.payload_timeliness_votes,
            payload_data_availability_votes: v29.payload_data_availability_votes,
            ptc_participation: v29.ptc_participation,
            payload_received: v29.payload_received,
            payload_inclusion_list_satisfied: true,
            proposer_index: v29.proposer_index,
            equivocating_attestation_score: v29.equivocating_attestation_score,
        }
    }
}

impl From<ProtoNodeV33> for ProtoNodeV29 {
    fn from(v33: ProtoNodeV33) -> Self {
        Self {
            slot: v33.slot,
            state_root: v33.state_root,
            target_root: v33.target_root,
            current_epoch_shuffling_id: v33.current_epoch_shuffling_id,
            next_epoch_shuffling_id: v33.next_epoch_shuffling_id,
            root: v33.root,
            parent: v33.parent,
            justified_checkpoint: v33.justified_checkpoint,
            finalized_checkpoint: v33.finalized_checkpoint,
            weight: v33.weight,
            execution_status: v33.execution_status,
            unrealized_justified_checkpoint: v33.unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint: v33.unrealized_finalized_checkpoint,
            parent_payload_status: v33.parent_payload_status,
            empty_payload_weight: v33.empty_payload_weight,
            full_payload_weight: v33.full_payload_weight,
            execution_payload_block_hash: v33.execution_payload_block_hash,
            execution_payload_parent_hash: v33.execution_payload_parent_hash,
            block_timeliness_attestation_threshold: v33.block_timeliness_attestation_threshold,
            block_timeliness_ptc_threshold: v33.block_timeliness_ptc_threshold,
            payload_timeliness_votes: v33.payload_timeliness_votes,
            payload_data_availability_votes: v33.payload_data_availability_votes,
            ptc_participation: v33.ptc_participation,
            payload_received: v33.payload_received,
            proposer_index: v33.proposer_index,
            equivocating_attestation_score: v33.equivocating_attestation_score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Decode;
    use types::Epoch;

    fn legacy_node() -> ProtoNodeV29 {
        let shuffling_id = AttestationShufflingId {
            shuffling_epoch: Epoch::new(1),
            shuffling_decision_block: Hash256::repeat_byte(1),
        };
        ProtoNodeV29 {
            slot: Slot::new(8),
            state_root: Hash256::repeat_byte(2),
            target_root: Hash256::repeat_byte(3),
            current_epoch_shuffling_id: shuffling_id.clone(),
            next_epoch_shuffling_id: shuffling_id,
            root: Hash256::repeat_byte(4),
            parent: Some(0),
            justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            weight: 5,
            execution_status: ExecutionStatus::Optimistic(ExecutionBlockHash::repeat_byte(6)),
            unrealized_justified_checkpoint: Some(Checkpoint::default()),
            unrealized_finalized_checkpoint: None,
            parent_payload_status: ParentPayloadStatus::Full,
            empty_payload_weight: 7,
            full_payload_weight: 8,
            execution_payload_block_hash: ExecutionBlockHash::repeat_byte(9),
            execution_payload_parent_hash: ExecutionBlockHash::repeat_byte(10),
            block_timeliness_attestation_threshold: true,
            block_timeliness_ptc_threshold: false,
            payload_timeliness_votes: BitVector::new(),
            payload_data_availability_votes: BitVector::new(),
            ptc_participation: BitVector::new(),
            payload_received: true,
            proposer_index: 11,
            equivocating_attestation_score: 12,
        }
    }

    // `ProtoNode::V33` reuses the union selector of the removed `ProtoNode::V29`, so a node that
    // skipped the migration must fail to decode rather than decode as the other layout.
    #[test]
    fn layouts_do_not_decode_as_each_other() {
        let v29_bytes = LegacyProtoNode::V29(legacy_node()).as_ssz_bytes();
        assert!(ProtoNode::from_ssz_bytes(&v29_bytes).is_err());

        let v33_bytes = ProtoNode::V33(legacy_node().into()).as_ssz_bytes();
        assert!(LegacyProtoNode::from_ssz_bytes(&v33_bytes).is_err());
    }

    #[test]
    fn legacy_node_round_trips_through_v33() {
        let v29 = legacy_node();
        let v33 = ProtoNodeV33::from(v29.clone());
        assert!(v33.payload_inclusion_list_satisfied);
        assert_eq!(ProtoNodeV29::from(v33), v29);
    }
}
