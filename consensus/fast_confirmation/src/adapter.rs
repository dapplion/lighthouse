//! Bridges Lighthouse's types to `fast_confirmation_core`.
//!
//! The core is written against six accessors and plain scalars so it can run
//! where `types` and `proto_array` cannot. This is the other side of that: a
//! `ProtoArray` wrapped to answer those six, and the conversions between
//! Lighthouse's newtypes and the core's.
//!
//! Nothing here makes a decision. If a behaviour question arises it is answered
//! in the core, once, for both consumers.

use fast_confirmation_core as core_rule;
use proto_array::core::{ProtoArray, VoteTracker};
use types::{Checkpoint, Epoch, Hash256, Slot, SlotAssignments};

use crate::Error;

pub fn root(h: Hash256) -> core_rule::Root {
    h.0
}

pub fn hash(r: core_rule::Root) -> Hash256 {
    Hash256::from(r)
}

pub fn slot(s: Slot) -> core_rule::Slot {
    core_rule::Slot::new(s.as_u64())
}

pub fn epoch(e: Epoch) -> core_rule::Epoch {
    core_rule::Epoch::new(e.as_u64())
}

pub fn checkpoint(c: &Checkpoint) -> core_rule::Checkpoint {
    core_rule::Checkpoint {
        epoch: epoch(c.epoch),
        root: root(c.root),
    }
}

pub fn from_checkpoint(c: core_rule::Checkpoint) -> Checkpoint {
    Checkpoint {
        epoch: Epoch::new(c.epoch.as_u64()),
        root: hash(c.root),
    }
}

/// `proto_array`'s vote trackers, read where they already live.
///
/// Copying the set into the core's `Vote` would allocate proportionally to the
/// validator set on every evaluation; at mainnet size that is tens of megabytes
/// per slot. The rule only ever reads one vote at a time, so it borrows.
pub struct VoteTrackers<'a>(pub &'a [VoteTracker]);

impl core_rule::Votes for VoteTrackers<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, index: usize) -> Option<core_rule::Vote> {
        self.0.get(index).map(|v| core_rule::Vote {
            current_root: root(v.current_root()),
            current_slot: slot(v.current_slot()),
        })
    }
}

/// A `ProtoArray` answering the six questions the rule asks.
pub struct ProtoArrayStore<'a> {
    pub proto_array: &'a ProtoArray,
}

impl core_rule::store::ForkChoiceStore for ProtoArrayStore<'_> {
    fn block_slot(&self, r: core_rule::Root) -> core_rule::Result<core_rule::Slot> {
        self.proto_array
            .get_block(hash(r))
            .map(|node| slot(node.slot()))
            .ok_or(core_rule::Error::NodeNotFound(r))
    }

    fn parent_root(&self, r: core_rule::Root) -> core_rule::Result<core_rule::Root> {
        let h = hash(r);
        let node = self
            .proto_array
            .indices
            .get(&h)
            .and_then(|&idx| self.proto_array.nodes.get(idx))
            .ok_or(core_rule::Error::NodeNotFound(r))?;
        let parent_idx = node
            .parent()
            .ok_or(core_rule::Error::ParentRootNotFound(r))?;
        self.proto_array
            .nodes
            .get(parent_idx)
            .map(|p| root(p.root()))
            .ok_or(core_rule::Error::ParentRootNotFound(r))
    }

    fn justified_checkpoint(&self, r: core_rule::Root) -> core_rule::Result<core_rule::Checkpoint> {
        self.proto_array
            .get_block(hash(r))
            .map(|node| checkpoint(node.justified_checkpoint()))
            .ok_or(core_rule::Error::NodeNotFound(r))
    }

    fn unrealized_justified_checkpoint(
        &self,
        r: core_rule::Root,
    ) -> core_rule::Result<core_rule::Checkpoint> {
        self.proto_array
            .get_block(hash(r))
            .and_then(|node| node.unrealized_justified_checkpoint())
            .map(|cp| checkpoint(&cp))
            .ok_or(core_rule::Error::UnrealizedJustificationNotFound(r))
    }

    fn execution_status(
        &self,
        r: core_rule::Root,
    ) -> core_rule::Result<core_rule::ExecutionStatus> {
        let node = self
            .proto_array
            .get_block(hash(r))
            .ok_or(core_rule::Error::NodeNotFound(r))?;
        Ok(match node.execution_status().ok() {
            Some(status) if status.is_optimistic_or_invalid() => {
                core_rule::ExecutionStatus::OptimisticOrInvalid
            }
            Some(_) => core_rule::ExecutionStatus::Valid,
            // Pre-bellatrix, and missing nodes, are not optimistic. The spec's
            // MUST is post-merge, and a missing node is rejected by `block_slot`
            // before this matters.
            None => core_rule::ExecutionStatus::Irrelevant,
        })
    }
}

/// `types::SlotAssignments`, answering the rule's one question of it.
pub struct Assignments(pub SlotAssignments);

impl core_rule::rule::SlotAssignments for Assignments {
    fn is_in_range(
        &self,
        validator_index: usize,
        start_slot: core_rule::Slot,
        end_slot: core_rule::Slot,
    ) -> core_rule::Result<bool> {
        self.0
            .is_in_range(
                validator_index,
                Slot::new(start_slot.as_u64()),
                Slot::new(end_slot.as_u64()),
            )
            .map_err(|_| core_rule::Error::SlotAssignmentsError)
    }
}

impl From<core_rule::Error> for Error {
    fn from(e: core_rule::Error) -> Self {
        match e {
            core_rule::Error::NodeNotFound(r) => Error::NodeNotFound(hash(r)),
            core_rule::Error::ParentRootNotFound(r) => Error::ParentRootNotFound(hash(r)),
            core_rule::Error::UnrealizedJustificationNotFound(r) => {
                Error::UnrealizedJustificationNotFound(hash(r))
            }
            core_rule::Error::MissingPrecomputedScore(r) => Error::MissingPrecomputedScore(hash(r)),
            core_rule::Error::IndexOutOfBounds(i) => Error::IndexOutOfBounds(i),
            other => Error::CoreRule(alloc_format(other)),
        }
    }
}

fn alloc_format(e: core_rule::Error) -> String {
    format!("{e:?}")
}
