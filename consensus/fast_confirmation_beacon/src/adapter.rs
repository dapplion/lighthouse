//! Lighthouse's types, lent to `fast_confirmation`.

use fast_confirmation as core_rule;
use proto_array::core::{ProtoArray, VoteTracker};
use std::marker::PhantomData;
use types::{Checkpoint, Epoch, EthSpec, Hash256, Slot, SlotAssignments};

#[inline]
pub fn root(h: Hash256) -> core_rule::Hash256 {
    core_rule::Hash256(h.0)
}

#[inline]
pub fn hash(r: core_rule::Hash256) -> Hash256 {
    Hash256::from(r.0)
}

#[inline]
pub fn slot(s: Slot) -> core_rule::Slot {
    core_rule::Slot::new(s.as_u64())
}

#[inline]
pub fn epoch(e: Epoch) -> core_rule::Epoch {
    core_rule::Epoch::new(e.as_u64())
}

#[inline]
pub fn checkpoint(c: &Checkpoint) -> core_rule::Checkpoint {
    core_rule::Checkpoint {
        epoch: epoch(c.epoch),
        root: root(c.root),
    }
}

#[inline]
pub fn from_checkpoint(c: core_rule::Checkpoint) -> Checkpoint {
    Checkpoint {
        epoch: Epoch::new(c.epoch.as_u64()),
        root: hash(c.root),
    }
}

/// `E: EthSpec`, at the one thing the rule reads off it.
pub struct Spec<E>(PhantomData<E>);

impl<E: EthSpec> core_rule::EthSpec for Spec<E> {
    #[inline(always)]
    fn slots_per_epoch() -> u64 {
        E::slots_per_epoch()
    }
}

/// A `ProtoArray`, answering the rule's questions. One map lookup each, and
/// an array index for the parent.
pub struct ProtoArrayStore<'a> {
    pub proto_array: &'a ProtoArray,
}

impl core_rule::ForkChoiceStore for ProtoArrayStore<'_> {
    #[inline]
    fn block_slot(&self, r: core_rule::Hash256) -> Option<core_rule::Slot> {
        self.proto_array
            .get_block(hash(r))
            .map(|node| slot(node.slot()))
    }

    #[inline]
    fn parent_root(&self, r: core_rule::Hash256) -> Option<core_rule::Hash256> {
        let node = self.proto_array.get_block(hash(r))?;
        self.proto_array.get_parent(node).map(|p| root(p.root()))
    }

    #[inline]
    fn slot_and_parent(
        &self,
        r: core_rule::Hash256,
    ) -> Option<(core_rule::Slot, Option<core_rule::Hash256>)> {
        let node = self.proto_array.get_block(hash(r))?;
        let parent = self.proto_array.get_parent(node).map(|p| root(p.root()));
        Some((slot(node.slot()), parent))
    }

    #[inline]
    fn justified_checkpoint(&self, r: core_rule::Hash256) -> Option<core_rule::Checkpoint> {
        self.proto_array
            .get_block(hash(r))
            .map(|node| checkpoint(node.justified_checkpoint()))
    }

    #[inline]
    fn unrealized_justified_checkpoint(
        &self,
        r: core_rule::Hash256,
    ) -> Option<core_rule::Checkpoint> {
        self.proto_array
            .get_block(hash(r))?
            .unrealized_justified_checkpoint()
            .map(|cp| checkpoint(&cp))
    }

    #[inline]
    fn is_optimistic_or_invalid(&self, r: core_rule::Hash256) -> Option<bool> {
        let node = self.proto_array.get_block(hash(r))?;
        Some(
            node.execution_status()
                .ok()
                .is_some_and(|s| s.is_optimistic_or_invalid()),
        )
    }
}

/// `proto_array`'s vote trackers, read where they already live rather than
/// copied: at mainnet size a copy is tens of megabytes per evaluation.
pub struct VoteTrackers<'a>(pub &'a [VoteTracker]);

impl core_rule::Votes for VoteTrackers<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn get(&self, index: usize) -> Option<core_rule::VoteTracker> {
        self.0.get(index).map(|v| core_rule::VoteTracker {
            current_root: root(v.current_root()),
            current_slot: slot(v.current_slot()),
        })
    }
}

/// `types::SlotAssignments`, answering the rule's one question of it.
#[derive(Debug, Clone)]
pub struct Assignments(pub SlotAssignments);

impl core_rule::SlotAssignments for Assignments {
    #[inline(always)]
    fn is_in_range(
        &self,
        validator_index: usize,
        start_slot: core_rule::Slot,
        end_slot: core_rule::Slot,
    ) -> Result<bool, core_rule::SlotAssignmentsError> {
        self.0
            .is_in_range(
                validator_index,
                Slot::new(start_slot.as_u64()),
                Slot::new(end_slot.as_u64()),
            )
            .map_err(|_| core_rule::SlotAssignmentsError)
    }
}
