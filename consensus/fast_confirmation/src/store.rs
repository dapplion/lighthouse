//! What the rule asks of fork choice.

use crate::primitives::{Checkpoint, Hash256, Slot};

/// A `ProtoArray`, at the questions the rule asks of it. `None` for a block
/// fork choice does not have.
pub trait ForkChoiceStore {
    fn block_slot(&self, root: Hash256) -> Option<Slot>;

    fn parent_root(&self, root: Hash256) -> Option<Hash256>;

    /// Both at once, for the ancestor walks: a store that keeps its nodes in an
    /// array serves them from one lookup.
    fn slot_and_parent(&self, root: Hash256) -> Option<(Slot, Option<Hash256>)> {
        Some((self.block_slot(root)?, self.parent_root(root)))
    }

    fn justified_checkpoint(&self, root: Hash256) -> Option<Checkpoint>;

    fn unrealized_justified_checkpoint(&self, root: Hash256) -> Option<Checkpoint>;

    /// `true` if the block's payload is `Optimistic` or `Invalid`. Pre-merge
    /// `Irrelevant` payloads are not.
    fn is_optimistic_or_invalid(&self, root: Hash256) -> Option<bool>;
}

/// Longer than any chain; a walk that runs this far is in a cycle.
const MAX_WALK: usize = 1 << 20;

/// `ProtoArray::iter_block_roots`: `root` and its ancestors, with their slots,
/// towards genesis.
pub fn iter_block_roots(
    proto_array: &dyn ForkChoiceStore,
    root: Hash256,
) -> impl Iterator<Item = (Hash256, Slot)> + '_ {
    core::iter::successors(
        proto_array
            .slot_and_parent(root)
            .map(|(slot, parent)| (root, slot, parent)),
        move |(_, _, parent)| {
            let parent = (*parent)?;
            let (slot, grandparent) = proto_array.slot_and_parent(parent)?;
            Some((parent, slot, grandparent))
        },
    )
    .take(MAX_WALK)
    .map(|(root, slot, _)| (root, slot))
}
