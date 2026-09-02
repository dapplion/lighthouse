//! What the rule needs to know about the block tree, and nothing else.
//!
//! Lighthouse reads this straight off a `ProtoArray`. A circuit has no store: it
//! has a witness, and whatever it can prove about it. Both can answer the six
//! questions below, so the rule is written against them rather than against
//! either representation.
//!
//! `iter_block_roots` is deliberately absent. Lighthouse walks ancestors with an
//! iterator, which a trait cannot return without allocation or GATs; the walk is
//! reconstructed here from `parent_root`, which is the same traversal and one
//! fewer thing an implementer has to get right.

use crate::primitives::{Checkpoint, ExecutionStatus, Root, Slot};
use crate::{Error, Result};

/// The block tree, as the fast confirmation rule reads it.
pub trait ForkChoiceStore {
    /// Spec: `get_block_slot`. `Err(NodeNotFound)` if the block is unknown.
    fn block_slot(&self, root: Root) -> Result<Slot>;

    /// The block's parent. `Err(ParentRootNotFound)` at the root of the tree.
    fn parent_root(&self, root: Root) -> Result<Root>;

    /// Spec: `store.block_states[root].current_justified_checkpoint`.
    fn justified_checkpoint(&self, root: Root) -> Result<Checkpoint>;

    /// Spec: `store.unrealized_justifications[root]`.
    fn unrealized_justified_checkpoint(&self, root: Root) -> Result<Checkpoint>;

    /// Pre-merge blocks are `Irrelevant`; the spec's MUST is post-merge.
    fn execution_status(&self, root: Root) -> Result<ExecutionStatus>;

    /// A node's slot and parent together, for the ancestor walks.
    ///
    /// Every hop of a walk needs both. Asking for them separately costs two
    /// lookups where a store that holds its nodes in an array can serve both
    /// from one, so a store with a cheaper path should override this. The
    /// default keeps the two-lookup behaviour for stores that have nothing
    /// faster. `None` for the parent means the walk has reached the tree root.
    fn slot_and_parent(&self, root: Root) -> Result<(Slot, Option<Root>)> {
        Ok((self.block_slot(root)?, self.parent_root(root).ok()))
    }
}

/// Spec: `get_block_epoch`.
pub fn block_epoch<S: ForkChoiceStore>(
    store: &S,
    root: Root,
    slots_per_epoch: u64,
) -> Result<crate::primitives::Epoch> {
    Ok(store.block_slot(root)?.epoch(slots_per_epoch))
}

/// Return `true` if the block's execution payload is optimistic or invalid.
pub fn is_optimistic_or_invalid<S: ForkChoiceStore>(store: &S, root: Root) -> Result<bool> {
    Ok(store.execution_status(root)?.is_optimistic_or_invalid())
}

/// How far an ancestor walk may go before the tree is assumed malformed. Fork
/// choice prunes to the finalized checkpoint, so a walk longer than this is a
/// cycle rather than a deep chain.
const MAX_WALK: usize = 1 << 20;

/// Spec: `is_ancestor`.
///
/// Walks from `block_root` towards the root, stopping once the walk is past the
/// ancestor's slot -- the same bound Lighthouse's `iter_block_roots` filter has.
pub fn is_ancestor<S: ForkChoiceStore>(
    store: &S,
    block_root: Root,
    ancestor_root: Root,
) -> Result<bool> {
    let ancestor_slot = store.block_slot(ancestor_root)?;
    let mut root = block_root;
    for _ in 0..MAX_WALK {
        let (slot, parent) = store.slot_and_parent(root)?;
        if slot <= ancestor_slot {
            return Ok(root == ancestor_root);
        }
        match parent {
            Some(parent) => root = parent,
            None => return Ok(false),
        }
    }
    Err(Error::WalkTooLong)
}

/// Spec: `get_ancestor`.
pub fn get_ancestor<S: ForkChoiceStore>(store: &S, block_root: Root, slot: Slot) -> Result<Root> {
    let mut root = block_root;
    for _ in 0..MAX_WALK {
        let (current, parent) = store.slot_and_parent(root)?;
        if current <= slot {
            return Ok(root);
        }
        root = parent.ok_or(Error::AncestorNotFound { block: block_root })?;
    }
    Err(Error::WalkTooLong)
}

/// Spec: `get_ancestor_roots`. The chain from just above `terminal_root` up to
/// and including `block_root`, oldest first. Empty when `terminal_root` is not
/// an ancestor -- which is what makes reconfirmation vacuous in that case, and
/// is preserved here rather than tidied away.
pub fn get_ancestor_roots<S: ForkChoiceStore>(
    store: &S,
    block_root: Root,
    terminal_root: Root,
) -> Result<alloc::vec::Vec<Root>> {
    let terminal_slot = store.block_slot(terminal_root)?;
    let mut roots = alloc::vec::Vec::new();
    let mut root = block_root;

    for _ in 0..MAX_WALK {
        if root == terminal_root {
            roots.reverse();
            return Ok(roots);
        }
        let (slot, parent) = store.slot_and_parent(root)?;
        if slot <= terminal_slot {
            return Ok(alloc::vec::Vec::new());
        }
        roots.push(root);
        match parent {
            Some(parent) => root = parent,
            None => return Ok(alloc::vec::Vec::new()),
        }
    }
    Err(Error::WalkTooLong)
}

/// Spec: `get_voting_source_epoch`.
pub fn get_voting_source_epoch<S: ForkChoiceStore>(
    store: &S,
    root: Root,
    current_slot: Slot,
    slots_per_epoch: u64,
) -> Result<crate::primitives::Epoch> {
    let current_epoch = current_slot.epoch(slots_per_epoch);
    let block_epoch = store.block_slot(root)?.epoch(slots_per_epoch);
    if current_epoch > block_epoch {
        Ok(store.unrealized_justified_checkpoint(root)?.epoch)
    } else {
        Ok(store.justified_checkpoint(root)?.epoch)
    }
}

/// Spec: `get_checkpoint_block_root`.
pub fn get_checkpoint_block_root<S: ForkChoiceStore>(
    store: &S,
    block_root: Root,
    epoch: crate::primitives::Epoch,
    slots_per_epoch: u64,
) -> Option<Root> {
    get_ancestor(store, block_root, epoch.start_slot(slots_per_epoch)).ok()
}

/// Spec: `get_checkpoint_for_block`.
pub fn get_checkpoint_for_block<S: ForkChoiceStore>(
    store: &S,
    block_root: Root,
    epoch: crate::primitives::Epoch,
    slots_per_epoch: u64,
) -> Option<Checkpoint> {
    Some(Checkpoint {
        epoch,
        root: get_checkpoint_block_root(store, block_root, epoch, slots_per_epoch)?,
    })
}

/// Spec: `get_current_target`.
pub fn get_current_target<S: ForkChoiceStore>(
    store: &S,
    head_root: Root,
    current_slot: Slot,
    slots_per_epoch: u64,
) -> Result<Checkpoint> {
    let current_epoch = current_slot.epoch(slots_per_epoch);
    get_checkpoint_for_block(store, head_root, current_epoch, slots_per_epoch)
        .ok_or(Error::HeadCheckpointNotFound(head_root))
}
