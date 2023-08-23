//! The `BeaconProposerCacheWhisk` stores the self-declarations of validators of when they will
//! propose.
//!
//! This cache is keyed by `(slot, block_root)` where `block_root` is the block root at
//! `end_slot(whisk_shuffling_period_epoch_start - 1)`. Proposer trackers are fixed during an entire
//! shuffling period, which is determinstic on whisk_shuffling_period_epoch_start.
//!
//! The information hold in this cache cannot be computed by the beacon node, so it cannot be
//! pruned. The beacon node must retain this data until its sure it cannot be used.

use std::collections::{hash_map::Entry, HashMap};
use types::{EthSpec, Slot, WhiskProposerShufflingRoot};

const RETAIN_OLD_SLOTS: Slot = Slot::new(128);
const MAX_SLOT_LOOKAHEAD: Slot = Slot::new(8192);

/// For some given slot, this contains the proposer index (`index`) and the `fork` that should be
/// used to verify their signature.
pub type Proposer = usize;

#[derive(Debug, Clone)]
pub enum Error {
    DifferentProposerAlreadyRegisteredForSlot,
    SlotTooOld,
    SlotTooAhead,
}

/// A cache to store validator declaration of which slot they are proposers post whisk.
///
/// See the module-level documentation for more information.
#[derive(Default)]
pub struct BeaconWhiskProposerRegistry {
    registry: HashMap<Slot, HashMap<WhiskProposerShufflingRoot, Proposer>>,
    pruned_slot: Slot,
}

impl BeaconWhiskProposerRegistry {
    pub fn new(current_slot: Slot) -> Self {
        Self {
            registry: HashMap::new(),
            pruned_slot: current_slot,
        }
    }

    /// Returns true if a validator has registered as proposal for any fork at `slot`.
    /// TODO WHISK: retrieve by fork once all code paths can retrieve the
    /// whisk_shuffling_decision_block of any head.
    pub fn has_some_at_slot(&self, slot: Slot) -> bool {
        self.registry.get(&slot).is_some()
    }

    /// If it is cached, returns the proposer for the block at `slot` where the block has the
    /// ancestor block root of `shuffling_decision_block` at `end_slot(slot.epoch() - 1)`.
    pub fn get_slot<T: EthSpec>(
        &self,
        whisk_shuffling_decision_block: WhiskProposerShufflingRoot,
        slot: Slot,
    ) -> Option<&Proposer> {
        self.registry
            .get(&slot)
            .and_then(|entry| entry.get(&whisk_shuffling_decision_block))
    }

    /// Insert the proposers into the cache.
    ///
    /// See `Self::get` for a description of `shuffling_decision_block`.
    ///
    /// The `fork` value must be valid to verify proposer signatures in `epoch`.
    pub fn insert(
        &mut self,
        slot: Slot,
        whisk_shuffling_decision_block: WhiskProposerShufflingRoot,
        proposer_index: Proposer,
    ) -> Result<(), Error> {
        if slot < self.pruned_slot {
            return Err(Error::SlotTooOld);
        }
        if slot > self.pruned_slot + RETAIN_OLD_SLOTS + MAX_SLOT_LOOKAHEAD {
            return Err(Error::SlotTooAhead);
        }

        match self
            .registry
            .entry(slot)
            .or_insert(HashMap::new())
            .entry(whisk_shuffling_decision_block)
        {
            Entry::Vacant(entry) => {
                entry.insert(proposer_index);
            }
            Entry::Occupied(entry) => {
                if *entry.get() != proposer_index {
                    return Err(Error::DifferentProposerAlreadyRegisteredForSlot);
                }
            }
        };

        Ok(())
    }

    /// Prune entries for slots that
    pub fn prune(&mut self, current_slot: Slot) {
        let up_to_slot = current_slot.saturating_sub(RETAIN_OLD_SLOTS);

        for slot in self.pruned_slot.as_u64()..up_to_slot.as_u64() {
            self.registry.remove(&Slot::new(slot));
        }

        self.pruned_slot = up_to_slot;
    }
}
