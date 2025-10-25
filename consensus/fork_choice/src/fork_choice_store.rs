use proto_array::JustifiedBalances;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::BTreeSet;
use std::fmt::Debug;
use types::{Checkpoint, Hash256, Slot};

/// Approximates the `Store` in "Ethereum 2.0 Phase 0 -- Beacon Chain Fork Choice":
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#store
///
/// ## Detail
///
/// This is only an approximation for two reasons:
///
/// - This crate stores the actual block DAG in `ProtoArrayForkChoice`.
/// - `time` is represented using `Slot` instead of UNIX epoch `u64`.
///
/// ## Motiviation
///
/// The primary motivation for defining this as a trait to be implemented upstream rather than a
/// concrete struct is to allow this crate to be free from "impure" on-disk database logic,
/// hopefully making auditing easier.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct ForkChoiceStore {
    pub(crate) time: Slot,
    pub(crate) finalized_checkpoint: Checkpoint,
    pub(crate) justified_checkpoint: Checkpoint,
    pub(crate) justified_balances: JustifiedBalances,
    pub(crate) justified_state_root: Hash256,
    pub(crate) unrealized_justified_checkpoint: Checkpoint,
    pub(crate) unrealized_justified_state_root: Hash256,
    pub(crate) unrealized_finalized_checkpoint: Checkpoint,
    pub(crate) proposer_boost_root: Hash256,
    pub(crate) equivocating_indices: BTreeSet<u64>,
}

impl ForkChoiceStore {
    pub(crate) fn get_current_slot(&self) -> Slot {
        self.time
    }

    pub(crate) fn set_current_slot(&mut self, slot: Slot) {
        self.time = slot
    }

    pub(crate) fn justified_checkpoint(&self) -> &Checkpoint {
        &self.justified_checkpoint
    }

    pub(crate) fn justified_balances(&self) -> &JustifiedBalances {
        &self.justified_balances
    }

    pub(crate) fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }

    pub(crate) fn unrealized_justified_checkpoint(&self) -> &Checkpoint {
        &self.unrealized_justified_checkpoint
    }

    pub(crate) fn unrealized_justified_state_root(&self) -> Hash256 {
        self.unrealized_justified_state_root
    }

    pub(crate) fn unrealized_finalized_checkpoint(&self) -> &Checkpoint {
        &self.unrealized_finalized_checkpoint
    }

    pub(crate) fn proposer_boost_root(&self) -> Hash256 {
        self.proposer_boost_root
    }

    pub(crate) fn set_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.finalized_checkpoint = checkpoint
    }

    pub(crate) fn set_justified_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        justified_balances: JustifiedBalances,
    ) {
        self.justified_checkpoint = checkpoint;
        self.justified_balances = justified_balances;
    }

    pub(crate) fn set_unrealized_justified_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        state_root: Hash256,
    ) {
        self.unrealized_justified_checkpoint = checkpoint;
        self.unrealized_justified_state_root = state_root;
    }

    pub(crate) fn set_unrealized_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.unrealized_finalized_checkpoint = checkpoint;
    }

    pub(crate) fn set_proposer_boost_root(&mut self, proposer_boost_root: Hash256) {
        self.proposer_boost_root = proposer_boost_root;
    }

    pub(crate) fn equivocating_indices(&self) -> &BTreeSet<u64> {
        &self.equivocating_indices
    }

    pub(crate) fn extend_equivocating_indices(&mut self, indices: impl IntoIterator<Item = u64>) {
        self.equivocating_indices.extend(indices);
    }
}
