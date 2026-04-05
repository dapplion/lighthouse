use beacon_chain::{BeaconChain, BeaconChainTypes};
use fixed_bytes::FixedBytesExtended;
use types::{EthSpec, Hash256};

use lighthouse_network::rpc::{StatusMessage, methods::StatusMessageV2};
/// Trait to produce a `StatusMessage` representing the state of the given `beacon_chain`.
///
/// NOTE: The purpose of this is simply to obtain a `StatusMessage` from the `BeaconChain` without
/// polluting/coupling the type with RPC concepts.
pub trait ToStatusMessage {
    fn status_message(&self) -> StatusMessage;
}

impl<T: BeaconChainTypes> ToStatusMessage for BeaconChain<T> {
    fn status_message(&self) -> StatusMessage {
        status_message(self)
    }
}

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) -> StatusMessage {
    let fork_digest = beacon_chain.enr_fork_id().fork_digest;
    let cached_head = beacon_chain.canonical_head.cached_head();
    let mut finalized_checkpoint = cached_head.finalized_checkpoint();

    // During checkpoint sync, the fork choice's finalized checkpoint is set to the anchor
    // block's epoch, which may be ahead of the network-agreed finalized epoch stored in the
    // state. Other clients (e.g. Prysm) reject peers whose finalized_root doesn't match
    // their IsFinalized check. Use the state's finalized checkpoint when it's behind the
    // fork choice value, as it reflects the actual network consensus.
    let state_finalized = cached_head.snapshot.beacon_state.finalized_checkpoint();
    if state_finalized.epoch < finalized_checkpoint.epoch {
        finalized_checkpoint = state_finalized;
    }

    // Alias the genesis checkpoint root to `0x00`.
    let spec = &beacon_chain.spec;
    let genesis_epoch = spec.genesis_slot.epoch(T::EthSpec::slots_per_epoch());
    if finalized_checkpoint.epoch == genesis_epoch {
        finalized_checkpoint.root = Hash256::zero();
    }

    // NOTE: We are making an assumption that `get_data_column_custody_info` wont fail.
    let earliest_available_data_column_slot = beacon_chain
        .store
        .get_data_column_custody_info()
        .ok()
        .flatten()
        .and_then(|info| info.earliest_data_column_slot);

    // If data_column_custody_info.earliest_data_column_slot is `None`,
    // no recent cgc changes have occurred and no cgc backfill is in progress.
    let earliest_available_slot =
        if let Some(earliest_available_data_column_slot) = earliest_available_data_column_slot {
            earliest_available_data_column_slot
        } else {
            beacon_chain.store.get_anchor_info().oldest_block_slot
        };
    StatusMessage::V2(StatusMessageV2 {
        fork_digest,
        finalized_root: finalized_checkpoint.root,
        finalized_epoch: finalized_checkpoint.epoch,
        head_root: cached_head.head_block_root(),
        head_slot: cached_head.head_slot(),
        earliest_available_slot,
    })
}
