use beacon_chain::{BeaconChain, BeaconChainTypes};
use types::{EthSpec, FixedBytesExtended, Hash256, VariableList};

use lighthouse_network::rpc::{StatusMessage, StatusMessageV1_9999};

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> StatusMessage<T::EthSpec> {
    let fork_digest = beacon_chain.enr_fork_id().fork_digest;
    let cached_head = beacon_chain.canonical_head.cached_head();
    let mut finalized_checkpoint = cached_head.finalized_checkpoint();

    // Alias the genesis checkpoint root to `0x00`.
    let spec = &beacon_chain.spec;
    let genesis_epoch = spec.genesis_slot.epoch(T::EthSpec::slots_per_epoch());
    if finalized_checkpoint.epoch == genesis_epoch {
        finalized_checkpoint.root = Hash256::zero();
    }

    let ancestor_roots = cached_head.head_chain_ancestor_roots().to_vec();

    let ancestor_roots_bounded = if ancestor_roots.len() > T::EthSpec::max_status_roots() {
        ancestor_roots[ancestor_roots.len() - T::EthSpec::max_status_roots()..].to_vec()
    } else {
        ancestor_roots
    };

    StatusMessage::V1_9999(StatusMessageV1_9999 {
        fork_digest,
        finalized_root: finalized_checkpoint.root,
        finalized_epoch: finalized_checkpoint.epoch,
        head_root: cached_head.head_block_root(),
        head_slot: cached_head.head_slot(),
        ancestor_roots: VariableList::new(ancestor_roots_bounded)
            .expect("ancestor_roots_max_len has len <= MAX_STATUS_ROOTS"),
    })
}
