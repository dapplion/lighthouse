//! State builders shared by the unit tests of this crate.

use proto_array::core::ProtoArray;
use state_processing::{GloasVerificationContext, per_slot_processing};
use types::{BeaconState, ChainSpec, Checkpoint, Epoch, EthSpec, Hash256, Slot, Validator};

/// A genesis state with `n` active validators at the maximum effective balance.
pub(crate) fn genesis_state<E: EthSpec>(n: usize) -> (BeaconState<E>, ChainSpec) {
    let spec = E::default_spec();
    let mut state = BeaconState::new(0, Default::default(), &spec);
    for _ in 0..n {
        state
            .validators_mut()
            .push(Validator {
                effective_balance: spec.max_effective_balance,
                activation_epoch: Epoch::new(0),
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            })
            .expect("push validator");
        state
            .balances_mut()
            .push(spec.max_effective_balance)
            .expect("push balance");
    }
    state
        .build_all_committee_caches(&spec)
        .expect("committee caches");
    (state, spec)
}

pub(crate) fn advance_state<E: EthSpec>(
    state: &mut BeaconState<E>,
    target: Slot,
    spec: &ChainSpec,
) {
    while state.slot() < target {
        per_slot_processing(
            state,
            None,
            GloasVerificationContext::FullVerification,
            spec,
        )
        .expect("advance slot");
    }
    state
        .build_all_committee_caches(spec)
        .expect("committee caches");
}

/// A proto-array holding a genesis block and its child at slot 1. Returns the child's root.
pub(crate) fn genesis_and_child_proto_array<E: EthSpec>(
    genesis_root: Hash256,
    spec: &ChainSpec,
) -> (ProtoArray, Hash256) {
    use proto_array::{Block, ExecutionStatus, ProtoArrayForkChoice};
    use std::time::Duration;
    use types::AttestationShufflingId;

    let child_root = Hash256::repeat_byte(2);
    let checkpoint = Checkpoint {
        epoch: Epoch::new(0),
        root: genesis_root,
    };
    let shuffling_id = AttestationShufflingId::from_components(Epoch::new(0), genesis_root);
    let mut fork_choice = ProtoArrayForkChoice::new::<E>(
        Slot::new(0),
        Slot::new(0),
        Hash256::ZERO,
        checkpoint,
        checkpoint,
        shuffling_id.clone(),
        shuffling_id.clone(),
        ExecutionStatus::irrelevant(),
        None,
        None,
        0,
        spec,
    )
    .unwrap();
    fork_choice
        .process_block::<E>(
            Block {
                slot: Slot::new(1),
                root: child_root,
                parent_root: Some(genesis_root),
                state_root: Hash256::ZERO,
                target_root: genesis_root,
                current_epoch_shuffling_id: shuffling_id.clone(),
                next_epoch_shuffling_id: shuffling_id,
                justified_checkpoint: checkpoint,
                finalized_checkpoint: checkpoint,
                execution_status: ExecutionStatus::irrelevant(),
                unrealized_justified_checkpoint: Some(checkpoint),
                unrealized_finalized_checkpoint: Some(checkpoint),
                execution_payload_parent_hash: None,
                execution_payload_block_hash: None,
                proposer_index: Some(0),
                payload_received: false,
            },
            Slot::new(1),
            spec,
            Duration::from_secs(0),
        )
        .unwrap();
    (fork_choice.core_proto_array().clone(), child_root)
}
