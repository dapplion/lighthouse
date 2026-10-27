//! State builders shared by the unit tests of this crate.

use state_processing::{GloasVerificationContext, per_slot_processing};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Slot, Validator};

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
