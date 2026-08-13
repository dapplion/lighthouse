#![cfg(test)]

use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::test_utils::{
    BeaconChainHarness, EphemeralHarnessType, generate_deterministic_keypairs,
};
use beacon_chain::{
    BlockError, ChainConfig, StateSkipConfig, WhenSlotSkipped,
    test_utils::{AttestationStrategy, BlockStrategy, RelativeSyncCommittee},
    types::{Epoch, EthSpec, MinimalEthSpec},
};
use bls::Keypair;
use eth2::types::{StandardAttestationRewards, TotalAttestationRewards, ValidatorId};
use state_processing::per_block_processing::{
    process_operations, process_parent_execution_payload,
};
use state_processing::{BlockReplayError, BlockReplayer, ConsensusContext, VerifySignatures};
use std::array::IntoIter;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use types::{ChainSpec, ForkName, Slot};

pub const VALIDATOR_COUNT: usize = 64;

// When set to true, cache any states fetched from the db.
pub const CACHE_STATE_IN_TESTS: bool = true;

type E = MinimalEthSpec;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_harness(spec: ChainSpec) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let chain_config = ChainConfig {
        archive: true,
        ..Default::default()
    };

    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(spec))
        .keypairs(KEYPAIRS.to_vec())
        .fresh_ephemeral_store()
        .chain_config(chain_config)
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

fn get_electra_harness(spec: ChainSpec) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let chain_config = ChainConfig {
        archive: true,
        ..Default::default()
    };

    let spec = Arc::new(spec);

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .keypairs(KEYPAIRS.to_vec())
        .with_genesis_state_builder(|builder| {
            builder.set_initial_balance_fn(Box::new(move |i| {
                // Use a variety of balances between min activation balance and max effective balance.
                let balance = spec.max_effective_balance_electra
                    / (i as u64 + 1)
                    / spec.effective_balance_increment
                    * spec.effective_balance_increment;
                balance.max(spec.min_activation_balance)
            }))
        })
        .fresh_ephemeral_store()
        .chain_config(chain_config)
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

#[tokio::test]
async fn test_sync_committee_rewards() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let num_block_produced = E::slots_per_epoch();

    let latest_block_root = harness
        .extend_chain(
            num_block_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Create and add sync committee message to op_pool
    let sync_contributions = harness.make_sync_contributions(
        &harness.get_current_state(),
        latest_block_root,
        harness.get_current_slot(),
        RelativeSyncCommittee::Current,
    );

    harness
        .process_sync_contributions(sync_contributions)
        .unwrap();

    // Add block
    let chain = &harness.chain;
    let head_state = harness.get_current_state();
    let target_slot = harness.get_current_slot() + 1;

    let (block_root, mut state) = harness
        .add_attested_block_at_slot(target_slot, head_state, &[])
        .await
        .unwrap();

    let block = harness.get_block(block_root).unwrap();
    let parent_block = chain
        .get_blinded_block(&block.parent_root())
        .unwrap()
        .unwrap();

    let parent_state = chain
        .get_state(
            &parent_block.state_root(),
            Some(parent_block.slot()),
            CACHE_STATE_IN_TESTS,
        )
        .unwrap()
        .unwrap();

    let reward_payload = chain
        .compute_sync_committee_rewards(block.message(), &mut state)
        .unwrap();

    let rewards = reward_payload
        .iter()
        .map(|reward| (reward.validator_index, reward.reward))
        .collect::<HashMap<_, _>>();

    let proposer_index = state
        .get_beacon_proposer_index(target_slot, &MinimalEthSpec::default_spec())
        .unwrap();

    let mut mismatches = vec![];

    for validator in state.validators() {
        let validator_index = state
            .clone()
            .get_validator_index(&validator.pubkey)
            .unwrap()
            .unwrap();
        let pre_state_balance = *parent_state.balances().get(validator_index).unwrap();
        let post_state_balance = *state.balances().get(validator_index).unwrap();
        let sync_committee_reward = rewards.get(&(validator_index as u64)).unwrap_or(&0);

        if validator_index == proposer_index {
            continue; // Ignore proposer
        }

        if pre_state_balance as i64 + *sync_committee_reward != post_state_balance as i64 {
            mismatches.push(validator_index.to_string());
        }
    }

    assert_eq!(
        mismatches.len(),
        0,
        "Expect 0 mismatches, but these validators have mismatches on balance: {} ",
        mismatches.join(",")
    );
}

#[tokio::test]
async fn test_rewards_base() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let initial_balances = harness.get_current_state().balances().to_vec();

    harness
        .extend_slots(E::slots_per_epoch() as usize * 2 - 1)
        .await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_inactivity_leak() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let initial_balances = harness.get_current_state().balances().to_vec();

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until end of target epoch
    harness
        .extend_slots_some_validators(
            ((E::slots_per_epoch() * target_epoch) - 1) as usize,
            half_validators.clone(),
        )
        .await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_inactivity_leak_justification_epoch() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let initial_balances = harness.get_current_state().balances().to_vec();

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let mut target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until end of target epoch
    harness
        .extend_chain(
            ((E::slots_per_epoch() * target_epoch) - 1) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(half_validators.clone()),
        )
        .await;

    // advance to create first justification epoch
    harness.extend_slots(E::slots_per_epoch() as usize).await;
    target_epoch += 1;

    // assert previous_justified_checkpoint matches 0 as we were in inactivity leak from beginning
    assert_eq!(
        0,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // extend slots to end of epoch target_epoch + 2
    harness.extend_slots(E::slots_per_epoch() as usize).await;

    check_all_base_rewards(&harness, initial_balances).await;

    // assert target epoch and previous_justified_checkpoint match
    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );
}

#[tokio::test]
async fn test_rewards_electra_slashings() {
    let spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let harness = get_electra_harness(spec);
    let state = harness.get_current_state();

    harness.extend_slots(E::slots_per_epoch() as usize).await;

    let mut initial_balances = harness.get_current_state().balances().to_vec();

    // add an attester slashing and calculate slashing penalties
    harness.add_attester_slashing(vec![0]).unwrap();
    let slashed_balance_1 = initial_balances.get_mut(0).unwrap();
    let validator_1_effective_balance = state.get_effective_balance(0).unwrap();
    let delta_1 =
        validator_1_effective_balance / state.get_min_slashing_penalty_quotient(&harness.spec);
    *slashed_balance_1 -= delta_1;

    // add a proposer slashing and calculating slashing penalties
    harness.add_proposer_slashing(1).unwrap();
    let slashed_balance_2 = initial_balances.get_mut(1).unwrap();
    let validator_2_effective_balance = state.get_effective_balance(1).unwrap();
    let delta_2 =
        validator_2_effective_balance / state.get_min_slashing_penalty_quotient(&harness.spec);
    *slashed_balance_2 -= delta_2;

    check_all_electra_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_slashings() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let mut initial_balances = harness.get_current_state().balances().to_vec();

    harness
        .extend_slots(E::slots_per_epoch() as usize - 1)
        .await;

    harness.add_attester_slashing(vec![0]).unwrap();
    let slashed_balance = initial_balances.get_mut(0).unwrap();
    *slashed_balance -= *slashed_balance / harness.spec.min_slashing_penalty_quotient;

    harness.extend_slots(E::slots_per_epoch() as usize).await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_multi_inclusion() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let initial_balances = harness.get_current_state().balances().to_vec();

    harness.extend_slots(2).await;

    let prev_block = harness.chain.head_beacon_block();

    harness.extend_slots(1).await;

    harness.advance_slot();
    let slot = harness.get_current_slot();
    let mut block =
        // pin to reduce stack size for clippy
        Box::pin(
            harness.make_block_with_modifier(harness.get_current_state(), slot, |block| {
                // add one attestation from the same block
                let attestations = &mut block.body_base_mut().unwrap().attestations;
                attestations
                    .push(attestations.first().unwrap().clone())
                    .unwrap();

                // add one attestation from the previous block
                let attestation = prev_block
                    .as_block()
                    .message_base()
                    .unwrap()
                    .body
                    .attestations
                    .first()
                    .unwrap()
                    .clone();
                attestations.push(attestation).unwrap();
            }),
        )
        .await
        .0;

    // funky hack: on first try, the state root will mismatch due to our modification
    // thankfully, the correct state root is reported back, so we just take that one :^)
    // there probably is a better way...
    let Err(BlockError::StateRootMismatch { local, .. }) = harness
        .process_block(slot, block.0.canonical_root(), block.clone())
        .await
    else {
        panic!("unexpected match of state root");
    };
    let mut new_block = block.0.message_base().unwrap().clone();
    new_block.state_root = local;
    block.0 = Arc::new(harness.sign_beacon_block(new_block.into(), &harness.get_current_state()));
    harness
        .process_block(slot, block.0.canonical_root(), block.clone())
        .await
        .unwrap();

    harness
        .extend_slots(E::slots_per_epoch() as usize * 2 - 4)
        .await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_altair() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let target_epoch = 0;

    // advance until epoch N + 1 and get initial balances
    harness
        .extend_slots((E::slots_per_epoch() * (target_epoch + 1)) as usize)
        .await;
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

        harness.extend_slots(1).await;
    }

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert ideal rewards are greater than 0
    assert!(
        ideal_rewards
            .iter()
            .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0)
    );

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_altair_inactivity_leak() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until beginning of epoch N + 1 and get balances
    harness
        .extend_slots_some_validators(
            (E::slots_per_epoch() * (target_epoch + 1)) as usize,
            half_validators.clone(),
        )
        .await;
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0i64);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

        harness
            .extend_slots_some_validators(1, half_validators.clone())
            .await;
    }

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert inactivity penalty for both ideal rewards and individual validators
    assert!(ideal_rewards.iter().all(|reward| reward.inactivity == 0));
    assert!(
        total_rewards[..half]
            .iter()
            .all(|reward| reward.inactivity == 0)
    );
    assert!(
        total_rewards[half..]
            .iter()
            .all(|reward| reward.inactivity < 0)
    );

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_altair_inactivity_leak_justification_epoch() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak + 1
    let mut target_epoch = &spec.min_epochs_to_inactivity_penalty + 2;

    // advance until beginning of epoch N + 1
    harness
        .extend_slots_some_validators(
            (E::slots_per_epoch() * (target_epoch + 1)) as usize,
            half_validators.clone(),
        )
        .await;

    let validator_inactivity_score = harness
        .get_current_state()
        .get_inactivity_score(VALIDATOR_COUNT - 1)
        .unwrap();

    //assert to ensure we are in inactivity leak
    assert_eq!(4, validator_inactivity_score);

    // advance for first justification epoch and get balances
    harness.extend_slots(E::slots_per_epoch() as usize).await;
    target_epoch += 1;
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

        harness.extend_slots(1).await;
    }

    //assert target epoch and previous_justified_checkpoint match
    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert ideal rewards are greater than 0
    assert!(
        ideal_rewards
            .iter()
            .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0)
    );

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();
    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_electra() {
    let spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let harness = get_electra_harness(spec.clone());
    let target_epoch = 0;

    // advance until epoch N + 1 and get initial balances
    harness
        .extend_slots((E::slots_per_epoch() * (target_epoch + 1)) as usize)
        .await;
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

        harness.extend_slots(1).await;
    }

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert ideal rewards are greater than 0
    assert_eq!(
        ideal_rewards.len() as u64,
        spec.max_effective_balance_electra / spec.effective_balance_increment
    );
    assert!(
        ideal_rewards
            .iter()
            .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0)
    );

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_base_subset_only() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let initial_balances = harness.get_current_state().balances().to_vec();

    // a subset of validators to compute attestation rewards for
    let validators_subset = (0..16).chain(56..64).collect::<Vec<_>>();

    // epoch 0 (N), only two thirds of validators vote.
    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let two_thirds_validators: Vec<usize> = (0..two_thirds).collect();
    harness
        .extend_slots_some_validators(E::slots_per_epoch() as usize, two_thirds_validators.clone())
        .await;

    check_all_base_rewards_for_subset(&harness, initial_balances, validators_subset).await;
}

async fn check_all_electra_rewards(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    mut balances: Vec<u64>,
) {
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

        harness.extend_slots(1).await;
    }

    // compute reward deltas for all validators in epoch 0
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(0), vec![])
        .unwrap();

    // assert ideal rewards are greater than 0
    assert_eq!(
        ideal_rewards.len() as u64,
        harness.spec.max_effective_balance_electra / harness.spec.effective_balance_increment
    );

    assert!(
        ideal_rewards
            .iter()
            .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0)
    );

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    apply_attestation_rewards(&mut balances, total_rewards);
    apply_other_rewards(&mut balances, &proposal_rewards_map);
    apply_other_rewards(&mut balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let actual_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(balances, actual_balances);
}

async fn check_all_base_rewards(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    balances: Vec<u64>,
) {
    // The box reduces the size on the stack for a clippy lint.
    Box::pin(check_all_base_rewards_for_subset(harness, balances, vec![])).await;
}

async fn check_all_base_rewards_for_subset(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    mut balances: Vec<u64>,
    validator_subset: Vec<u64>,
) {
    let validator_subset_ids: Vec<ValidatorId> = validator_subset
        .iter()
        .map(|&idx| ValidatorId::Index(idx))
        .collect();

    // capture the amount of epochs generated by the caller
    let epochs = harness.get_current_slot().epoch(E::slots_per_epoch()) + 1;

    // advance two empty epochs to ensure balances are updated by the epoch boundaries
    for _ in 0..E::slots_per_epoch() * 2 {
        harness.advance_slot();
    }
    // fill one slot to ensure state is updated
    harness.extend_slots(1).await;

    // calculate proposal awards
    let mut proposal_rewards_map = HashMap::new();
    for slot in 1..(E::slots_per_epoch() * epochs.as_u64()) {
        if let Some(block) = harness
            .chain
            .block_at_slot(Slot::new(slot), WhenSlotSkipped::None)
            .unwrap()
        {
            let parent_state = harness
                .chain
                .state_at_slot(Slot::new(slot - 1), StateSkipConfig::WithoutStateRoots)
                .unwrap();

            let mut pre_state = BlockReplayer::<E, BlockReplayError, IntoIter<_, 0>>::new(
                parent_state,
                &harness.spec,
            )
            .no_signature_verification()
            .minimal_block_root_verification()
            .apply_blocks(vec![], Some(block.slot()))
            .unwrap()
            .into_state();

            let beacon_block_reward = harness
                .chain
                .compute_beacon_block_reward(block.message(), &mut pre_state)
                .unwrap();
            let total_proposer_reward = proposal_rewards_map
                .entry(beacon_block_reward.proposer_index)
                .or_insert(0);
            *total_proposer_reward += beacon_block_reward.total as i64;
        }
    }
    apply_other_rewards(&mut balances, &proposal_rewards_map);

    for epoch in 0..epochs.as_u64() {
        // compute reward deltas in epoch
        let total_rewards = harness
            .chain
            .compute_attestation_rewards(Epoch::new(epoch), validator_subset_ids.clone())
            .unwrap()
            .total_rewards;

        // apply attestation rewards to balances
        apply_attestation_rewards(&mut balances, total_rewards);
    }

    // verify expected balances against actual balances
    let actual_balances: Vec<u64> = harness.get_current_state().balances().to_vec();
    if validator_subset.is_empty() {
        assert_eq!(balances, actual_balances);
    } else {
        for validator in validator_subset {
            assert_eq!(
                balances[validator as usize],
                actual_balances[validator as usize]
            );
        }
    }
}

/// Apply a vec of `TotalAttestationRewards` to initial balances, and return
fn apply_attestation_rewards(
    balances: &mut [u64],
    attestation_rewards: Vec<TotalAttestationRewards>,
) {
    for rewards in attestation_rewards {
        let balance = balances.get_mut(rewards.validator_index as usize).unwrap();
        *balance = (*balance as i64
            + rewards.head
            + rewards.source
            + rewards.target
            + rewards.inclusion_delay.map(|q| q.value).unwrap_or(0) as i64
            + rewards.inactivity) as u64;
    }
}

fn apply_other_rewards(balances: &mut [u64], rewards_map: &HashMap<u64, i64>) {
    for (i, balance) in balances.iter_mut().enumerate() {
        *balance = balance.saturating_add_signed(*rewards_map.get(&(i as u64)).unwrap_or(&0));
    }
}

/// A block that packs attestations cast in a skipped slot, voting for a parent whose payload was
/// revealed, must be credited with the timely head flag those attestations earn.
///
/// The availability bit for the parent's slot is written by `process_parent_execution_payload` at
/// the start of block processing, so a pre-block state does not carry it and the head flag was
/// silently dropped from the reported reward. The oracle here is the state transition itself: the
/// reward API's job is to predict what `process_attestations` actually pays the proposer.
#[tokio::test]
async fn test_gloas_block_reward_credits_head_flag_across_skipped_slot() {
    let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let chain = &harness.chain;

    // Blocks at slots 1..=3, each with its payload envelope processed.
    harness
        .extend_chain(
            3,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    let head = chain.head_snapshot();
    assert_eq!(head.beacon_block.slot(), Slot::new(3));
    let block_3_root = head.beacon_block_root;
    let state_at_3 = head.beacon_state.clone();
    let state_at_3_root = head.beacon_state_root();
    drop(head);

    // Slot 4 is skipped. Attesting there votes for block 3 with `index == 1`, because block 3's
    // payload was revealed.
    harness.advance_slot();
    let validators: Vec<usize> = (0..VALIDATOR_COUNT).collect();
    let attestations = harness.make_attestations(
        &validators,
        &state_at_3,
        state_at_3_root,
        block_3_root.into(),
        Slot::new(4),
    );
    assert_eq!(
        attestations[0].0[0].0.data().index,
        1,
        "attestation to a full parent should signal payload present"
    );
    harness.process_attestations(attestations, &state_at_3);

    // Slot 5 proposes a block including them at inclusion delay 1.
    harness.advance_slot();
    let (block_contents, _envelope, _post_state) = harness
        .make_block_with_envelope(state_at_3.clone(), Slot::new(5))
        .await;
    let block = block_contents.0.clone();
    assert!(
        block
            .message()
            .body()
            .attestations()
            .any(|att| att.data().slot == Slot::new(4)),
        "block should pack the skipped-slot attestations"
    );

    // The pre-block state the reward API is handed.
    let mut pre_state = BlockReplayer::<E, BlockReplayError, IntoIter<_, 0>>::new(
        state_at_3.clone(),
        &harness.spec,
    )
    .no_signature_verification()
    .minimal_block_root_verification()
    .apply_blocks(vec![], Some(Slot::new(5)))
    .unwrap()
    .into_state();
    assert!(
        !pre_state
            .execution_payload_availability()
            .unwrap()
            .get(3)
            .unwrap(),
        "the parent's availability bit is not yet written on a pre-block state"
    );

    let reward = chain
        .compute_beacon_block_reward(block.message(), &mut pre_state)
        .unwrap();

    // The reward API must not disturb the caller's state: block production reuses it for
    // `per_block_processing`, which applies the parent payload itself.
    assert!(
        !pre_state
            .execution_payload_availability()
            .unwrap()
            .get(3)
            .unwrap(),
        "computing the reward must not mutate the caller's state"
    );

    // Oracle: what `process_attestations` actually pays the proposer.
    let mut stf_state = pre_state.clone();
    process_parent_execution_payload(&mut stf_state, block.message(), &harness.spec).unwrap();
    let parent_slot = Some(stf_state.latest_execution_payload_bid().unwrap().slot);
    let proposer = block.message().proposer_index() as usize;
    let balance_before = stf_state.balances().get(proposer).copied().unwrap();
    let mut ctxt = ConsensusContext::new(block.slot());
    process_operations::process_attestations(
        &mut stf_state,
        block.message().body(),
        VerifySignatures::False,
        parent_slot,
        &mut ctxt,
        &harness.spec,
    )
    .unwrap();
    let paid = stf_state.balances().get(proposer).copied().unwrap() - balance_before;

    assert_eq!(
        reward.attestations, paid,
        "reported attestation reward should match what block processing pays the proposer"
    );
}
