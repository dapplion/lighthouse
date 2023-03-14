#![cfg(not(debug_assertions))] // Tests run too slow in debug.

use beacon_chain::test_utils::BeaconChainHarness;
use types::*;

// Progress:
// - [x] Can produce and validate blocks
// - [ ] Validate is correct proposer on gossip + ReqResp paths
//
// Blockers
// - This tests run with mainnet preset so WHISK_CANDIDATE_TRACKERS_COUNT = 16000
//   but VALIDATOR_COUNT = 32 so there are many repetitions in the selected trackers
//   If a validator first and second proposal are in the same whisk round, it will
//   not be able to produce a valid opening proof since the tracker and commitment in
//   the state are computed with different k values.

const VALIDATOR_COUNT: usize = 32;
type E = MainnetEthSpec;
// type E = MinimalEthSpec;

#[tokio::test]
async fn whisk_few_epochs() {
    let altair_fork_epoch = Epoch::new(0);
    let bellatrix_fork_epoch = Epoch::new(0);
    let capella_fork_epoch = Epoch::new(0);
    let stop_at_slot = Epoch::new(10).start_slot(E::slots_per_epoch());

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
    spec.capella_fork_epoch = Some(capella_fork_epoch);

    println!("building harness");

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec)
        .logger(logging::test_logger())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    println!("built harness");

    /*
     * Start with the base fork.
     */
    assert!(harness
        .chain
        .head_snapshot()
        .beacon_block
        .as_capella()
        .is_ok());

    // Progress into whisk
    for _ in 0..stop_at_slot.as_usize() {
        harness.extend_slots(1).await;
        let block = &harness.chain.head_snapshot().beacon_block;
        let full_payload: FullPayload<E> = block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .clone()
            .into();

        // post-capella should have withdrawals
        assert!(full_payload.withdrawals_root().is_ok());

        // post-whisk should have trackers
        assert!(
            block.message().body().whisk_k_commitment().is_ok(),
            "block {} has no whisk_k_commitment",
            block.message().slot()
        );
    }
}
