//! Profile MemoryTracker::track_item on a mainnet-scale state.
//! Run with: cargo flamegraph -p store --example profile_memory_tracker

use fixed_bytes::FixedBytesExtended;
use milhouse::mem::MemoryTracker;
use milhouse::{List, Vector};
use ssz_types::BitVector;
use std::sync::Arc;
use types::state::*;
use types::*;

type E = MainnetEthSpec;

fn make_state(n: usize) -> BeaconState<E> {
    let validator = Validator {
        pubkey: bls::PublicKeyBytes::empty(),
        withdrawal_credentials: Hash256::ZERO,
        effective_balance: 32_000_000_000,
        slashed: false,
        activation_eligibility_epoch: Epoch::new(0),
        activation_epoch: Epoch::new(0),
        exit_epoch: Epoch::new(u64::MAX),
        withdrawable_epoch: Epoch::new(u64::MAX),
    };
    let validators = List::new(vec![validator; n]).unwrap();
    let balances = List::new(vec![32_000_000_000u64; n]).unwrap();
    let inactivity_scores = List::new(vec![0u64; n]).unwrap();
    let participation = List::new(vec![ParticipationFlags::default(); n]).unwrap();
    let default_cc = Arc::new(CommitteeCache::default());
    let sync = Arc::new(SyncCommittee::temporary());

    BeaconState::Altair(BeaconStateAltair {
        genesis_time: 0,
        genesis_validators_root: Hash256::ZERO,
        slot: Slot::new(0),
        fork: Fork::default(),
        latest_block_header: BeaconBlockHeader::empty(),
        block_roots: Vector::default(),
        state_roots: Vector::default(),
        historical_roots: List::default(),
        eth1_data: Eth1Data::default(),
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators,
        balances,
        randao_mixes: Vector::default(),
        slashings: Vector::default(),
        previous_epoch_participation: participation.clone(),
        current_epoch_participation: participation,
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: Checkpoint::default(),
        current_justified_checkpoint: Checkpoint::default(),
        finalized_checkpoint: Checkpoint::default(),
        inactivity_scores,
        current_sync_committee: sync.clone(),
        next_sync_committee: sync,
        total_active_balance: None,
        progressive_balances_cache: ProgressiveBalancesCache::default(),
        committee_caches: [default_cc.clone(), default_cc.clone(), default_cc],
        pubkey_cache: PubkeyCache::default(),
        exit_cache: ExitCache::default(),
        slashings_cache: SlashingsCache::default(),
        epoch_cache: EpochCache::default(),
        approx_owned_bytes: ApproxOwnedBytesList::default(),
    })
}

fn main() {
    let n = 1_000_000;
    eprintln!("Building state with {n} validators...");
    let state = make_state(n);
    eprintln!("State built. Starting profiling loop...");

    // Run 5 iterations to get a good profile.
    for i in 0..5 {
        let mut tracker = MemoryTracker::default();
        let stats = tracker.track_item(&state);
        eprintln!(
            "iter {i}: total_size = {} MB",
            stats.total_size / (1024 * 1024)
        );
    }

    eprintln!("Done.");
}
