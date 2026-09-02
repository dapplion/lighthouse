#![cfg(not(debug_assertions))]

//! Tests for the Fast Confirmation Rule as it runs inside `recompute_head`.
//!
//! The interesting property here is recovery. Once FCR falls back to the finalized block, the
//! `get_block_epoch(confirmed_root) + 1 >= current_epoch` guard that gates
//! `find_latest_confirmed_descendant` can never be satisfied from the finalized root, because the
//! finalized checkpoint trails the current epoch by at least two epochs. The only way back is the
//! restart-from-observed-justified branch, which runs at the first slot of an epoch. See
//! sigp/lighthouse#9664.

use beacon_chain::{
    ChainConfig, WhenSlotSkipped,
    chain_config::FastConfirmationMode,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, test_spec,
    },
};
use std::sync::Arc;
use types::{Epoch, EthSpec, Hash256, MinimalEthSpec, Slot};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<EphemeralHarnessType<E>>;

const VALIDATOR_COUNT: usize = 64;

/// Epochs of full participation before a test starts poking at FCR. Enough to reach FFG steady
/// state (justified == epoch - 1, finalized == epoch - 2) with room for a stale confirmed root.
const WARMUP_EPOCHS: u64 = 4;

fn build_harness() -> Harness {
    BeaconChainHarness::builder(E::default())
        .spec(Arc::new(test_spec::<E>()))
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .chain_config(ChainConfig {
            fast_confirmation: FastConfirmationMode::Enabled,
            // The mock EL produces synthetic execution block hashes, which cannot survive a real
            // RLP block hash recompute.
            verify_envelope_payload_hash_in_backfill: false,
            ..ChainConfig::default()
        })
        .build()
}

fn confirmed_root(harness: &Harness) -> Hash256 {
    harness
        .chain
        .canonical_head
        .fast_confirmation
        .as_ref()
        .expect("FCR is enabled")
        .lock()
        .confirmed_root
}

fn set_confirmed_root(harness: &Harness, root: Hash256) {
    harness
        .chain
        .canonical_head
        .fast_confirmation
        .as_ref()
        .expect("FCR is enabled")
        .lock()
        .confirmed_root = root;
}

fn block_slot(harness: &Harness, root: Hash256) -> Slot {
    harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&root)
        .unwrap_or_else(|| panic!("{root:?} should be in fork choice"))
        .slot
}

/// Build a chain with full participation up to the end of `WARMUP_EPOCHS`.
async fn warmed_up_harness() -> Harness {
    let harness = build_harness();
    harness.advance_slot();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize * WARMUP_EPOCHS as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    harness
}

/// On a chain with full participation the confirmed root tracks the head within a couple of slots,
/// which is the whole point of FCR: a `safe_block_hash` far ahead of the justified block.
#[tokio::test]
async fn confirms_close_to_the_head_on_a_healthy_chain() {
    let harness = warmed_up_harness().await;

    let head_slot = block_slot(&harness, harness.head_block_root());
    let confirmed_slot = block_slot(&harness, confirmed_root(&harness));
    let justified_slot = block_slot(&harness, harness.justified_checkpoint().root);

    assert!(
        confirmed_slot > justified_slot,
        "confirmed block {confirmed_slot} should be ahead of the justified block {justified_slot}"
    );
    assert!(
        head_slot - confirmed_slot <= 2,
        "confirmed block {confirmed_slot} should be within 2 slots of the head {head_slot}"
    );
}

/// A confirmed root older than the previous epoch makes `get_latest_confirmed` fall back to the
/// finalized block, and the fallback is sticky for the rest of the epoch: the finalized block is
/// always at least two epochs old, so `find_latest_confirmed_descendant` is never reached.
/// Recovery happens at the next epoch boundary, via the restart from the current epoch observed
/// justified checkpoint.
#[tokio::test]
async fn falls_back_to_finalized_then_restarts_from_observed_justified() {
    let harness = warmed_up_harness().await;

    // A block from the first warm-up epoch: old enough to trip the `epoch_too_old` fallback, and
    // still canonical, so this is a fallback and not a reorg.
    let stale_root = harness
        .chain
        .block_root_at_slot(
            Epoch::new(1).start_slot(E::slots_per_epoch()),
            WhenSlotSkipped::Prev,
        )
        .expect("chain is readable")
        .expect("epoch 1 has a block");
    set_confirmed_root(&harness, stale_root);

    // Mid-epoch: FCR falls back to finalized and cannot advance from there.
    let mid_epoch_slot = harness.get_current_slot() + 1;
    assert!(
        !mid_epoch_slot.as_u64().is_multiple_of(E::slots_per_epoch()),
        "the fallback must be observed away from an epoch boundary"
    );
    harness.extend_to_slot(mid_epoch_slot).await;

    let finalized_root = harness.finalized_checkpoint().root;
    assert_eq!(
        confirmed_root(&harness),
        finalized_root,
        "a confirmed root older than the previous epoch falls back to finalized"
    );
    // Read the slot now: finalization advances over the epoch boundary below, and proto array
    // prunes the block FCR fell back to.
    let fallback_slot = block_slot(&harness, finalized_root);

    // Still stuck at finalized on the following mid-epoch slot: the advance guard rejects a
    // confirmed root that is two epochs behind.
    harness.extend_to_slot(mid_epoch_slot + 1).await;
    assert_eq!(
        confirmed_root(&harness),
        finalized_root,
        "the fallback is sticky until the next epoch boundary"
    );

    // First slot of the next epoch: the restart branch moves the confirmed root up to the observed
    // justified checkpoint, from where it can advance again.
    let epoch_start = (harness.get_current_slot().epoch(E::slots_per_epoch()) + 1)
        .start_slot(E::slots_per_epoch());
    harness.extend_to_slot(epoch_start).await;

    let recovered_root = confirmed_root(&harness);
    assert_ne!(
        recovered_root,
        harness.finalized_checkpoint().root,
        "FCR should have restarted from the observed justified checkpoint"
    );
    assert!(
        block_slot(&harness, recovered_root) > fallback_slot,
        "the recovered confirmed root should be ahead of the block FCR fell back to"
    );
}
