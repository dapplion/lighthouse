//! Store initialization for ERA import (not used in the production beacon node path).
//!
//! [`init_genesis_store`] sets up a store from genesis so that [`super::consumer::EraFileDir::import_all`]
//! can import ERA files and then [`crate::builder::BeaconChainBuilder::resume_from_db`] can boot
//! a chain from the result.

use crate::beacon_chain::{BEACON_CHAIN_DB_KEY, FORK_CHOICE_DB_KEY};
use crate::persisted_beacon_chain::PersistedBeaconChain;
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::{BeaconForkChoiceStore, BeaconSnapshot};
use fork_choice::ForkChoice;
use ssz::Encode;
use std::sync::Arc;
use store::{
    ColdStore, DBColumnCold, HotColdDB, ItemStore, StoreItem,
    hot_cold_store::{HotStateSummary, OptionalDiffBaseState},
};
use tracing::info;
use types::{BeaconBlock, BeaconState, ChainSpec, EthSpec, SignedBeaconBlock, Slot};

/// Initialize a store from genesis for ERA import.
///
/// Creates the genesis block, stores genesis state and block, and sets up initial store
/// metadata (split at genesis, anchor, fork choice, `PersistedBeaconChain`).
/// Call this before [`super::consumer::EraFileDir::import_all`].
pub fn init_genesis_store<E: EthSpec, Hot: ItemStore<E>, Cold: ColdStore<E>>(
    store: &Arc<HotColdDB<E, Hot, Cold>>,
    genesis_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), String> {
    let mut genesis_block = BeaconBlock::<E>::empty(spec);
    *genesis_block.state_root_mut() = genesis_state
        .update_tree_hash_cache()
        .map_err(|e| format!("failed to hash genesis state: {e:?}"))?;
    let signed_block = SignedBeaconBlock::from_block(genesis_block, bls::Signature::empty());
    let block_root = signed_block.canonical_root();
    let state_root = signed_block.message().state_root();

    // Store genesis state and block
    store
        .put_cold_state(&state_root, genesis_state)
        .map_err(|e| format!("failed to store genesis state: {e:?}"))?;
    // Genesis blinded block lands in the static cold archive at slot 0; no hot-DB write.
    let genesis_blinded_bytes = signed_block.clone_as_blinded().as_ssz_bytes();
    store
        .cold_db
        .put_batch(
            DBColumnCold::Block,
            vec![(Slot::new(0), genesis_blinded_bytes)],
        )
        .map_err(|e| format!("failed to store genesis block: {e:?}"))?;
    store
        .store_frozen_block_root_at_skip_slots(Slot::new(0), Slot::new(1), block_root)
        .and_then(|ops| store.cold_db.put_batch(DBColumnCold::BlockRoots, ops))
        .map_err(|e| format!("failed to store genesis block root: {e:?}"))?;

    // Set split at genesis
    store.set_split(Slot::new(0), state_root, block_root);

    // Initialize anchor
    let mut batch = vec![];
    batch.push(
        store
            .init_anchor_info(
                signed_block.parent_root(),
                Slot::new(0),
                Slot::new(0),
                false,
            )
            .map_err(|e| format!("failed to init anchor: {e:?}"))?,
    );
    batch.push(
        store
            .init_blob_info(Slot::new(0))
            .map_err(|e| format!("failed to init blob info: {e:?}"))?,
    );
    batch.push(
        store
            .init_data_column_info(Slot::new(0))
            .map_err(|e| format!("failed to init data column info: {e:?}"))?,
    );
    batch.push(store.store_split_in_batch());

    // Genesis HotStateSummary so the next-open path's `load_split` ->
    // `load_block_root_from_summary(genesis_state_root)` finds the block root.
    // Built directly (not via `HotStateSummary::new`, which calls
    // `hot_storage_strategy` and would error here because anchor info is being
    // initialized in this same batch). Genesis is a snapshot with no diff base
    // and no previous state.
    let genesis_summary = HotStateSummary {
        slot: Slot::new(0),
        latest_block_root: block_root,
        latest_block_slot: Slot::new(0),
        diff_base_state: OptionalDiffBaseState::Snapshot(0),
        previous_state_root: bls::FixedBytesExtended::zero(),
    };
    batch.push(genesis_summary.as_kv_store_op(state_root));

    // Fork choice from genesis
    let snapshot = BeaconSnapshot {
        beacon_block_root: block_root,
        beacon_block: Arc::new(signed_block),
        execution_envelope: None,
        beacon_state: genesis_state.clone(),
    };
    let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store.clone(), snapshot.clone())
        .map_err(|e| format!("failed to create fork choice store: {e:?}"))?;
    let fork_choice = ForkChoice::from_anchor(
        fc_store,
        block_root,
        &snapshot.beacon_block,
        &snapshot.beacon_state,
        None,
        spec,
    )
    .map_err(|e| format!("failed to create fork choice: {e:?}"))?;

    // Persist chain metadata
    batch.push(
        PersistedBeaconChain {
            genesis_block_root: block_root,
        }
        .as_kv_store_op(BEACON_CHAIN_DB_KEY),
    );
    let persisted_fork_choice = PersistedForkChoice {
        fork_choice: fork_choice.to_persisted(),
        fork_choice_store: fork_choice.fc_store().to_persisted(),
    };
    batch.push(
        persisted_fork_choice
            .as_kv_store_op(FORK_CHOICE_DB_KEY, store.get_config())
            .map_err(|e| format!("failed to persist fork choice: {e:?}"))?,
    );

    store
        .hot_db
        .do_atomically(batch)
        .map_err(|e| format!("failed to write genesis metadata: {e:?}"))?;

    info!("Initialized store from genesis for ERA import");
    Ok(())
}
