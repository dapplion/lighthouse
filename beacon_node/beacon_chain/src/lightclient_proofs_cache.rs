use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use parking_lot::{Mutex, RwLock};
use ssz::{Decode, Encode};
use ssz_types::FixedVector;
use std::sync::Arc;
use store::{DBColumn, Error as StoreError, StoreItem};
use types::light_client_bootstrap::LightClientBootstrap;
use types::light_client_update::{
    CurrentSyncCommitteeProofLen, FinalizedRootProofLen, LightClientUpdate,
    NextSyncCommitteeProofLen, CURRENT_SYNC_COMMITTEE_INDEX, FINALIZED_ROOT_INDEX,
    NEXT_SYNC_COMMITTEE_INDEX,
};
use types::{
    BeaconBlockHeader, BeaconBlockRef, BeaconState, ChainSpec, EthSpec, ForkName, Hash256,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, Slot, SyncAggregate, SyncCommittee,
};

/// This cache computes light client messages ahead of time, required to satisfy p2p and API
/// requests. These messages include proofs on historical states, so on-demand computation is
/// expensive.
///
/// ### `LightClientBootstrap`
///
/// Should support requests for all finalized checkpoint block roots up to
/// `MIN_EPOCHS_FOR_BLOCK_REQUESTS`. Message includes:
///
/// - `header`: already stored by root for the required range
/// - `current_sync_committee`: eagerly persisted when each sync period finalizes
/// - `current_sync_committee_branch`: eagerly persisted after block processing for checkpoint
///    blocks only. Current version does not prune, as a trade-off for simplicity. Each re-org through
///    an epoch boundary will add ~200 bytes of non-prunable data to the DB.
///    TODO: extend store prune routine to add delete ops for checkpoint roots.
///
/// ### `LightClientUpdate`
///
/// Should support requests for all periods within `MIN_EPOCHS_FOR_BLOCK_REQUESTS` for a subjective
/// best update. Message includes multiple headers and proofs.
///
///
pub struct LightclientServerCache<T: BeaconChainTypes> {
    latest_finality_update: RwLock<Option<LightClientFinalityUpdate<T::EthSpec>>>,
    latest_optimistic_update: RwLock<Option<LightClientOptimisticUpdate<T::EthSpec>>>,
    finality_update_cache: Mutex<lru::LruCache<Hash256, LightclientCachedData<T::EthSpec>>>,
}

impl<T: BeaconChainTypes> LightclientServerCache<T> {
    pub fn new() -> Self {
        Self {
            latest_finality_update: None.into(),
            latest_optimistic_update: None.into(),
            finality_update_cache: lru::LruCache::new(100).into(),
        }
    }

    /// Compute and cache state proofs for latter production of light-client messages. Does not
    /// trigger block replay. May result in multiple DB write ops.
    /// TODO: Should return StoreOps to batch with rest of db operations?
    pub fn cache_state_data(
        &self,
        store: BeaconStore<T>,
        spec: &ChainSpec,
        block: BeaconBlockRef<T::EthSpec>,
        block_root: Hash256,
        block_post_state: &mut BeaconState<T::EthSpec>,
        parent_block_slot: Slot,
    ) -> Result<(), BeaconChainError> {
        // Only post-altair
        if spec.fork_name_at_slot::<T::EthSpec>(block.slot()) == ForkName::Base {
            return Ok(());
        }

        // Persist in memory cache for a descendent block

        let cached_data = LightclientCachedData::from_state(block_post_state)?;
        self.finality_update_cache
            .lock()
            .put(block_root, cached_data);

        // Persist current_sync_committee_branch for checkpoint blocks only

        // block in first slot of epoch, is always a checkpoint
        if is_first_slot_in_epoch::<T::EthSpec>(block.slot()) {
            let current_sync_committee_branch =
                block_post_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;
            store.put_sync_committee_branch(&block_root, &current_sync_committee_branch)?;
        }

        // This statement may be moved into
        if parent_is_checkpoint::<T::EthSpec>(parent_block_slot, block.slot()) {
            // TODO: should compute finality data for parent if missing?
            if let Some(data) = self.finality_update_cache.lock().get(&block.parent_root()) {
                store.put_sync_committee_branch(
                    &block.parent_root(),
                    &data.current_sync_committee_branch,
                )?;
            }
        }

        // Persist finalized sync committees by period

        let state_period = block_post_state
            .slot()
            .epoch(T::EthSpec::slots_per_epoch())
            .sync_committee_period(spec)?;
        let finalized_period = block_post_state
            .finalized_checkpoint()
            .epoch
            .sync_committee_period(spec)?;

        // If the current state period is finalized, persist the next sync committee
        if finalized_period >= state_period {
            store.put_sync_committee(state_period + 1, block_post_state.next_sync_committee()?)?;
        }

        // if the previous state period is finalized, persist the current sync committee
        if finalized_period >= state_period - 1 {
            store.put_sync_committee(state_period, block_post_state.current_sync_committee()?)?;
        }

        Ok(())
    }

    /// Given a block with a SyncAggregte computes better or more recent light client updates. The
    /// results are cached either on disk or memory to be served via p2p and rest API
    pub fn recompute_and_cache_updates(
        &self,
        store: BeaconStore<T>,
        chain_spec: &ChainSpec,
        block_parent_root: &Hash256,
        block_slot: Slot,
        block_sync_aggregate: &SyncAggregate<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let attested_block_root = block_parent_root;
        let attested_block = store.get_blinded_block(&attested_block_root)?.ok_or(
            BeaconChainError::DBInconsistent(format!(
                "Block not found in DB {:?}",
                attested_block_root
            )),
        )?;

        let cached_parts = self.get_or_compute_prev_block_cache(
            store.clone(),
            &attested_block_root,
            &attested_block.state_root(),
            attested_block.slot(),
        )?;

        let attested_slot = attested_block.slot();
        let signature_slot = block_slot;

        // Spec: Full nodes SHOULD provide the LightClientOptimisticUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        let is_latest_optimistic = match &self.latest_optimistic_update.read().clone() {
            Some(latest_optimistic_update) => is_latest_optimistic_update(
                &latest_optimistic_update,
                attested_slot,
                signature_slot,
            ),
            None => true,
        };
        if is_latest_optimistic {
            // can create an optimistic update, that is more recent
            *self.latest_optimistic_update.write() = Some(LightClientOptimisticUpdate {
                attested_header: block_to_light_client_header(attested_block.message()),
                sync_aggregate: block_sync_aggregate.clone(),
                signature_slot,
            });
        };

        // Spec: Full nodes SHOULD provide the LightClientFinalityUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        let is_latest_finality = match &self.latest_finality_update.read().clone() {
            Some(latest_finality_update) => {
                is_latest_finality_update(&latest_finality_update, attested_slot, signature_slot)
            }
            None => true,
        };
        if is_latest_finality {
            // Can this error naturally immediately after checkpoint sync? If the finalized
            // checkpoint in the head state points to a block not yet fetched by backfill sync.
            let finalized_block = store
                .get_blinded_block(&cached_parts.finalized_block_root)?
                .ok_or(BeaconChainError::DBInconsistent(format!(
                    "Block not found in DB {:?}",
                    cached_parts.finalized_block_root
                )))?;

            *self.latest_finality_update.write() = Some(LightClientFinalityUpdate {
                attested_header: block_to_light_client_header(attested_block.message()),
                finalized_header: block_to_light_client_header(finalized_block.message()),
                finality_branch: cached_parts.finality_branch.clone(),
                sync_aggregate: block_sync_aggregate.clone(),
                signature_slot,
            });
        }

        // Spec: Full nodes SHOULD provide the best derivable LightClientUpdate (according to is_better_update)
        // for each sync committee period
        let period = signature_slot
            .epoch(T::EthSpec::slots_per_epoch())
            .sync_committee_period(chain_spec)?;

        let is_better = match store.get_lightclient_update(period)? {
            Some(current_best_update) => is_better_update::<T::EthSpec>(
                LightClientUpdateSummary::from_update(&current_best_update),
                LightClientUpdateSummary::from_cached_data(
                    &cached_parts,
                    block_slot,
                    block_sync_aggregate,
                )?,
            ),
            None => true,
        };
        if is_better {
            let finalized_block = store
                .get_blinded_block(&cached_parts.finalized_block_root)?
                .ok_or(BeaconChainError::DBInconsistent(format!(
                    "Block not found in DB {:?}",
                    cached_parts.finalized_block_root
                )))?;

            let update = LightClientUpdate {
                attested_header: block_to_light_client_header(attested_block.message()),
                next_sync_committee: cached_parts.next_sync_committee.clone(),
                next_sync_committee_branch: cached_parts.next_sync_committee_branch.clone(),
                finalized_header: block_to_light_client_header(finalized_block.message()),
                finality_branch: cached_parts.finality_branch.clone(),
                sync_aggregate: block_sync_aggregate.clone(),
                signature_slot,
            };
            store.put_light_client_update(update)?;
        }

        Ok(())
    }

    /// Retrieves prev block cached data from cache. If not present re-computes by retrieving the
    /// parent state, and inserts an entry to the cache.
    ///
    /// In separate function since FnOnce of get_or_insert can not be fallible.
    fn get_or_compute_prev_block_cache(
        &self,
        store: BeaconStore<T>,
        block_root: &Hash256,
        block_state_root: &Hash256,
        block_slot: Slot,
    ) -> Result<LightclientCachedData<T::EthSpec>, BeaconChainError> {
        // Attempt to get the value from the cache first.
        if let Some(cached_parts) = self.finality_update_cache.lock().get(block_root) {
            return Ok(cached_parts.clone());
        }

        // Compute the value, handling potential errors.
        let mut state = store
            .get_state(block_state_root, Some(block_slot))?
            .ok_or_else(|| {
                BeaconChainError::DBInconsistent(format!("Missing state {:?}", block_state_root))
            })?;
        let new_value = LightclientCachedData::from_state(&mut state)?;

        // Insert value and return owned
        self.finality_update_cache
            .lock()
            .put(*block_root, new_value.clone());
        Ok(new_value)
    }

    /// Produce a `LightclientBootstrap` from cached branches to prevent reading a full state.
    /// Fallbacks to generating from historical states.
    pub fn produce_bootstrap(
        &self,
        store: BeaconStore<T>,
        chain_spec: &ChainSpec,
        block_root: Hash256,
    ) -> Result<Option<LightClientBootstrap<T::EthSpec>>, BeaconChainError> {
        if let Some(block) = store.get_block_any_variant(&block_root)? {
            let period = block.message().epoch().sync_committee_period(chain_spec)?;

            // TODO: Can re-use the persisted best update to recover the sync committee by period
            if let (Some(current_sync_committee_branch), Some(current_sync_committee)) = (
                store.get_sync_committee_branch(&block_root)?,
                store.get_sync_committee(period)?,
            ) {
                Ok(Some(LightClientBootstrap {
                    header: block_to_light_client_header(block.message()),
                    current_sync_committee: current_sync_committee.into(),
                    current_sync_committee_branch: current_sync_committee_branch.into(),
                }))
            } else {
                // TODO: Must be aware of what data is meant to be aailable, or put behind flag due to
                // it being more expensive, something ala --lc-archive
                // store.get_state() will replay if necessary
                let mut state = store
                    .get_state(&block.message().state_root(), Some(block.message().slot()))?
                    .ok_or_else(|| {
                        BeaconChainError::DBInconsistent(format!(
                            "Missing state {:?}",
                            block.message().state_root()
                        ))
                    })?;

                Ok(Some(LightClientBootstrap {
                    header: block_to_light_client_header(block.message()),
                    current_sync_committee: state.current_sync_committee()?.clone(),
                    current_sync_committee_branch: state
                        .compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?
                        .into(),
                }))
            }
        } else {
            Ok(None)
        }
    }

    /// Produce a `LightclientUpdate` with cached parts
    pub fn produce_update(
        &self,
        store: BeaconStore<T>,
        period: u64,
    ) -> Result<LightClientUpdate<T::EthSpec>, BeaconChainError> {
        // TODO: retrieve update from DB, if very recent return from in-memory cache
        // Should implement fallback to state regen? Once cached for period N, result can be re-used
        // forever. Max work is bounded
        Ok(store
            .get_lightclient_update(period)?
            .expect("TODO produce as fallback"))
    }

    pub fn get_latest_finality_update(&self) -> Option<LightClientFinalityUpdate<T::EthSpec>> {
        self.latest_finality_update.read().clone()
    }

    pub fn get_latest_optimistic_update(&self) -> Option<LightClientOptimisticUpdate<T::EthSpec>> {
        self.latest_optimistic_update.read().clone()
    }
}

#[derive(Clone)]
struct LightclientCachedData<T: EthSpec> {
    slot: Slot,
    finality_branch: FinalityBranch,
    finalized_block_root: Hash256,
    finalized_slot: Slot,
    current_sync_committee_branch: CurrentSyncCommitteeBranch,
    next_sync_committee_branch: NextSyncCommitteeBranch,
    next_sync_committee: Arc<SyncCommittee<T>>,
}

impl<T: EthSpec> LightclientCachedData<T> {
    fn from_state(state: &mut BeaconState<T>) -> Result<Self, BeaconChainError> {
        Ok(Self {
            slot: state.slot(),
            finality_branch: state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?.into(),
            finalized_block_root: state.finalized_checkpoint().root,
            finalized_slot: state
                .finalized_checkpoint()
                .epoch
                .start_slot(T::slots_per_epoch()),
            current_sync_committee_branch: state
                .compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?
                .into(),
            next_sync_committee_branch: state
                .compute_merkle_proof(NEXT_SYNC_COMMITTEE_INDEX)?
                .into(),
            next_sync_committee: state.next_sync_committee()?.clone(),
        })
    }
}

fn is_first_slot_in_epoch<T: EthSpec>(slot: Slot) -> bool {
    slot % T::slots_per_epoch() == 0
}

fn parent_is_checkpoint<T: EthSpec>(parent_slot: Slot, block_slot: Slot) -> bool {
    let block_epoch = block_slot.epoch(T::slots_per_epoch());
    let parent_epoch = parent_slot.epoch(T::slots_per_epoch());
    return (!is_first_slot_in_epoch::<T>(block_slot) && parent_epoch < block_epoch)
        || parent_epoch < block_epoch - 1;
}

fn is_latest_finality_update<T: EthSpec>(
    prev: &LightClientFinalityUpdate<T>,
    attested_slot: Slot,
    signature_slot: Slot,
) -> bool {
    if attested_slot > prev.attested_header.slot {
        true
    } else if attested_slot == prev.attested_header.slot && signature_slot > prev.signature_slot {
        true
    } else {
        false
    }
}

fn is_latest_optimistic_update<T: EthSpec>(
    prev: &LightClientOptimisticUpdate<T>,
    attested_slot: Slot,
    signature_slot: Slot,
) -> bool {
    if attested_slot > prev.attested_header.slot {
        true
    } else if attested_slot == prev.attested_header.slot && signature_slot > prev.signature_slot {
        true
    } else {
        false
    }
}

struct LightClientUpdateSummary {
    participants: usize,
    attested_slot: Slot,
    finalized_header_slot: Slot,
    signature_slot: Slot,
}

impl LightClientUpdateSummary {
    fn from_update<T: EthSpec>(update: &LightClientUpdate<T>) -> Self {
        Self {
            participants: update.sync_aggregate.num_set_bits().count_ones() as usize,
            attested_slot: update.attested_header.slot,
            finalized_header_slot: update.finalized_header.slot,
            signature_slot: update.signature_slot,
        }
    }

    fn from_cached_data<T: EthSpec>(
        cached_data: &LightclientCachedData<T>,
        block_slot: Slot,
        block_sync_aggregate: &SyncAggregate<T>,
    ) -> Result<Self, BeaconChainError> {
        Ok(Self {
            participants: block_sync_aggregate.num_set_bits().count_ones() as usize,
            attested_slot: cached_data.slot,
            finalized_header_slot: cached_data.finalized_slot,
            signature_slot: block_slot,
        })
    }
}

fn is_better_update<T: EthSpec>(
    _a: LightClientUpdateSummary,
    _b: LightClientUpdateSummary,
) -> bool {
    todo!();
}

fn block_to_light_client_header<T: EthSpec>(
    block: BeaconBlockRef<T, types::BlindedPayload<T>>,
) -> BeaconBlockHeader {
    // TODO: make fork aware
    block.block_header()
}

type CurrentSyncCommitteeBranch = FixedVector<Hash256, CurrentSyncCommitteeProofLen>;
type NextSyncCommitteeBranch = FixedVector<Hash256, NextSyncCommitteeProofLen>;
type FinalityBranch = FixedVector<Hash256, FinalizedRootProofLen>;

struct DatabaseCurrentSyncCommitteeBranch(CurrentSyncCommitteeBranch);

impl StoreItem for DatabaseCurrentSyncCommitteeBranch {
    fn db_column() -> DBColumn {
        DBColumn::LightClientCurrentSyncCommitteeBranch
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self(CurrentSyncCommitteeBranch::from_ssz_bytes(bytes)?))
    }
}

struct DatabaseNextSyncCommitteeBranch(NextSyncCommitteeBranch);

impl StoreItem for DatabaseNextSyncCommitteeBranch {
    fn db_column() -> DBColumn {
        DBColumn::LightClientNextSyncCommitteeBranch
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self(NextSyncCommitteeBranch::from_ssz_bytes(bytes)?))
    }
}

struct DatabaseFinalityBranch(FinalityBranch);

impl StoreItem for DatabaseFinalityBranch {
    fn db_column() -> DBColumn {
        DBColumn::LightClientFinalityBranch
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self(FinalityBranch::from_ssz_bytes(bytes)?))
    }
}