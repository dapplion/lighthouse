use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use ssz::{Decode, Encode};
use ssz_types::FixedVector;
use store::{DBColumn, Error as StoreError, StoreItem, StoreOp};
use types::light_client_bootstrap::LightClientBootstrap;
use types::light_client_update::{
    CurrentSyncCommitteeProofLen, FinalizedRootProofLen, LightClientUpdate,
    NextSyncCommitteeProofLen, CURRENT_SYNC_COMMITTEE_INDEX, FINALIZED_ROOT_INDEX,
    NEXT_SYNC_COMMITTEE_INDEX,
};
use types::{
    BeaconBlockHeader, BeaconBlockRef, BeaconState, ChainSpec, EthSpec, Hash256,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, PublicKeyBytes, Slot, SyncCommittee,
};

struct FinalityUpdateParts {
    finality_branch: FinalityBranch,
    finalized_block_root: Hash256,
    finalized_slot: Slot,
}

pub type LightclientBlockUpdates<T: EthSpec> = (
    Option<LightClientOptimisticUpdate<T>>,
    Option<LightClientFinalityUpdate<T>>,
);

///
/// This cache exists for two reasons:
///
/// 1. To avoid reading a `BeaconState` from disk each time we need a public key.
/// 2. To reduce the amount of public key _decompression_ required. A `BeaconState` stores public
///    keys in compressed form and they are needed in decompressed form for signature verification.
///    Decompression is expensive when many keys are involved.
///
/// This cache allows to produce lightclient messages in most cases without reading a `BeaconState`
/// from disk.
///
/// ### `LightClientBootstrap`
///
/// requested via ReqResp on historical checkpoint blocks. Needs:
///
/// - current sync committee branch: eagerly persisted after every block. Pruned on finalization.
/// - current sync committee: TODO
///
/// ### `LightClientUpdate`
///
/// requested via ReqResp, on historical sync periods, one best update per period. Needs:
///
/// - TODO
///
pub struct LightclientServerCache<T: BeaconChainTypes> {
    latest_finality_update: Option<LightClientFinalityUpdate<T::EthSpec>>,
    latest_optimistic_update: Option<LightClientOptimisticUpdate<T::EthSpec>>,
    current_best_update: Option<LightClientUpdate<T::EthSpec>>,
    finality_update_cache: lru::LruCache<Hash256, FinalityUpdateParts>,
}

impl<T: BeaconChainTypes> LightclientServerCache<T> {
    pub fn new() -> Self {
        Self {
            latest_finality_update: None,
            latest_optimistic_update: None,
            current_best_update: None,
            finality_update_cache: lru::LruCache::default(),
        }
    }

    /// Adds zero or more validators to `self`.
    pub fn import_block<I>(
        &mut self,
        block_root: Hash256,
        block_post_state: &BeaconState<T::EthSpec>,
    ) -> Result<Vec<StoreOp<'static, T::EthSpec>>, BeaconChainError>
    where
        I: Iterator<Item = PublicKeyBytes> + ExactSizeIterator,
    {
        let current_sync_committee_branch =
            block_post_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;
        let next_sync_committee_branch =
            block_post_state.compute_merkle_proof(NEXT_SYNC_COMMITTEE_INDEX)?;
        let finality_branch = block_post_state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?;

        let store_ops = vec![];

        store_ops.push(StoreOp::KeyValueOp(
            DatabaseCurrentSyncCommitteeBranch(current_sync_committee_branch)
                .as_kv_store_op(block_root),
        ));

        // TODO: persist next_sync_committee once it's finalized

        self.finality_update_cache.put(
            block_root,
            FinalityUpdateParts {
                finality_branch: finality_branch.into(),
                finalized_block_root: block_post_state.finalized_checkpoint().root,
            },
        );

        Ok(store_ops)
    }

    pub fn produce_latest_updates_on_block(
        &self,
        store: BeaconStore<T>,
        block: BeaconBlockRef<T::EthSpec>,
    ) -> Result<LightclientBlockUpdates<T::EthSpec>, Error> {
        let attested_block = store
            .get_blinded_block(&block.parent_root())?
            .expect("TODO: handle missing block");

        let cached_parts = match self.finality_update_cache.get(&block.parent_root()) {
            Some(cached_parts) => *cached_parts,
            None => {
                let mut state = store
                    .get_state(&attested_block.state_root(), Some(attested_block.slot()))?
                    .expect("TODO: no state");
                let finality_branch = state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?;
                // TODO: cache this parts?
                FinalityUpdateParts {
                    finality_branch: finality_branch.into(),
                    finalized_block_root: state.finalized_checkpoint().root,
                    finalized_slot: state
                        .finalized_checkpoint()
                        .epoch
                        .start_slot(T::EthSpec::slots_per_epoch()),
                }
            }
        };

        let attested_slot = attested_block.slot();
        let signature_slot = block.slot();

        // Spec: Full nodes SHOULD provide the LightClientOptimisticUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        if is_latest_optimistic_update(self.latest_optimistic_update, attested_slot, signature_slot)
        {
            // can create an optimistic update, that is more recent
            self.latest_optimistic_update = LightClientOptimisticUpdate {
                attested_header: block_to_light_client_header(attested_block),
                sync_aggregate: block.body().sync_aggregate()?.clone(),
                signature_slot: block.slot(),
            };
        };

        // Spec: Full nodes SHOULD provide the LightClientFinalityUpdate with the highest
        // attested_header.beacon.slot (if multiple, highest signature_slot) as selected by fork choice
        if is_latest_finality_update(self.latest_finality_update, attested_slot, signature_slot) {
            let finalized_block = store
                .get_full_block(&cached_parts.finalized_block_root)?
                .expect("TODO: handle missing finalized block");

            self.latest_finality_update = Some(LightClientFinalityUpdate {
                attested_header: block_to_light_client_header(attested_block.message()),
                finalized_header: block_to_light_client_header(finalized_block.message()),
                finality_branch: cached_parts.finality_branch,
                sync_aggregate: block.body().sync_aggregate()?.clone(),
                signature_slot: block.slot(),
            });
        }

        // Spec: Full nodes SHOULD provide the best derivable LightClientUpdate (according to is_better_update)
        // for each sync committee period
        if is_better_update(self.current_best_update, update) {
            store.put_item(key, update)
        }
    }

    /// Produce a `LightclientBootstrap` from cached branches to prevent reading a full state.
    /// Fallbacks to generating from historical states.
    pub fn produce_bootstrap(
        &self,
        store: BeaconStore<T>,
        chain_spec: &ChainSpec,
        block_root: Hash256,
    ) -> Result<LightClientBootstrap<T::EthSpec>, Error> {
        let block = store
            .get_block_any_variant(&block_root)?
            .expect("TODO block not found");
        let period = block.message().epoch().sync_committee_period(chain_spec)?;

        if let (Some(current_sync_committee_branch), Some(update)) = (
            store.get_item(DatabaseCurrentSyncCommitteeBranch::key(block_root)),
            store.get_lightclient_update(period - 1)?,
        ) {
            Ok(LightClientBootstrap {
                header: block_to_light_client_header(block),
                current_sync_committee: update.next_sync_committee,
                current_sync_committee_branch,
            })
        } else {
            // store.get_state() will replay if necessary
            let state = store
                .get_state(&block.message().state_root(), Some(block.message().slot()))?
                .expect("TODO: regen state");
            Ok(LightClientBootstrap {
                header: block_to_light_client_header(block.message()),
                current_sync_committee: state.current_sync_committee()?.clone(),
                current_sync_committee_branch: state
                    .compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?
                    .into(),
            })
        }
    }

    /// Called with fork-choice finalizes a new checkpoint.
    /// Flushes updates to disk and persist the best update
    pub fn on_finalized() {}
    /// current_sync
    /// next_sync    <----

    /// Produce a `LightclientUpdate` with cached parts
    pub fn produce_update(
        &self,
        store: BeaconStore<T>,
        period: u64,
    ) -> Result<LightClientUpdate<T::EthSpec>, Error> {
        // TODO: retrieve update from DB, if very recent return from in-memory cache
        // Should implement fallback to state regen? Once cached for period N, result can be re-used
        // forever. Max work is bounded
        store.get_lightclient_update(period)
    }

    pub fn get_latest_finality_update(&self) -> &Option<LightClientFinalityUpdate<T::EthSpec>> {
        &self.latest_finality_update
    }

    pub fn get_latest_optimistic_update(&self) -> &Option<LightClientOptimisticUpdate<T::EthSpec>> {
        &self.latest_optimistic_update
    }
}

fn is_latest_finality_update<T: EthSpec>(
    prev: LightClientFinalityUpdate<T>,
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
    prev: LightClientOptimisticUpdate<T>,
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

fn block_to_light_client_header<T: EthSpec>(block: BeaconBlockRef<T>) -> BeaconBlockHeader {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use logging::test_logger;
    use std::sync::Arc;
    use store::HotColdDB;
    use types::{BeaconState, EthSpec, Keypair, MainnetEthSpec};

    type E = MainnetEthSpec;
    type T = EphemeralHarnessType<E>;

    fn get_state(validator_count: usize) -> (BeaconState<E>, Vec<Keypair>) {
        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .default_spec()
            .deterministic_keypairs(validator_count)
            .fresh_ephemeral_store()
            .build();

        harness.advance_slot();

        (harness.get_current_state(), harness.validator_keypairs)
    }

    fn get_store() -> BeaconStore<T> {
        Arc::new(
            HotColdDB::open_ephemeral(<_>::default(), E::default_spec(), test_logger()).unwrap(),
        )
    }

    #[allow(clippy::needless_range_loop)]
    fn check_cache_get(cache: &ValidatorPubkeyCache<T>, keypairs: &[Keypair]) {
        let validator_count = keypairs.len();

        for i in 0..validator_count + 1 {
            if i < validator_count {
                let pubkey = cache.get(i).expect("pubkey should be present");
                assert_eq!(pubkey, &keypairs[i].pk, "pubkey should match cache");

                let pubkey_bytes: PublicKeyBytes = pubkey.clone().into();

                assert_eq!(
                    i,
                    cache
                        .get_index(&pubkey_bytes)
                        .expect("should resolve index"),
                    "index should match cache"
                );
            } else {
                assert_eq!(
                    cache.get(i),
                    None,
                    "should not get pubkey for out of bounds index",
                );
            }
        }
    }

    #[test]
    fn basic_operation() {
        let (state, keypairs) = get_state(8);

        let store = get_store();

        let mut cache = ValidatorPubkeyCache::new(&state, store).expect("should create cache");

        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with the same number of keypairs.
        let (state, keypairs) = get_state(8);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with less keypairs.
        let (state, _) = get_state(1);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with more keypairs.
        let (state, keypairs) = get_state(12);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn persistence() {
        let (state, keypairs) = get_state(8);

        let store = get_store();

        // Create a new cache.
        let cache = ValidatorPubkeyCache::new(&state, store.clone()).expect("should create cache");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let mut cache =
            ValidatorPubkeyCache::load_from_store(store.clone()).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);

        // Add some more keypairs.
        let (state, keypairs) = get_state(12);
        let ops = cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        store.do_atomically(ops).unwrap();
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let cache = ValidatorPubkeyCache::load_from_store(store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }
}