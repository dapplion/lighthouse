use crate::blob_verification::{verify_kzg_for_blob_list, GossipVerifiedBlob, KzgVerifiedBlobList};
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableExecutedBlock, RpcBlock,
};
pub use crate::data_availability_checker::child_components::ChildComponents;
use crate::data_availability_checker::overflow_lru_cache::OverflowLRUCache;
pub use crate::data_availability_checker::overflow_lru_cache::{
    compute_custody_requirements, compute_sample_requirements,
};
use crate::{BeaconChain, BeaconChainTypes, BeaconStore};
use kzg::Kzg;
use slasher::test_utils::E;
use slog::{debug, error, Logger};
use slot_clock::SlotClock;
use ssz_types::FixedVector;
use std::fmt;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar, FixedBlobSidecarList};
use types::{
    BlobSidecarList, ChainSpec, DataColumnSidecar, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot,
};

mod child_components;
mod error;
mod overflow_lru_cache;
mod state_lru_cache;

use crate::data_column_verification::{
    verify_kzg_for_data_column_list, GossipVerifiedDataColumn, KzgVerifiedDataColumn,
};
pub use error::{Error as AvailabilityCheckError, ErrorCategory as AvailabilityCheckErrorCategory};
use types::data_column_sidecar::{ColumnIndex, DataColumnIdentifier, DataColumnSidecarList};
use types::non_zero_usize::new_non_zero_usize;

#[derive(Clone, Copy)]
pub struct NodeIdRaw(pub [u8; 32]);

pub struct CustodyConfig {
    node_id: NodeIdRaw,
    custody_requirement: u64,
}

impl CustodyConfig {
    pub fn new(node_id: NodeIdRaw, custody_requirement: u64) -> Self {
        Self {
            node_id,
            custody_requirement,
        }
    }
}

impl From<[u8; 32]> for NodeIdRaw {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// The LRU Cache stores `PendingComponents` which can store up to
/// `MAX_BLOBS_PER_BLOCK = 6` blobs each. A `BlobSidecar` is 0.131256 MB. So
/// the maximum size of a `PendingComponents` is ~ 0.787536 MB. Setting this
/// to 1024 means the maximum size of the cache is ~ 0.8 GB. But the cache
/// will target a size of less than 75% of capacity.
pub const OVERFLOW_LRU_CAPACITY: NonZeroUsize = new_non_zero_usize(1024);
/// Until tree-states is implemented, we can't store very many states in memory :(
pub const STATE_LRU_CAPACITY_NON_ZERO: NonZeroUsize = new_non_zero_usize(2);
pub const STATE_LRU_CAPACITY: usize = STATE_LRU_CAPACITY_NON_ZERO.get();

/// This includes a cache for any blocks or blobs that have been received over gossip or RPC
/// and are awaiting more components before they can be imported. Additionally the
/// `DataAvailabilityChecker` is responsible for KZG verification of block components as well as
/// checking whether a "availability check" is required at all.
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    availability_cache: Arc<OverflowLRUCache<T>>,
    slot_clock: T::SlotClock,
    kzg: Option<Arc<Kzg>>,
    log: Logger,
    spec: ChainSpec,
}

/// This type is returned after adding a block / blob to the `DataAvailabilityChecker`.
///
/// Indicates if the block is fully `Available` or if we need blobs or blocks
///  to "complete" the requirements for an `AvailableBlock`.
#[derive(PartialEq)]
pub enum Availability<T: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedBlock<T>>),
}

impl<T: EthSpec> Debug for Availability<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            Self::Available(block) => write!(f, "Available({:?})", block.import_data.block_root),
        }
    }
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        slot_clock: T::SlotClock,
        kzg: Option<Arc<Kzg>>,
        store: BeaconStore<T>,
        log: &Logger,
        spec: ChainSpec,
        custody_config: CustodyConfig,
    ) -> Result<Self, AvailabilityCheckError> {
        let overflow_cache =
            OverflowLRUCache::new(OVERFLOW_LRU_CAPACITY, store, spec.clone(), custody_config)?;
        Ok(Self {
            availability_cache: Arc::new(overflow_cache),
            slot_clock,
            log: log.clone(),
            kzg,
            spec,
        })
    }

    pub fn get_custody_config(&self) -> &CustodyConfig {
        self.availability_cache.get_custody_config()
    }

    /// Return this node's custody column requirements at `slot`
    pub fn custody_columns_at_slot(&self, slot: Slot) -> Vec<ColumnIndex> {
        self.availability_cache.custody_columns_at_slot(slot)
    }

    /// Checks if the block root is currenlty in the availability cache awaiting processing because
    /// of missing components.
    pub fn block_slot(&self, block_root: &Hash256) -> Option<Slot> {
        self.availability_cache.block_slot(block_root)
    }

    /// Checks if the block root is currenlty in the availability cache awaiting processing because
    /// of missing components.
    pub fn has_block(&self, block_root: &Hash256) -> bool {
        self.availability_cache.has_block(block_root)
    }

    pub fn get_missing_blob_ids_with(&self, block_root: Hash256) -> MissingBlobs {
        self.availability_cache
            .with_pending_components(&block_root, |pending_components| {
                self.get_missing_blob_ids(
                    block_root,
                    &pending_components
                        .and_then(|p| p.executed_block.clone())
                        .map(|b| b.as_block_cloned()),
                    &pending_components.map(|p| p.verified_blobs.clone()),
                )
            })
    }

    /// A `None` indicates blobs are not required.
    ///
    /// If there's no block, all possible ids will be returned that don't exist in the given blobs.
    /// If there no blobs, all possible ids will be returned.
    pub fn get_missing_blob_ids<V>(
        &self,
        block_root: Hash256,
        block: &Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
        blobs: &Option<FixedVector<Option<V>, <T::EthSpec as EthSpec>::MaxBlobsPerBlock>>,
    ) -> MissingBlobs {
        let Some(current_slot) = self.slot_clock.now_or_genesis() else {
            error!(
                self.log,
                "Failed to read slot clock when checking for missing blob ids"
            );
            return MissingBlobs::BlobsNotRequired;
        };

        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

        if self.da_check_required_for_epoch(current_epoch) {
            if let (Some(block), Some(blobs)) = (block, blobs) {
                let block_commitments = block
                    .message()
                    .body()
                    .blob_kzg_commitments()
                    .ok()
                    .cloned()
                    .unwrap_or_default();

                let num_blobs_expected = block_commitments.len();
                let mut blob_ids = Vec::with_capacity(num_blobs_expected);

                // Zip here will always limit the number of iterations to the size of
                // `block_commitment` because `blob_commitments` will always be populated
                // with `Option` values up to `MAX_BLOBS_PER_BLOCK`.
                for (index, (_, blob_commitment_opt)) in
                    block_commitments.into_iter().zip(blobs.iter()).enumerate()
                {
                    // Always add a missing blob.
                    if blob_commitment_opt.is_none() {
                        blob_ids.push(BlobIdentifier {
                            block_root,
                            index: index as u64,
                        });
                    };
                }
                MissingBlobs::KnownMissing(blob_ids)
            } else {
                MissingBlobs::PossibleMissing(BlobIdentifier::get_all_blob_ids::<E>(block_root))
            }
        } else {
            MissingBlobs::BlobsNotRequired
        }
    }

    pub fn get_missing_data_column_ids(
        &self,
        block_root: Hash256,
        block: &Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> MissingDataColumns {
        let Some(current_slot) = self.slot_clock.now_or_genesis() else {
            error!(
                self.log,
                "Failed to read slot clock when checking for missing blob ids"
            );
            return MissingDataColumns::NotRequired;
        };

        if !self.da_check_required_for_epoch(current_slot.epoch(T::EthSpec::slots_per_epoch())) {
            return MissingDataColumns::NotRequired;
        }

        // Compute ids for sampling
        let mut sampling_ids = self
            .compute_sampling_column_ids(block_root)
            .into_iter()
            .map(|index| BlobIdentifier {
                block_root,
                index: index as u64,
            })
            .collect::<Vec<_>>();

        // Compute ids for custody
        match block {
            Some(cached_block) => {
                sampling_ids.extend_from_slice(
                    &self
                        .compute_custody_column_ids(cached_block.slot())
                        .into_iter()
                        .map(|index| BlobIdentifier {
                            block_root,
                            index: index as u64,
                        })
                        .collect::<Vec<_>>(),
                );
                MissingDataColumns::KnownMissing(sampling_ids)
            }
            // TODO(das): without knowledge of the block's slot you can't know your custody
            // requirements. When syncing a block via single block lookup, you need to fetch the
            // block first, then fetch your custody columns
            None => MissingDataColumns::KnownMissingIncomplete(sampling_ids),
        }
    }

    fn compute_sampling_column_ids(&self, block_root: Hash256) -> Vec<usize> {
        todo!("Use local randomness to derive this block's sample column ids")
    }

    fn compute_custody_column_ids(&self, slot: Slot) -> Vec<usize> {
        todo!("Use local node ID and custody parameter to compute column ids for this slot");
    }

    /// Get a blob from the availability cache.
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_blob(blob_id)
    }

    /// Get a data column from the availability cache.
    pub fn get_data_column(
        &self,
        data_column_id: &DataColumnIdentifier,
    ) -> Result<Option<Arc<DataColumnSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.availability_cache.peek_data_column(data_column_id)
    }

    /// Put a list of blobs received via RPC into the availability cache. This performs KZG
    /// verification on the blobs in the list.
    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let Some(kzg) = self.kzg.as_ref() else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        let verified_blobs = KzgVerifiedBlobList::new(Vec::from(blobs).into_iter().flatten(), kzg)
            .map_err(AvailabilityCheckError::Kzg)?;

        self.availability_cache
            .put_kzg_verified_blobs(block_root, verified_blobs)
    }

    pub fn put_rpc_data_column(
        &self,
        block_root: Hash256,
        data_column: Arc<DataColumnSidecar<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let Some(kzg) = self.kzg.as_ref() else {
            return Err(AvailabilityCheckError::KzgNotInitialized);
        };

        // TODO(das): batch verify data columns
        let verified_data_column = KzgVerifiedDataColumn::new(data_column.clone(), kzg)
            .map_err(AvailabilityCheckError::Kzg)?;

        self.availability_cache
            .put_kzg_verified_data_column(block_root, verified_data_column)
    }

    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the blob sidecar.
    ///
    /// This should only accept gossip verified blobs, so we should not have to worry about dupes.
    pub fn put_gossip_blob(
        &self,
        gossip_blob: GossipVerifiedBlob<T>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_kzg_verified_blobs(gossip_blob.block_root(), vec![gossip_blob.into_inner()])
    }

    /// Check if we've cached other data columns for this block. If it satisfies the custody requirement and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the data column sidecar.
    ///
    /// This should only accept gossip verified data columns, so we should not have to worry about dupes.
    pub fn put_gossip_data_column(
        &self,
        gossip_data_column: GossipVerifiedDataColumn<T>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache.put_kzg_verified_data_column(
            gossip_data_column.block_root(),
            gossip_data_column.into_inner(),
        )
    }

    /// Check if we have all the blobs for a block. Returns `Availability` which has information
    /// about whether all components have been received or more are required.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.availability_cache
            .put_pending_executed_block(executed_block)
    }

    /// Verifies kzg commitments for an RpcBlock, returns a `MaybeAvailableBlock` that may
    /// include the fully available block.
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_rpc_block(
        &self,
        block: RpcBlock<T::EthSpec>,
    ) -> Result<MaybeAvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        let (block_root, block, blobs, data_columns) = block.deconstruct();
        match (blobs, data_columns) {
            (None, None) => {
                if self.blobs_required_for_block(&block) {
                    Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
                } else {
                    Ok(MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blobs: None,
                        custody_data_columns: None,
                    }))
                }
            }
            (maybe_blob_list, maybe_data_column_list) => {
                let (verified_blobs, verified_data_column) =
                    if self.blobs_required_for_block(&block) {
                        let kzg = self
                            .kzg
                            .as_ref()
                            .ok_or(AvailabilityCheckError::KzgNotInitialized)?;

                        if let Some(blob_list) = maybe_blob_list.as_ref() {
                            verify_kzg_for_blob_list(blob_list.iter(), kzg)
                                .map_err(AvailabilityCheckError::Kzg)?;
                        }
                        if let Some(data_column_list) = maybe_data_column_list.as_ref() {
                            verify_kzg_for_data_column_list(data_column_list.iter(), kzg)
                                .map_err(AvailabilityCheckError::Kzg)?;
                        }
                        (maybe_blob_list, maybe_data_column_list)
                    } else {
                        (None, None)
                    };
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blobs: verified_blobs,
                    custody_data_columns: verified_data_column,
                }))
            }
        }
    }

    /// Checks if a vector of blocks are available. Returns a vector of `MaybeAvailableBlock`
    /// This is more efficient than calling `verify_kzg_for_rpc_block` in a loop as it does
    /// all kzg verification at once
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_rpc_blocks(
        &self,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<Vec<MaybeAvailableBlock<T::EthSpec>>, AvailabilityCheckError> {
        let mut results = Vec::with_capacity(blocks.len());
        let all_blobs: BlobSidecarList<T::EthSpec> = blocks
            .iter()
            .filter(|block| self.blobs_required_for_block(block.as_block()))
            // this clone is cheap as it's cloning an Arc
            .filter_map(|block| block.blobs().cloned())
            .flatten()
            .collect::<Vec<_>>()
            .into();

        // verify kzg for all blobs at once
        if !all_blobs.is_empty() {
            let kzg = self
                .kzg
                .as_ref()
                .ok_or(AvailabilityCheckError::KzgNotInitialized)?;
            verify_kzg_for_blob_list(all_blobs.iter(), kzg)?;
        }

        for block in blocks {
            let (block_root, block, blobs, data_columns) = block.deconstruct();
            match (blobs, data_columns) {
                (None, None) => {
                    if self.blobs_required_for_block(&block) {
                        results.push(MaybeAvailableBlock::AvailabilityPending { block_root, block })
                    } else {
                        results.push(MaybeAvailableBlock::Available(AvailableBlock {
                            block_root,
                            block,
                            blobs: None,
                            custody_data_columns: None,
                        }))
                    }
                }
                (maybe_blob_list, maybe_data_column_list) => {
                    let (verified_blobs, verified_data_columns) =
                        if self.blobs_required_for_block(&block) {
                            (maybe_blob_list, maybe_data_column_list)
                        } else {
                            (None, None)
                        };
                    // already verified kzg for all blobs
                    results.push(MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blobs: verified_blobs,
                        custody_data_columns: verified_data_columns,
                    }))
                }
            }
        }

        Ok(results)
    }

    /// Determines the blob requirements for a block. If the block is pre-deneb, no blobs are required.
    /// If the block's epoch is from prior to the data availability boundary, no blobs are required.
    fn blobs_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.num_expected_blobs() > 0 && self.da_check_required_for_epoch(block.epoch())
    }

    /// The epoch at which we require a data availability check in block processing.
    /// `None` if the `Deneb` fork is disabled.
    pub fn data_availability_boundary(&self) -> Option<Epoch> {
        self.spec.deneb_fork_epoch.and_then(|fork_epoch| {
            self.slot_clock
                .now()
                .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                .map(|current_epoch| {
                    std::cmp::max(
                        fork_epoch,
                        current_epoch
                            .saturating_sub(self.spec.min_epochs_for_blob_sidecars_requests),
                    )
                })
        })
    }

    /// Returns true if the given epoch lies within the da boundary and false otherwise.
    pub fn da_check_required_for_epoch(&self, block_epoch: Epoch) -> bool {
        self.data_availability_boundary()
            .map_or(false, |da_epoch| block_epoch >= da_epoch)
    }

    /// Returns `true` if the current epoch is greater than or equal to the `Deneb` epoch.
    pub fn is_deneb(&self) -> bool {
        self.slot_clock.now().map_or(false, |slot| {
            self.spec.deneb_fork_epoch.map_or(false, |deneb_epoch| {
                let now_epoch = slot.epoch(T::EthSpec::slots_per_epoch());
                now_epoch >= deneb_epoch
            })
        })
    }

    /// Persist all in memory components to disk
    pub fn persist_all(&self) -> Result<(), AvailabilityCheckError> {
        self.availability_cache.write_all_to_disk()
    }

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        DataAvailabilityCheckerMetrics {
            num_store_entries: self.availability_cache.num_store_entries(),
            state_cache_size: self.availability_cache.state_cache_size(),
            block_cache_size: self.availability_cache.block_cache_size(),
        }
    }
}

/// Helper struct to group data availability checker metrics.
pub struct DataAvailabilityCheckerMetrics {
    pub num_store_entries: usize,
    pub state_cache_size: usize,
    pub block_cache_size: usize,
}

pub fn start_availability_cache_maintenance_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // this cache only needs to be maintained if deneb is configured
    if chain.spec.deneb_fork_epoch.is_some() {
        let overflow_cache = chain.data_availability_checker.availability_cache.clone();
        executor.spawn(
            async move { availability_cache_maintenance_service(chain, overflow_cache).await },
            "availability_cache_service",
        );
    } else {
        debug!(
            chain.log,
            "Deneb fork not configured, not starting availability cache maintenance service"
        );
    }
}

async fn availability_cache_maintenance_service<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    overflow_cache: Arc<OverflowLRUCache<T>>,
) {
    let epoch_duration = chain.slot_clock.slot_duration() * T::EthSpec::slots_per_epoch() as u32;
    loop {
        match chain
            .slot_clock
            .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
        {
            Some(duration) => {
                // this service should run 3/4 of the way through the epoch
                let additional_delay = (epoch_duration * 3) / 4;
                tokio::time::sleep(duration + additional_delay).await;

                let Some(deneb_fork_epoch) = chain.spec.deneb_fork_epoch else {
                    // shutdown service if deneb fork epoch not set
                    break;
                };

                debug!(
                    chain.log,
                    "Availability cache maintenance service firing";
                );
                let Some(current_epoch) = chain
                    .slot_clock
                    .now()
                    .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                else {
                    continue;
                };

                if current_epoch < deneb_fork_epoch {
                    // we are not in deneb yet
                    continue;
                }

                let finalized_epoch = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .finalized_checkpoint()
                    .epoch;
                // any data belonging to an epoch before this should be pruned
                let cutoff_epoch = std::cmp::max(
                    finalized_epoch + 1,
                    std::cmp::max(
                        current_epoch
                            .saturating_sub(chain.spec.min_epochs_for_blob_sidecars_requests),
                        deneb_fork_epoch,
                    ),
                );

                if let Err(e) = overflow_cache.do_maintenance(cutoff_epoch) {
                    error!(chain.log, "Failed to maintain availability cache"; "error" => ?e);
                }
            }
            None => {
                error!(chain.log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                tokio::time::sleep(chain.slot_clock.slot_duration()).await;
            }
        };
    }
}

/// A fully available block that is ready to be imported into fork choice.
#[derive(Clone, Debug, PartialEq)]
pub struct AvailableBlock<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    blobs: Option<BlobSidecarList<E>>,
    custody_data_columns: Option<DataColumnSidecarList<E>>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn __new_for_testing(
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Option<BlobSidecarList<E>>,
        custody_data_columns: Option<DataColumnSidecarList<E>>,
    ) -> Self {
        Self {
            block_root,
            block,
            blobs,
            custody_data_columns,
        }
    }

    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }

    pub fn blobs(&self) -> Option<&BlobSidecarList<E>> {
        self.blobs.as_ref()
    }

    pub fn custody_data_columns(&self) -> Option<&DataColumnSidecarList<E>> {
        self.custody_data_columns.as_ref()
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(
        self,
    ) -> (
        Hash256,
        Arc<SignedBeaconBlock<E>>,
        Option<BlobSidecarList<E>>,
        Option<DataColumnSidecarList<E>>,
    ) {
        let AvailableBlock {
            block_root,
            block,
            blobs,
            custody_data_columns,
        } = self;
        (block_root, block, blobs, custody_data_columns)
    }
}

#[derive(Debug, Clone)]
pub enum MaybeAvailableBlock<E: EthSpec> {
    /// This variant is fully available.
    /// i.e. for pre-deneb blocks, it contains a (`SignedBeaconBlock`, `Blobs::None`) and for
    /// post-4844 blocks, it contains a `SignedBeaconBlock` and a Blobs variant other than `Blobs::None`.
    Available(AvailableBlock<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending {
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
    },
}

impl<E: EthSpec> MaybeAvailableBlock<E> {
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match self {
            Self::Available(block) => block.block_cloned(),
            Self::AvailabilityPending { block, .. } => block.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MissingBlobs {
    /// We know for certain these blobs are missing.
    KnownMissing(Vec<BlobIdentifier>),
    /// We think these blobs might be missing.
    PossibleMissing(Vec<BlobIdentifier>),
    /// Blobs are not required.
    BlobsNotRequired,
}

impl MissingBlobs {
    pub fn new_without_block(block_root: Hash256, is_deneb: bool) -> Self {
        if is_deneb {
            MissingBlobs::PossibleMissing(BlobIdentifier::get_all_blob_ids::<E>(block_root))
        } else {
            MissingBlobs::BlobsNotRequired
        }
    }
    pub fn is_empty(&self) -> bool {
        match self {
            MissingBlobs::KnownMissing(v) => v.is_empty(),
            MissingBlobs::PossibleMissing(v) => v.is_empty(),
            MissingBlobs::BlobsNotRequired => true,
        }
    }
    pub fn contains(&self, blob_id: &BlobIdentifier) -> bool {
        match self {
            MissingBlobs::KnownMissing(v) => v.contains(blob_id),
            MissingBlobs::PossibleMissing(v) => v.contains(blob_id),
            MissingBlobs::BlobsNotRequired => false,
        }
    }
    pub fn remove(&mut self, blob_id: &BlobIdentifier) {
        match self {
            MissingBlobs::KnownMissing(v) => v.retain(|id| id != blob_id),
            MissingBlobs::PossibleMissing(v) => v.retain(|id| id != blob_id),
            MissingBlobs::BlobsNotRequired => {}
        }
    }
    pub fn indices(&self) -> Vec<u64> {
        match self {
            MissingBlobs::KnownMissing(v) => v.iter().map(|id| id.index).collect(),
            MissingBlobs::PossibleMissing(v) => v.iter().map(|id| id.index).collect(),
            MissingBlobs::BlobsNotRequired => vec![],
        }
    }
}

impl Into<Vec<BlobIdentifier>> for MissingBlobs {
    fn into(self) -> Vec<BlobIdentifier> {
        match self {
            MissingBlobs::KnownMissing(v) => v,
            MissingBlobs::PossibleMissing(v) => v,
            MissingBlobs::BlobsNotRequired => vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub enum MissingDataColumns {
    /// We know for certain we must fetch this column ids
    KnownMissing(Vec<BlobIdentifier>),
    /// We don't know yet the full list of column ids to fetch
    KnownMissingIncomplete(Vec<BlobIdentifier>),
    /// Not required.
    NotRequired,
}

impl MissingDataColumns {
    pub fn is_empty(&self) -> bool {
        match self {
            MissingDataColumns::KnownMissing(v) => v.is_empty(),
            MissingDataColumns::KnownMissingIncomplete(_) => false,
            MissingDataColumns::NotRequired => true,
        }
    }

    pub fn indices(&self) -> Vec<u64> {
        match self {
            MissingDataColumns::KnownMissing(v) | MissingDataColumns::KnownMissingIncomplete(v) => {
                v.iter().map(|id| id.index).collect()
            }
            MissingDataColumns::NotRequired => vec![],
        }
    }
}
