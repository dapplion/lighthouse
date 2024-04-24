use self::single_block_lookup::{LookupRequestError, SingleBlockLookup};
use super::manager::{BlockProcessType, BlockProcessingResult};
use super::network_context::LookupVerifyError;
use super::network_context::{RpcProcessingResult, SyncNetworkContext};
use crate::metrics;
use crate::sync::block_lookups::common::LookupType;
use crate::sync::manager::Id;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_availability_checker::{
    AvailabilityCheckErrorCategory, DataAvailabilityChecker,
};
use beacon_chain::{AvailabilityProcessingStatus, BeaconChainTypes, BlockError};
pub use common::RequestState;
use fnv::FnvHashMap;
use lighthouse_network::{PeerAction, PeerId};
use lru_cache::LRUTimeCache;
pub use single_block_lookup::{BlobRequestState, BlockRequestState};
use slog::{debug, error, trace, warn, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock, Slot};

pub mod common;
mod single_block_lookup;
#[cfg(test)]
mod tests;

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

pub enum UnknownParentTrigger<E: EthSpec> {
    Block(Arc<SignedBeaconBlock<E>>),
    Blob(Arc<BlobSidecar<E>>),
}

pub type SingleLookupId = u32;

enum Action {
    Retry,
    ParentUnknown { parent_root: Hash256, slot: Slot },
    Drop,
    Continue,
}

pub struct BlockLookups<T: BeaconChainTypes> {
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: FnvHashMap<SingleLookupId, SingleBlockLookup<T>>,

    pub(crate) da_checker: Arc<DataAvailabilityChecker<T>>,

    /// The logger for the import manager.
    log: Logger,
}

impl<T: BeaconChainTypes> BlockLookups<T> {
    pub fn new(da_checker: Arc<DataAvailabilityChecker<T>>, log: Logger) -> Self {
        Self {
            failed_chains: LRUTimeCache::new(Duration::from_secs(
                FAILED_CHAINS_CACHE_EXPIRY_SECONDS,
            )),
            single_block_lookups: Default::default(),
            da_checker,
            log,
        }
    }

    #[cfg(test)]
    pub(crate) fn active_single_lookups(&self) -> Vec<(Id, Hash256, Option<Hash256>)> {
        self.single_block_lookups
            .iter()
            .map(|(id, e)| (*id, e.block_root(), e.parent_root()))
            .collect()
    }

    /// Returns a vec of all parent lookup chains by tip, in descending slot order (tip first)
    pub(crate) fn active_parent_lookups(&self) -> Vec<Vec<Hash256>> {
        let mut child_to_parent = HashMap::new();
        let mut parent_to_child = HashMap::<Hash256, Vec<Hash256>>::new();
        for lookup in self.single_block_lookups.values() {
            let block_root = lookup.block_root();
            let parent_root = lookup.parent_root();
            child_to_parent.insert(block_root, parent_root);
            if let Some(parent_root) = parent_root {
                parent_to_child
                    .entry(parent_root)
                    .or_default()
                    .push(block_root);
            }
        }

        let mut parent_chains = vec![];

        // Iterate blocks which no child
        for lookup in self.single_block_lookups.values() {
            let mut block_root = lookup.block_root();
            if parent_to_child.get(&block_root).is_none() {
                let mut chain = vec![];

                // Resolve chain of blocks
                loop {
                    if let Some(parent_root) = child_to_parent.get(&block_root) {
                        // block_root is a known block that may or may not have a parent root
                        chain.push(block_root);
                        if let Some(parent_root) = parent_root {
                            block_root = *parent_root;
                            continue;
                        }
                    }
                    break;
                }

                if chain.len() > 1 {
                    parent_chains.push(chain);
                }
            }
        }

        parent_chains
    }

    #[cfg(test)]
    pub(crate) fn failed_chains_contains(&mut self, chain_hash: &Hash256) -> bool {
        self.failed_chains.contains(chain_hash)
    }

    /* Lookup requests */

    /// Creates a lookup for the block with the given `block_root` and immediately triggers it.
    pub fn search_block(
        &mut self,
        block_root: Hash256,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(block_root, None, None, peer_source, cx)
    }

    /// Creates a lookup for the block with the given `block_root`, while caching other block
    /// components we've already received. The block components are cached here because we haven't
    /// imported its parent and therefore can't fully validate it and store it in the data
    /// availability cache.
    ///
    /// The request is immediately triggered.
    pub fn search_child_block(
        &mut self,
        block_root: Hash256,
        parent_root: Hash256,
        unknown_parent_trigger: UnknownParentTrigger<T::EthSpec>,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(
            block_root,
            Some(parent_root),
            Some(unknown_parent_trigger),
            peer_source,
            cx,
        )
    }

    /// Attempts to trigger the request matching the given `block_root`.
    pub fn trigger_single_lookup(
        &mut self,
        mut single_block_lookup: SingleBlockLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = single_block_lookup.block_root();
        match single_block_lookup.continue_requests(cx) {
            Ok(()) => self.add_single_lookup(single_block_lookup),
            Err(e) => {
                debug!(self.log, "Single block lookup failed";
                    "error" => ?e,
                    "block_root" => ?block_root,
                );
            }
        }
    }

    /// Adds a lookup to the `single_block_lookups` map.
    pub fn add_single_lookup(&mut self, single_block_lookup: SingleBlockLookup<T>) {
        self.single_block_lookups
            .insert(single_block_lookup.id, single_block_lookup);

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /// Searches for a single block hash. If the blocks parent is unknown, a chain of blocks is
    /// constructed.
    pub fn new_current_lookup(
        &mut self,
        block_root: Hash256,
        parent_root: Option<Hash256>,
        unknown_parent_trigger: Option<UnknownParentTrigger<T::EthSpec>>,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block_root) {
            debug!(self.log, "Block is from a past failed chain. Dropping"; "block_root" => ?block_root);
            // TODO: Look for blocks whose parent_root is in the failed chains
            return;
        }

        // Do not re-request a block that is already being requested
        if let Some((_, lookup)) = self
            .single_block_lookups
            .iter_mut()
            .find(|(_id, lookup)| lookup.is_for_block(block_root))
        {
            trace!(self.log, "Adding peer to existing single block lookup"; "block_root" => %block_root);
            lookup.add_peers(peers);
            if let Some(unknown_parent_trigger) = unknown_parent_trigger {
                lookup.add_child_components(unknown_parent_trigger);
            }
            return;
        }

        let msg = if unknown_parent_trigger.is_some() {
            "Searching for components of a block with unknown parent"
        } else {
            "Searching for block components"
        };

        let lookup = SingleBlockLookup::new(
            block_root,
            unknown_parent_trigger,
            peers,
            self.da_checker.clone(),
            cx.next_id(),
            LookupType::Current,
            parent_root,
        );

        debug!(
            self.log,
            "{}", msg;
            "peer_ids" => ?peers,
            "block" => ?block_root,
        );
        self.trigger_single_lookup(lookup, cx);
    }

    /// If a block is attempted to be processed but we do not know its parent, this function is
    /// called in order to find the block's parent.
    pub fn search_parent(
        &mut self,
        slot: Slot,
        block_root: Hash256,
        parent_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        debug!(self.log, "Created new parent lookup"; "block_root" => ?block_root, "parent_root" => ?parent_root);

        // TODO: Should check failed_chains inside new_current_lookup
        // TODO: Check max chain length

        self.new_current_lookup(parent_root, Some(parent_root), None, peers, cx);
    }

    /* Lookup responses */

    /// Process a block or blob response received from a single lookup request.
    pub fn on_download_response<R: RequestState<T>>(
        &mut self,
        id: SingleLookupId,
        peer_id: PeerId,
        response: RpcProcessingResult<R::VerifiedResponseType>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let response_type = R::response_type();

        let Some(mut lookup) = self.single_block_lookups.get_mut(&id) else {
            // We don't have the ability to cancel in-flight RPC requests. So this can happen
            // if we started this RPC request, and later saw the block/blobs via gossip.
            debug!(
                self.log,
                "Block returned for single block lookup not present"; "id" => id,
                    "response_type" => ?response_type,
            );
            return;
        };

        let lookup_type = lookup.lookup_type;
        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        let result = match response {
            Ok((response, seen_timestamp)) => {
                debug!(self.log,
                    "Block lookup download success";
                    "block_root" => %block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                );

                if let Err(e) = request_state.get_state_mut().on_download_success((
                    response,
                    block_root,
                    seen_timestamp,
                )) {
                    Err(e)
                } else {
                    // TOOD: May choose to delay blobs for sending if we know that their parent is unknown.
                    // However, da_checker does not ever error with unknown parent. Plus we should not request
                    // blobs for blocks that are not rooted on a valid chain, as an attacker can trigger us into
                    // fetching garbage.

                    request_state.continue_request(id, lookup_type, cx)
                }
            }
            Err(e) => {
                debug!(self.log,
                    "Block lookup download failure";
                    "block_root" => %block_root,
                    "peer_id" => %peer_id,
                    "response_type" => ?response_type,
                    "error" => %e,
                );

                if let Err(e) = request_state.get_state_mut().on_download_failure() {
                    Err(e)
                } else {
                    request_state.continue_request(id, lookup_type, cx)
                }
            }
        };

        if let Err(e) = result {
            debug!(self.log, "Dropping single lookup"; "id" => id, "err" => ?e);
            self.single_block_lookups.remove(&id);
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        /* Check disconnection for single lookups */
        self.single_block_lookups.retain(|_, req| {
            let should_drop_lookup =
                req.should_drop_lookup_on_disconnected_peer(peer_id, cx, &self.log);

            if should_drop_lookup {
                debug!(self.log, "Dropping single lookup after peer disconnection"; "block_root" => %req.block_root());
            }

            !should_drop_lookup
        });
    }

    /* Processing responses */

    pub fn single_block_component_processed_2(
        &mut self,
        process_type: BlockProcessType,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if let Err(e) = match process_type {
            BlockProcessType::SingleBlock { id } => self
                .single_block_component_processed::<BlockRequestState<T::EthSpec>>(id, result, cx),
            BlockProcessType::SingleBlob { id } => self
                .single_block_component_processed::<BlobRequestState<T::EthSpec>>(id, result, cx),
        } {
            let id = match process_type {
                BlockProcessType::SingleBlock { id } | BlockProcessType::SingleBlob { id } => id,
            };
            debug!(self.log, "Dropping lookup on request error"; "id" => id, "error" => ?e);
            self.drop_lookup_and_childs(id);
        }
    }

    pub fn single_block_component_processed<R: RequestState<T>>(
        &mut self,
        lookup_id: SingleLookupId,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let Some(mut lookup) = self.single_block_lookups.remove(&lookup_id) else {
            debug!(self.log, "Unknown single block lookup"; "target_id" => lookup_id);
            return Ok(());
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup).get_state_mut();

        debug!(
            self.log,
            "Block component processed for lookup";
            "response_type" => ?R::response_type(),
            "block_root" => ?block_root,
            "result" => ?result,
            "id" => lookup_id,
        );

        let action = match result {
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown(_)) => {
                request_state.on_processing_success()?;

                // Successfully imported
                // TODO: Potentially import child blocks
                trace!(self.log, "Single block processing succeeded"; "block" => %block_root);
                Action::Continue
            }

            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                _,
                _block_root,
            )) => {
                // `on_processing_success` is called here to ensure the request state is updated prior to checking
                // if both components have been processed.
                request_state.on_processing_success()?;

                // If this was the result of a block request, we can't determined if the block peer did anything
                // wrong. If we already had both a block and blobs response processed, we should penalize the
                // blobs peer because they did not provide all blobs on the initial request.
                if lookup.both_components_processed() {
                    lookup.penalize_blob_peer(cx);

                    // Try it again if possible.
                    lookup.blob_request_state.state.on_processing_failure();
                    Action::Retry
                } else {
                    Action::Retry
                }
            }
            BlockProcessingResult::Ignored => {
                // This request will be dropped, it's not strictly necessary to change its state,
                // but doing it for completeness
                request_state.on_processing_failure()?;

                // Beacon processor signalled to ignore the block processing result.
                // This implies that the cpu is overloaded. Drop the request.
                warn!(
                    self.log,
                    "Single block processing was ignored, cpu might be overloaded";
                    "action" => "dropping single block request"
                );
                Action::Drop
            }
            BlockProcessingResult::Err(e) => {
                let peer_id = request_state.on_processing_failure()?;

                let root = lookup.block_root();
                trace!(self.log, "Single block processing failed"; "block" => %root, "error" => %e);
                match e {
                    BlockError::BeaconChainError(e) => {
                        // Internal error
                        error!(self.log, "Beacon chain error processing single block"; "block_root" => %root, "error" => ?e);
                        Action::Drop
                    }
                    BlockError::ParentUnknown(block) => {
                        let slot = block.slot();
                        let parent_root = block.parent_root();
                        todo!();
                        // lookup.add_child_components(block.into());
                        Action::ParentUnknown { parent_root, slot }
                    }
                    ref e @ BlockError::ExecutionPayloadError(ref epe) if !epe.penalize_peer() => {
                        // These errors indicate that the execution layer is offline
                        // and failed to validate the execution payload. Do not downscore peer.
                        debug!(
                            self.log,
                            "Single block lookup failed. Execution layer is offline / unsynced / misconfigured";
                            "root" => %root,
                            "error" => ?e
                        );
                        Action::Drop
                    }
                    BlockError::AvailabilityCheck(e) => match e.category() {
                        AvailabilityCheckErrorCategory::Internal => {
                            warn!(self.log, "Internal availability check failure"; "root" => %root, "peer_id" => %peer_id, "error" => ?e);
                            lookup.block_request_state.state.on_download_failure();
                            lookup.blob_request_state.state.on_download_failure();
                            Action::Retry
                        }
                        AvailabilityCheckErrorCategory::Malicious => {
                            warn!(self.log, "Availability check failure"; "root" => %root, "peer_id" => %peer_id, "error" => ?e);
                            lookup.penalize_blob_peer(cx);
                            // TODO: This cross request state changes are not cool
                            lookup.blob_request_state.state.on_processing_failure();
                            Action::Retry
                        }
                    },
                    other => {
                        warn!(self.log, "Peer sent invalid block in single block lookup"; "root" => %root, "error" => ?other, "peer_id" => %peer_id);
                        if let Ok(block_peer) = lookup.block_request_state.state.processing_peer() {
                            cx.report_peer(
                                block_peer,
                                PeerAction::MidToleranceError,
                                "single_block_failure",
                            );

                            lookup.block_request_state.state.on_processing_failure();
                        }
                        Action::Retry
                    }
                }
            }
        };

        match action {
            Action::Retry => {
                // Trigger download
                lookup.continue_requests(cx)?;
            }
            Action::ParentUnknown { parent_root, slot } => {
                // TODO: Consider including all peers from the lookup, claiming to know this block, not
                // just the one that sent this specific block
                self.search_parent(
                    slot,
                    block_root,
                    parent_root,
                    &lookup.all_available_peers().cloned().collect::<Vec<_>>(),
                    cx,
                );
                self.single_block_lookups.insert(lookup_id, lookup);
            }
            Action::Drop => {
                // Drop with noop
                self.single_block_lookups.remove(&lookup_id);
                self.drop_lookup_and_childs(lookup_id);
                self.update_metrics();
            }
            Action::Continue => {
                // Block imported, continue the requests of pending child blocks
                self.continue_child_lookups(block_root, cx);
            }
        }
        Ok(())
    }

    pub fn continue_child_lookups(&mut self, block_root: Hash256, cx: &mut SyncNetworkContext<T>) {
        for (id, lookup) in self.single_block_lookups.iter_mut() {
            if lookup.parent_root() == Some(block_root) {
                // Continue lookup
                debug!(self.log, "Continuing child lookup"; "block_root" => %lookup.block_root());
                lookup.continue_requests(cx);
            }
        }
    }

    pub fn drop_lookup_and_childs(&mut self, dropped_id: SingleLookupId) {
        if let Some(dropped_lookup) = self.single_block_lookups.remove(&dropped_id) {
            debug!(self.log, "Dropping child lookup"; "id" => ?dropped_id, "block_root" => %dropped_lookup.block_root());

            let child_lookup_ids = self
                .single_block_lookups
                .iter()
                .filter_map(|(id, lookup)| {
                    if lookup.parent_root() == Some(dropped_lookup.block_root()) {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            for id in child_lookup_ids {
                self.drop_lookup_and_childs(id);
            }
        }
    }

    /* Helper functions */

    pub fn drop_single_lookup(&mut self, block_root: Hash256) {
        if let Some(id) = self
            .single_block_lookups
            .iter()
            .find_map(|(id, req)| (req.block_root() == block_root).then_some(*id))
        {
            debug!(self.log, "Dropping single block lookup"; "id" => id, "block_root" => %block_root);
            self.single_block_lookups.remove(&id);
        };
    }

    /// Drops all the single block requests and returns how many requests were dropped.
    pub fn drop_single_block_requests(&mut self) -> usize {
        let requests_to_drop = self.single_block_lookups.len();
        self.single_block_lookups.clear();
        requests_to_drop
    }

    pub fn downscore_on_rpc_error(
        &self,
        peer_id: &PeerId,
        error: &LookupVerifyError,
        cx: &SyncNetworkContext<T>,
    ) {
        // Note: logging the report event here with the full error display. The log inside
        // `report_peer` only includes a smaller string, like "invalid_data"
        debug!(self.log, "reporting peer for sync lookup error"; "error" => ?error);
        cx.report_peer(*peer_id, PeerAction::LowToleranceError, error.into());
    }

    pub fn update_metrics(&self) {
        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }
}
