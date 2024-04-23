use self::single_block_lookup::SingleBlockLookup;
use super::manager::BlockProcessingResult;
use super::network_context::{LookupFailure, LookupVerifyError};
use super::{manager::BlockProcessType, network_context::SyncNetworkContext};
use crate::metrics;
use crate::sync::block_lookups::common::LookupType;
use crate::sync::block_lookups::parent_lookup::{ParentLookup, RequestError};
use crate::sync::block_lookups::single_block_lookup::{CachedChild, LookupRequestError};
use crate::sync::manager::{Id, SingleLookupReqId};
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
pub use beacon_chain::data_availability_checker::ChildComponents;
use beacon_chain::data_availability_checker::{
    AvailabilityCheckErrorCategory, DataAvailabilityChecker,
};
use beacon_chain::validator_monitor::timestamp_now;
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
use types::blob_sidecar::FixedBlobSidecarList;
use types::Slot;

pub mod common;
mod parent_lookup;
mod single_block_lookup;
#[cfg(test)]
mod tests;

const FAILED_CHAINS_CACHE_EXPIRY_SECONDS: u64 = 60;
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 3;

enum Action {
    Retry,
    ParentUnknown { parent_root: Hash256, slot: Slot },
    Drop,
    Continue,
}

pub struct BlockLookups<T: BeaconChainTypes> {
    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUTimeCache<Hash256>,

    single_block_lookups: FnvHashMap<Id, SingleBlockLookup<T>>,

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
        self.new_current_lookup(block_root, None, peer_source, cx)
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
        child_components: ChildComponents<T::EthSpec>,
        peer_source: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.new_current_lookup(block_root, Some(child_components), peer_source, cx)
    }

    /// Attempts to trigger the request matching the given `block_root`.
    pub fn trigger_single_lookup(
        &mut self,
        mut single_block_lookup: SingleBlockLookup<T>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = single_block_lookup.block_root();
        match single_block_lookup.request_block_and_blobs(cx) {
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
        child_components: Option<ChildComponents<T::EthSpec>>,
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
            if let Some(components) = child_components {
                lookup.add_child_components(components);
            }
            return;
        }

        let msg = if child_components.is_some() {
            "Searching for components of a block with unknown parent"
        } else {
            "Searching for block components"
        };

        let lookup = SingleBlockLookup::new(
            block_root,
            child_components,
            peers,
            self.da_checker.clone(),
            cx.next_id(),
            LookupType::Current,
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
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        debug!(self.log, "Created new parent lookup"; "block_root" => ?block_root, "parent_root" => ?parent_root);

        // TODO: Should check failed_chains inside new_current_lookup
        // TODO: Check max chain length

        self.new_current_lookup(parent_root, None, &[peer_id], cx);
    }

    /* Lookup responses */

    /// Get a single block lookup by its ID. This method additionally ensures the `req_counter`
    /// matches the current `req_counter` for the lookup. This ensures any stale responses from requests
    /// that have been retried are ignored.
    fn get_single_lookup<R: RequestState<T>>(
        &mut self,
        id: SingleLookupReqId,
    ) -> Option<SingleBlockLookup<T>> {
        let mut lookup = self.single_block_lookups.remove(&id.id)?;

        let request_state = R::request_state_mut(&mut lookup);
        if request_state
            .get_state()
            .is_current_req_counter(id.req_counter)
        {
            Some(lookup)
        } else {
            // We don't want to drop the lookup, just ignore the old response.
            self.single_block_lookups.insert(id.id, lookup);
            None
        }
    }

    /// Checks whether a single block lookup is waiting for a parent lookup to complete. This is
    /// necessary because we want to make sure all parents are processed before sending a child
    /// for processing, otherwise the block will fail validation and will be returned to the network
    /// layer with an `UnknownParent` error.
    pub fn has_pending_parent_request(&self, block_root: Hash256) -> bool {
        self.active_parent_lookups()
            .iter()
            .any(|parent_chain| parent_chain.contains(&block_root))
    }

    /// Process a block or blob response received from a single lookup request.
    pub fn single_lookup_response<R: RequestState<T>>(
        &mut self,
        lookup_id: SingleLookupReqId,
        peer_id: PeerId,
        response: R::VerifiedResponseType,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let id = lookup_id.id;
        let response_type = R::response_type();

        let Some(mut lookup) = self.get_single_lookup::<R>(lookup_id) else {
            // We don't have the ability to cancel in-flight RPC requests. So this can happen
            // if we started this RPC request, and later saw the block/blobs via gossip.
            debug!(
                self.log,
                "Block returned for single block lookup not present";
                    "response_type" => ?response_type,
            );
            return;
        };

        let expected_block_root = lookup.block_root();
        debug!(self.log,
            "Peer returned response for single lookup";
            "peer_id" => %peer_id ,
            "id" => ?id,
            "block_root" => ?expected_block_root,
            "response_type" => ?response_type,
        );

        match self.handle_verified_response::<R>(
            seen_timestamp,
            cx,
            BlockProcessType::SingleBlock { id: lookup.id },
            response,
            &mut lookup,
        ) {
            Ok(_) => {
                self.single_block_lookups.insert(id, lookup);
            }
            Err(e) => {
                debug!(self.log,
                    "Single lookup request failed";
                    "error" => ?e,
                    "block_root" => ?expected_block_root,
                );
            }
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /// Consolidates error handling for `single_lookup_response`. An `Err` here should always mean
    /// the lookup is dropped.
    fn handle_verified_response<R: RequestState<T>>(
        &self,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
        process_type: BlockProcessType,
        verified_response: R::VerifiedResponseType,
        lookup: &mut SingleBlockLookup<T>,
    ) -> Result<(), LookupRequestError> {
        let id = lookup.id;
        let block_root = lookup.block_root();

        let Some(cached_child) = lookup.add_response::<R>(verified_response.clone()) else {
            R::request_state_mut(lookup)
                .get_state_mut()
                .on_download_success()
                .map_err(LookupRequestError::BadState)?;

            return R::send_for_processing(
                id,
                self,
                block_root,
                verified_response,
                seen_timestamp,
                cx,
            );
        };

        self.send_cached_child_for_processing::<R>(
            seen_timestamp,
            cx,
            process_type,
            cached_child,
            lookup,
        )
    }

    /// Consolidates error handling for `single_lookup_response`. An `Err` here should always mean
    /// the lookup is dropped.
    fn send_cached_child_for_processing<R: RequestState<T>>(
        &self,
        seen_timestamp: Duration,
        cx: &mut SyncNetworkContext<T>,
        process_type: BlockProcessType,
        cached_child: CachedChild<T::EthSpec>,
        lookup: &mut SingleBlockLookup<T>,
    ) -> Result<(), LookupRequestError> {
        let id = lookup.id;
        let block_root = lookup.block_root();

        match cached_child {
            CachedChild::Ok(block) => {
                // If we have an outstanding parent request for this block, delay sending the response until
                // all parent blocks have been processed, otherwise we will fail validation with an
                // `UnknownParent`.
                let delay_send = match lookup.lookup_type {
                    LookupType::Parent => false,
                    LookupType::Current => self.has_pending_parent_request(lookup.block_root()),
                };

                if delay_send {
                    debug!(self.log, "Delaying import of response"; "block_root" => %lookup.block_root(), "lookup_type" => ?lookup.lookup_type, "type" => ?R::response_type());
                } else {
                    R::request_state_mut(lookup)
                        .get_state_mut()
                        .on_download_success()
                        .map_err(LookupRequestError::BadState)?;
                    self.send_block_for_processing(
                        block_root,
                        block,
                        seen_timestamp,
                        process_type,
                        cx,
                    )?
                }
            }
            CachedChild::DownloadIncomplete(reason) => {
                debug!(self.log, "CacheChild download incomplete"; "block_root" => %lookup.block_root(), "lookup_type" => ?lookup.lookup_type, "type" => ?R::response_type(), "reason" => reason);

                R::request_state_mut(lookup)
                    .get_state_mut()
                    .on_download_success()
                    .map_err(LookupRequestError::BadState)?;
                // If this was the result of a block request, we can't determine if the block peer
                // did anything wrong. If we already had both a block and blobs response processed,
                // we should penalize the blobs peer because they did not provide all blobs on the
                // initial request.
                if lookup.both_components_downloaded() {
                    lookup.penalize_blob_peer(cx);
                    lookup.blob_request_state.state.on_download_failure();
                }
                lookup.request_block_and_blobs(cx)?;
            }
            CachedChild::Err(e) => {
                warn!(self.log, "Consistency error in cached block";
                    "error" => ?e,
                    "block_root" => ?block_root
                );
                lookup.handle_consistency_failure(cx);
                lookup.request_block_and_blobs(cx)?;
            }
        }
        Ok(())
    }

    /// Handle logging and peer scoring for `RequestError`s during parent lookup requests.
    fn handle_parent_request_error(
        &mut self,
        parent_lookup: &mut ParentLookup<T>,
        cx: &SyncNetworkContext<T>,
        e: RequestError,
    ) {
        debug!(self.log, "Failed to request parent"; "error" => ?e);
        match e {
            RequestError::SendFailed(_) => {
                // Probably shutting down, nothing to do here. Drop the request
            }
            RequestError::ChainTooLong => {
                self.failed_chains.insert(parent_lookup.chain_hash());
                // This indicates faulty peers.
                for &peer_id in parent_lookup.all_used_peers() {
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e.as_static())
                }
            }
            RequestError::TooManyAttempts { cannot_process } => {
                // We only consider the chain failed if we were unable to process it.
                // We could have failed because one peer continually failed to send us
                // bad blocks. We still allow other peers to send us this chain. Note
                // that peers that do this, still get penalised.
                if cannot_process {
                    self.failed_chains.insert(parent_lookup.chain_hash());
                }
                // This indicates faulty peers.
                for &peer_id in parent_lookup.all_used_peers() {
                    cx.report_peer(peer_id, PeerAction::LowToleranceError, e.as_static())
                }
            }
            RequestError::NoPeers => {
                // This happens if the peer disconnects while the block is being
                // processed. Drop the request without extra penalty
            }
            RequestError::BadState(..) => {
                warn!(self.log, "Request parent on bad state"; "error" => e.as_static());
                #[cfg(test)]
                panic!("bad state");
            }
        }
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

    /// An RPC error has occurred during a single lookup. This function handles this case.\
    pub fn single_block_lookup_failed<R: RequestState<T>>(
        &mut self,
        id: SingleLookupReqId,
        peer_id: &PeerId,
        cx: &mut SyncNetworkContext<T>,
        error: LookupFailure,
    ) {
        // Only downscore lookup verify errors. RPC errors are downscored in the network handler.
        if let LookupFailure::LookupVerifyError(e) = &error {
            // Downscore peer even if lookup is not known
            self.downscore_on_rpc_error(peer_id, e, cx);
        }

        let log = self.log.clone();
        let Some(mut lookup) = self.get_single_lookup::<R>(id) else {
            debug!(log, "Error response to dropped lookup"; "error" => %error);
            return;
        };
        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);
        let response_type = R::response_type();
        trace!(log,
            "Single lookup failed";
            "block_root" => ?block_root,
            "error" => %error,
            "peer_id" => %peer_id,
            "response_type" => ?response_type
        );
        let id = id.id;
        request_state.register_failure_downloading();
        if let Err(e) = lookup.request_block_and_blobs(cx) {
            debug!(self.log,
                "Single lookup retry failed";
                "error" => ?e,
                "block_root" => ?block_root,
            );
        } else {
            self.single_block_lookups.insert(id, lookup);
        }

        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }

    /* Processing responses */

    pub fn single_block_component_processed<R: RequestState<T>>(
        &mut self,
        target_id: Id,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(mut lookup) = self.single_block_lookups.remove(&target_id) else {
            debug!(self.log, "Unknown single block lookup"; "target_id" => target_id);
            return;
        };

        let block_root = lookup.block_root();
        let request_state = R::request_state_mut(&mut lookup);

        let peer_id = match request_state.get_state().processing_peer() {
            Ok(peer_id) => peer_id,
            Err(e) => {
                // TODO: This log will fire when processing the child block that triggered a parent
                // lookup. If the result is Ok(Imported) or Err(BlockIsAlreadyKnown), there's no
                // effect since the lookup is dropped anyway. However, for other variants there may
                // be inconsistencies. The problem lies on the lookup transitioning from a child
                // components into a regular lookup.
                warn!(self.log, "Attempting to process single block lookup in bad state"; "id" => target_id, "response_type" => ?R::response_type(), "error" => e);
                #[cfg(test)]
                panic!("bad state");
                #[cfg(not(test))]
                return;
            }
        };
        debug!(
            self.log,
            "Block component processed for lookup";
            "response_type" => ?R::response_type(),
            "block_root" => ?block_root,
            "result" => ?result,
            "id" => target_id,
        );

        let action = match result {
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(_))
            | BlockProcessingResult::Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                // Successfully imported
                // TODO: Potentially import child blocks
                trace!(self.log, "Single block processing succeeded"; "block" => %block_root);
                Action::Drop
            }

            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                _,
                _block_root,
            )) => {
                // `on_processing_success` is called here to ensure the request state is updated prior to checking
                // if both components have been processed.
                if R::request_state_mut(&mut lookup)
                    .get_state_mut()
                    .on_processing_success()
                    .is_err()
                {
                    warn!(
                        self.log,
                        "Single block processing state incorrect";
                        "action" => "dropping single block request"
                    );
                    Action::Drop
                // If this was the result of a block request, we can't determined if the block peer did anything
                // wrong. If we already had both a block and blobs response processed, we should penalize the
                // blobs peer because they did not provide all blobs on the initial request.
                } else if lookup.both_components_processed() {
                    lookup.penalize_blob_peer(cx);

                    // Try it again if possible.
                    lookup.blob_request_state.state.on_processing_failure();
                    Action::Retry
                } else {
                    Action::Continue
                }
            }
            BlockProcessingResult::Ignored => {
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
                        lookup.add_child_components(block.into());
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
                            lookup.handle_availability_check_failure(cx);
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
                if let Err(e) = lookup.request_block_and_blobs(cx) {
                    warn!(self.log, "Single block lookup failed"; "block_root" => %block_root, "error" => ?e);
                    // Failed with too many retries, drop with noop
                    self.update_metrics();
                } else {
                    self.single_block_lookups.insert(target_id, lookup);
                }
            }
            Action::ParentUnknown { parent_root, slot } => {
                // TODO: Consider including all peers from the lookup, claiming to know this block, not
                // just the one that sent this specific block
                self.search_parent(slot, block_root, parent_root, peer_id, cx);
                self.single_block_lookups.insert(target_id, lookup);
            }
            Action::Drop => {
                // drop with noop
                self.update_metrics();
            }
            Action::Continue => {
                self.single_block_lookups.insert(target_id, lookup);
            }
        }
    }

    pub fn send_child_of_parent_chain_for_processing(
        &mut self,
        chain_hash: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(id) = self
            .single_block_lookups
            .iter()
            .find_map(|(id, req)| (req.block_root() == chain_hash).then_some(*id))
        else {
            warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
            return;
        };

        let Some(lookup) = self.single_block_lookups.get_mut(&id) else {
            warn!(self.log, "No id found for single block lookup"; "chain_hash" => %chain_hash);
            return;
        };

        let Some(cached_child) = lookup.get_cached_child_block() else {
            warn!(self.log, "Child not cached for parent lookup"; "chain_hash" => %chain_hash);
            return;
        };

        match cached_child {
            CachedChild::Ok(rpc_block) => {
                let some_peer_lol = if let Some(peer_id) = lookup.all_used_peers().next() {
                    *peer_id
                } else {
                    warn!(self.log, "Should have at least one peer");
                    PeerId::random()
                };
                if let Err(e) = lookup.force_into_processing_state(some_peer_lol) {
                    warn!(self.log, "Request in bad state"; "error" => e);
                }

                // This is the correct block, send it for processing
                if self
                    .send_block_for_processing(
                        chain_hash,
                        rpc_block,
                        timestamp_now(),
                        BlockProcessType::SingleBlock { id },
                        cx,
                    )
                    .is_err()
                {
                    // Remove to avoid inconsistencies
                    self.single_block_lookups.remove(&id);
                }
            }
            CachedChild::DownloadIncomplete(reason) => {
                debug!(self.log, "Parent chain complete, awaiting child response"; "chain_hash" => %chain_hash, "reason" => reason);
            }
            CachedChild::Err(e) => {
                warn!(
                    self.log,
                    "Consistency error in child block triggering parent lookup";
                    "chain_hash" => %chain_hash,
                    "error" => ?e
                );
                lookup.handle_consistency_failure(cx);
                if let Err(e) = lookup.request_block_and_blobs(cx) {
                    debug!(self.log,
                        "Failed to request block and blobs, dropping lookup";
                        "error" => ?e
                    );
                    self.single_block_lookups.remove(&id);
                }
            }
        }
    }

    /* Helper functions */

    fn send_block_for_processing(
        &self,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        match cx.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                debug!(self.log, "Sending block for processing"; "block" => ?block_root, "process" => ?process_type);
                if let Err(e) = beacon_processor.send_rpc_beacon_block(
                    block_root,
                    block,
                    duration,
                    process_type,
                ) {
                    error!(
                        self.log,
                        "Failed to send sync block to processor";
                        "error" => ?e
                    );
                    Err(LookupRequestError::SendFailed(
                        "beacon processor send failure",
                    ))
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping block ready for processing. Beacon processor not available"; "block" => %block_root);
                Err(LookupRequestError::SendFailed(
                    "beacon processor unavailable",
                ))
            }
        }
    }

    fn send_blobs_for_processing(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        match cx.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                trace!(self.log, "Sending blobs for processing"; "block" => ?block_root, "process_type" => ?process_type);
                if let Err(e) =
                    beacon_processor.send_rpc_blobs(block_root, blobs, duration, process_type)
                {
                    error!(
                        self.log,
                        "Failed to send sync blobs to processor";
                        "error" => ?e
                    );
                    Err(LookupRequestError::SendFailed(
                        "beacon processor send failure",
                    ))
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping blobs ready for processing. Beacon processor not available"; "block_root" => %block_root);
                Err(LookupRequestError::SendFailed(
                    "beacon processor unavailable",
                ))
            }
        }
    }

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
        let error_str: &'static str = error.into();

        debug!(self.log, "reporting peer for sync lookup error"; "error" => error_str);
        cx.report_peer(*peer_id, PeerAction::LowToleranceError, error_str);
    }

    pub fn update_metrics(&self) {
        metrics::set_gauge(
            &metrics::SYNC_SINGLE_BLOCK_LOOKUPS,
            self.single_block_lookups.len() as i64,
        );
    }
}
