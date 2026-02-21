use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::sync::network_context::{
    LookupRequestResult, PeerGroup, ReqId, RpcRequestSendError, SendErrorProcessor,
    SyncNetworkContext,
};
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_availability_checker::AvailableBlockData;
use educe::Educe;
use lighthouse_network::service::api_types::Id;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use tracing::{Span, debug_span};
use types::data::{BlobSidecarList, FixedBlobSidecarList};
use types::{
    DataColumnSidecarList, EthSpec, ForkName, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
    Slot,
};

// === Public types re-exported by mod.rs ===

#[derive(Debug, Clone)]
pub struct DownloadResult<T: Clone> {
    pub value: T,
    pub block_root: Hash256,
    pub seen_timestamp: Duration,
    pub peer_group: PeerGroup,
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    /// Error sending event to network
    SendFailedNetwork(RpcRequestSendError),
    /// Error sending event to processor
    SendFailedProcessor(SendErrorProcessor),
    /// Inconsistent lookup request state
    BadState(String),
    /// Lookup failed for some other reason and should be dropped
    Failed(/* reason: */ String),
    /// Attempted to retrieve a not known lookup id
    UnknownLookup,
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: ReqId,
        req_id: ReqId,
    },
    InternalError(String),
}

// Dedicated enum for LookupResult to force its usage
#[must_use = "LookupResult must be handled with on_lookup_result"]
pub enum LookupResult {
    /// Lookup completed successfully
    Completed,
    /// Lookup is expecting some future event from the network
    Pending,
    /// Block's parent is not known to fork-choice, a parent lookup is needed
    ParentUnknown { parent_root: Hash256 },
}

/// Tracks which peers served which block components in a completed request. When the
/// beacon processor returns an error identifying a specific invalid component, this
/// struct allows attributing fault to the peer(s) that actually served that data.
///
/// The block is always from a single peer, and blobs come from the same peer as
/// the block, so only the block peer needs tracking. Custody columns have per-index
/// peer attribution for granular scoring on InvalidColumn errors.
#[derive(Debug, Clone)]
pub struct RequestsPeers {
    pub block: PeerId,
    pub custody_columns: Option<PeerGroup>,
}

// === SingleBlockLookup ===

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    state: LookupState<T>,
    /// Peers that claim to have imported this set of block components. This state is shared with
    /// the custody request to have an updated view of the peers that claim to have imported the
    /// block associated with this lookup. The peer set of a lookup can change rapidly, and faster
    /// than the lifetime of a custody request.
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: Arc<RwLock<HashSet<PeerId>>>,
    block_root: Hash256,
    awaiting_parent: Option<Hash256>,
    created: Instant,
    pub(crate) span: Span,
}

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
enum LookupState<T: BeaconChainTypes> {
    Downloading(BlockComponentsByRootRequest<T>),
    Processing {
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        #[educe(Debug(ignore))]
        extras: BlockExtras<T::EthSpec>,
        requests_peers: RequestsPeers,
    },
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
        peers: &[PeerId],
        id: Id,
        awaiting_parent: Option<Hash256>,
    ) -> Self {
        let lookup_span = debug_span!(
            "lh_single_block_lookup",
            block_root = %requested_block_root,
            id = id,
        );

        let peers = Arc::new(RwLock::new(HashSet::from_iter(peers.iter().copied())));

        Self {
            id,
            state: LookupState::Downloading(BlockComponentsByRootRequest::new(
                requested_block_root,
                peers.clone(),
            )),
            peers,
            block_root: requested_block_root,
            awaiting_parent,
            created: Instant::now(),
            span: lookup_span,
        }
    }

    /// Reset the status of all internal requests
    pub fn reset_requests(&mut self) {
        self.state = LookupState::Downloading(BlockComponentsByRootRequest::new(
            self.block_root,
            self.peers.clone(),
        ));
    }

    /// Return the slot of this lookup's block if it's currently cached
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        match &self.state {
            LookupState::Downloading(req) => req.peek_downloaded_block_slot(),
            LookupState::Processing { block, .. } => Some(block.slot()),
        }
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn awaiting_parent(&self) -> Option<Hash256> {
        self.awaiting_parent
    }

    /// Mark this lookup as awaiting a parent lookup from being processed. Meanwhile don't send
    /// components for processing.
    pub fn set_awaiting_parent(&mut self, parent_root: Hash256) {
        self.awaiting_parent = Some(parent_root)
    }

    /// Mark this lookup as no longer awaiting a parent lookup. Components can be sent for
    /// processing.
    pub fn resolve_awaiting_parent(&mut self) {
        self.awaiting_parent = None;
    }

    /// Returns the time elapsed since this lookup was created
    pub fn elapsed_since_created(&self) -> Duration {
        self.created.elapsed()
    }

    /// Maybe insert a verified response into this lookup. Returns true if imported
    pub fn add_child_components(&mut self, block_component: BlockComponent<T::EthSpec>) -> bool {
        match block_component {
            BlockComponent::Block(block) => match &mut self.state {
                LookupState::Downloading(req) => req.add_child_block(block),
                _ => false,
            },
            BlockComponent::Blob(_) | BlockComponent::DataColumn(_) => {
                // For now ignore single blobs and columns, as the blob request state assumes all blobs are
                // attributed to the same peer = the peer serving the remaining blobs. Ignoring this
                // block component has a minor effect, causing the node to re-request this blob
                // once the parent chain is successfully resolved
                false
            }
        }
    }

    /// Check the block root matches the requested block root.
    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_root() == block_root
    }

    /// Returns true if this request is expecting some event to make progress
    pub fn is_awaiting_event(&self) -> bool {
        self.awaiting_parent.is_some()
            || match &self.state {
                LookupState::Downloading(req) => req.is_awaiting_event(),
                LookupState::Processing { .. } => false,
            }
    }

    /// Returns the component peer attribution if the lookup is in processing state.
    /// Used for granular peer penalization on processing errors.
    pub fn requests_peers(&self) -> Option<&RequestsPeers> {
        match &self.state {
            LookupState::Processing { requests_peers, .. } => Some(requests_peers),
            _ => None,
        }
    }

    /// Makes progress on all requests of this lookup. Any error is not recoverable and must result
    /// in dropping the lookup. May mark the lookup as completed.
    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        let _guard = self.span.clone().entered();
        let id = self.id;

        loop {
            match &mut self.state {
                LookupState::Downloading(req) => {
                    let result = req.continue_requests(id, cx)?;

                    if let Some(result) = result {
                        self.state = LookupState::Processing {
                            block: result.block,
                            extras: result.extras,
                            requests_peers: result.requests_peers,
                        };
                        if self.awaiting_parent.is_some() {
                            break;
                        }
                        // Continue the loop to handle Processing
                    } else {
                        // Awaiting downloads
                        break;
                    }
                }
                LookupState::Processing { block, extras, .. } => {
                    // If awaiting parent, don't send for processing yet
                    if self.awaiting_parent.is_some() {
                        break;
                    }

                    let parent_root = block.parent_root();
                    if !cx.chain.block_is_known_to_fork_choice(&parent_root) {
                        return Ok(LookupResult::ParentUnknown { parent_root });
                    }

                    let block_root = self.block_root;
                    let block_data = extras.into_available_block_data()?;

                    cx.send_block_for_processing(
                        id,
                        block_root,
                        block.clone(),
                        block_data,
                        Duration::ZERO, // TODO: track seen_timestamp properly
                    )
                    .map_err(LookupRequestError::SendFailedProcessor)?;

                    return Ok(LookupResult::Pending);
                }
            }
        }

        Ok(LookupResult::Pending)
    }

    /// Handle a block download response. Updates download state and advances the lookup.
    pub fn on_block_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<(Arc<SignedBeaconBlock<T::EthSpec>>, PeerGroup, Duration), ()>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        match &mut self.state {
            LookupState::Downloading(req) => {
                req.on_block_response(req_id, result, self.id, cx)?;
            }
            _ => {
                return Err(LookupRequestError::BadState(
                    "block response not active".to_owned(),
                ));
            }
        }
        self.continue_requests(cx)
    }

    /// Handle a blob download response. Updates download state and advances the lookup.
    pub fn on_blob_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<(FixedBlobSidecarList<T::EthSpec>, PeerGroup, Duration), ()>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        match &mut self.state {
            LookupState::Downloading(req) => {
                req.on_blob_response(req_id, result, self.id, cx)?;
            }
            _ => {
                return Err(LookupRequestError::BadState(
                    "blob response not active".to_owned(),
                ));
            }
        }
        self.continue_requests(cx)
    }

    /// Handle a custody columns download response. Updates download state and advances the lookup.
    pub fn on_custody_download_response(
        &mut self,
        req_id: ReqId,
        result: Result<(DataColumnSidecarList<T::EthSpec>, PeerGroup, Duration), ()>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<LookupResult, LookupRequestError> {
        match &mut self.state {
            LookupState::Downloading(req) => {
                req.on_custody_response(req_id, result, self.id, cx)?;
            }
            _ => {
                return Err(LookupRequestError::BadState(
                    "custody response not active".to_owned(),
                ));
            }
        }
        self.continue_requests(cx)
    }

    /// Get all unique peers that claim to have imported this set of block components
    pub fn all_peers(&self) -> Vec<PeerId> {
        self.peers.read().iter().copied().collect()
    }

    /// Add peer to all request states. The peer must be able to serve this request.
    /// Returns true if the peer was newly inserted into some request state.
    pub fn add_peer(&mut self, peer_id: PeerId) -> bool {
        self.peers.write().insert(peer_id)
    }

    /// Remove peer from available peers.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }

    /// Returns true if this lookup has zero peers
    pub fn has_no_peers(&self) -> bool {
        self.peers.read().is_empty()
    }
}

// === BlockComponentsByRootRequest — two-phase download state machine ===

/// Result returned when all block components have been downloaded.
#[derive(Debug)]
struct BlockComponentsResult<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    extras: BlockExtras<E>,
    requests_peers: RequestsPeers,
}

#[derive(Debug)]
pub(crate) enum BlockExtras<E: EthSpec> {
    Electra(FixedBlobSidecarList<E>),
    Fulu(CustodyColumnsResult<E>),
    Gloas(PayloadResult<E>, CustodyColumnsResult<E>),
    None,
}

impl<E: EthSpec> BlockExtras<E> {
    /// Convert downloaded extras into `AvailableBlockData` for block processing.
    fn into_available_block_data(
        &self,
    ) -> Result<Option<AvailableBlockData<E>>, LookupRequestError> {
        match self {
            BlockExtras::None => Ok(None),
            BlockExtras::Electra(fixed_blobs) => {
                let blobs: Vec<_> = fixed_blobs.iter().flatten().cloned().collect();
                if blobs.is_empty() {
                    Ok(Some(AvailableBlockData::NoData))
                } else {
                    // Use the fixed vector length as max_len since it matches max_blobs_per_block
                    let blob_list = BlobSidecarList::new(blobs, fixed_blobs.len())
                        .map_err(|e| LookupRequestError::Failed(format!("invalid blobs: {e:?}")))?;
                    Ok(Some(AvailableBlockData::Blobs(blob_list)))
                }
            }
            BlockExtras::Fulu(columns) => match columns {
                CustodyColumnsResult::NoData => Ok(Some(AvailableBlockData::NoData)),
                CustodyColumnsResult::Columns(cols) => {
                    Ok(Some(AvailableBlockData::DataColumns(cols.clone())))
                }
            },
            BlockExtras::Gloas(_payload, columns) => {
                // TODO(gloas): Handle payload envelope when supported
                match columns {
                    CustodyColumnsResult::NoData => Ok(Some(AvailableBlockData::NoData)),
                    CustodyColumnsResult::Columns(cols) => {
                        Ok(Some(AvailableBlockData::DataColumns(cols.clone())))
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum PayloadResult<E: EthSpec> {
    Full(Arc<SignedExecutionPayloadEnvelope<E>>),
    Empty,
}

#[derive(Debug)]
enum CustodyColumnsResult<E: EthSpec> {
    Columns(DataColumnSidecarList<E>),
    NoData,
}

/// Manages the download of a block and its associated extras (blobs, custody columns, payload)
/// via a two-phase state machine: first download the block, then download fork-dependent extras.
#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
struct BlockComponentsByRootRequest<T: BeaconChainTypes> {
    block_root: Hash256,
    #[educe(Debug(method(fmt_peer_set_as_len)))]
    peers: Arc<RwLock<HashSet<PeerId>>>,
    state: DownloadPhase<T::EthSpec>,
}

#[derive(Debug)]
enum DownloadPhase<E: EthSpec> {
    BlockDownload {
        block_req: BlockRequestState<E>,
    },
    ExtrasDownload {
        block: Arc<SignedBeaconBlock<E>>,
        block_peer: PeerId,
        extra_requests: BlockExtraRequests<E>,
    },
}

#[derive(Debug)]
enum BlockExtraRequests<E: EthSpec> {
    ElectraBlobs(Option<BlobRequestState<E>>),
    FuluColumns(Option<CustodyRequestState<E>>),
    Gloas {
        payload_req: Option<PayloadRequestState<E>>,
        columns_req: Option<CustodyRequestState<E>>,
    },
}

impl<T: BeaconChainTypes> BlockComponentsByRootRequest<T> {
    fn new(block_root: Hash256, peers: Arc<RwLock<HashSet<PeerId>>>) -> Self {
        Self {
            block_root,
            peers,
            state: DownloadPhase::BlockDownload {
                block_req: BlockRequestState::new(block_root),
            },
        }
    }

    fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        match &self.state {
            DownloadPhase::BlockDownload { block_req } => block_req
                .state
                .peek_downloaded_data()
                .map(|block| block.slot()),
            DownloadPhase::ExtrasDownload { block, .. } => Some(block.slot()),
        }
    }

    fn is_awaiting_event(&self) -> bool {
        match &self.state {
            DownloadPhase::BlockDownload { block_req } => block_req.state.is_awaiting_event(),
            DownloadPhase::ExtrasDownload {
                extra_requests: extras,
                ..
            } => match extras {
                BlockExtraRequests::ElectraBlobs(Some(blobs)) => blobs.state.is_awaiting_event(),
                BlockExtraRequests::ElectraBlobs(None) => false,
                BlockExtraRequests::FuluColumns(Some(columns)) => columns.state.is_awaiting_event(),
                BlockExtraRequests::FuluColumns(None) => false,
                BlockExtraRequests::Gloas {
                    payload_req,
                    columns_req,
                } => {
                    payload_req
                        .as_ref()
                        .map(|req| req.state.is_awaiting_event())
                        .unwrap_or(false)
                        || columns_req
                            .as_ref()
                            .map(|c| c.state.is_awaiting_event())
                            .unwrap_or(false)
                }
            },
        }
    }

    fn add_child_block(
        &mut self,
        block: DownloadResult<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> bool {
        match &mut self.state {
            DownloadPhase::BlockDownload { block_req } => {
                block_req.state.insert_verified_response(block)
            }
            _ => false,
        }
    }

    /// Drive the state machine. Returns `Some(result)` when all components are downloaded.
    fn continue_requests(
        &mut self,
        id: Id,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<BlockComponentsResult<T::EthSpec>>, LookupRequestError> {
        loop {
            match &mut self.state {
                DownloadPhase::BlockDownload { block_req } => {
                    block_req.continue_request(id, self.peers.clone(), cx)?;

                    if let Some(block) = block_req.take_completed() {
                        let block_peer = block_req
                            .state
                            .peek_downloaded_peer_group()
                            .and_then(|pg| pg.all().next().copied())
                            .expect("block download must have a peer");
                        let expected_blobs = block.num_expected_blobs();
                        let block_fork =
                            cx.chain.spec.fork_name_at_slot::<T::EthSpec>(block.slot());

                        let extras = match block_fork {
                            ForkName::Base
                            | ForkName::Altair
                            | ForkName::Bellatrix
                            | ForkName::Capella => {
                                return Err(LookupRequestError::Failed(
                                    "Unsupported fork pre-deneb".to_string(),
                                ));
                            }
                            ForkName::Deneb | ForkName::Electra => {
                                BlockExtraRequests::ElectraBlobs(if expected_blobs > 0 {
                                    Some(BlobRequestState::new(self.block_root, expected_blobs))
                                } else {
                                    None
                                })
                            }
                            ForkName::Fulu => {
                                BlockExtraRequests::FuluColumns(if expected_blobs > 0 {
                                    Some(CustodyRequestState::new(self.block_root))
                                } else {
                                    None
                                })
                            }
                            ForkName::Gloas => BlockExtraRequests::Gloas {
                                // TODO(gloas): Only request if full
                                payload_req: Some(PayloadRequestState::new(self.block_root)),
                                columns_req: if expected_blobs > 0 {
                                    Some(CustodyRequestState::new(self.block_root))
                                } else {
                                    None
                                },
                            },
                        };

                        self.state = DownloadPhase::ExtrasDownload {
                            block,
                            block_peer,
                            extra_requests: extras,
                        };
                        // Continue the loop to make progress on extras
                    } else {
                        break;
                    }
                }
                DownloadPhase::ExtrasDownload { extra_requests, .. } => {
                    // Make progress on all extra requests
                    match extra_requests {
                        BlockExtraRequests::ElectraBlobs(Some(blobs_req)) => {
                            blobs_req.continue_request(id, self.peers.clone(), cx)?;
                        }
                        BlockExtraRequests::FuluColumns(Some(columns_req)) => {
                            columns_req.continue_request(id, self.peers.clone(), cx)?;
                        }
                        BlockExtraRequests::ElectraBlobs(None)
                        | BlockExtraRequests::FuluColumns(None) => {}
                        BlockExtraRequests::Gloas {
                            payload_req,
                            columns_req,
                        } => {
                            if let Some(payload_req) = payload_req {
                                payload_req.continue_request(id, self.peers.clone(), cx)?;
                            }
                            if let Some(columns_req) = columns_req {
                                columns_req.continue_request(id, self.peers.clone(), cx)?;
                            }
                        }
                    }

                    // Check if all extras are completed
                    let extras_completed = match extra_requests {
                        BlockExtraRequests::ElectraBlobs(Some(blobs_req)) => {
                            blobs_req.take_completed().map(BlockExtras::Electra)
                        }
                        BlockExtraRequests::FuluColumns(Some(columns_req)) => columns_req
                            .take_completed()
                            .map(|cols| BlockExtras::Fulu(CustodyColumnsResult::Columns(cols))),
                        BlockExtraRequests::ElectraBlobs(None) => Some(BlockExtras::None),
                        BlockExtraRequests::FuluColumns(None) => Some(BlockExtras::None),
                        BlockExtraRequests::Gloas {
                            payload_req,
                            columns_req,
                        } => {
                            let payload_done = match payload_req {
                                Some(req) => req.take_completed().map(PayloadResult::Full),
                                None => Some(PayloadResult::Empty),
                            };
                            let columns_done = match columns_req {
                                Some(req) => {
                                    req.take_completed().map(CustodyColumnsResult::Columns)
                                }
                                None => Some(CustodyColumnsResult::NoData),
                            };
                            match (payload_done, columns_done) {
                                (Some(payload), Some(columns)) => {
                                    Some(BlockExtras::Gloas(payload, columns))
                                }
                                _ => None,
                            }
                        }
                    };

                    if let Some(extras) = extras_completed {
                        let custody_peer_group = match extra_requests {
                            BlockExtraRequests::FuluColumns(Some(req)) => {
                                req.state.peek_downloaded_peer_group().cloned()
                            }
                            BlockExtraRequests::Gloas {
                                columns_req: Some(req),
                                ..
                            } => req.state.peek_downloaded_peer_group().cloned(),
                            _ => None,
                        };

                        let old_state = std::mem::replace(
                            &mut self.state,
                            DownloadPhase::BlockDownload {
                                block_req: BlockRequestState::new(self.block_root),
                            },
                        );
                        let (block, block_peer) = match old_state {
                            DownloadPhase::ExtrasDownload {
                                block, block_peer, ..
                            } => (block, block_peer),
                            _ => unreachable!(),
                        };

                        return Ok(Some(BlockComponentsResult {
                            block,
                            extras,
                            requests_peers: RequestsPeers {
                                block: block_peer,
                                custody_columns: custody_peer_group,
                            },
                        }));
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(None)
    }

    fn on_block_response(
        &mut self,
        req_id: ReqId,
        result: Result<(Arc<SignedBeaconBlock<T::EthSpec>>, PeerGroup, Duration), ()>,
        id: Id,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<BlockComponentsResult<T::EthSpec>>, LookupRequestError> {
        let state = match &mut self.state {
            DownloadPhase::BlockDownload { block_req } => &mut block_req.state,
            _ => {
                return Err(LookupRequestError::BadState(
                    "block response not active".to_owned(),
                ));
            }
        };
        match result {
            Ok((value, peer_group, seen_timestamp)) => {
                state.on_download_success(
                    req_id,
                    DownloadResult {
                        value,
                        block_root: self.block_root,
                        seen_timestamp,
                        peer_group,
                    },
                )?;
            }
            Err(()) => {
                state.on_download_failure(req_id)?;
            }
        }
        self.continue_requests(id, cx)
    }

    fn on_blob_response(
        &mut self,
        req_id: ReqId,
        result: Result<(FixedBlobSidecarList<T::EthSpec>, PeerGroup, Duration), ()>,
        id: Id,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<BlockComponentsResult<T::EthSpec>>, LookupRequestError> {
        let state = match &mut self.state {
            DownloadPhase::ExtrasDownload {
                extra_requests: BlockExtraRequests::ElectraBlobs(Some(req)),
                ..
            } => &mut req.state,
            _ => {
                return Err(LookupRequestError::BadState(
                    "blob response not active".to_owned(),
                ));
            }
        };
        match result {
            Ok((value, peer_group, seen_timestamp)) => {
                state.on_download_success(
                    req_id,
                    DownloadResult {
                        value,
                        block_root: self.block_root,
                        seen_timestamp,
                        peer_group,
                    },
                )?;
            }
            Err(()) => {
                state.on_download_failure(req_id)?;
            }
        }
        self.continue_requests(id, cx)
    }

    fn on_custody_response(
        &mut self,
        req_id: ReqId,
        result: Result<(DataColumnSidecarList<T::EthSpec>, PeerGroup, Duration), ()>,
        id: Id,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Option<BlockComponentsResult<T::EthSpec>>, LookupRequestError> {
        let state = match &mut self.state {
            DownloadPhase::ExtrasDownload {
                extra_requests:
                    BlockExtraRequests::FuluColumns(Some(req))
                    | BlockExtraRequests::Gloas {
                        columns_req: Some(req),
                        ..
                    },
                ..
            } => &mut req.state,
            _ => {
                return Err(LookupRequestError::BadState(
                    "custody response not active".to_owned(),
                ));
            }
        };
        match result {
            Ok((value, peer_group, seen_timestamp)) => {
                state.on_download_success(
                    req_id,
                    DownloadResult {
                        value,
                        block_root: self.block_root,
                        seen_timestamp,
                        peer_group,
                    },
                )?;
            }
            Err(()) => {
                state.on_download_failure(req_id)?;
            }
        }
        self.continue_requests(id, cx)
    }
}

// === Per-component request states ===

#[derive(Educe)]
#[educe(Debug)]
struct BlobRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    block_root: Hash256,
    expected_blobs: usize,
    state: SingleLookupRequestState<FixedBlobSidecarList<E>>,
}

impl<E: EthSpec> BlobRequestState<E> {
    fn new(block_root: Hash256, expected_blobs: usize) -> Self {
        Self {
            block_root,
            expected_blobs,
            state: SingleLookupRequestState::new(),
        }
    }

    fn continue_request<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: Id,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        if self.state.is_awaiting_download() {
            if self.state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = self.state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            match cx
                .blob_lookup_request(id, peers, self.block_root, self.expected_blobs)
                .map_err(LookupRequestError::SendFailedNetwork)?
            {
                LookupRequestResult::RequestSent(req_id) => self.state.on_download_start(req_id)?,
                LookupRequestResult::NoRequestNeeded(reason) => {
                    self.state.on_completed_request(reason)?;
                }
                LookupRequestResult::Pending(reason) => {
                    self.state.update_awaiting_download_status(reason);
                }
            }
        }
        Ok(())
    }

    fn take_completed(&self) -> Option<FixedBlobSidecarList<E>> {
        self.state.peek_downloaded_data().cloned()
    }
}

#[derive(Educe)]
#[educe(Debug)]
struct CustodyRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    block_root: Hash256,
    state: SingleLookupRequestState<DataColumnSidecarList<E>>,
}

impl<E: EthSpec> CustodyRequestState<E> {
    fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    fn continue_request<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: Id,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        if self.state.is_awaiting_download() {
            if self.state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = self.state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            match cx
                .custody_lookup_request(id, self.block_root, peers)
                .map_err(LookupRequestError::SendFailedNetwork)?
            {
                LookupRequestResult::RequestSent(req_id) => self.state.on_download_start(req_id)?,
                LookupRequestResult::NoRequestNeeded(reason) => {
                    self.state.on_completed_request(reason)?;
                }
                LookupRequestResult::Pending(reason) => {
                    self.state.update_awaiting_download_status(reason);
                }
            }
        }
        Ok(())
    }

    fn take_completed(&self) -> Option<DataColumnSidecarList<E>> {
        self.state.peek_downloaded_data().cloned()
    }
}

#[derive(Educe)]
#[educe(Debug)]
struct BlockRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    block_root: Hash256,
    state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlockRequestState<E> {
    fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    fn continue_request<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: Id,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        if self.state.is_awaiting_download() {
            if self.state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = self.state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            match cx
                .block_lookup_request(id, peers, self.block_root)
                .map_err(LookupRequestError::SendFailedNetwork)?
            {
                LookupRequestResult::RequestSent(req_id) => self.state.on_download_start(req_id)?,
                LookupRequestResult::NoRequestNeeded(reason) => {
                    self.state.on_completed_request(reason)?;
                }
                LookupRequestResult::Pending(reason) => {
                    self.state.update_awaiting_download_status(reason);
                }
            }
        }
        Ok(())
    }

    fn take_completed(&self) -> Option<Arc<SignedBeaconBlock<E>>> {
        self.state.peek_downloaded_data().cloned()
    }
}

#[derive(Educe)]
#[educe(Debug)]
struct PayloadRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    block_root: Hash256,
    state: SingleLookupRequestState<Arc<SignedExecutionPayloadEnvelope<E>>>,
}

impl<E: EthSpec> PayloadRequestState<E> {
    fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    fn continue_request<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: Id,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        if self.state.is_awaiting_download() {
            if self.state.failed_attempts() >= SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS {
                let cannot_process = self.state.more_failed_processing_attempts();
                return Err(LookupRequestError::TooManyAttempts { cannot_process });
            }

            // TODO(gloas): Use a proper payload lookup request method
            match cx
                .block_lookup_request(id, peers, self.block_root)
                .map_err(LookupRequestError::SendFailedNetwork)?
            {
                LookupRequestResult::RequestSent(req_id) => self.state.on_download_start(req_id)?,
                LookupRequestResult::NoRequestNeeded(reason) => {
                    self.state.on_completed_request(reason)?;
                }
                LookupRequestResult::Pending(reason) => {
                    self.state.update_awaiting_download_status(reason);
                }
            }
        }
        Ok(())
    }

    fn take_completed(&self) -> Option<Arc<SignedExecutionPayloadEnvelope<E>>> {
        self.state.peek_downloaded_data().cloned()
    }
}

// === Generic download state machine ===

#[derive(IntoStaticStr)]
enum DownloadState<T: Clone> {
    AwaitingDownload(/* reason */ &'static str),
    Downloading(ReqId),
    Downloaded(DownloadResult<T>),
}

/// Object representing the state of a single block or blob lookup request.
#[derive(Debug)]
struct SingleLookupRequestState<T: Clone> {
    state: DownloadState<T>,
    failed_processing: u8,
    failed_downloading: u8,
}

impl<T: Clone> SingleLookupRequestState<T> {
    fn new() -> Self {
        Self {
            state: DownloadState::AwaitingDownload("not started"),
            failed_processing: 0,
            failed_downloading: 0,
        }
    }

    fn is_awaiting_download(&self) -> bool {
        matches!(self.state, DownloadState::AwaitingDownload { .. })
    }

    fn is_awaiting_event(&self) -> bool {
        matches!(self.state, DownloadState::Downloading { .. })
    }

    fn peek_downloaded_data(&self) -> Option<&T> {
        match &self.state {
            DownloadState::Downloaded(data) => Some(&data.value),
            _ => None,
        }
    }

    fn peek_downloaded_peer_group(&self) -> Option<&PeerGroup> {
        match &self.state {
            DownloadState::Downloaded(data) => Some(&data.peer_group),
            _ => None,
        }
    }

    fn insert_verified_response(&mut self, result: DownloadResult<T>) -> bool {
        if let DownloadState::AwaitingDownload { .. } = &self.state {
            self.state = DownloadState::Downloaded(result);
            true
        } else {
            false
        }
    }

    fn update_awaiting_download_status(&mut self, new_status: &'static str) {
        if let DownloadState::AwaitingDownload(status) = &mut self.state {
            *status = new_status;
        }
    }

    fn on_download_start(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::AwaitingDownload { .. } => {
                self.state = DownloadState::Downloading(req_id);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_start expected AwaitingDownload got {other}"
            ))),
        }
    }

    fn on_download_failure(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.failed_downloading = self.failed_downloading.saturating_add(1);
                self.state = DownloadState::AwaitingDownload("not started");
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_failure expected Downloading got {other}"
            ))),
        }
    }

    fn on_download_success(
        &mut self,
        req_id: ReqId,
        result: DownloadResult<T>,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.state = DownloadState::Downloaded(result);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_success expected Downloading got {other}"
            ))),
        }
    }

    fn on_completed_request(&mut self, reason: &'static str) -> Result<(), LookupRequestError> {
        match &self.state {
            DownloadState::AwaitingDownload { .. } => {
                self.state = DownloadState::AwaitingDownload(reason);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_completed_request expected AwaitingDownload got {other}"
            ))),
        }
    }

    fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    fn more_failed_processing_attempts(&self) -> bool {
        self.failed_processing >= self.failed_downloading
    }
}

impl<T: Clone> std::fmt::Display for DownloadState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self))
    }
}

impl<T: Clone> std::fmt::Debug for DownloadState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwaitingDownload(reason) => write!(f, "AwaitingDownload({})", reason),
            Self::Downloading(req_id) => write!(f, "Downloading({:?})", req_id),
            Self::Downloaded(_) => write!(f, "Downloaded()"),
        }
    }
}

fn fmt_peer_set_as_len(
    peer_set: &Arc<RwLock<HashSet<PeerId>>>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{}", peer_set.read().len())
}
