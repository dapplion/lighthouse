use super::{BlockComponent, PeerId, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS};
use crate::sync::manager::BlockProcessType;
use crate::sync::network_context::{
    LookupRequestResult, PeerGroup, ReqId, RpcRequestSendError, SendErrorProcessor,
    SyncNetworkContext,
};
use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::data_column_verification::CustodyDataColumnList;
use beacon_chain::{BeaconChainTypes, BlockProcessStatus};
use educe::Educe;
use lighthouse_network::service::api_types::Id;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Hash256;
use strum::IntoStaticStr;
use tracing::{Span, debug_span};
use types::data::FixedBlobSidecarList;
use types::{
    DataColumnSidecarList, EthSpec, ExecutionPayload, ForkName, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, Slot,
};

// Dedicated enum for LookupResult to force its usage
#[must_use = "LookupResult must be handled with on_lookup_result"]
pub enum LookupResult {
    /// Lookup completed successfully
    Completed,
    /// Lookup is expecting some future event from the network
    Pending,
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
    /// Received MissingComponents when all components have been processed. This should never
    /// happen, and indicates some internal bug
    MissingComponentsAfterAllProcessed,
    /// Attempted to retrieve a not known lookup id
    UnknownLookup,
    /// Received a download result for a different request id than the in-flight request.
    /// There should only exist a single request at a time. Having multiple requests is a bug and
    /// can result in undefined state, so it's treated as a hard error and the lookup is dropped.
    UnexpectedRequestId {
        expected_req_id: ReqId,
        req_id: ReqId,
    },
}

#[derive(Educe)]
#[educe(Debug(bound(T: BeaconChainTypes)))]
pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    state: LookupState<T::EthSpec>,
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

enum LookupState<E: EthSpec> {
    BlockDownload {
        block_req: BlockRequestState<E>,
    },
    ExtrasDownload {
        block: Arc<SignedBeaconBlock<E>>,
        extra_requests: BlockExtraRequests<E>,
    },
    Processing {
        block: Arc<SignedBeaconBlock<E>>,
        extras: BlockExtras<E>,
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

enum PayloadResult<E: EthSpec> {
    Full(Arc<SignedExecutionPayloadEnvelope<E>>),
    Empty,
}

enum CustodyColumnsResult<E: EthSpec> {
    Columns(DataColumnSidecarList<E>),
    NoData,
}

enum BlockExtras<E> {
    Electra(FixedBlobSidecarList<E>),
    Fulu(CustodyColumnsResult<E>),
    Gloas(PayloadResult<E>, CustodyColumnsResult<E>),
}

enum ProcessingState {
    AwaitingProcessing(u8),
    Processing(u8),
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

        Self {
            id,
            state: LookupState::BlockDownload {
                block_req: BlockRequestState::new(requested_block_root),
            },
            peers: Arc::new(RwLock::new(HashSet::from_iter(peers.iter().copied()))),
            block_root: requested_block_root,
            awaiting_parent,
            created: Instant::now(),
            span: lookup_span,
        }
    }

    /// Reset the status of all internal requests
    pub fn reset_requests(&mut self) {
        self.state = LookupState::BlockDownload {
            block_req: BlockRequestState::new(self.block_root),
        };
    }

    /// Return the slot of this lookup's block if it's currently cached as `AwaitingProcessing`
    pub fn peek_downloaded_block_slot(&self) -> Option<Slot> {
        match self.state {
            LookupState::BlockDownload { block_req } => block_req
                .state
                .peek_downloaded_data()
                .map(|block| block.slot()),
            LookupState::ExtrasDownload { block, .. } => Some(block.slot()),
            LookupState::Processing { .. } => todo!(),
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
            BlockComponent::Block(block) => self.block_state_mut().insert_verified_response(block),
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
                LookupState::BlockDownload { block_req } => block_req.state.is_awaiting_event(),
                LookupState::ExtrasDownload {
                    block: _,
                    extra_requests: extras,
                } => match extras {
                    BlockExtraRequests::ElectraBlobs(Some(blobs)) => {
                        blobs.state.is_awaiting_event()
                    }
                    BlockExtraRequests::ElectraBlobs(None) => false,
                    BlockExtraRequests::FuluColumns(Some(columns)) => {
                        columns.state.is_awaiting_event()
                    }
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
                LookupState::Processing { .. } => false,
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
        let awaiting_parent = self.awaiting_parent.is_some();
        let peers = self.peers.clone();

        loop {
            match self.state {
                LookupState::BlockDownload { mut block_req } => {
                    block_req.continue_request(cx);

                    if let Some(block) = block_req.completed() {
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

                        self.state = LookupState::ExtrasDownload {
                            block,
                            extra_requests: extras,
                        };
                    } else {
                        // Awaiting block request
                        break;
                    }
                }
                LookupState::ExtrasDownload {
                    block,
                    mut extra_requests,
                } => {
                    match &mut extra_requests {
                        BlockExtraRequests::ElectraBlobs(Some(blobs_req)) => {
                            blobs_req.continue_request(cx);
                        }
                        BlockExtraRequests::FuluColumns(Some(columns_req)) => {
                            columns_req.continue_request(cx);
                        }
                        BlockExtraRequests::ElectraBlobs(None)
                        | BlockExtraRequests::FuluColumns(None) => {} // Nothing to do
                        BlockExtraRequests::Gloas {
                            payload_req,
                            columns_req,
                        } => {
                            if let Some(payload_req) = payload_req {
                                payload_req.continue_request(cx);
                            }
                            if let Some(columns_req) = columns_req {
                                columns_req.continue_request(cx);
                            }
                        }
                    }

                    if let Some(extras) = match &mut extra_requests {
                        BlockExtraRequests::ElectraBlobs(Some(blobs_req)) => {
                            blobs_req.completed().map(BlockExtras::Electra)
                        }
                        BlockExtraRequests::FuluColumns(Some(columns_req)) => {
                            columns_req.completed().map(BlockExtras::Fulu)
                        }
                        BlockExtraRequests::ElectraBlobs(None)
                        | BlockExtraRequests::FuluColumns(None) => {
                            // No data request was needed
                            todo!();
                        }
                        BlockExtraRequests::Gloas {
                            payload_req,
                            columns_req,
                        } => {
                            // Todo implement, if requests completed or None construct extras for Gloas
                            if let (Some(payload), Some(columns)) = (
                                if let Some(req) = payload_req {
                                    req.completed().map(PayloadResult::Full)
                                } else {
                                    Some(PayloadResult::Empty)
                                },
                                if let Some(req) = columns_req {
                                    req.completed().map(CustodyColumnsResult::Columns)
                                } else {
                                    Some(CustodyColumnsResult::NoData)
                                },
                            ) {
                                Some(BlockExtras::Gloas(payload, columns))
                            } else {
                                None
                            }
                        }
                    } {
                        self.state = LookupState::Processing { block, extras };
                    } else {
                        // Awaiting some extra request(s)
                        break;
                    }
                }
                LookupState::Processing { mut block, extras } => {
                    // TODO: Fix this, potentially wrap this in a processing request
                    // Hmm but processing requests can't be retried, we need to go back to download
                    if !awaiting_parent && let Some(result) = block.state.maybe_start_processing() {
                        cx.send_block_for_processing(id, block_root, value, seen_timestamp)
                            .map_err(LookupRequestError::SendFailedProcessor)
                            .map(|_| LookupResult::Pending);
                        break;
                    }
                }
            }
        }

        Ok(LookupResult::Pending)
    }

    pub(crate) fn block_state_mut(
        &mut self,
    ) -> Result<&mut SingleLookupRequestState<Arc<SignedBeaconBlock<T::EthSpec>>>, &'static str>
    {
        match &mut self.state {
            LookupState::BlockDownload { block_req } => Ok(&mut block_req.state),
            _ => Err("block request not active"),
        }
    }

    pub(crate) fn blob_state_mut(
        &mut self,
    ) -> Result<&mut SingleLookupRequestState<FixedBlobSidecarList<T::EthSpec>>, &'static str> {
        match &mut self.state {
            LookupState::ExtrasDownload {
                extra_requests: BlockExtraRequests::ElectraBlobs(Some(req)),
                ..
            } => Ok(&mut req.state),
            _ => Err("blob request not active"),
        }
    }

    pub(crate) fn custody_state_mut(
        &mut self,
    ) -> Result<&mut SingleLookupRequestState<DataColumnSidecarList<T::EthSpec>>, &'static str>
    {
        match &mut self.state {
            LookupState::ExtrasDownload {
                extra_requests:
                    BlockExtraRequests::FuluColumns(Some(req))
                    | BlockExtraRequests::Gloas {
                        columns_req: Some(req),
                        ..
                    },
                ..
            } => Ok(&mut req.state),
            _ => Err("custody request not active"),
        }
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

/// The state of the blob request component of a `SingleBlockLookup`.
#[derive(Educe)]
#[educe(Debug)]
pub struct BlobRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    pub block_root: Hash256,
    pub expected_blobs: usize,
    pub state: SingleLookupRequestState<FixedBlobSidecarList<E>>,
    peers: Arc<RwLock<HashSet<PeerId>>>,
}

impl<E: EthSpec> BlobRequestState<E> {
    pub fn new(
        peers: Arc<RwLock<HashSet<PeerId>>>,
        block_root: Hash256,
        expected_blobs: usize,
    ) -> Self {
        Self {
            peers,
            block_root,
            expected_blobs,
            state: SingleLookupRequestState::new(),
        }
    }

    pub fn continue_request(&mut self, cx: &mut SyncNetworkContext<T>) {
        match self.state.state {
            State::AwaitingDownload(_) => {
                match cx
                    .blob_lookup_request(
                        id,
                        self.peers.clone(),
                        self.block_root,
                        self.expected_blobs,
                    )
                    .map_err(LookupRequestError::SendFailedNetwork)
                {
                    LookupRequestResult::RequestSent(req_id) => {
                        self.state.on_download_start(req_id)?
                    }
                    LookupRequestResult::NoRequestNeeded(reason) => {
                        self.state.on_completed_request(reason)?
                    }
                    LookupRequestResult::Pending(reason) => {
                        self.state.update_awaiting_download_status(reason);
                        return Ok(Some(LookupResult::Pending));
                    }
                }
            }
            State::Downloading(_) => {} // Waiting for event
            State::Downloaded(_) => {}  // Done
        }
    }

    pub fn completed(&self) -> Option<FixedBlobSidecarList<E>> {
        todo!();
    }
}

/// The state of the custody request component of a `SingleBlockLookup`.
#[derive(Educe)]
#[educe(Debug)]
pub struct CustodyRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    pub block_root: Hash256,
    pub state: SingleLookupRequestState<DataColumnSidecarList<E>>,
}

impl<E: EthSpec> CustodyRequestState<E> {
    pub fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    pub fn continue_request(&mut self, cx: &mut SyncNetworkContext<T>) {
        match self.state.state {
            State::AwaitingDownload(_) => {
                match cx
                    .custody_lookup_request(id, peers.clone(), self.block_root)
                    .map_err(LookupRequestError::SendFailedNetwork)
                {
                    LookupRequestResult::RequestSent(req_id) => {
                        self.state.on_download_start(req_id)?
                    }
                    LookupRequestResult::NoRequestNeeded(reason) => {
                        self.state.on_completed_request(reason)?
                    }
                    LookupRequestResult::Pending(reason) => {
                        self.state.update_awaiting_download_status(reason);
                        return Ok(Some(LookupResult::Pending));
                    }
                }
            }
            State::Downloading(_) => {} // Waiting for event
            State::Downloaded(_) => {}  // Done
        }
    }

    pub fn completed(&self) -> Option<DataColumnSidecarList<E>> {
        todo!();
    }
}

/// The state of the block request component of a `SingleBlockLookup`.
#[derive(Educe)]
#[educe(Debug)]
pub struct BlockRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    pub block_root: Hash256,
    pub state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlockRequestState<E> {
    pub fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    pub fn continue_request(&mut self, cx: &mut SyncNetworkContext<T>) {
        match self.state.state {
            State::AwaitingDownload(_) => {
                match cx
                    .block_lookup_request(id, peers.clone(), self.block_root)
                    .map_err(LookupRequestError::SendFailedNetwork)
                {
                    LookupRequestResult::RequestSent(req_id) => {
                        self.state.on_download_start(req_id)?
                    }
                    LookupRequestResult::NoRequestNeeded(reason) => {
                        self.state.on_completed_request(reason)?
                    }
                    LookupRequestResult::Pending(reason) => {
                        self.state.update_awaiting_download_status(reason);
                        return Ok(Some(LookupResult::Pending));
                    }
                }
            }
            State::Downloading(_) => {} // Waiting for event
            State::Downloaded(_) => {}  // Done
        }
    }

    pub fn completed(&self) -> Option<Arc<SignedBeaconBlock<E>>> {
        todo!();
    }
}

/// The state of the payload request component of a `SingleBlockLookup`.
#[derive(Educe)]
#[educe(Debug)]
pub struct PayloadRequestState<E: EthSpec> {
    #[educe(Debug(ignore))]
    pub block_root: Hash256,
    pub state: SingleLookupRequestState<Arc<SignedExecutionPayloadEnvelope<E>>>,
}

impl<E: EthSpec> PayloadRequestState<E> {
    pub fn new(block_root: Hash256) -> Self {
        Self {
            block_root,
            state: SingleLookupRequestState::new(),
        }
    }

    pub fn continue_request(&mut self, cx: &mut SyncNetworkContext<T>) {
        match self.state.state {
            State::AwaitingDownload(_) => {
                match cx
                    .block_lookup_request(id, peers.clone(), self.block_root)
                    .map_err(LookupRequestError::SendFailedNetwork)
                {
                    LookupRequestResult::RequestSent(req_id) => {
                        self.state.on_download_start(req_id)?
                    }
                    LookupRequestResult::NoRequestNeeded(reason) => {
                        self.state.on_completed_request(reason)?
                    }
                    LookupRequestResult::Pending(reason) => {
                        self.state.update_awaiting_download_status(reason);
                        return Ok(Some(LookupResult::Pending));
                    }
                }
            }
            State::Downloading(_) => {} // Waiting for event
            State::Downloaded(_) => {}  // Done
        }
    }

    pub fn completed(&self) -> Option<Arc<SignedExecutionPayloadEnvelope<E>>> {
        todo!();
    }
}

#[derive(Debug, Clone)]
pub struct DownloadResult<T: Clone> {
    pub value: T,
    pub block_root: Hash256,
    pub seen_timestamp: Duration,
    pub peer_group: PeerGroup,
}

#[derive(IntoStaticStr)]
pub enum State<T: Clone> {
    AwaitingDownload(/* reason */ &'static str),
    Downloading(ReqId),
    Downloaded(DownloadResult<T>),
}

/// Object representing the state of a single block or blob lookup request.
#[derive(Debug)]
pub struct SingleLookupRequestState<T: Clone> {
    /// State of this request.
    state: State<T>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
}

trait DownloadStateOps {
    fn is_awaiting_download(&self) -> bool;
    fn failed_attempts(&self) -> u8;
    fn more_failed_processing_attempts(&self) -> bool;
    fn on_download_start(&mut self, req_id: ReqId) -> Result<(), LookupRequestError>;
    fn on_completed_request(&mut self, reason: &'static str) -> Result<(), LookupRequestError>;
    fn update_awaiting_download_status(&mut self, new_status: &'static str);
}

impl<T: Clone> DownloadStateOps for SingleLookupRequestState<T> {
    fn is_awaiting_download(&self) -> bool {
        Self::is_awaiting_download(self)
    }

    fn failed_attempts(&self) -> u8 {
        Self::failed_attempts(self)
    }

    fn more_failed_processing_attempts(&self) -> bool {
        Self::more_failed_processing_attempts(self)
    }

    fn on_download_start(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        Self::on_download_start(self, req_id)
    }

    fn on_completed_request(&mut self, reason: &'static str) -> Result<(), LookupRequestError> {
        Self::on_completed_request(self, reason)
    }

    fn update_awaiting_download_status(&mut self, new_status: &'static str) {
        Self::update_awaiting_download_status(self, new_status)
    }
}

struct ProcessingRequest<T> {
    a: T,
}

impl ProcessingRequest<T> {
    pub fn is_processed(&self) -> bool {
        match self.state {
            State::AwaitingProcess { .. } | State::Processing { .. } => false,
            State::Processed { .. } => true,
        }
    }

    /// Returns true if we can expect some future event to progress this block component request
    /// specifically.
    pub fn is_awaiting_event(&self) -> bool {
        match self.state {
            State::AwaitingProcess { .. } => false,
            // Beacon processor will emit a processing result event
            State::Processing { .. } => true,
            // Request complete, no future event left
            State::Processed { .. } => false,
        }
    }
}

impl<T: Clone> SingleLookupRequestState<T> {
    pub fn new() -> Self {
        Self {
            state: State::AwaitingDownload("not started"),
            failed_processing: 0,
            failed_downloading: 0,
        }
    }

    /// Returns true if we can expect some future event to progress this block component request
    /// specifically.
    pub fn is_awaiting_event(&self) -> bool {
        match self.state {
            // No event will progress this request specifically, but the request may be put on hold
            // due to some external event
            State::AwaitingDownload { .. } => false,
            // Network will emit a download success / error event
            State::Downloading { .. } => true,
            State::Downloaded(_) => false,
        }
    }

    pub fn peek_downloaded_data(&self) -> Option<&T> {
        match &self.state {
            State::AwaitingDownload { .. } => None,
            State::Downloading { .. } => None,
            State::Downloaded(data) => Some(&data.value),
        }
    }

    /// Switch to `AwaitingProcessing` if the request is in `AwaitingDownload` state, otherwise
    /// ignore.
    pub fn insert_verified_response(&mut self, result: DownloadResult<T>) -> bool {
        if let State::AwaitingDownload { .. } = &self.state {
            self.state = State::Downloaded(result);
            true
        } else {
            false
        }
    }

    /// Append metadata on why this request is in AwaitingDownload status. Very helpful to debug
    /// stuck lookups. Not fallible as it's purely informational.
    pub fn update_awaiting_download_status(&mut self, new_status: &'static str) {
        if let State::AwaitingDownload(status) = &mut self.state {
            *status = new_status
        }
    }

    /// Switch to `Downloading` if the request is in `AwaitingDownload` state, otherwise returns None.
    pub fn on_download_start(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            State::AwaitingDownload { .. } => {
                self.state = State::Downloading(req_id);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_start expected AwaitingDownload got {other}"
            ))),
        }
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn on_download_failure(&mut self, req_id: ReqId) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.failed_downloading = self.failed_downloading.saturating_add(1);
                self.state = State::AwaitingDownload("not started");
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_failure expected Downloading got {other}"
            ))),
        }
    }

    pub fn on_download_success(
        &mut self,
        req_id: ReqId,
        result: DownloadResult<T>,
    ) -> Result<(), LookupRequestError> {
        match &self.state {
            State::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(LookupRequestError::UnexpectedRequestId {
                        expected_req_id: *expected_req_id,
                        req_id,
                    });
                }
                self.state = State::Downloaded(result);
                Ok(())
            }
            other => Err(LookupRequestError::BadState(format!(
                "Bad state on_download_success expected Downloading got {other}"
            ))),
        }
    }

    /// The total number of failures, whether it be processing or downloading.
    pub fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    pub fn more_failed_processing_attempts(&self) -> bool {
        self.failed_processing >= self.failed_downloading
    }
}

// Display is used in the BadState assertions above
impl<T: Clone> std::fmt::Display for State<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self))
    }
}

// Debug is used in the log_stuck_lookups print to include some more info. Implements custom Debug
// to not dump an entire block or blob to terminal which don't add valuable data.
impl<T: Clone> std::fmt::Debug for State<T> {
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
