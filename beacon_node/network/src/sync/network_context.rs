//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::custody_by_root::ActiveCustodyByRootRequest;
use super::SyncMessage;
use crate::metrics;
#[cfg(test)]
use crate::network_beacon_processor::TestBeaconChainType;
use crate::network_beacon_processor::{NetworkBeaconProcessor, PeerGroupAction};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes, EngineState};
pub use block_components_by_range::BlockComponentsByRootRequest;
#[cfg(test)]
pub use block_components_by_range::BlockComponentsByRootRequestStep;
pub use download_request::{DownloadRequest, Error as DownloadRequestError};
use fnv::FnvHashMap;
use itertools::Itertools;
use lighthouse_network::rpc::methods::{
    BlobsByRootRequest, BlocksByRootRequest, DataColumnsByRootRequest,
};
use lighthouse_network::rpc::{GoodbyeReason, RPCError, RequestType};
pub use lighthouse_network::service::api_types::RangeRequestId;
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRootRequestId, BlocksByRootRequestId, BlocksByRootRequester,
    ComponentsByRootRequestId, CustodyByRootRequestId, DataColumnsByRootRequestId,
    DataColumnsByRootRequester, Id, SyncRequestId,
};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource};
use parking_lot::RwLock;
pub use requests::LookupVerifyError;
use requests::{
    ActiveRequests, BlobsByRootRequestItems, BlocksByRootRequestItems,
    DataColumnsByRootRequestItems,
};
#[cfg(test)]
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tracing::{debug, span, warn, Level};
use types::{
    BlobIdentifier, BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList,
    DataColumnsByRootIdentifier, EthSpec, ForkContext, ForkName, Hash256, RuntimeVariableList,
    SignedBeaconBlock,
};

pub mod block_components_by_range;
pub mod custody_by_root;
mod download_request;
mod requests;

#[derive(Debug)]
pub enum RpcEvent<T> {
    StreamTermination,
    Response(T, Duration),
    RPCError(RPCError),
}

impl<T> RpcEvent<T> {
    pub fn from_chunk(chunk: Option<T>, seen_timestamp: Duration) -> Self {
        match chunk {
            Some(item) => RpcEvent::Response(item, seen_timestamp),
            None => RpcEvent::StreamTermination,
        }
    }
}

pub type RpcResponseResult<T> = Result<(T, Duration), RpcResponseError>;

/// Duration = latest seen timestamp of all received data columns
pub type RpcResponseBatchResult<T> = Result<(T, PeerGroup, Duration), RpcResponseError>;

/// Common result type for `custody_by_root` and `custody_by_range` requests. The peers are part of
/// the `Ok` response since they are not known until the entire request succeeds.
pub type CustodyRequestResult<E> = RpcResponseBatchResult<DataColumnSidecarList<E>>;

#[derive(Debug, Clone)]
pub enum RpcResponseError {
    RpcError(#[allow(dead_code)] RPCError),
    VerifyError(LookupVerifyError),
    RequestExpired(String),
    InternalError(#[allow(dead_code)] String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RpcRequestSendError {
    /// These errors should never happen, including unreachable custody errors or network send
    /// errors.
    InternalError(String),
    // If RpcRequestSendError has a single variant `InternalError` it's to signal to downstream
    // consumers that sends are expected to be infallible. If this assumption changes in the future,
    // add a new variant.
    NoPeers,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendErrorProcessor {
    SendError,
    ProcessorNotAvailable,
}

impl From<RPCError> for RpcResponseError {
    fn from(e: RPCError) -> Self {
        RpcResponseError::RpcError(e)
    }
}

impl From<LookupVerifyError> for RpcResponseError {
    fn from(e: LookupVerifyError) -> Self {
        RpcResponseError::VerifyError(e)
    }
}

/// Represents a group of peers that served a block component.
#[derive(Clone, Debug)]
pub struct PeerGroup {
    /// Peers group by which indexed section of the block component they served. For example:
    /// - PeerA served = [blob index 0, blob index 2]
    /// - PeerA served = [blob index 1]
    peers: HashMap<usize, PeerId>,
}

impl PeerGroup {
    pub(crate) fn empty() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub(crate) fn from_set(peer_to_indices: HashMap<PeerId, Vec<usize>>) -> Self {
        let mut peers = HashMap::new();
        for (peer, indices) in peer_to_indices {
            for index in indices {
                peers.insert(index, peer);
            }
        }
        Self { peers }
    }

    pub(crate) fn of_index(&self, index: &usize) -> Option<&PeerId> {
        self.peers.get(index)
    }
}

#[derive(Clone, Debug)]
pub struct BatchPeers {
    block_peer: PeerId,
    column_peers: PeerGroup,
}

impl BatchPeers {
    pub(crate) fn new_from_block_peer(block_peer: PeerId) -> Self {
        Self {
            block_peer,
            column_peers: PeerGroup::empty(),
        }
    }
    pub(crate) fn new(block_peer: PeerId, column_peers: PeerGroup) -> Self {
        Self {
            block_peer,
            column_peers,
        }
    }

    pub(crate) fn blame(&self, peer_action: PeerGroupAction) -> Vec<(PeerId, PeerAction)> {
        // Penalize each peer only once. Currently a peer_action does not mix different
        // PeerAction levels.
        let mut peer_penalties = peer_action
            .column_peer
            .iter()
            .filter_map(|(column_index, penalty)| {
                self.column(column_index).map(|peer| (*peer, *penalty))
            })
            .unique()
            .collect::<Vec<_>>();

        if let Some(penalty) = peer_action.block_peer {
            // Penalize the peer appropiately.
            peer_penalties.push((self.block(), penalty));
        }

        peer_penalties
    }

    fn block(&self) -> PeerId {
        self.block_peer
    }

    fn column(&self, index: &ColumnIndex) -> Option<&PeerId> {
        self.column_peers.of_index(&((*index) as usize))
    }
}

/// Sequential ID that uniquely identifies ReqResp outgoing requests
pub type ReqId = u32;

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.
pub struct SyncNetworkContext<T: BeaconChainTypes> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// A sequential ID for all RPC requests.
    request_id: Id,

    /// A mapping of active BlocksByRoot requests, including both current slot and parent lookups.
    blocks_by_root_requests:
        ActiveRequests<BlocksByRootRequestId, BlocksByRootRequestItems<T::EthSpec>>,
    /// A mapping of active BlobsByRoot requests, including both current slot and parent lookups.
    blobs_by_root_requests:
        ActiveRequests<BlobsByRootRequestId, BlobsByRootRequestItems<T::EthSpec>>,
    /// A mapping of active DataColumnsByRoot requests
    data_columns_by_root_requests:
        ActiveRequests<DataColumnsByRootRequestId, DataColumnsByRootRequestItems<T::EthSpec>>,

    /// Mapping of active custody column by root requests for a block root
    custody_by_root_requests: FnvHashMap<CustodyByRootRequestId, ActiveCustodyByRootRequest<T>>,

    /// BlocksByRoot requests paired with other ByRoot requests for data components
    block_components_by_root_requests:
        FnvHashMap<ComponentsByRootRequestId, BlockComponentsByRootRequest<T>>,

    /// Whether the ee is online. If it's not, we don't allow access to the
    /// `beacon_processor_send`.
    execution_engine_state: EngineState,

    /// Sends work to the beacon processor via a channel.
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,

    pub chain: Arc<BeaconChain<T>>,

    fork_context: Arc<ForkContext>,
}

/// Small enumeration to make dealing with block and blob requests easier.
pub enum RangeBlockComponent<E: EthSpec> {
    Block(
        BlocksByRootRequestId,
        RpcResponseResult<Vec<Arc<SignedBeaconBlock<E>>>>,
        PeerId,
    ),
    Blob(
        BlobsByRootRequestId,
        RpcResponseResult<Vec<Arc<BlobSidecar<E>>>>,
        PeerId,
    ),
    CustodyColumns(CustodyByRootRequestId, CustodyRequestResult<E>),
}

#[cfg(test)]
impl<E: EthSpec> SyncNetworkContext<TestBeaconChainType<E>> {
    pub fn new_for_testing(
        beacon_chain: Arc<BeaconChain<TestBeaconChainType<E>>>,
        network_globals: Arc<NetworkGlobals<E>>,
        task_executor: TaskExecutor,
    ) -> Self {
        let fork_context = Arc::new(ForkContext::new::<E>(
            beacon_chain.slot_clock.now().unwrap_or(Slot::new(0)),
            beacon_chain.genesis_validators_root,
            &beacon_chain.spec,
        ));
        let (network_tx, _network_rx) = mpsc::unbounded_channel();
        let (beacon_processor, _) = NetworkBeaconProcessor::null_for_testing(
            network_globals,
            mpsc::unbounded_channel().0,
            beacon_chain.clone(),
            task_executor,
        );

        SyncNetworkContext::new(
            network_tx,
            Arc::new(beacon_processor),
            beacon_chain,
            fork_context,
        )
    }
}

impl<T: BeaconChainTypes> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
        chain: Arc<BeaconChain<T>>,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();
        SyncNetworkContext {
            network_send,
            execution_engine_state: EngineState::Online, // always assume `Online` at the start
            request_id: 1,
            blocks_by_root_requests: ActiveRequests::new("blocks_by_root"),
            blobs_by_root_requests: ActiveRequests::new("blobs_by_root"),
            data_columns_by_root_requests: ActiveRequests::new("data_columns_by_root"),
            custody_by_root_requests: <_>::default(),
            block_components_by_root_requests: <_>::default(),
            network_beacon_processor,
            chain,
            fork_context,
        }
    }

    pub fn send_sync_message(&mut self, sync_message: SyncMessage<T::EthSpec>) {
        self.network_beacon_processor
            .send_sync_message(sync_message);
    }

    /// Returns the ids of all the requests made to the given peer_id.
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Vec<SyncRequestId> {
        self.active_requests()
            .filter(|(_, request_peer)| *request_peer == peer_id)
            .map(|(id, _)| id)
            .collect()
    }

    /// Returns the ids of all active requests
    pub fn active_requests(&mut self) -> impl Iterator<Item = (SyncRequestId, &PeerId)> {
        // Note: using destructuring pattern without a default case to make sure we don't forget to
        // add new request types to this function. Otherwise, lookup sync can break and lookups
        // will get stuck if a peer disconnects during an active requests.
        let Self {
            network_send: _,
            request_id: _,
            blocks_by_root_requests,
            blobs_by_root_requests,
            data_columns_by_root_requests,
            // custody_by_root_requests is a meta request of data_columns_by_root_requests
            custody_by_root_requests: _,
            // components_by_root_requests is a meta request of various _by_root requests
            block_components_by_root_requests: _,
            execution_engine_state: _,
            network_beacon_processor: _,
            chain: _,
            fork_context: _,
        } = self;

        let blocks_by_root_ids = blocks_by_root_requests
            .active_requests()
            .map(|(id, peer)| (SyncRequestId::BlocksByRoot(*id), peer));
        let blobs_by_root_ids = blobs_by_root_requests
            .active_requests()
            .map(|(id, peer)| (SyncRequestId::BlobsByRoot(*id), peer));
        let data_column_by_root_ids = data_columns_by_root_requests
            .active_requests()
            .map(|(id, peer)| (SyncRequestId::DataColumnsByRoot(*id), peer));

        blocks_by_root_ids
            .chain(blobs_by_root_ids)
            .chain(data_column_by_root_ids)
    }

    #[cfg(test)]
    pub fn active_block_components_by_root_requests(
        &self,
    ) -> Vec<(ComponentsByRootRequestId, BlockComponentsByRootRequestStep)> {
        self.block_components_by_root_requests
            .iter()
            .map(|(id, req)| (*id, req.state_step()))
            .collect()
    }

    pub fn get_custodial_peers(&self, column_index: ColumnIndex) -> Vec<PeerId> {
        self.network_globals()
            .custody_peers_for_column(column_index)
    }

    pub fn network_globals(&self) -> &NetworkGlobals<T::EthSpec> {
        &self.network_beacon_processor.network_globals
    }

    pub fn spec(&self) -> &ChainSpec {
        &self.chain.spec
    }

    /// Returns the Client type of the peer if known
    pub fn client_type(&self, peer_id: &PeerId) -> Client {
        self.network_globals()
            .peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client().clone())
            .unwrap_or_default()
    }

    pub fn status_peers<C: ToStatusMessage>(&self, chain: &C, peers: impl Iterator<Item = PeerId>) {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        let status_message = chain.status_message();
        for peer_id in peers {
            debug!(
                peer = %peer_id,
                fork_digest = ?status_message.fork_digest,
                finalized_root = ?status_message.finalized_root,
                finalized_epoch = ?status_message.finalized_epoch,
                head_root = %status_message.head_root,
                head_slot = %status_message.head_slot,
                "Sending Status Request"
            );

            let request = RequestType::Status(status_message.clone());
            let app_request_id = AppRequestId::Router;
            let _ = self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request,
                app_request_id,
            });
        }
    }

    fn active_request_count_by_peer(&self) -> HashMap<PeerId, usize> {
        let Self {
            network_send: _,
            request_id: _,
            blocks_by_root_requests,
            blobs_by_root_requests,
            data_columns_by_root_requests,
            // custody_by_root_requests is a meta request of data_columns_by_root_requests
            custody_by_root_requests: _,
            // components_by_range_requests is a meta request of various _by_range requests
            block_components_by_root_requests: _,
            execution_engine_state: _,
            network_beacon_processor: _,
            chain: _,
            fork_context: _,
            // Don't use a fallback match. We want to be sure that all requests are considered when
            // adding new ones
        } = self;

        let mut active_request_count_by_peer = HashMap::<PeerId, usize>::new();

        for peer_id in blocks_by_root_requests
            .iter_request_peers()
            .chain(blobs_by_root_requests.iter_request_peers())
            .chain(data_columns_by_root_requests.iter_request_peers())
        {
            *active_request_count_by_peer.entry(peer_id).or_default() += 1;
        }

        active_request_count_by_peer
    }

    /// A blocks by range request sent by the range sync algorithm
    pub fn block_components_by_range_request(
        &mut self,
        block_root: Hash256,
        requester: RangeRequestId,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        peers_to_deprioritize: &HashSet<PeerId>,
    ) -> Result<Id, RpcRequestSendError> {
        let id = ComponentsByRootRequestId {
            id: self.next_id(),
            requester,
        };

        let req =
            BlockComponentsByRootRequest::new(id, block_root, peers, peers_to_deprioritize, self)?;

        self.block_components_by_root_requests.insert(id, req);

        Ok(id.id)
    }

    /// Request to send a single `data_columns_by_root` request to the network.
    pub fn data_columns_by_root_request(
        &mut self,
        requester: DataColumnsByRootRequester,
        peer_id: PeerId,
        block_root: Hash256,
        indices: Vec<ColumnIndex>,
        expect_max_responses: bool,
    ) -> Result<DataColumnsByRootRequestId, &'static str> {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        let id = DataColumnsByRootRequestId {
            id: self.next_id(),
            parent_request_id: requester,
        };

        let request = DataColumnsByRootRequest::new(
            vec![DataColumnsByRootIdentifier {
                block_root,
                columns: RuntimeVariableList::from_vec(indices.clone(), usize::MAX),
            }],
            usize::MAX,
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: RequestType::DataColumnsByRoot(request),
            app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRoot(id)),
        })?;

        debug!(
            method = "DataColumnsByRoot",
            peer = %peer_id,
            ?block_root,
            ?indices,
            %id,
            "Sync RPC request sent"
        );

        self.data_columns_by_root_requests.insert(
            id,
            peer_id,
            expect_max_responses,
            DataColumnsByRootRequestItems::new(block_root, indices),
        );

        Ok(id)
    }

    /// Request to fetch all needed custody columns of a specific block. This function may not send
    /// any request to the network if no columns have to be fetched based on the import state of the
    /// node. A custody request is a "super request" that may trigger 0 or more `data_columns_by_root`
    /// requests.
    pub fn send_custody_by_root_request(
        &mut self,
        parent_request_id: ComponentsByRootRequestId,
        block_root: Hash256,
        lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
    ) -> Result<CustodyByRootRequestId, RpcRequestSendError> {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        let id = CustodyByRootRequestId { parent_request_id };
        debug!(
            %id,
            "Starting custody columns request"
        );

        let custody_indices = self
            .network_globals()
            .sampling_columns()
            .into_iter()
            .collect::<Vec<_>>();

        let mut request =
            ActiveCustodyByRootRequest::new(block_root, id, &custody_indices, lookup_peers);

        // Note that you can only send, but not handle a response here
        match request.continue_requests(self) {
            Ok(_) => {
                // Ignoring the result of `continue_requests` is okay. A request that has just been
                // created cannot return data immediately, it must send some request to the network
                // first. And there must exist some request, `custody_indexes_to_fetch` is not empty.
                self.custody_by_root_requests.insert(id, request);
                Ok(id)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn send_blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        block_root: Hash256,
        parent_request_id: BlocksByRootRequester,
    ) -> Result<BlocksByRootRequestId, RpcRequestSendError> {
        let id = BlocksByRootRequestId {
            id: self.next_id(),
            parent_request_id,
        };

        let request = BlocksByRootRequest::new(vec![block_root], self.spec(), ForkName::Fulu);

        // Lookup sync event safety: If network_send.send() returns Ok(_) we are guaranteed that
        // eventually at least one this 3 events will be received:
        // - StreamTermination(request_id): handled by `Self::on_single_block_response`
        // - RPCError(request_id): handled by `Self::on_single_block_response`
        // - Disconnect(peer_id) handled by `Self::peer_disconnected``which converts it to a
        // ` RPCError(request_id)`event handled by the above method
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlocksByRoot(request),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlocksByRoot(id)),
            })
            .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "BlocksByRoot",
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        self.blocks_by_root_requests.insert(
            id,
            peer_id,
            // true = enforce max_requests as returned for blocks_by_root. We always request from
            // peers to claim to have these blocks
            true,
            BlocksByRootRequestItems::new(block_root),
        );
        Ok(id)
    }

    fn send_blobs_by_root_request(
        &mut self,
        peer_id: PeerId,
        block_root: Hash256,
        blobs_per_block: usize,
        parent_request_id: ComponentsByRootRequestId,
    ) -> Result<BlobsByRootRequestId, RpcRequestSendError> {
        let id = BlobsByRootRequestId {
            id: self.next_id(),
            parent_request_id,
        };

        let indices = (0..(blobs_per_block as u64)).collect::<Vec<_>>();
        let blob_identifiers = indices
            .iter()
            .map(|index| BlobIdentifier {
                block_root,
                index: *index,
            })
            .collect::<Vec<_>>();

        // Create the blob request based on the blocks request.
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlobsByRoot(BlobsByRootRequest {
                    blob_ids: RuntimeVariableList::new(blob_identifiers, usize::MAX).unwrap(),
                }),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlobsByRoot(id)),
            })
            .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "BlobsByRoot",
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        self.blobs_by_root_requests.insert(
            id,
            peer_id,
            // true = we know exactly how many blobs total we expect
            true,
            BlobsByRootRequestItems::new(block_root, indices),
        );
        Ok(id)
    }

    pub fn is_execution_engine_online(&self) -> bool {
        self.execution_engine_state == EngineState::Online
    }

    pub fn update_execution_engine_state(&mut self, engine_state: EngineState) {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        debug!(past_state = ?self.execution_engine_state, new_state = ?engine_state, "Sync's view on execution engine state updated");
        self.execution_engine_state = engine_state;
    }

    /// Terminates the connection with the peer and bans them.
    pub fn goodbye_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        self.network_send
            .send(NetworkMessage::GoodbyePeer {
                peer_id,
                reason,
                source: ReportSource::SyncService,
            })
            .unwrap_or_else(|_| {
                warn!("Could not report peer: channel failed");
            });
    }

    /// Reports to the scoring algorithm the behaviour of a peer.
    pub fn report_peer(&self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        debug!(%peer_id, %action, %msg, client = %self.client_type(&peer_id), "Sync reporting peer");
        self.network_send
            .send(NetworkMessage::ReportPeer {
                peer_id,
                action,
                source: ReportSource::SyncService,
                msg,
            })
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not report peer: channel failed");
            });
    }

    /// Subscribes to core topics.
    pub fn subscribe_core_topics(&self) {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not subscribe to core topics.");
            });
    }

    /// Sends an arbitrary network message.
    fn send_network_msg(&self, msg: NetworkMessage<T::EthSpec>) -> Result<(), &'static str> {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        self.network_send.send(msg).map_err(|_| {
            debug!("Could not send message to the network service");
            "Network channel send Failed"
        })
    }

    pub fn beacon_processor_if_enabled(&self) -> Option<&Arc<NetworkBeaconProcessor<T>>> {
        self.is_execution_engine_online()
            .then_some(&self.network_beacon_processor)
    }

    pub fn beacon_processor(&self) -> &Arc<NetworkBeaconProcessor<T>> {
        &self.network_beacon_processor
    }

    pub fn next_id(&mut self) -> Id {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    /// Attempt to make progress on all custody_by_root requests. Some request may be stale waiting
    /// for custody peers. Returns a Vec of results as zero or more requests may fail in this
    /// attempt.
    pub fn continue_custody_by_root_requests(
        &mut self,
    ) -> Vec<(CustodyByRootRequestId, CustodyRequestResult<T::EthSpec>)> {
        let ids = self
            .custody_by_root_requests
            .keys()
            .copied()
            .collect::<Vec<_>>();

        // Need to collect ids and results in separate steps to re-borrow self.
        ids.into_iter()
            .filter_map(|id| {
                let mut request = self
                    .custody_by_root_requests
                    .remove(&id)
                    .expect("key of hashmap");
                let result = request
                    .continue_requests(self)
                    .map_err(Into::<RpcResponseError>::into)
                    .transpose();
                self.handle_custody_by_root_result(id, request, result)
                    .map(|result| (id, result))
            })
            .collect()
    }

    // Request handlers

    /// Processes a single `RpcEvent` for a blocks_by_root RPC request.
    /// - If the event completes the request, it returns `Some(Ok)` with a vec of blocks
    /// - If the event is an error it fails the request and returns `Some(Err)`
    /// - else it appends the response chunk to the active request state and returns `None`
    pub(crate) fn on_blocks_by_root_response(
        &mut self,
        id: BlocksByRootRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>> {
        let resp = self.blocks_by_root_requests.on_response(id, rpc_event);
        self.on_rpc_response_result(id, "BlocksByRoot", resp, peer_id, |_| 1)
    }

    /// Processes a single `RpcEvent` blobs_by_root RPC request.
    /// Same logic as [`on_blocks_by_root_response`]
    pub(crate) fn on_blobs_by_root_response(
        &mut self,
        id: BlobsByRootRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<BlobSidecar<T::EthSpec>>>>> {
        let resp = self.blobs_by_root_requests.on_response(id, rpc_event);
        self.on_rpc_response_result(id, "BlobsByRoot", resp, peer_id, |_| 1)
    }

    /// Processes a single `RpcEvent` for a data_columns_by_root RPC request.
    /// Same logic as [`on_blocks_by_root_response`]
    #[allow(clippy::type_complexity)]
    pub(crate) fn on_data_columns_by_root_response(
        &mut self,
        id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<DataColumnSidecarList<T::EthSpec>>> {
        let resp = self
            .data_columns_by_root_requests
            .on_response(id, rpc_event);
        self.on_rpc_response_result(id, "DataColumnsByRoot", resp, peer_id, |_| 1)
    }

    /// Common logic for `on_*_response` handlers. Ensures we have consistent logging and metrics
    /// and peer reporting for all request types.
    fn on_rpc_response_result<I: std::fmt::Display, R, F: FnOnce(&R) -> usize>(
        &mut self,
        id: I,
        method: &'static str,
        resp: Option<RpcResponseResult<R>>,
        peer_id: PeerId,
        get_count: F,
    ) -> Option<RpcResponseResult<R>> {
        match &resp {
            None => {}
            Some(Ok((v, _))) => {
                debug!(
                    %id,
                    method,
                    count = get_count(v),
                    "Sync RPC request completed"
                );
            }
            Some(Err(e)) => {
                debug!(
                    %id,
                    method,
                    error = ?e,
                    "Sync RPC request error"
                );
            }
        }
        if let Some(Err(RpcResponseError::VerifyError(e))) = &resp {
            self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }
        resp
    }

    /// Insert a downloaded column into an active custody request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Some`: Request completed, won't make more progress. Expect requester to act on the result.
    /// - `None`: Request still active, requester should do no action
    #[allow(clippy::type_complexity)]
    pub fn on_custody_by_root_response(
        &mut self,
        id: CustodyByRootRequestId,
        req_id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        resp: RpcResponseResult<DataColumnSidecarList<T::EthSpec>>,
    ) -> Option<CustodyRequestResult<T::EthSpec>> {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        // Note: need to remove the request to borrow self again below. Otherwise we can't
        // do nested requests
        let Some(mut request) = self.custody_by_root_requests.remove(&id) else {
            metrics::inc_counter_vec(
                &metrics::SYNC_UNKNOWN_NETWORK_REQUESTS,
                &["custody_by_root"],
            );
            return None;
        };

        let result = request
            .on_data_column_downloaded(peer_id, req_id, resp, self)
            .map_err(Into::<RpcResponseError>::into)
            .transpose();

        self.handle_custody_by_root_result(id, request, result)
    }

    fn handle_custody_by_root_result(
        &mut self,
        id: CustodyByRootRequestId,
        request: ActiveCustodyByRootRequest<T>,
        result: Option<CustodyRequestResult<T::EthSpec>>,
    ) -> Option<CustodyRequestResult<T::EthSpec>> {
        let span = span!(
            Level::INFO,
            "SyncNetworkContext",
            service = "network_context"
        );
        let _enter = span.enter();

        match &result {
            Some(Ok((columns, peer_group, _))) => {
                debug!(%id, count = columns.len(), peers = ?peer_group, "Custody by root request success, removing")
            }
            Some(Err(e)) => {
                debug!(%id, error = ?e, "Custody by root request failure, removing")
            }
            None => {
                self.custody_by_root_requests.insert(id, request);
            }
        }
        result
    }

    /// Processes the result of an `*_by_range` RPC request issued by a
    /// block_components_by_range_request.
    ///
    /// - If the result completes the request, it returns `Some(Ok)` with a vec of coupled RpcBlocks
    /// - If the result fails the request, it returns `Some(Err)`. Note that a failed request may
    ///   not fail the block_components_by_range_request as it implements retries.
    /// - else it appends the result to the active request state and returns `None`
    #[allow(clippy::type_complexity)]
    pub fn on_block_components_by_root_response(
        &mut self,
        id: ComponentsByRootRequestId,
        range_block_component: RangeBlockComponent<T::EthSpec>,
    ) -> Option<Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>> {
        // Note: need to remove the request to borrow self again below. Otherwise we can't
        // do nested requests
        let Some(mut request) = self.block_components_by_root_requests.remove(&id) else {
            metrics::inc_counter_vec(
                &metrics::SYNC_UNKNOWN_NETWORK_REQUESTS,
                &["block_components_by_range"],
            );
            return None;
        };

        let result = match range_block_component {
            RangeBlockComponent::Block(req_id, resp, peer_id) => resp.and_then(|(blocks, _)| {
                let block = blocks.first().ok_or(RpcResponseError::InternalError(
                    "blocks_by_root returned zero blocks".to_owned(),
                ))?;
                request
                    .on_blocks_by_root_result(req_id, block.clone(), peer_id, self)
                    .map_err(Into::<RpcResponseError>::into)
            }),
            RangeBlockComponent::Blob(req_id, resp, peer_id) => resp.and_then(|(blobs, _)| {
                request
                    .on_blobs_by_root_result(req_id, blobs, peer_id, self)
                    .map_err(Into::<RpcResponseError>::into)
            }),
            RangeBlockComponent::CustodyColumns(req_id, resp) => {
                resp.and_then(|(custody_columns, peers, _)| {
                    request
                        .on_custody_by_root_result(req_id, custody_columns, peers, self)
                        .map_err(Into::<RpcResponseError>::into)
                })
            }
        }
        // Convert a result from internal format of `ActiveCustodyRequest` (error first to use ?) to
        // an Option first to use in an `if let Some() { act on result }` block.
        .transpose();

        match result.as_ref() {
            Some(Ok((block, peer_group))) => {
                // Don't log the peer_group here, it's very long (could be up to 128 peers). If you
                // want to trace which peer sent the column at index X, search for the log:
                // `Sync RPC request sent method="DataColumnsByRoot" ...`
                debug!(
                    %id,
                    slot = %block.as_block().slot(),
                    block_has_data = block.as_block().has_data(),
                    block_peer = ?peer_group.block(),
                    "Block components by range request success, removing"
                )
            }
            Some(Err(e)) => {
                debug!(%id, error = ?e, "Block components by range request failure, removing" )
            }
            None => {
                self.block_components_by_root_requests.insert(id, request);
            }
        }
        result
    }

    pub(crate) fn register_metrics(&self) {
        for (id, count) in [
            ("blocks_by_root", self.blocks_by_root_requests.len()),
            ("blobs_by_root", self.blobs_by_root_requests.len()),
            (
                "data_columns_by_root",
                self.data_columns_by_root_requests.len(),
            ),
            ("custody_by_root", self.custody_by_root_requests.len()),
            (
                "block_components_by_root",
                self.block_components_by_root_requests.len(),
            ),
        ] {
            metrics::set_gauge_vec(&metrics::SYNC_ACTIVE_NETWORK_REQUESTS, &[id], count as i64);
        }
    }
}
