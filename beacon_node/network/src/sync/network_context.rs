//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::block_sidecar_coupling::BlocksAndBlobsRequestInfo;
use super::manager::{Id, RequestId as SyncRequestId, SingleLookupReqId2};
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{get_block_root, BeaconChain, BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, BlobsByRootRequest};
use lighthouse_network::rpc::RPCError;
use lighthouse_network::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
use slog::{debug, trace, warn};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::{BlobSidecar, EthSpec, Hash256, SignedBeaconBlock};

pub struct BlocksAndBlobsByRangeResponse<E: EthSpec> {
    pub batch_id: BatchId,
    pub responses: Result<Vec<RpcBlock<E>>, String>,
}

pub struct BlocksAndBlobsByRangeRequest<E: EthSpec> {
    pub chain_id: ChainId,
    pub batch_id: BatchId,
    pub block_blob_info: BlocksAndBlobsRequestInfo<E>,
}

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.
pub struct SyncNetworkContext<T: BeaconChainTypes> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// A sequential ID for all RPC requests.
    request_id: Id,

    /// Whether the ee is online. If it's not, we don't allow access to the
    /// `beacon_processor_send`.
    execution_engine_state: EngineState,

    /// Sends work to the beacon processor via a channel.
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,

    blocks_by_root_requests: FnvHashMap<Id, ActiveBlocksByRootRequest>,
    blocks_by_range_requests: FnvHashMap<Id, ActiveBlocksByRangeRequest<T::EthSpec>>,
    blobs_by_root_requests: FnvHashMap<Id, ActiveBlobsByRootRequest<T::EthSpec>>,
    blobs_by_range_requests: FnvHashMap<Id, ActiveBlobsByRangeRequest<T::EthSpec>>,

    on_going_block_and_blobs_requests:
        FnvHashMap<Id, (BBRId, BlocksAndBlobsRequestInfo<T::EthSpec>)>,

    pub chain: Arc<BeaconChain<T>>,

    /// Logger for the `SyncNetworkContext`.
    pub log: slog::Logger,
}

pub struct BlobsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indexes: Vec<u64>,
}

struct ActiveBlocksByRootRequest {
    request: Hash256,
    sender_id: SingleLookupReqId2,
    resolved: bool,
}

impl ActiveBlocksByRootRequest {
    fn is_valid_response<E: EthSpec>(&self, block: &SignedBeaconBlock<E>) -> bool {
        self.request != get_block_root(block)
    }
}

struct ActiveBlocksByRangeRequest<E: EthSpec> {
    request: BlocksByRangeRequest,
    sender_id: BBRId,
    blocks: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> ActiveBlocksByRangeRequest<E> {
    fn add_response(&mut self, block: Arc<SignedBeaconBlock<E>>) -> Result<(), RPCError> {
        if !self.request.in_range(block.slot()) {
            return Err(RPCError::InvalidData("un-requested data".to_string()));
        }
        if self.blocks.iter().any(|b| b.slot() == block.slot()) {
            return Err(RPCError::InvalidData("duplicated data".to_string()));
        }
        self.blocks.push(block);
        Ok(())
    }
}

struct ActiveBlobsByRootRequest<E: EthSpec> {
    request: BlobsByRootSingleBlockRequest,
    sender_id: SingleLookupReqId2,
    blobs: Vec<Arc<BlobSidecar<E>>>,
    resolved: bool,
}

impl<E: EthSpec> ActiveBlobsByRootRequest<E> {
    fn add_response(&mut self, blob: Arc<BlobSidecar<E>>) -> Result<(), RPCError> {
        if self.request.block_root != blob.block_root() {
            return Err(RPCError::InvalidData("un-requested block root".to_string()));
        }
        if !blob.verify_blob_sidecar_inclusion_proof().unwrap_or(false) {
            return Err(RPCError::InvalidData("invalid inclusion proof".to_string()));
        }
        if !self.request.indexes.contains(&blob.index) {
            return Err(RPCError::InvalidData("un-requested blob index".to_string()));
        }
        if self.blobs.iter().any(|b| b.index == blob.index) {
            return Err(RPCError::InvalidData("duplicated data".to_string()));
        }
        self.blobs.push(blob);
        Ok(())
    }
}

struct ActiveBlobsByRangeRequest<E: EthSpec> {
    request: BlocksByRangeRequest,
    sender_id: BBRId,
    blobs: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> ActiveBlobsByRangeRequest<E> {
    fn add_response(&mut self, blob: Arc<BlobSidecar<E>>) -> Result<(), RPCError> {
        if !self.request.in_range(blob.slot()) {
            return Err(RPCError::InvalidData("un-requested data".to_string()));
        }
        if self
            .blobs
            .iter()
            .any(|b| b.slot() == blob.slot() && b.index == blob.index)
        {
            return Err(RPCError::InvalidData("duplicated data".to_string()));
        }
        self.blobs.push(blob);
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BBRId {
    BackfillSync {
        batch_id: BatchId,
    },
    RangeSync {
        chain_id: ChainId,
        batch_id: BatchId,
    },
}

#[derive(Debug)]
pub enum RpcEvent<T> {
    StreamTermination,
    Response(T, Duration),
    RPCError(RPCError),
}

impl<T> From<Option<T>> for RpcEvent<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::Response(value, timestamp_now()),
            None => Self::StreamTermination,
        }
    }
}

/// Small enumeration to make dealing with block and blob requests easier.
pub enum BlockOrBlob<E: EthSpec> {
    Block(Result<Vec<Arc<SignedBeaconBlock<E>>>, RPCError>),
    Blob(Result<Vec<Arc<BlobSidecar<E>>>, RPCError>),
}

impl<T: BeaconChainTypes> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
        chain: Arc<BeaconChain<T>>,
        log: slog::Logger,
    ) -> Self {
        SyncNetworkContext {
            network_send,
            execution_engine_state: EngineState::Online, // always assume `Online` at the start
            request_id: 1,
            network_beacon_processor,
            on_going_block_and_blobs_requests: <_>::default(),
            blocks_by_root_requests: <_>::default(),
            blocks_by_range_requests: <_>::default(),
            blobs_by_root_requests: <_>::default(),
            blobs_by_range_requests: <_>::default(),
            chain,
            log,
        }
    }

    pub fn network_globals(&self) -> &NetworkGlobals<T::EthSpec> {
        &self.network_beacon_processor.network_globals
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
        let status_message = chain.status_message();
        for peer_id in peers {
            debug!(
                self.log,
                "Sending Status Request";
                "peer" => %peer_id,
                "fork_digest" => ?status_message.fork_digest,
                "finalized_root" => ?status_message.finalized_root,
                "finalized_epoch" => ?status_message.finalized_epoch,
                "head_root" => %status_message.head_root,
                "head_slot" => %status_message.head_slot,
            );

            let request = Request::Status(status_message.clone());
            let request_id = RequestId::Router;
            let _ = self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request,
                request_id,
            });
        }
    }

    /// Received a blocks by range response for a request that couples blocks and blobs.
    pub fn on_block_and_blob_response(
        &mut self,
        sender_id: BBRId,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) -> Option<(BBRId, Result<Vec<RpcBlock<T::EthSpec>>, String>)> {
        let Entry::Occupied(mut request) = self.on_going_block_and_blobs_requests.entry(todo!())
        else {
            return None;
        };

        match block_or_blob {
            BlockOrBlob::Block(blocks) => match blocks {
                Ok(blocks) => request.get_mut().1.add_block_response(blocks),
                Err(e) => {
                    let (sender, _) = request.remove();
                    return Some((sender, Err(e.to_string())));
                }
            },
            BlockOrBlob::Blob(blobs) => match blobs {
                Ok(blobs) => request.get_mut().1.add_sidecar_response(blobs),
                Err(e) => {
                    let (sender, _) = request.remove();
                    return Some((sender, Err(e.to_string())));
                }
            },
        }

        if request.get().1.is_finished() {
            // If the request is finished, dequeue everything
            let (sender, info) = request.remove();
            Some((sender, info.into_responses()))
        } else {
            None
        }
    }

    pub fn on_blocks_by_root_response(
        &mut self,
        request_id: Id,
        block: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<(
        SingleLookupReqId2,
        Result<(Arc<SignedBeaconBlock<T::EthSpec>>, Duration), RPCError>,
    )> {
        let Entry::Occupied(mut request) = self.blocks_by_root_requests.entry(request_id) else {
            return None;
        };

        Some((
            request.get().sender_id,
            match block {
                RpcEvent::Response(block, seen_timestamp) => {
                    let request = request.get_mut();
                    if request.resolved {
                        Err(RPCError::InvalidData("too many responses".to_string()))
                    } else if !request.is_valid_response(&block) {
                        Err(RPCError::InvalidData("wrong block root".to_string()))
                    } else {
                        // Valid data, blocks by root expects a single response
                        request.resolved = true;
                        Ok((block, seen_timestamp))
                    }
                }
                RpcEvent::StreamTermination => {
                    // Stream terminator
                    let request = request.remove();
                    if request.resolved {
                        return None;
                    } else {
                        Err(RPCError::InvalidData("no response returned".to_string()))
                    }
                }
                RpcEvent::RPCError(e) => {
                    request.remove();
                    Err(e)
                }
            },
        ))
    }

    pub fn on_blobs_by_root_response(
        &mut self,
        request_id: Id,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<(
        SingleLookupReqId2,
        Result<FixedBlobSidecarList<T::EthSpec>, RPCError>,
    )> {
        let Entry::Occupied(mut request) = self.blobs_by_root_requests.entry(request_id) else {
            return None;
        };

        Some((
            request.get().sender_id,
            match blob {
                RpcEvent::Response(blob, _) => {
                    let request = request.get_mut();
                    if request.resolved {
                        Err(RPCError::InvalidData("too many responses".to_string()))
                    } else if let Err(e) = request.add_response(blob) {
                        Err(e)
                    } else {
                        return None;
                    }
                }
                RpcEvent::StreamTermination => {
                    // Stream terminator
                    let request = request.remove();
                    if request.resolved {
                        return None;
                    } else {
                        // TODO: Should deal only with Vec<Arc<BlobSidecar>>
                        to_fixed_blob_sidecar_list(request.blobs).map_err(RPCError::InvalidData)
                    }
                }
                RpcEvent::RPCError(e) => {
                    request.remove();
                    Err(e)
                }
            },
        ))
    }

    pub fn on_blocks_by_range_response(
        &mut self,
        request_id: Id,
        peer_id: PeerId,
        block: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<(
        BBRId,
        Result<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>, RPCError>,
    )> {
        let Entry::Occupied(mut request) = self.blocks_by_range_requests.entry(request_id) else {
            return None;
        };

        Some((
            request.get().sender_id,
            match block {
                RpcEvent::Response(blob, seen_timestamp) => {
                    let request = request.get_mut();
                    if let Err(e) = request.add_response(blob) {
                        Err(e)
                    } else {
                        // TODO: We could return early when we get `request.count` blocks, instead
                        // of waiting for the stream terminator. Post deneb the logic to
                        // pre-emptively consider a batch complete is more complicated, as we need
                        // to wait for all blobs to arrive too. So we choose to not return early for
                        // simplicity.
                        return None;
                    }
                }
                RpcEvent::StreamTermination => {
                    // Stream terminator
                    let request = request.remove();
                    Ok(request.blocks)
                }
                RpcEvent::RPCError(e) => {
                    request.remove();
                    Err(e)
                }
            },
        ))
    }

    pub fn on_blobs_by_range_response(
        &mut self,
        request_id: Id,
        peer_id: PeerId,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<(BBRId, Result<Vec<Arc<BlobSidecar<T::EthSpec>>>, RPCError>)> {
        let Entry::Occupied(mut request) = self.blobs_by_range_requests.entry(request_id) else {
            return None;
        };

        Some((
            request.get().sender_id,
            match blob {
                RpcEvent::Response(blob, seen_timestamp) => {
                    let request = request.get_mut();
                    if let Err(e) = request.add_response(blob) {
                        Err(e)
                    } else {
                        return None;
                    }
                }
                RpcEvent::StreamTermination => {
                    // Stream terminator
                    let request = request.remove();
                    Ok(request.blobs)
                }
                RpcEvent::RPCError(e) => {
                    request.remove();
                    Err(e)
                }
            },
        ))
    }

    pub fn block_lookup_request(
        &mut self,
        sender_id: SingleLookupReqId2,
        peer_id: PeerId,
        block_root: Hash256,
    ) -> Result<(), &'static str> {
        let id = self.next_id();

        debug!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "block_root" => ?block_root,
            "peer" => %peer_id,
            "sender" => ?sender_id,
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRoot(BlocksByRootRequest::new(
                vec![block_root],
                &self.chain.spec,
            )),
            request_id: RequestId::Sync(SyncRequestId::BlocksByRoot(id)),
        })?;

        self.blocks_by_root_requests.insert(
            id,
            ActiveBlocksByRootRequest {
                request: block_root,
                sender_id,
                resolved: false,
            },
        );

        Ok(())
    }

    pub fn blob_lookup_request(
        &mut self,
        sender_id: SingleLookupReqId2,
        peer_id: PeerId,
        request: BlobsByRootSingleBlockRequest,
    ) -> Result<(), &'static str> {
        let id = self.next_id();

        debug!(
            self.log,
            "Sending BlobsByRoot Request";
            "method" => "BlobsByRoot",
            "block_root" => ?request.block_root,
            "blob_indices" => ?request.indexes,
            "peer" => %peer_id,
            "sender" => ?sender_id
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlobsByRoot(BlobsByRootRequest::new(
                request
                    .indexes
                    .iter()
                    .map(|index| BlobIdentifier {
                        block_root: request.block_root,
                        index: *index,
                    })
                    .collect(),
                &self.chain.spec,
            )),
            request_id: RequestId::Sync(SyncRequestId::BlobsByRoot(id)),
        })?;

        self.blobs_by_root_requests.insert(
            id,
            ActiveBlobsByRootRequest {
                request,
                sender_id,
                resolved: false,
                blobs: vec![],
            },
        );

        Ok(())
    }

    /// A blocks by range request sent by the backfill sync algorithm
    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        sender_id: BBRId,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending backfill BlocksByRange request";
            "method" => "BlocksByRange",
            "count" => request.count(),
            "peer" => %peer_id,
        );

        // TODO: Should BlocksByRange and BlobsByRange have different ids?
        let id = self.next_id();

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRange(request.clone()),
            request_id: RequestId::Sync(SyncRequestId::BlocksByRange(id)),
        })?;

        self.blocks_by_range_requests.insert(
            id,
            ActiveBlocksByRangeRequest {
                request: request.clone(),
                sender_id,
                blocks: vec![],
            },
        );

        if let ByRangeRequestType::BlocksAndBlobs = batch_type {
            self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
                }),
                request_id: RequestId::Sync(SyncRequestId::BlobsByRange(id)),
            })?;

            self.blobs_by_range_requests.insert(
                id,
                ActiveBlobsByRangeRequest {
                    request,
                    sender_id,
                    blobs: vec![],
                },
            );
        }

        self.on_going_block_and_blobs_requests
            .insert(id, (sender_id, BlocksAndBlobsRequestInfo::default()));

        Ok(id)
    }

    pub fn is_execution_engine_online(&self) -> bool {
        self.execution_engine_state == EngineState::Online
    }

    pub fn update_execution_engine_state(&mut self, engine_state: EngineState) {
        debug!(self.log, "Sync's view on execution engine state updated";
            "past_state" => ?self.execution_engine_state, "new_state" => ?engine_state);
        self.execution_engine_state = engine_state;
    }

    /// Terminates the connection with the peer and bans them.
    pub fn goodbye_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.network_send
            .send(NetworkMessage::GoodbyePeer {
                peer_id,
                reason,
                source: ReportSource::SyncService,
            })
            .unwrap_or_else(|_| {
                warn!(self.log, "Could not report peer: channel failed");
            });
    }

    /// Reports to the scoring algorithm the behaviour of a peer.
    pub fn report_peer(&self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
        debug!(self.log, "Sync reporting peer"; "peer_id" => %peer_id, "action" => %action);
        self.network_send
            .send(NetworkMessage::ReportPeer {
                peer_id,
                action,
                source: ReportSource::SyncService,
                msg,
            })
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not report peer: channel failed"; "error"=> %e);
            });
    }

    /// Subscribes to core topics.
    pub fn subscribe_core_topics(&self) {
        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not subscribe to core topics."; "error" => %e);
            });
    }

    /// Sends an arbitrary network message.
    fn send_network_msg(&self, msg: NetworkMessage<T::EthSpec>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!(self.log, "Could not send message to the network service");
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

    /// Check whether a batch for this epoch (and only this epoch) should request just blocks or
    /// blocks and blobs.
    pub fn batch_type(&self, epoch: types::Epoch) -> ByRangeRequestType {
        // Induces a compile time panic if this doesn't hold true.
        #[allow(clippy::assertions_on_constants)]
        const _: () = assert!(
            super::backfill_sync::BACKFILL_EPOCHS_PER_BATCH == 1
                && super::range_sync::EPOCHS_PER_BATCH == 1,
            "To deal with alignment with deneb boundaries, batches need to be of just one epoch"
        );

        if let Some(data_availability_boundary) = self.chain.data_availability_boundary() {
            if epoch >= data_availability_boundary {
                ByRangeRequestType::BlocksAndBlobs
            } else {
                ByRangeRequestType::Blocks
            }
        } else {
            ByRangeRequestType::Blocks
        }
    }
}

fn to_fixed_blob_sidecar_list<E: EthSpec>(
    blobs: Vec<Arc<BlobSidecar<E>>>,
) -> Result<FixedBlobSidecarList<E>, String> {
    let mut fixed_list = FixedBlobSidecarList::default();
    for blob in blobs.into_iter() {
        let index = blob.index as usize;
        *fixed_list
            .get_mut(index)
            .ok_or("invalid index".to_string())? = Some(blob)
    }
    Ok(fixed_list)
}
