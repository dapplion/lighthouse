use crate::sync::network_context::{
    BatchPeers, PeerGroup, RpcRequestSendError, RpcResponseError, SyncNetworkContext,
};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::{get_block_root, BeaconChainTypes};
use lighthouse_network::service::api_types::{
    BlobsByRootRequestId, BlocksByRootRequestId, BlocksByRootRequester, ComponentsByRootRequestId,
    CustodyByRootRequestId,
};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecarList, EthSpec, Hash256,
    RuntimeVariableList, SignedBeaconBlock,
};

/// Given a `BlocksByRootRequest` (a collection of block roots) fetches all necessary data to
/// return potentially available RpcBlocks.
///
/// See [`State`] for the set of `*_by_root` it may issue depending on the fork.
pub struct BlockComponentsByRootRequest<T: BeaconChainTypes> {
    id: ComponentsByRootRequestId,
    peers: Arc<RwLock<HashSet<PeerId>>>,
    block_root: Hash256,
    state: State<T::EthSpec>,
}

// Request blocks first, then columns. Assuming the block peer is honest we can attribute
// custody failures to the peers serving us columns. We want to get rid of the honest block
// peer assumption in the future, see https://github.com/sigp/lighthouse/issues/6258
enum State<E: EthSpec> {
    BlocksRequest {
        blocks_request: Request<BlocksByRootRequestId, Arc<SignedBeaconBlock<E>>>,
    },
    DataRequest {
        block: Arc<SignedBeaconBlock<E>>,
        block_peer: PeerId,
        data_request: DataRequest<E>,
    },
}

enum DataRequest<E: EthSpec> {
    Deneb {
        blobs_request: Request<BlobsByRootRequestId, Vec<Arc<BlobSidecar<E>>>>,
    },
    Fulu {
        custody_request: Request<CustodyByRootRequestId, DataColumnSidecarList<E>, PeerGroup>,
    },
}

enum Request<I: PartialEq + std::fmt::Display, T, P = PeerId> {
    /// Active(RequestIndex)
    Active(I),
    /// Complete(DownloadedData, Peers)
    Complete(T, P),
}

pub type BlockComponentsByRootRequestResult<E> = Result<Option<(RpcBlock<E>, BatchPeers)>, Error>;

pub enum Error {
    InternalError(String),
}

impl From<Error> for RpcResponseError {
    fn from(e: Error) -> Self {
        match e {
            Error::InternalError(e) => RpcResponseError::InternalError(e),
        }
    }
}

impl From<Error> for RpcRequestSendError {
    fn from(e: Error) -> Self {
        match e {
            Error::InternalError(e) => RpcRequestSendError::InternalError(e),
        }
    }
}

/// Used to typesafe assertions of state in range sync tests
#[cfg(test)]
#[derive(Debug)]
pub enum BlockComponentsByRootRequestStep {
    BlocksRequest,
    CustodyRequest,
}

impl<T: BeaconChainTypes> BlockComponentsByRootRequest<T> {
    pub fn new(
        id: ComponentsByRootRequestId,
        block_root: Hash256,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        peers_to_deprioritize: &HashSet<PeerId>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Self, RpcRequestSendError> {
        // TODO(das): a change of behaviour here is that if the SyncingChain has a single peer we
        // will request all blocks for the first 5 epochs to that same single peer. Before we would
        // query only idle peers in the syncing chain.
        let Some(block_peer) = peers
            .read()
            .iter()
            .map(|peer| {
                (
                    // If contains -> 1 (order after), not contains -> 0 (order first)
                    peers_to_deprioritize.contains(peer),
                    // Random factor to break ties, otherwise the PeerID breaks ties
                    rand::random::<u32>(),
                    peer,
                )
            })
            .min()
            .map(|(_, _, peer)| *peer)
        else {
            // When a peer disconnects and is removed from the SyncingChain peer set, if the set
            // reaches zero the SyncingChain is removed.
            return Err(RpcRequestSendError::NoPeers);
        };

        let blocks_req_id = cx.send_blocks_by_root_request(
            block_peer,
            block_root,
            BlocksByRootRequester::RangeSync(id),
        )?;

        let state = State::BlocksRequest {
            blocks_request: Request::Active(blocks_req_id),
        };

        Ok(Self {
            id,
            peers,
            block_root,
            state,
        })
    }

    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> BlockComponentsByRootRequestResult<T::EthSpec> {
        match &mut self.state {
            State::BlocksRequest {
                blocks_request: blocks_by_range_request,
            } => {
                if let Some((block, block_peer)) = blocks_by_range_request.to_finished() {
                    let fork = cx.spec().fork_name_at_slot::<T::EthSpec>(block.slot());
                    let block_has_data = block.has_data();

                    if block_has_data && fork.fulu_enabled() {
                        let mut column_indices = cx
                            .network_globals()
                            .sampling_columns()
                            .iter()
                            .copied()
                            .collect::<Vec<_>>();
                        column_indices.sort_unstable();

                        let req_id = cx
                            .send_custody_by_root_request(
                                self.id,
                                self.block_root,
                                self.peers.clone(),
                            )
                            .map_err(|e| match e {
                                RpcRequestSendError::InternalError(e) => Error::InternalError(e),
                                RpcRequestSendError::NoPeers => Error::InternalError(
                                    "send_custody_by_range_request does not error with NoPeers"
                                        .to_owned(),
                                ),
                            })?;

                        self.state = State::DataRequest {
                            block: block.clone(),
                            block_peer: *block_peer,
                            data_request: DataRequest::Fulu {
                                custody_request: Request::Active(req_id),
                            },
                        };
                        Ok(None)
                    } else if block_has_data && fork.deneb_enabled() {
                        // TODO(deneb): is it okay to send blobs_by_range requests outside the DA window? I
                        // would like the beacon processor / da_checker to be the one that decides if an
                        // RpcBlock is valid or not with respect to containing blobs. Having sync not even
                        // attempt a requests seems like an added limitation.
                        let req_id = cx
                            .send_blobs_by_root_request(
                                *block_peer,
                                self.block_root,
                                block.num_expected_blobs(),
                                self.id,
                            )
                            .map_err(|e| match e {
                                RpcRequestSendError::InternalError(e) => Error::InternalError(e),
                                RpcRequestSendError::NoPeers => Error::InternalError(
                                    "send_custody_by_range_request does not error with NoPeers"
                                        .to_owned(),
                                ),
                            })?;

                        self.state = State::DataRequest {
                            block: block.clone(),
                            block_peer: *block_peer,
                            data_request: DataRequest::Deneb {
                                blobs_request: Request::Active(req_id),
                            },
                        };
                        Ok(None)
                    } else {
                        let peer_group = BatchPeers::new_from_block_peer(*block_peer);
                        let rpc_block = couple_block_base(block.clone());
                        Ok(Some((rpc_block, peer_group)))
                    }
                } else {
                    // Wait for blocks_by_range requests to complete
                    Ok(None)
                }
            }
            State::DataRequest {
                block,
                block_peer,
                data_request,
            } => match data_request {
                DataRequest::Deneb {
                    blobs_request: blobs_by_range_request,
                } => {
                    if let Some((blobs, _)) = blobs_by_range_request.to_finished() {
                        // We use the same block_peer for the blobs request
                        let peer_group = BatchPeers::new_from_block_peer(*block_peer);
                        let rpc_block =
                            couple_block_deneb(block.clone(), blobs.to_vec(), cx.spec())?;
                        Ok(Some((rpc_block, peer_group)))
                    } else {
                        // Wait for blocks_by_range and blobs_by_range requests to complete
                        Ok(None)
                    }
                }
                DataRequest::Fulu {
                    custody_request: custody_by_range_request,
                } => {
                    if let Some((columns, column_peers)) = custody_by_range_request.to_finished() {
                        let custody_column_indices = cx
                            .network_globals()
                            .sampling_columns()
                            .iter()
                            .copied()
                            .collect();

                        let peer_group = BatchPeers::new(*block_peer, column_peers.clone());
                        let rpc_block = couple_block_fulu(
                            block.clone(),
                            columns.to_vec(),
                            custody_column_indices,
                            cx.spec(),
                        )?;
                        Ok(Some((rpc_block, peer_group)))
                    } else {
                        // Wait for the custody_by_range request to complete
                        Ok(None)
                    }
                }
            },
        }
    }

    pub fn on_blocks_by_root_result(
        &mut self,
        id: BlocksByRootRequestId,
        data: Arc<SignedBeaconBlock<T::EthSpec>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) -> BlockComponentsByRootRequestResult<T::EthSpec> {
        match &mut self.state {
            State::BlocksRequest { blocks_request } => {
                blocks_request.finish(id, data, peer_id)?;
            }
            _ => {
                return Err(Error::InternalError(
                    "Received unexpected blocks_by_range response".to_string(),
                ))
            }
        }

        self.continue_requests(cx)
    }

    pub fn on_blobs_by_root_result(
        &mut self,
        id: BlobsByRootRequestId,
        data: Vec<Arc<BlobSidecar<T::EthSpec>>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) -> BlockComponentsByRootRequestResult<T::EthSpec> {
        match &mut self.state {
            State::DataRequest {
                data_request: DataRequest::Deneb { blobs_request },
                ..
            } => {
                blobs_request.finish(id, data, peer_id)?;
            }
            _ => {
                return Err(Error::InternalError(
                    "Received unexpected blobs_by_range response".to_string(),
                ))
            }
        }

        self.continue_requests(cx)
    }

    pub fn on_custody_by_root_result(
        &mut self,
        id: CustodyByRootRequestId,
        data: DataColumnSidecarList<T::EthSpec>,
        peers: PeerGroup,
        cx: &mut SyncNetworkContext<T>,
    ) -> BlockComponentsByRootRequestResult<T::EthSpec> {
        match &mut self.state {
            State::DataRequest {
                data_request: DataRequest::Fulu { custody_request },
                ..
            } => {
                custody_request.finish(id, data, peers)?;
            }
            _ => {
                return Err(Error::InternalError(
                    "Received unexpected custody_by_range response".to_string(),
                ))
            }
        }

        self.continue_requests(cx)
    }

    #[cfg(test)]
    pub fn state_step(&self) -> BlockComponentsByRootRequestStep {
        match &self.state {
            State::BlocksRequest { .. } => BlockComponentsByRootRequestStep::BlocksRequest,
            State::DataRequest { .. } => BlockComponentsByRootRequestStep::CustodyRequest,
        }
    }
}

fn couple_block_base<E: EthSpec>(block: Arc<SignedBeaconBlock<E>>) -> RpcBlock<E> {
    RpcBlock::new_without_blobs(None, block)
}

fn couple_block_deneb<E: EthSpec>(
    block: Arc<SignedBeaconBlock<E>>,
    blobs: Vec<Arc<BlobSidecar<E>>>,
    spec: &ChainSpec,
) -> Result<RpcBlock<E>, Error> {
    let mut blobs_by_block = HashMap::<Hash256, Vec<Arc<BlobSidecar<E>>>>::new();
    for blob in blobs {
        let block_root = blob.block_root();
        blobs_by_block.entry(block_root).or_default().push(blob);
    }

    // Now collect all blobs that match to the block by block root. BlobsByRange request checks
    // the inclusion proof so we know that the commitment is the expected.
    //
    // BlobsByRange request handler ensures that we don't receive more blobs than possible.
    // If the peer serving the request sends us blobs that don't pair well we'll send to the
    // processor blocks without expected blobs, resulting in a downscoring event. A serving peer
    // could serve fake blobs for blocks that don't have data, but it would gain nothing by it
    // wasting theirs and our bandwidth 1:1. Therefore blobs that don't pair well are just ignored.
    //
    // RpcBlock::new ensures that the count of blobs is consistent with the block
    let block_root = get_block_root(&block);
    let max_blobs_per_block = spec.max_blobs_per_block(block.epoch()) as usize;
    let blobs = blobs_by_block.remove(&block_root).unwrap_or_default();
    // BlobsByRange request handler enforces that blobs are sorted by index
    let blobs = RuntimeVariableList::new(blobs, max_blobs_per_block)
        .map_err(|_| Error::InternalError("Blobs returned exceeds max length".to_string()))?;
    Ok(RpcBlock::new(Some(block_root), block, Some(blobs)).expect("TODO: don't do matching here"))
}

fn couple_block_fulu<E: EthSpec>(
    block: Arc<SignedBeaconBlock<E>>,
    data_columns: DataColumnSidecarList<E>,
    custody_column_indices: Vec<ColumnIndex>,
    spec: &ChainSpec,
) -> Result<RpcBlock<E>, Error> {
    // Group data columns by block_root and index
    let mut custody_columns_by_block = HashMap::<Hash256, Vec<CustodyDataColumn<E>>>::new();

    for column in data_columns {
        let block_root = column.block_root();

        if custody_column_indices.contains(&column.index) {
            custody_columns_by_block
                .entry(block_root)
                .or_default()
                // Safe to convert to `CustodyDataColumn`: we have asserted that the index of
                // this column is in the set of `expects_custody_columns` and with the expected
                // block root, so for the expected epoch of this batch.
                .push(CustodyDataColumn::from_asserted_custody(column));
        }
    }

    // Now iterate all blocks ensuring that the block roots of each block and data column match,
    let block_root = get_block_root(&block);
    let data_columns_with_block_root = custody_columns_by_block
        // Remove to only use columns once
        .remove(&block_root)
        .unwrap_or_default();

    RpcBlock::new_with_custody_columns(Some(block_root), block, data_columns_with_block_root, spec)
        .map_err(Error::InternalError)
}

impl<I: PartialEq + std::fmt::Display, T, P> Request<I, T, P> {
    fn finish(&mut self, id: I, data: T, peer_id: P) -> Result<(), Error> {
        match self {
            Self::Active(expected_id) => {
                if expected_id != &id {
                    return Err(Error::InternalError(format!(
                        "unexpected req_id expected {expected_id} got {id}"
                    )));
                }
                *self = Self::Complete(data, peer_id);
                Ok(())
            }
            Self::Complete(_, _) => Err(Error::InternalError(format!(
                "request already complete {id}"
            ))),
        }
    }

    fn to_finished(&self) -> Option<(&T, &P)> {
        match self {
            Self::Active(_) => None,
            Self::Complete(data, peer_id) => Some((data, peer_id)),
        }
    }
}
