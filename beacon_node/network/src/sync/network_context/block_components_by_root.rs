//! A coupled block download by root: the spec's `download_blocks(roots, peers)`.
//!
//! Blocks and columns are each fetched for the whole set in one request — one
//! `BlocksByRoot` carrying every root, one custody request covering the same roots — so a
//! chain costs two round trips rather than two per block. The two are tracked separately
//! and retried independently: a blocks request that fails is re-issued to a different peer
//! without disturbing an in-flight or completed column request.
//!
//! Blocks are requested before columns. Assuming the block peer is honest, a custody
//! failure is then attributable to the peer serving the columns.

use super::{
    LookupRequestResult, NoPeerError, RpcRequestSendError, RpcResponseError, SyncNetworkContext,
};
use crate::sync::block_sidecar_coupling::RangeBlockComponentsRequest;
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::RangeSyncBlock;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::{CustodyRequester, Id, SingleLookupReqId};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use types::{DataColumnSidecarList, Epoch, EthSpec, Hash256, SignedBeaconBlock};

/// Attempts at each of the two requests before the whole download fails.
const MAX_ATTEMPTS: u8 = 5;

pub type BlockComponentsByRootResult<E> = Result<Vec<RangeSyncBlock<E>>, Error>;

#[derive(Debug)]
pub enum Error {
    /// A request could not be completed within `MAX_ATTEMPTS`.
    TooManyAttempts(&'static str),
    /// Blocks and columns could not be coupled into importable blocks.
    Coupling(String),
    Internal(String),
}

/// One coupled download. Lives in `SyncNetworkContext`, keyed by `id`, which is also the
/// `lookup_id` of every request it issues — so the presence of that key is what tells the
/// manager a response belongs to forward sync rather than to lookup sync.
pub struct BlockComponentsByRootRequest<T: BeaconChainTypes> {
    id: Id,
    /// Requested roots, oldest first. Also the order blocks are returned in.
    roots: Vec<Hash256>,
    epoch: Epoch,
    /// Live, not captured: a peer admitted mid-flight is usable by this request.
    peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Peers that failed a request here, deprioritized on retry.
    failed_peers: HashSet<PeerId>,
    blocks: BlocksState<T::EthSpec>,
    block_attempts: u8,
    columns: ColumnsState<T::EthSpec>,
    column_attempts: u8,
}

enum BlocksState<E: EthSpec> {
    Active(SingleLookupReqId),
    Complete(Vec<Arc<SignedBeaconBlock<E>>>),
}

enum ColumnsState<E: EthSpec> {
    /// Waiting on the blocks: we cannot tell whether columns are needed until we see them.
    NotStarted,
    Active,
    Complete(DataColumnSidecarList<E>),
    /// Pre-Fulu, or no block in the set carries data.
    NotNeeded,
}

impl<T: BeaconChainTypes> BlockComponentsByRootRequest<T> {
    pub fn new(
        id: Id,
        roots: Vec<Hash256>,
        epoch: Epoch,
        peers: Arc<RwLock<HashSet<PeerId>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<Self, RpcRequestSendError> {
        let req_id =
            cx.blocks_by_root_batch_request(id, roots.clone(), peers.clone(), &HashSet::new())?;
        Ok(Self {
            id,
            roots,
            epoch,
            peers,
            failed_peers: HashSet::new(),
            blocks: BlocksState::Active(req_id),
            block_attempts: 1,
            columns: ColumnsState::NotStarted,
            column_attempts: 0,
        })
    }

    /// Handles the batched `blocks_by_root` response.
    pub fn on_blocks_response(
        &mut self,
        req_id: SingleLookupReqId,
        peer_id: PeerId,
        result: Result<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>, RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<BlockComponentsByRootResult<T::EthSpec>> {
        match &self.blocks {
            // A response for an attempt we have already superseded.
            BlocksState::Active(active) if *active != req_id => return None,
            BlocksState::Complete(_) => return None,
            BlocksState::Active(_) => {}
        }

        match result {
            // A short response is not a protocol violation — the peer may simply not have
            // a root — but it is not usable either, so retry elsewhere without penalty.
            Ok(blocks) if blocks.len() == self.roots.len() => {
                self.blocks = BlocksState::Complete(blocks)
            }
            Ok(_) => {
                self.failed_peers.insert(peer_id);
                if self.block_attempts >= MAX_ATTEMPTS {
                    return Some(Err(Error::TooManyAttempts("blocks")));
                }
                return match cx.blocks_by_root_batch_request(
                    self.id,
                    self.roots.clone(),
                    self.peers.clone(),
                    &self.failed_peers,
                ) {
                    Ok(req_id) => {
                        self.blocks = BlocksState::Active(req_id);
                        self.block_attempts = self.block_attempts.saturating_add(1);
                        None
                    }
                    Err(e) => Some(Err(Error::Internal(format!("{e:?}")))),
                };
            }
            Err(_) => {
                self.failed_peers.insert(peer_id);
                if self.block_attempts >= MAX_ATTEMPTS {
                    return Some(Err(Error::TooManyAttempts("blocks")));
                }
                // Retry the blocks request alone; any column request is unaffected.
                return match cx.blocks_by_root_batch_request(
                    self.id,
                    self.roots.clone(),
                    self.peers.clone(),
                    &self.failed_peers,
                ) {
                    Ok(req_id) => {
                        self.blocks = BlocksState::Active(req_id);
                        self.block_attempts = self.block_attempts.saturating_add(1);
                        None
                    }
                    Err(e) => Some(Err(Error::Internal(format!("{e:?}")))),
                };
            }
        }

        self.continue_request(cx)
    }

    /// Handles the custody response covering the whole set.
    /// A custody request spans several peers, so a failure is not attributable to one of
    /// them and none is deprioritized here.
    pub fn on_custody_response(
        &mut self,
        result: Result<DataColumnSidecarList<T::EthSpec>, RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<BlockComponentsByRootResult<T::EthSpec>> {
        match result {
            Ok(columns) => {
                self.columns = ColumnsState::Complete(columns);
                self.continue_request(cx)
            }
            Err(_) => {
                if self.column_attempts >= MAX_ATTEMPTS {
                    return Some(Err(Error::TooManyAttempts("columns")));
                }
                // Retry the columns alone; the blocks are already in hand.
                self.columns = ColumnsState::NotStarted;
                self.continue_request(cx)
            }
        }
    }

    /// Starts the column request once the blocks are in, then couples both.
    fn continue_request(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Option<BlockComponentsByRootResult<T::EthSpec>> {
        let BlocksState::Complete(blocks) = &self.blocks else {
            return None;
        };

        if matches!(self.columns, ColumnsState::NotStarted) {
            let fork = cx.chain.spec.fork_name_at_epoch(self.epoch);
            // Only blocks carrying data have columns. Asking for the whole set would make an
            // honest peer's response look short, and a short custody response is a verify
            // error that downscores the peer.
            let roots_with_data = blocks
                .iter()
                .filter(|block| block.num_expected_blobs() > 0)
                .map(|block| block.canonical_root())
                .collect::<Vec<_>>();
            if !fork.fulu_enabled() || roots_with_data.is_empty() {
                self.columns = ColumnsState::NotNeeded;
            } else {
                let requester = CustodyRequester::SingleLookup(SingleLookupReqId {
                    lookup_id: self.id,
                    req_id: 0,
                });
                match cx.custody_lookup_request(
                    requester,
                    &roots_with_data,
                    self.epoch,
                    false,
                    self.peers.clone(),
                ) {
                    Ok(LookupRequestResult::RequestSent(_)) => {
                        self.columns = ColumnsState::Active;
                        self.column_attempts = self.column_attempts.saturating_add(1);
                        return None;
                    }
                    Ok(LookupRequestResult::NoRequestNeeded(_, columns)) => {
                        self.columns = ColumnsState::Complete(columns);
                    }
                    // No custody peer yet. Retried when the peer set changes.
                    Ok(LookupRequestResult::Pending(_)) => return None,
                    Err(RpcRequestSendError::NoPeer(NoPeerError::CustodyPeer(_))) => return None,
                    Err(e) => return Some(Err(Error::Internal(format!("{e:?}")))),
                }
            }
        }

        let columns = match &self.columns {
            ColumnsState::NotStarted | ColumnsState::Active => return None,
            ColumnsState::NotNeeded => vec![],
            ColumnsState::Complete(columns) => columns.clone(),
        };

        // Present blocks in the order the roots were requested, which is import order.
        let ordered = self
            .roots
            .iter()
            .filter_map(|root| {
                blocks
                    .iter()
                    .find(|block| block.canonical_root() == *root)
                    .cloned()
            })
            .collect::<Vec<_>>();

        Some(
            RangeBlockComponentsRequest::responses_with_custody_columns(
                ordered,
                columns,
                &cx.chain.custody_context,
                None,
            )
            .map_err(|e| Error::Coupling(format!("{e:?}"))),
        )
    }
}
