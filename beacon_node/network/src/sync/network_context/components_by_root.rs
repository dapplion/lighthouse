use super::{
    BlockRootsRequest, LookupRequestResult, RpcRequestSendError, RpcResponseError,
    SyncNetworkContext,
};
use crate::sync::block_sidecar_coupling::{CouplingError, RangeBlockComponentsRequest};
use crate::sync::network_context::{DownloadError, DownloadRequest};
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::RangeSyncBlock;
use beacon_chain::custody_context::CustodyContext;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::{
    BeaconBlocksByRootRequestId, BeaconBlocksByRootRequester, ComponentsByRootRequestId,
    PayloadEnvelopesByRootRequestId,
};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use types::{
    DataColumnSidecarList, EthSpec, Hash256, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
    Slot,
};

pub type ComponentsByRootResult<E> = Result<Vec<RangeSyncBlock<E>>, Error>;
pub type ComponentsByRootRequestResult<E> = Result<Option<Vec<RangeSyncBlock<E>>>, Error>;

pub enum ComponentsByRootResponse<E: EthSpec> {
    Blocks(
        BeaconBlocksByRootRequestId,
        Result<Vec<Arc<SignedBeaconBlock<E>>>, RpcResponseError>,
    ),
    Columns(
        ComponentsByRootRequestId,
        Result<DataColumnSidecarList<E>, RpcResponseError>,
    ),
    Payloads(
        PayloadEnvelopesByRootRequestId,
        Result<Vec<Arc<SignedExecutionPayloadEnvelope<E>>>, RpcResponseError>,
    ),
}

#[derive(Debug)]
pub enum Error {
    Download(#[allow(dead_code)] DownloadError),
    Coupling(#[allow(dead_code)] CouplingError),
}

impl From<DownloadError> for Error {
    fn from(e: DownloadError) -> Self {
        Error::Download(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSummary {
    pub block_root: Hash256,
    pub slot: Slot,
    pub has_data: bool,
    pub has_payload: bool,
}

pub struct ComponentsByRootRequest<T: BeaconChainTypes> {
    req_id: ComponentsByRootRequestId,
    oldest_slot: Slot,
    roots: Vec<Hash256>,
    roots_with_data: Vec<Hash256>,
    roots_with_payload: Vec<Hash256>,
    peers: Arc<RwLock<HashSet<PeerId>>>,
    blocks: DownloadRequest<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>, BeaconBlocksByRootRequestId>,
    columns: DownloadRequest<DataColumnSidecarList<T::EthSpec>, ComponentsByRootRequestId>,
    payloads: DownloadRequest<
        Vec<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>>,
        PayloadEnvelopesByRootRequestId,
    >,
}

impl<T: BeaconChainTypes> ComponentsByRootRequest<T> {
    pub fn new(
        req_id: ComponentsByRootRequestId,
        blocks: &[BlockSummary],
        peers: Arc<RwLock<HashSet<PeerId>>>,
    ) -> Result<Self, RpcRequestSendError> {
        let oldest_slot = blocks
            .first()
            .map(|block| block.slot)
            .ok_or_else(|| RpcRequestSendError::InternalError("no roots to download".to_owned()))?;
        let roots_with = |predicate: fn(&BlockSummary) -> bool| -> Vec<Hash256> {
            blocks
                .iter()
                .filter(|block| predicate(block))
                .map(|block| block.block_root)
                .collect()
        };
        Ok(Self {
            req_id,
            oldest_slot,
            roots: roots_with(|_| true),
            roots_with_data: roots_with(|block| block.has_data),
            roots_with_payload: roots_with(|block| block.has_payload),
            peers,
            blocks: DownloadRequest::new(),
            columns: DownloadRequest::new(),
            payloads: DownloadRequest::new(),
        })
    }

    pub fn on_response(
        &mut self,
        response: ComponentsByRootResponse<T::EthSpec>,
        peer_id: Option<PeerId>,
        cx: &mut SyncNetworkContext<T>,
    ) -> ComponentsByRootRequestResult<T::EthSpec> {
        let is_current_attempt = match response {
            ComponentsByRootResponse::Blocks(id, result) => {
                self.blocks.on_response(id, result.map_err(|_| ()), peer_id)
            }
            ComponentsByRootResponse::Columns(id, result) => {
                self.columns
                    .on_response(id, result.map_err(|_| ()), peer_id)
            }
            ComponentsByRootResponse::Payloads(id, result) => {
                self.payloads
                    .on_response(id, result.map_err(|_| ()), peer_id)
            }
        };
        if !is_current_attempt {
            return Ok(None);
        }
        self.continue_requests(cx)
    }

    pub fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> ComponentsByRootRequestResult<T::EthSpec> {
        let Self {
            req_id,
            oldest_slot,
            roots,
            roots_with_data,
            roots_with_payload,
            peers,
            blocks,
            columns,
            payloads,
            ..
        } = self;

        blocks.maybe_start_downloading(|failed_peers| {
            match cx.send_blocks_by_root_request(
                BlockRootsRequest(roots.clone()),
                BeaconBlocksByRootRequester::ComponentsByRoot(*req_id),
                peers,
                failed_peers,
                true,
            )? {
                Some(id) => Ok(LookupRequestResult::RequestSent(id)),
                None => Ok(LookupRequestResult::Pending("no peers")),
            }
        })?;

        columns.maybe_start_downloading(|_failed_peers| {
            let epoch = oldest_slot.epoch(<T::EthSpec as EthSpec>::slots_per_epoch());
            cx.custody_by_root_request(*req_id, roots_with_data, epoch, peers)
        })?;

        payloads.maybe_start_downloading(|failed_peers| {
            cx.payloads_by_root_request(*req_id, roots_with_payload, peers, failed_peers)
        })?;

        if let (Some(blocks), Some(columns), Some(payloads)) =
            (blocks.complete(), columns.complete(), payloads.complete())
        {
            Ok(Some(couple(
                blocks,
                columns,
                payloads,
                &cx.chain.custody_context,
            )?))
        } else {
            Ok(None)
        }
    }
}

fn couple<T: BeaconChainTypes>(
    blocks: &[Arc<SignedBeaconBlock<T::EthSpec>>],
    columns: &DataColumnSidecarList<T::EthSpec>,
    payloads: &[Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>],
    custody_context: &CustodyContext<T>,
) -> ComponentsByRootResult<T::EthSpec> {
    let mut ordered = blocks.to_vec();
    ordered.sort_unstable_by_key(|block| block.slot());
    let payload_envelopes = if payloads.is_empty() {
        None
    } else {
        Some(payloads.to_vec())
    };

    RangeBlockComponentsRequest::responses_with_custody_columns(
        ordered,
        columns.clone(),
        custody_context,
        payload_envelopes,
    )
    .map_err(Error::Coupling)
}
