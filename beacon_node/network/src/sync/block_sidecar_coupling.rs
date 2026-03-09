use beacon_chain::{
    BeaconChainTypes,
    block_verification_types::{AvailableBlockData, RpcBlock},
    data_availability_checker::DataAvailabilityChecker,
    data_column_verification::CustodyDataColumn,
    get_block_root,
};
use lighthouse_network::{
    PeerId,
    service::api_types::{
        BlocksByRangeRequestId, ComponentsByRangeRequestId, CustodyRequester, RangeSyncCustodyId,
    },
};
use parking_lot::RwLock;
use ssz_types::RuntimeVariableList;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::debug;
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    Hash256, SignedBeaconBlock,
};

use crate::sync::network_context::{LookupRequestResult, PeerGroup, SyncNetworkContext};

pub use lighthouse_network::service::api_types::BlobsByRangeRequestId;

/// Accumulates and couples beacon blocks with their associated data (blobs or data columns)
/// from range sync network responses.
///
/// This struct acts as temporary storage while multiple network responses arrive:
/// - Blocks themselves (always required)
/// - Blob sidecars (pre-Fulu fork)
/// - Data columns (Fulu fork and later, via custody-by-root)
///
/// It accumulates responses until all expected components are received, then couples
/// them together and returns complete `RpcBlock`s ready for processing.
pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    blocks_request: ByRangeRequest<BlocksByRangeRequestId, Vec<Arc<SignedBeaconBlock<E>>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    block_data_request: RangeBlockDataRequest<E>,
}

pub enum ByRangeRequest<I: PartialEq + std::fmt::Display, T> {
    Active(I),
    Complete(T),
}

enum RangeBlockDataRequest<E: EthSpec> {
    NoData,
    Blobs(ByRangeRequest<BlobsByRangeRequestId, Vec<Arc<BlobSidecar<E>>>>),
    DataColumns {
        custody_columns_by_root: HashMap<Hash256, DataColumnsState<E>>,
        expected_custody_columns: Vec<ColumnIndex>,
    },
}

#[derive(Clone)]
enum DataColumnsState<E: EthSpec> {
    Requesting,
    Complete(DataColumnSidecarList<E>, PeerGroup),
}

#[derive(Debug)]
pub(crate) enum CouplingError {
    InternalError(String),
    /// The peer we requested the columns from was faulty/malicious
    DataColumnPeerFailure {
        error: String,
        faulty_peers: Vec<(ColumnIndex, PeerId)>,
    },
    BlobPeerFailure(String),
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    /// Creates a new range request for blocks and their associated data (blobs or data columns).
    ///
    /// # Arguments
    /// * `blocks_req_id` - Request ID for the blocks
    /// * `blobs_req_id` - Optional request ID for blobs (pre-Fulu fork)
    /// * `expects_custody_columns` - If Some, custody-by-root will be used after blocks arrive
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        expects_custody_columns: Option<Vec<ColumnIndex>>,
    ) -> Self {
        let block_data_request = if let Some(blobs_req_id) = blobs_req_id {
            RangeBlockDataRequest::Blobs(ByRangeRequest::Active(blobs_req_id))
        } else if let Some(expected_custody_columns) = expects_custody_columns {
            RangeBlockDataRequest::DataColumns {
                custody_columns_by_root: HashMap::new(),
                expected_custody_columns,
            }
        } else {
            RangeBlockDataRequest::NoData
        };

        Self {
            blocks_request: ByRangeRequest::Active(blocks_req_id),
            block_data_request,
        }
    }

    /// Returns true if the blocks component of this request has been received.
    pub fn blocks_received(&self) -> bool {
        self.blocks_request.to_finished().is_some()
    }

    /// Adds received blocks to the request.
    ///
    /// Returns an error if the request ID doesn't match the expected blocks request.
    pub fn add_blocks(
        &mut self,
        req_id: BlocksByRangeRequestId,
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
    ) -> Result<(), String> {
        self.blocks_request.finish(req_id, blocks)
    }

    /// Adds received blobs to the request.
    ///
    /// Returns an error if this request expects data columns instead of blobs,
    /// or if the request ID doesn't match.
    pub fn add_blobs(
        &mut self,
        req_id: BlobsByRangeRequestId,
        blobs: Vec<Arc<BlobSidecar<E>>>,
    ) -> Result<(), String> {
        match &mut self.block_data_request {
            RangeBlockDataRequest::NoData => Err("received blobs but expected no data".to_owned()),
            RangeBlockDataRequest::Blobs(req) => req.finish(req_id, blobs),
            RangeBlockDataRequest::DataColumns { .. } => {
                Err("received blobs but expected data columns".to_owned())
            }
        }
    }

    /// Adds received custody columns for a specific block root.
    ///
    /// Returns an error if not in DataColumns mode, or if columns for this root
    /// were already completed.
    pub fn add_custody_columns(
        &mut self,
        block_root: Hash256,
        columns: DataColumnSidecarList<E>,
        peer_group: PeerGroup,
    ) -> Result<(), String> {
        let RangeBlockDataRequest::DataColumns {
            custody_columns_by_root,
            ..
        } = &mut self.block_data_request
        else {
            return Err("received custody columns but not in DataColumns mode".to_owned());
        };
        match custody_columns_by_root.get(&block_root) {
            Some(DataColumnsState::Complete(..)) => Err(format!(
                "duplicate custody columns for block root {block_root:?}"
            )),
            None => Err(format!(
                "received custody columns for unregistered block root {block_root:?}"
            )),
            Some(DataColumnsState::Requesting) => {
                custody_columns_by_root
                    .insert(block_root, DataColumnsState::Complete(columns, peer_group));
                Ok(())
            }
        }
    }

    /// After blocks arrive, initiates custody-by-root requests for blocks that need data columns.
    ///
    /// Only does work when blocks have arrived and we're in DataColumns mode. For each block
    /// with data, inserts a `Requesting` entry and fires a custody request via the network context.
    pub fn continue_requests<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        id: ComponentsByRangeRequestId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let Some(blocks) = self.blocks_request.to_finished() else {
            return Ok(());
        };
        let RangeBlockDataRequest::DataColumns {
            custody_columns_by_root,
            ..
        } = &mut self.block_data_request
        else {
            return Ok(());
        };

        let mut errors = vec![];

        for block in blocks {
            if block.num_expected_blobs() == 0 {
                continue;
            }
            let block_root = get_block_root(block);
            if custody_columns_by_root.contains_key(&block_root) {
                continue;
            }

            let block_epoch = block.slot().epoch(E::slots_per_epoch());
            let requester = CustodyRequester::RangeSync(RangeSyncCustodyId { id, block_root });
            match cx.custody_lookup_request(
                requester,
                block_root,
                block_epoch,
                true, // ignore_cache: range blocks won't have gossip-imported columns
                Arc::new(RwLock::new(HashSet::new())),
            ) {
                Ok(LookupRequestResult::RequestSent(_)) => {
                    custody_columns_by_root.insert(block_root, DataColumnsState::Requesting);
                    debug!(?block_root, %id, "Initiated custody-by-root for range block");
                }
                Ok(LookupRequestResult::NoRequestNeeded(reason)) => {
                    // All columns already available (e.g. arrived via gossip). Mark as complete.
                    debug!(?block_root, %id, %reason, "Custody-by-root not needed for range block");
                    custody_columns_by_root.insert(
                        block_root,
                        DataColumnsState::Complete(vec![], PeerGroup::from_set(Default::default())),
                    );
                }
                Ok(LookupRequestResult::Pending(reason)) => {
                    errors.push(format!(
                        "Custody request for {block_root:?} pending: {reason}"
                    ));
                }
                Err(e) => {
                    errors.push(format!(
                        "Failed to initiate custody for {block_root:?}: {e:?}"
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Registers a block root as awaiting custody columns. Used in tests to simulate
    /// the effect of `continue_requests` without requiring a full network context.
    #[cfg(test)]
    pub fn register_custody_block(&mut self, block_root: Hash256) {
        if let RangeBlockDataRequest::DataColumns {
            custody_columns_by_root,
            ..
        } = &mut self.block_data_request
        {
            custody_columns_by_root.insert(block_root, DataColumnsState::Requesting);
        }
    }

    /// Attempts to construct RPC blocks from all received components.
    ///
    /// Returns `None` if not all expected requests have completed.
    /// Returns `Some(Ok(_))` with valid RPC blocks if all data is present and valid.
    /// Returns `Some(Err(_))` if there are issues coupling blocks with their data.
    pub fn responses<T>(
        &mut self,
        da_checker: Arc<DataAvailabilityChecker<T>>,
        spec: Arc<ChainSpec>,
    ) -> Option<Result<Vec<RpcBlock<E>>, CouplingError>>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let Some(blocks) = self.blocks_request.to_finished() else {
            return None;
        };

        match &self.block_data_request {
            RangeBlockDataRequest::NoData => Some(Self::responses_with_blobs(
                blocks.to_vec(),
                vec![],
                da_checker,
                spec,
            )),
            RangeBlockDataRequest::Blobs(request) => {
                let Some(blobs) = request.to_finished() else {
                    return None;
                };
                Some(Self::responses_with_blobs(
                    blocks.to_vec(),
                    blobs.to_vec(),
                    da_checker,
                    spec,
                ))
            }
            RangeBlockDataRequest::DataColumns {
                custody_columns_by_root,
                expected_custody_columns,
            } => {
                if custody_columns_by_root
                    .values()
                    .any(|s| matches!(s, DataColumnsState::Requesting))
                {
                    return None;
                }

                Some(Self::responses_with_custody_columns(
                    blocks.to_vec(),
                    custody_columns_by_root.clone(),
                    expected_custody_columns,
                    da_checker,
                    spec,
                ))
            }
        }
    }

    fn responses_with_blobs<T>(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        da_checker: Arc<DataAvailabilityChecker<T>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Vec<RpcBlock<E>>, CouplingError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        // There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(blocks.len());
        let mut blob_iter = blobs.into_iter().peekable();
        for block in blocks.into_iter() {
            let max_blobs_per_block = spec.max_blobs_per_block(block.epoch()) as usize;
            let mut blob_list = Vec::with_capacity(max_blobs_per_block);
            while {
                blob_iter
                    .peek()
                    .map(|sidecar| sidecar.slot() == block.slot())
                    .unwrap_or(false)
            } {
                blob_list.push(blob_iter.next().ok_or_else(|| {
                    CouplingError::BlobPeerFailure("Missing next blob".to_string())
                })?);
            }

            let mut blobs_buffer = vec![None; max_blobs_per_block];
            for blob in blob_list {
                let blob_index = blob.index as usize;
                let Some(blob_opt) = blobs_buffer.get_mut(blob_index) else {
                    return Err(CouplingError::BlobPeerFailure(
                        "Invalid blob index".to_string(),
                    ));
                };
                if blob_opt.is_some() {
                    return Err(CouplingError::BlobPeerFailure(
                        "Repeat blob index".to_string(),
                    ));
                } else {
                    *blob_opt = Some(blob);
                }
            }
            let blobs = RuntimeVariableList::new(
                blobs_buffer.into_iter().flatten().collect::<Vec<_>>(),
                max_blobs_per_block,
            )
            .map_err(|_| {
                CouplingError::BlobPeerFailure("Blobs returned exceeds max length".to_string())
            })?;
            let block_data = AvailableBlockData::new_with_blobs(blobs);
            responses.push(
                RpcBlock::new(block, Some(block_data), &da_checker, spec.clone())
                    .map_err(|e| CouplingError::BlobPeerFailure(format!("{e:?}")))?,
            )
        }

        // if accumulated sidecars is not empty, log an error but return the responses
        // as we can still make progress.
        if blob_iter.next().is_some() {
            let remaining_blobs = blob_iter
                .map(|b| (b.index, b.block_root()))
                .collect::<Vec<_>>();
            debug!(?remaining_blobs, "Received sidecars that don't pair well",);
        }

        Ok(responses)
    }

    fn responses_with_custody_columns<T>(
        blocks: Vec<Arc<SignedBeaconBlock<E>>>,
        custody_columns_by_root: HashMap<Hash256, DataColumnsState<E>>,
        expects_custody_columns: &[ColumnIndex],
        da_checker: Arc<DataAvailabilityChecker<T>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Vec<RpcBlock<E>>, CouplingError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let mut custody_columns_by_root = custody_columns_by_root;
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            rpc_blocks.push(if block.num_expected_blobs() > 0 {
                let Some(DataColumnsState::Complete(data_columns, _peer_group)) =
                    custody_columns_by_root.remove(&block_root)
                else {
                    return Err(CouplingError::InternalError(format!(
                        "No columns for block {block_root:?} with data"
                    )));
                };

                let mut data_columns_by_index =
                    HashMap::<ColumnIndex, Arc<DataColumnSidecar<E>>>::new();
                for column in data_columns {
                    let index = *column.index();
                    if data_columns_by_index.insert(index, column).is_some() {
                        debug!(?block_root, ?index, "Repeated column for block_root");
                    }
                }

                let mut custody_columns = vec![];
                for index in expects_custody_columns {
                    if let Some(data_column) = data_columns_by_index.remove(index) {
                        custody_columns.push(CustodyDataColumn::from_asserted_custody(data_column));
                    } else {
                        return Err(CouplingError::InternalError(format!(
                            "Missing custody column {index} for block {block_root:?}"
                        )));
                    }
                }

                if !data_columns_by_index.is_empty() {
                    let remaining_indices = data_columns_by_index.keys().collect::<Vec<_>>();
                    debug!(
                        ?block_root,
                        ?remaining_indices,
                        "Not all columns consumed for block"
                    );
                }

                let block_data = AvailableBlockData::new_with_data_columns(
                    custody_columns
                        .iter()
                        .map(|c| c.as_data_column().clone())
                        .collect::<Vec<_>>(),
                );

                RpcBlock::new(block, Some(block_data), &da_checker, spec.clone())
                    .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            } else {
                // Block has no data, expects zero columns
                RpcBlock::new(
                    block,
                    Some(AvailableBlockData::NoData),
                    &da_checker,
                    spec.clone(),
                )
                .map_err(|e| CouplingError::InternalError(format!("{:?}", e)))?
            });
        }

        // Assert that there are no columns left for other blocks
        if !custody_columns_by_root.is_empty() {
            let remaining_roots = custody_columns_by_root.keys().collect::<Vec<_>>();
            debug!(?remaining_roots, "Not all columns consumed for block");
        }

        Ok(rpc_blocks)
    }
}

impl<I: PartialEq + std::fmt::Display, T> ByRangeRequest<I, T> {
    pub fn finish(&mut self, id: I, data: T) -> Result<(), String> {
        match self {
            Self::Active(expected_id) => {
                if expected_id != &id {
                    return Err(format!("unexpected req_id expected {expected_id} got {id}"));
                }
                *self = Self::Complete(data);
                Ok(())
            }
            Self::Complete(_) => Err("request already complete".to_owned()),
        }
    }

    pub fn to_finished(&self) -> Option<&T> {
        match self {
            Self::Active(_) => None,
            Self::Complete(data) => Some(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBlockComponentsRequest;
    use beacon_chain::custody_context::NodeCustodyType;
    use beacon_chain::test_utils::{
        NumBlobs, generate_rand_block_and_blobs, generate_rand_block_and_data_columns,
        test_da_checker, test_spec,
    };
    use lighthouse_network::service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId, RangeRequestId,
    };
    use rand::SeedableRng;
    use std::sync::Arc;
    use types::{Epoch, ForkName, MinimalEthSpec as E, SignedBeaconBlock, test_utils::XorShiftRng};

    use crate::sync::network_context::PeerGroup;

    fn components_id() -> ComponentsByRangeRequestId {
        ComponentsByRangeRequestId {
            id: 0,
            requester: RangeRequestId::RangeSync {
                chain_id: 1,
                batch_id: Epoch::new(0),
            },
        }
    }

    fn blocks_id(parent_request_id: ComponentsByRangeRequestId) -> BlocksByRangeRequestId {
        BlocksByRangeRequestId {
            id: 1,
            parent_request_id,
        }
    }

    fn blobs_id(parent_request_id: ComponentsByRangeRequestId) -> BlobsByRangeRequestId {
        BlobsByRangeRequestId {
            id: 1,
            parent_request_id,
        }
    }

    #[test]
    fn no_blobs_into_responses() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_blobs::<E>(ForkName::Base, NumBlobs::None, &mut rng)
                    .0
                    .into()
            })
            .collect::<Vec<Arc<SignedBeaconBlock<E>>>>();

        let blocks_req_id = blocks_id(components_id());
        let mut info = RangeBlockComponentsRequest::<E>::new(blocks_req_id, None, None);

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks).unwrap();

        let spec = Arc::new(test_spec::<E>());
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));

        // Assert response is finished and RpcBlocks can be constructed
        info.responses(da_checker, spec).unwrap().unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                // Always generate some blobs.
                generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Number(3), &mut rng)
                    .0
                    .into()
            })
            .collect::<Vec<Arc<SignedBeaconBlock<E>>>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let blobs_req_id = blobs_id(components_id);
        let mut info =
            RangeBlockComponentsRequest::<E>::new(blocks_req_id, Some(blobs_req_id), None);

        // Send blocks and complete terminate response
        info.add_blocks(blocks_req_id, blocks).unwrap();
        // Expect no blobs returned
        info.add_blobs(blobs_req_id, vec![]).unwrap();

        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        // Assert response is finished and RpcBlocks cannot be constructed, because blobs weren't returned.
        let result = info.responses(da_checker, spec).unwrap();
        assert!(result.is_err())
    }

    #[test]
    fn rpc_block_with_custody_columns() {
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Fulu,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns.clone()),
        );

        // Send blocks
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();

        // Register block roots as awaiting custody, then add columns
        for (block, _) in &blocks {
            let block_root = beacon_chain::get_block_root(block);
            info.register_custody_block(block_root);
        }
        for (block, data_columns) in &blocks {
            let block_root = beacon_chain::get_block_root(block);
            let custody_columns: Vec<_> = data_columns
                .iter()
                .filter(|d| expects_custody_columns.contains(d.index()))
                .cloned()
                .collect();
            info.add_custody_columns(
                block_root,
                custody_columns,
                PeerGroup::from_set(Default::default()),
            )
            .unwrap();
        }

        // All completed construct response
        info.responses(da_checker, spec).unwrap().unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns_no_data_blocks() {
        // Test blocks that don't have blob commitments don't need custody
        let mut spec = test_spec::<E>();
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(spec);
        let da_checker = Arc::new(test_da_checker(spec.clone(), NodeCustodyType::Fullnode));
        let expects_custody_columns = da_checker
            .custody_context()
            .sampling_columns_for_epoch(Epoch::new(0), &spec)
            .to_vec();
        let mut rng = XorShiftRng::from_seed([42; 16]);
        // Generate blocks with NO blobs
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Fulu,
                    NumBlobs::None,
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        let components_id = components_id();
        let blocks_req_id = blocks_id(components_id);
        let mut info = RangeBlockComponentsRequest::<E>::new(
            blocks_req_id,
            None,
            Some(expects_custody_columns),
        );

        // Send blocks
        info.add_blocks(
            blocks_req_id,
            blocks.iter().map(|b| b.0.clone().into()).collect(),
        )
        .unwrap();

        // Response should be ready immediately (no blocks need custody columns)
        info.responses(da_checker, spec).unwrap().unwrap();
    }
}
