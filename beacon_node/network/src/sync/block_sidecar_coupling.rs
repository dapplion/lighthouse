use beacon_chain::{
    block_verification_types::RpcBlock, data_column_verification::CustodyDataColumn, get_block_root,
};
use lighthouse_network::{
    service::api_types::{
        BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
    },
    PeerId,
};
use ssz_types::VariableList;
use std::{collections::HashMap, sync::Arc};
use types::{
    BlobSidecar, ChainSpec, ColumnIndex, DataColumnSidecar, EthSpec, Hash256, RuntimeVariableList,
    SignedBeaconBlock,
};

use super::network_context::PeerGroup;

#[derive(Debug)]
pub struct RangeBlockComponentsRequest<E: EthSpec> {
    /// Active blocks_by_range request
    blocks_request: Status<BlocksByRangeRequestId, Vec<Arc<SignedBeaconBlock<E>>>>,
    /// Active 1 or 0 blobs_by_range request
    blobs_request: Status<BlobsByRangeRequestId, Vec<Arc<BlobSidecar<E>>>>,
    /// Active set of data_column_by_range requests
    data_column_requests: HashMap<
        DataColumnsByRangeRequestId,
        Status<DataColumnsByRangeRequestId, Vec<Arc<DataColumnSidecar<E>>>>,
    >,
    /// Attribute which peer is responsible for each column
    peer_by_data_column: HashMap<ColumnIndex, PeerId>,
}

impl<E: EthSpec> RangeBlockComponentsRequest<E> {
    pub fn new(
        blocks_req_id: BlocksByRangeRequestId,
        blobs_req_id: Option<BlobsByRangeRequestId>,
        data_column_requests: Vec<(DataColumnsByRangeRequestId, PeerId, Vec<ColumnIndex>)>,
    ) -> Self {
        let mut peer_by_data_column = HashMap::new();
        for (_, peer_id, indices) in &data_column_requests {
            for index in indices {
                peer_by_data_column.insert(*index, *peer_id);
            }
        }

        Self {
            blocks_request: Status::Downloading(blocks_req_id),
            blobs_request: match blobs_req_id {
                Some(blobs_req_id) => Status::Downloading(blobs_req_id),
                None => Status::NotRequired,
            },
            data_column_requests: data_column_requests
                .into_iter()
                .map(|(id, _, _)| (id, Status::Downloading(id)))
                .collect(),
            peer_by_data_column,
        }
    }

    pub fn add_block_response(&mut self, peer_id: PeerId, blocks: Vec<Arc<SignedBeaconBlock<E>>>) {
        // TODO: Harden Status state transitions
        self.blocks_request = Status::Downloaded(blocks, peer_id);
    }

    pub fn add_sidecar_response(&mut self, peer_id: PeerId, blobs: Vec<Arc<BlobSidecar<E>>>) {
        // TODO: Harden Status state transitions
        self.blobs_request = Status::Downloaded(blobs, peer_id);
    }

    pub fn add_data_column(
        &mut self,
        req_id: DataColumnsByRangeRequestId,
        peer_id: PeerId,
        columns: Vec<Arc<DataColumnSidecar<E>>>,
    ) -> Result<(), String> {
        let Some(req) = self.data_column_requests.get_mut(&req_id) else {
            return Err(format!("unknown req_id {req_id:?}"));
        };

        // TODO: Harden Status state transitions
        *req = Status::Downloaded(columns, peer_id);
        Ok(())
    }

    pub fn into_responses(
        self,
        spec: &ChainSpec,
    ) -> Result<RangeBlockComponentsResponse<E>, String> {
        if !self.data_column_requests.is_empty() {
            self.into_responses_with_custody_columns(spec)
        } else {
            self.into_responses_with_blobs()
        }
    }

    fn into_responses_with_blobs(self) -> Result<RangeBlockComponentsResponse<E>, String> {
        let (blocks, block_peer) = match self.blocks_request {
            Status::NotRequired => unreachable!(),
            Status::Downloading { .. } => return Err("block_request pending".to_owned()),
            Status::Downloaded(blocks, peer) => (blocks, peer),
        };
        let (blobs, blob_peer) = match self.blobs_request {
            Status::NotRequired => (vec![], None),
            Status::Downloading { .. } => return Err("blob_request pending".to_owned()),
            Status::Downloaded(blobs, peer) => (blobs, Some(peer)),
        };

        let mut blobs_by_block = HashMap::<Hash256, Vec<Arc<BlobSidecar<E>>>>::new();

        for blob in blobs {
            let block_root = blob.block_root();
            blobs_by_block.entry(block_root).or_default().push(blob);
        }

        // Now iterate all blocks ensuring that the block roots of each block and data column match,
        // plus we have columns for our custody requirements
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            let blobs = blobs_by_block.remove(&block_root).map(VariableList::from);
            rpc_blocks.push(RpcBlock::new_unchecked(block_root, block, blobs, None));
        }

        Ok(RangeBlockComponentsResponse {
            rpc_blocks,
            peers: RangeBlockComponentsPeers {
                block_peer,
                blob_peer,
                data_columns_peer_group: None,
                peer_by_data_column: self.peer_by_data_column,
            },
        })
    }

    fn into_responses_with_custody_columns(
        self,
        spec: &ChainSpec,
    ) -> Result<RangeBlockComponentsResponse<E>, String> {
        let (blocks, block_peer) = match self.blocks_request {
            Status::NotRequired => unreachable!(),
            Status::Downloading { .. } => return Err("block_request pending".to_owned()),
            Status::Downloaded(blocks, peer) => (blocks, peer),
        };

        let mut data_columns = vec![];
        let mut columns_by_peer = HashMap::<PeerId, Vec<usize>>::new();
        for req in self.data_column_requests.into_values() {
            match req {
                Status::NotRequired => unreachable!(),
                Status::Downloading { .. } => return Err("data_column_request pending".to_owned()),
                Status::Downloaded(columns, peer) => {
                    columns_by_peer
                        .entry(peer)
                        .or_default()
                        .extend(columns.iter().map(|d| d.index as usize));
                    data_columns.extend(columns);
                }
            }
        }

        // Group data columns by block_root and index
        let mut data_columns_by_block = HashMap::<Hash256, Vec<_>>::new();

        for column in data_columns {
            data_columns_by_block
                .entry(column.block_root())
                .or_default()
                // Safe to convert to `CustodyDataColumn`: we have asserted that the index of
                // this column is in the set of `expects_custody_columns` and with the expected
                // block root, so for the expected epoch of this batch.
                .push(CustodyDataColumn::from_asserted_custody(column));
            // Note: no need to check for duplicates `ActiveDataColumnsByRangeRequest` ensures that
            // only requested column indices are returned.
        }

        // Here we don't know what's the canonical block at a specific slot. A block may claim to
        // have data (some blob transactions) but be invalid. Therefore, the block peer may disagree
        // with the data column peer wether a block has data or not. However, we can match columns to
        // blocks by block roots safely. If the block peer and column peer disagree we will have a
        // mismatch of columns, which we HAVE to tolerate here.
        //
        // Note that we can have a partial match of columns. Column peers can disagree between them,
        // so we must track who was expected to provide what columns for a set of indexes. If the
        // block ends up with data and we are missing columns, penalize the peers that did not send
        // the columns.

        // Now iterate all blocks ensuring that the block roots of each block and data column match,
        // plus we have columns for our custody requirements
        let mut rpc_blocks = Vec::with_capacity(blocks.len());

        for block in blocks {
            let block_root = get_block_root(&block);
            let columns = match data_columns_by_block.remove(&block_root) {
                Some(columns) => Some(
                    RuntimeVariableList::new(columns, spec.number_of_columns)
                        .map_err(|e| format!("{:?}", e))?,
                ),
                None => None,
            };
            rpc_blocks.push(RpcBlock::new_unchecked(block_root, block, None, columns));
        }

        // Assert that there are no columns left for other blocks
        if !data_columns_by_block.is_empty() {
            let remaining_roots = data_columns_by_block.keys().collect::<Vec<_>>();
            return Err(format!("Not all columns consumed: {remaining_roots:?}"));
        }

        Ok(RangeBlockComponentsResponse {
            rpc_blocks,
            peers: RangeBlockComponentsPeers {
                block_peer,
                blob_peer: None,
                data_columns_peer_group: Some(PeerGroup::from_set(columns_by_peer)),
                peer_by_data_column: self.peer_by_data_column,
            },
        })
    }

    pub fn is_finished(&self) -> bool {
        if !self.blocks_request.completed() {
            return false;
        }
        if !self.blobs_request.completed() {
            return false;
        }
        for data_column_request in self.data_column_requests.values() {
            if !data_column_request.completed() {
                return false;
            }
        }
        true
    }
}

pub struct RangeBlockComponentsPeers {
    pub block_peer: PeerId,
    pub blob_peer: Option<PeerId>,
    pub data_columns_peer_group: Option<PeerGroup>,
    pub peer_by_data_column: HashMap<ColumnIndex, PeerId>,
}

pub struct RangeBlockComponentsResponse<E: EthSpec> {
    pub rpc_blocks: Vec<RpcBlock<E>>,
    pub peers: RangeBlockComponentsPeers,
}

impl<E: EthSpec> RangeBlockComponentsResponse<E> {
    pub fn len(&self) -> usize {
        self.rpc_blocks.len()
    }
}

#[derive(Debug)]
enum Status<I, T> {
    NotRequired,
    Downloading(I),
    Downloaded(T, PeerId),
}

impl<I, T> Status<I, T> {
    fn completed(&self) -> bool {
        match self {
            Self::NotRequired => true,
            Self::Downloading { .. } => false,
            Self::Downloaded { .. } => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBlockComponentsRequest;
    use beacon_chain::test_utils::{
        generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec, NumBlobs,
    };
    use lighthouse_network::PeerId;
    use rand::SeedableRng;
    use types::{test_utils::XorShiftRng, ForkName, MinimalEthSpec as E};

    #[test]
    fn no_blobs_into_responses() {
        let peer_id = PeerId::random();
        let mut info = RangeBlockComponentsRequest::<E>::new(false, None, None, vec![peer_id]);
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_blobs::<E>(ForkName::Base, NumBlobs::None, &mut rng)
                    .0
                    .into()
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        info.add_block_response(blocks);

        // Assert response is finished and RpcBlocks can be constructed
        assert!(info.is_finished());
        info.into_responses(&test_spec::<E>()).unwrap();
    }

    #[test]
    fn empty_blobs_into_responses() {
        let peer_id = PeerId::random();
        let mut info = RangeBlockComponentsRequest::<E>::new(true, None, None, vec![peer_id]);
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                // Always generate some blobs.
                generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Number(3), &mut rng)
                    .0
                    .into()
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        info.add_block_response(blocks);
        // Expect no blobs returned
        info.add_sidecar_response(vec![]);

        // Assert response is finished and RpcBlocks can be constructed, even if blobs weren't returned.
        // This makes sure we don't expect blobs here when they have expired. Checking this logic should
        // be hendled elsewhere.
        assert!(info.is_finished());
        info.into_responses(&test_spec::<E>()).unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns() {
        let spec = test_spec::<E>();
        let expects_custody_columns = vec![1, 2, 3, 4];
        let custody_column_request_ids = vec![0, 1, 2, 3];
        let mut info = RangeBlockComponentsRequest::<E>::new(
            false,
            Some(expects_custody_columns.clone()),
            Some(custody_column_request_ids),
            vec![PeerId::random()],
        );
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Deneb,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        info.add_block_response(blocks.iter().map(|b| b.0.clone().into()).collect());
        // Assert response is not finished
        assert!(!info.is_finished());

        // Send data columns
        for (i, &column_index) in expects_custody_columns.iter().enumerate() {
            info.add_data_column(
                blocks
                    .iter()
                    .flat_map(|b| b.1.iter().filter(|d| d.index == column_index).cloned())
                    .collect(),
            );

            if i < expects_custody_columns.len() - 1 {
                assert!(
                    !info.is_finished(),
                    "requested should not be finished at loop {i}"
                );
            } else {
                assert!(
                    info.is_finished(),
                    "request should be finishied at loop {i}"
                );
            }
        }

        // All completed construct response
        info.into_responses(&spec).unwrap();
    }

    #[test]
    fn rpc_block_with_custody_columns_batched() {
        let spec = test_spec::<E>();
        let batched_column_requests = vec![vec![1_u64, 2], vec![3, 4]];
        let expects_custody_columns = batched_column_requests
            .iter()
            .cloned()
            .flatten()
            .collect::<Vec<_>>();
        let custody_column_request_ids =
            (0..batched_column_requests.len() as u32).collect::<Vec<_>>();
        let num_of_data_column_requests = custody_column_request_ids.len();
        let mut info = RangeBlockComponentsRequest::<E>::new(
            false,
            Some(expects_custody_columns.clone()),
            Some(custody_column_request_ids),
            vec![PeerId::random()],
        );
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let blocks = (0..4)
            .map(|_| {
                generate_rand_block_and_data_columns::<E>(
                    ForkName::Deneb,
                    NumBlobs::Number(1),
                    &mut rng,
                    &spec,
                )
            })
            .collect::<Vec<_>>();

        // Send blocks and complete terminate response
        info.add_block_response(blocks.iter().map(|b| b.0.clone().into()).collect());
        // Assert response is not finished
        assert!(!info.is_finished());

        for (i, column_indices) in batched_column_requests.iter().enumerate() {
            // Send the set of columns in the same batch request
            info.add_data_column(
                blocks
                    .iter()
                    .flat_map(|b| {
                        b.1.iter()
                            .filter(|d| column_indices.contains(&d.index))
                            .cloned()
                    })
                    .collect::<Vec<_>>(),
            );

            if i < num_of_data_column_requests - 1 {
                assert!(
                    !info.is_finished(),
                    "requested should not be finished at loop {i}"
                );
            } else {
                assert!(info.is_finished(), "request should be finished at loop {i}");
            }
        }

        // All completed construct response
        info.into_responses(&spec).unwrap();
    }
}
