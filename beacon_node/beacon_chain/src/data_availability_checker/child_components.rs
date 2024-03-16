use crate::block_verification_types::RpcBlock;
use crate::data_availability_checker::AvailabilityView;
use bls::Hash256;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::data_column_sidecar::FixedDataColumnSidecarList;
use types::{EthSpec, SignedBeaconBlock};

/// For requests triggered by an `UnknownBlockParent` or `UnknownBlobParent`, this struct
/// is used to cache components as they are sent to the network service. We can't use the
/// data availability cache currently because any blocks or blobs without parents
/// won't pass validation and therefore won't make it into the cache.
pub struct ChildComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub downloaded_block: Option<Arc<SignedBeaconBlock<E>>>,
    pub downloaded_blobs: FixedBlobSidecarList<E>,
    pub downloaded_data_columns: FixedDataColumnSidecarList<E>,
    pub node_id: [u8; 32],
    pub custody_requirement: u64,
}

impl<E: EthSpec> From<RpcBlock<E>> for ChildComponents<E> {
    fn from(value: RpcBlock<E>) -> Self {
        let (block_root, block, blobs, data_columns) = value.deconstruct();
        let fixed_blobs = blobs.map(|blobs| {
            FixedBlobSidecarList::from(blobs.into_iter().map(Some).collect::<Vec<_>>())
        });
        let fixed_data_columns = data_columns.map(|data_columns| {
            FixedDataColumnSidecarList::from(data_columns.into_iter().map(Some).collect::<Vec<_>>())
        });
        Self::new(block_root, Some(block), fixed_blobs, fixed_data_columns)
    }
}

impl<E: EthSpec> ChildComponents<E> {
    pub fn empty(block_root: Hash256) -> Self {
        Self {
            block_root,
            downloaded_block: None,
            downloaded_blobs: <_>::default(),
            downloaded_data_columns: <_>::default(),
            node_id: todo!(),
            custody_requirement: todo!(),
        }
    }
    pub fn new(
        block_root: Hash256,
        block: Option<Arc<SignedBeaconBlock<E>>>,
        blobs: Option<FixedBlobSidecarList<E>>,
        data_columns: Option<FixedDataColumnSidecarList<E>>,
    ) -> Self {
        let mut cache = Self::empty(block_root);
        if let Some(block) = block {
            cache.merge_block(block);
        }
        if let Some(blobs) = blobs {
            cache.merge_blobs(blobs);
        }
        if let Some(data_columns) = data_columns {
            cache.merge_data_columns(data_columns);
        }
        cache
    }

    pub fn clear_blobs(&mut self) {
        self.downloaded_blobs = FixedBlobSidecarList::default();
    }
}
