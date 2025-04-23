use crate::data_availability_checker::AvailabilityCheckError;
pub use crate::data_availability_checker::{AvailableBlock, MaybeAvailableBlock};
use crate::data_column_verification::{CustodyDataColumn, CustodyDataColumnList};
use crate::eth1_finalization_cache::Eth1FinalizationData;
use crate::{get_block_root, PayloadVerificationOutcome};
use derivative::Derivative;
use state_processing::ConsensusContext;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use types::blob_sidecar::BlobIdentifier;
use types::{
    BeaconBlockRef, BeaconState, BlindedPayload, BlobSidecarList, ChainSpec, ColumnIndex, Epoch,
    EthSpec, Hash256, RuntimeVariableList, SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};

/// A block that has been received over RPC. It has 2 internal variants:
///
/// 1. `BlockAndBlobs`: A fully available post deneb block with all the blobs available. This variant
///    is only constructed after making consistency checks between blocks and blobs.
///    Hence, it is fully self contained w.r.t verification. i.e. this block has all the required
///    data to get verified and imported into fork choice.
///
/// 2. `Block`: This can be a fully available pre-deneb block **or** a post-deneb block that may or may
///    not require blobs to be considered fully available.
///
/// Note: We make a distinction over blocks received over gossip because
/// in a post-deneb world, the blobs corresponding to a given block that are received
/// over rpc do not contain the proposer signature for dos resistance.
#[derive(Clone, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
pub struct RpcBlock<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    custody_columns_count: usize,
}

#[derive(Clone)]
pub struct ChainSegmentBlock<E: EthSpec> {
    pub block: RpcBlock<E>,
    pub blob_data: ChainSegmentBlockData<E>,
}

impl<E: EthSpec> ChainSegmentBlock<E> {
    pub fn block_root(&self) -> Hash256 {
        self.block.block_root()
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        self.block.as_block()
    }
}

#[derive(Clone)]
pub enum ChainSegmentBlockData<E: EthSpec> {
    /// Variant for all pre-Deneb blocks
    PreDeneb,
    /// Variant for all >= Deneb && < Fulu blocks regardless if they have data or not
    PostDeneb(BlobSidecarList<E>),
    /// Variant for all >= Fulu blocks regardless if they have data or not
    PostFulu(CustodyDataColumnList<E>, Vec<ColumnIndex>),
}

impl<E: EthSpec> Debug for RpcBlock<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcBlock({:?})", self.block_root)
    }
}

impl<E: EthSpec> RpcBlock<E> {
    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn custody_columns_count(&self) -> usize {
        self.custody_columns_count
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }
}

impl<E: EthSpec> ChainSegmentBlock<E> {
    pub fn non_matching_blobs_signed_headers(&self) -> Option<Vec<ColumnIndex>> {
        match &self.blob_data {
            ChainSegmentBlockData::PreDeneb => None,
            ChainSegmentBlockData::PostDeneb(blobs) => Some(
                blobs
                    .iter()
                    .filter(|blob| {
                        &blob.signed_block_header.signature != self.block.as_block().signature()
                    })
                    .map(|blob| blob.index)
                    .collect(),
            ),
            ChainSegmentBlockData::PostFulu(..) => None,
        }
    }

    pub fn non_matching_custody_columns_signed_headers(&self) -> Option<Vec<ColumnIndex>> {
        match &self.blob_data {
            ChainSegmentBlockData::PreDeneb => None,
            ChainSegmentBlockData::PostDeneb(..) => None,
            ChainSegmentBlockData::PostFulu(data_columns, ..) => Some(
                data_columns
                    .iter()
                    .filter(|column| {
                        &column.as_data_column().signed_block_header.signature
                            != self.block.as_block().signature()
                    })
                    .map(|column| column.index())
                    .collect(),
            ),
        }
    }

    pub fn new_pre_deneb(block: RpcBlock<E>) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            block,
            blob_data: ChainSegmentBlockData::PreDeneb,
        })
    }

    pub fn new_post_deneb(
        block: RpcBlock<E>,
        blobs: BlobSidecarList<E>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            block,
            blob_data: ChainSegmentBlockData::PostDeneb(blobs),
        })
    }

    pub fn new_post_fulu(
        block: RpcBlock<E>,
        custody_columns: Vec<CustodyDataColumn<E>>,
        expected_custody_indices: Vec<ColumnIndex>,
        spec: &ChainSpec,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            block,
            blob_data: ChainSegmentBlockData::PostFulu(
                RuntimeVariableList::new(custody_columns, spec.number_of_columns as usize)?,
                expected_custody_indices,
            ),
        })
    }
}

impl<E: EthSpec> RpcBlock<E> {
    pub fn new(
        block_root: Option<Hash256>,
        block: Arc<SignedBeaconBlock<E>>,
        custody_columns_count: usize,
    ) -> Self {
        Self {
            block_root: block_root.unwrap_or_else(|| get_block_root(&block)),
            block,
            custody_columns_count,
        }
    }
}

/// A block that has gone through all pre-deneb block processing checks including block processing
/// and execution by an EL client. This block hasn't necessarily completed data availability checks.
///
///
/// It contains 2 variants:
/// 1. `Available`: This block has been executed and also contains all data to consider it a
///    fully available block. i.e. for post-deneb, this implies that this contains all the
///    required blobs.
/// 2. `AvailabilityPending`: This block hasn't received all required blobs to consider it a
///    fully available block.
pub enum ExecutedBlock<E: EthSpec> {
    Available(AvailableExecutedBlock<E>),
    AvailabilityPending(AvailabilityPendingExecutedBlock<E>),
}

impl<E: EthSpec> ExecutedBlock<E> {
    pub fn new(
        block: MaybeAvailableBlock<E>,
        import_data: BlockImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        match block {
            MaybeAvailableBlock::Available(available_block) => {
                Self::Available(AvailableExecutedBlock::new(
                    available_block,
                    import_data,
                    payload_verification_outcome,
                ))
            }
            MaybeAvailableBlock::AvailabilityPending {
                block_root: _,
                block: pending_block,
                custody_columns_count,
            } => Self::AvailabilityPending(AvailabilityPendingExecutedBlock::new(
                pending_block,
                import_data,
                payload_verification_outcome,
                custody_columns_count,
            )),
        }
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        match self {
            Self::Available(available) => available.block.block(),
            Self::AvailabilityPending(pending) => &pending.block,
        }
    }

    pub fn block_root(&self) -> Hash256 {
        match self {
            ExecutedBlock::AvailabilityPending(pending) => pending.import_data.block_root,
            ExecutedBlock::Available(available) => available.import_data.block_root,
        }
    }
}

/// A block that has completed all pre-deneb block processing checks including verification
/// by an EL client **and** has all requisite blob data to be imported into fork choice.
pub struct AvailableExecutedBlock<E: EthSpec> {
    pub block: AvailableBlock<E>,
    pub import_data: BlockImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailableExecutedBlock<E> {
    pub fn new(
        block: AvailableBlock<E>,
        import_data: BlockImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            block,
            import_data,
            payload_verification_outcome,
        }
    }

    pub fn get_all_blob_ids(&self) -> Vec<BlobIdentifier> {
        let num_blobs_expected = self
            .block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len());
        let mut blob_ids = Vec::with_capacity(num_blobs_expected);
        for i in 0..num_blobs_expected {
            blob_ids.push(BlobIdentifier {
                block_root: self.import_data.block_root,
                index: i as u64,
            });
        }
        blob_ids
    }
}

/// A block that has completed all pre-deneb block processing checks, verification
/// by an EL client but does not have all requisite blob data to get imported into
/// fork choice.
pub struct AvailabilityPendingExecutedBlock<E: EthSpec> {
    pub block: Arc<SignedBeaconBlock<E>>,
    pub import_data: BlockImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
    pub custody_columns_count: usize,
}

impl<E: EthSpec> AvailabilityPendingExecutedBlock<E> {
    pub fn new(
        block: Arc<SignedBeaconBlock<E>>,
        import_data: BlockImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
        custody_columns_count: usize,
    ) -> Self {
        Self {
            block,
            import_data,
            payload_verification_outcome,
            custody_columns_count,
        }
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len())
    }
}

#[derive(Debug, PartialEq)]
pub struct BlockImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub state: BeaconState<E>,
    pub parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    pub parent_eth1_finalization_data: Eth1FinalizationData,
    pub consensus_context: ConsensusContext<E>,
}

impl<E: EthSpec> BlockImportData<E> {
    pub fn __new_for_test(
        block_root: Hash256,
        state: BeaconState<E>,
        parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    ) -> Self {
        Self {
            block_root,
            state,
            parent_block,
            parent_eth1_finalization_data: Eth1FinalizationData {
                eth1_data: <_>::default(),
                eth1_deposit_index: 0,
            },
            consensus_context: ConsensusContext::new(Slot::new(0)),
        }
    }
}

/// Trait for common block operations.
pub trait AsBlock<E: EthSpec> {
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<E>;
    fn as_block(&self) -> &SignedBeaconBlock<E>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>>;
    fn canonical_root(&self) -> Hash256;
}

impl<E: EthSpec> AsBlock<E> for Arc<SignedBeaconBlock<E>> {
    fn slot(&self) -> Slot {
        SignedBeaconBlock::slot(self)
    }

    fn epoch(&self) -> Epoch {
        SignedBeaconBlock::epoch(self)
    }

    fn parent_root(&self) -> Hash256 {
        SignedBeaconBlock::parent_root(self)
    }

    fn state_root(&self) -> Hash256 {
        SignedBeaconBlock::state_root(self)
    }

    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        SignedBeaconBlock::signed_block_header(self)
    }

    fn message(&self) -> BeaconBlockRef<E> {
        SignedBeaconBlock::message(self)
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        self
    }

    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        Arc::<SignedBeaconBlock<E>>::clone(self)
    }

    fn canonical_root(&self) -> Hash256 {
        SignedBeaconBlock::canonical_root(self)
    }
}

impl<E: EthSpec> AsBlock<E> for MaybeAvailableBlock<E> {
    fn slot(&self) -> Slot {
        self.as_block().slot()
    }
    fn epoch(&self) -> Epoch {
        self.as_block().epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.as_block().parent_root()
    }
    fn state_root(&self) -> Hash256 {
        self.as_block().state_root()
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.as_block().signed_block_header()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.as_block(),
            MaybeAvailableBlock::AvailabilityPending { block, .. } => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.block_cloned(),
            MaybeAvailableBlock::AvailabilityPending { block, .. } => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }
}

impl<E: EthSpec> AsBlock<E> for AvailableBlock<E> {
    fn slot(&self) -> Slot {
        self.block().slot()
    }

    fn epoch(&self) -> Epoch {
        self.block().epoch()
    }

    fn parent_root(&self) -> Hash256 {
        self.block().parent_root()
    }

    fn state_root(&self) -> Hash256 {
        self.block().state_root()
    }

    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.block().signed_block_header()
    }

    fn message(&self) -> BeaconBlockRef<E> {
        self.block().message()
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        self.block()
    }

    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        AvailableBlock::block_cloned(self)
    }

    fn canonical_root(&self) -> Hash256 {
        self.block().canonical_root()
    }
}

impl<E: EthSpec> AsBlock<E> for RpcBlock<E> {
    fn slot(&self) -> Slot {
        self.as_block().slot()
    }
    fn epoch(&self) -> Epoch {
        self.as_block().epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.as_block().parent_root()
    }
    fn state_root(&self) -> Hash256 {
        self.as_block().state_root()
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.as_block().signed_block_header()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }
}
