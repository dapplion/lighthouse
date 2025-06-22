use crate::rpc::methods::{ResponseTermination, RpcResponse, RpcSuccessResponse, StatusMessage};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use types::{
    BlobSidecar, DataColumnSidecar, EthSpec, Hash256, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate, SignedBeaconBlock,
};

pub type Id = u32;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SingleLookupReqId {
    pub lookup_id: Id,
    pub req_id: Id,
}

/// Id of rpc requests sent by sync to the network.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum SyncRequestId {
    /// Request searching for a block given a hash.
    BlocksByRoot(BlocksByRootRequestId),
    /// Request searching for a set of blobs given a hash.
    BlobsByRoot(BlobsByRootRequestId),
    /// Request searching for a set of data columns given a hash and list of column indices.
    DataColumnsByRoot(DataColumnsByRootRequestId),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct BlocksByRootRequestId {
    pub id: Id,
    pub parent_request_id: BlocksByRootRequester,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct HeaderLookupId(pub Hash256, pub Id);

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct BatchId(pub Id);

/// Request ID for data_columns_by_root requests. Block lookups do not issue this request directly.
/// Wrapping this particular req_id, ensures not mixing this request with a custody req_id.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct DataColumnsByRootRequestId {
    pub id: Id,
    pub parent_request_id: DataColumnsByRootRequester,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct BlobsByRootRequestId {
    /// Id to identify this attempt at a blobs_by_range request for `parent_request_id`
    pub id: Id,
    /// The Id of the overall By Range request for block components.
    pub parent_request_id: ComponentsByRootRequestId,
}

/// Block components by range request for range sync. Includes an ID for downstream consumers to
/// handle retries and tie all their sub requests together.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct ComponentsByRootRequestId {
    /// Each `RangeRequestId` may request the same data in a later retry. This Id identifies the
    /// current attempt.
    pub id: Id,
    /// What sync component is issuing a components by range request and expecting data back
    pub requester: RangeRequestId,
}

/// Range sync chain or backfill batch
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum RangeRequestId {
    ForwardSync(HeaderLookupId),
    BackfillSync(Id),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum BlocksByRootRequester {
    Header(HeaderLookupId),
    ForwardSync(ComponentsByRootRequestId),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum DataColumnsByRootRequester {
    Sampling(SamplingId),
    Custody(CustodyByRootRequestId),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SamplingId {
    pub id: SamplingRequester,
    pub sampling_request_id: SamplingRequestId,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum SamplingRequester {
    ImportedBlock(Hash256),
}

/// Identifier of sampling requests.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SamplingRequestId(pub usize);

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct CustodyByRootRequestId {
    pub parent_request_id: ComponentsByRootRequestId,
}

/// Application level requests sent to the network.
#[derive(Debug, Clone, Copy)]
pub enum AppRequestId {
    Sync(SyncRequestId),
    Router,
    Internal,
}

/// The type of RPC responses the Behaviour informs it has received, and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level responses that can be
//       sent. The main difference is the absense of Pong and Metadata, which don't leave the
//       Behaviour. For all protocol reponses managed by RPC see `RPCResponse` and
//       `RPCCodedResponse`.
#[derive(Debug, Clone, PartialEq)]
pub enum Response<E: EthSpec> {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get BLOCKS_BY_RANGE request. A None response signals the end of the batch.
    BlocksByRange(Option<Arc<SignedBeaconBlock<E>>>),
    /// A response to a get BLOBS_BY_RANGE request. A None response signals the end of the batch.
    BlobsByRange(Option<Arc<BlobSidecar<E>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_Range request.
    DataColumnsByRange(Option<Arc<DataColumnSidecar<E>>>),
    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Option<Arc<SignedBeaconBlock<E>>>),
    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Option<Arc<BlobSidecar<E>>>),
    /// A response to a get DATA_COLUMN_SIDECARS_BY_ROOT request.
    DataColumnsByRoot(Option<Arc<DataColumnSidecar<E>>>),
    /// A response to a LightClientUpdate request.
    LightClientBootstrap(Arc<LightClientBootstrap<E>>),
    /// A response to a LightClientOptimisticUpdate request.
    LightClientOptimisticUpdate(Arc<LightClientOptimisticUpdate<E>>),
    /// A response to a LightClientFinalityUpdate request.
    LightClientFinalityUpdate(Arc<LightClientFinalityUpdate<E>>),
    /// A response to a LightClientUpdatesByRange request.
    LightClientUpdatesByRange(Option<Arc<LightClientUpdate<E>>>),
}

impl<E: EthSpec> std::convert::From<Response<E>> for RpcResponse<E> {
    fn from(resp: Response<E>) -> RpcResponse<E> {
        match resp {
            Response::BlocksByRoot(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlocksByRoot(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlocksByRoot),
            },
            Response::BlocksByRange(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlocksByRange(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlocksByRange),
            },
            Response::BlobsByRoot(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlobsByRoot(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlobsByRoot),
            },
            Response::BlobsByRange(r) => match r {
                Some(b) => RpcResponse::Success(RpcSuccessResponse::BlobsByRange(b)),
                None => RpcResponse::StreamTermination(ResponseTermination::BlobsByRange),
            },
            Response::DataColumnsByRoot(r) => match r {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::DataColumnsByRoot(d)),
                None => RpcResponse::StreamTermination(ResponseTermination::DataColumnsByRoot),
            },
            Response::DataColumnsByRange(r) => match r {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::DataColumnsByRange(d)),
                None => RpcResponse::StreamTermination(ResponseTermination::DataColumnsByRange),
            },
            Response::Status(s) => RpcResponse::Success(RpcSuccessResponse::Status(s)),
            Response::LightClientBootstrap(b) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientBootstrap(b))
            }
            Response::LightClientOptimisticUpdate(o) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientOptimisticUpdate(o))
            }
            Response::LightClientFinalityUpdate(f) => {
                RpcResponse::Success(RpcSuccessResponse::LightClientFinalityUpdate(f))
            }
            Response::LightClientUpdatesByRange(f) => match f {
                Some(d) => RpcResponse::Success(RpcSuccessResponse::LightClientUpdatesByRange(d)),
                None => {
                    RpcResponse::StreamTermination(ResponseTermination::LightClientUpdatesByRange)
                }
            },
        }
    }
}

macro_rules! impl_display {
    ($structname: ty, $format: literal, $($field:ident),*) => {
        impl Display for $structname {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, $format, $(self.$field,)*)
            }
        }
    };
}

// Since each request Id is deeply nested with various types, if rendered with Debug on logs they
// take too much visual space. This custom Display implementations make the overall Id short while
// not losing information
impl_display!(ComponentsByRootRequestId, "{}/{}", id, requester);
impl_display!(BlocksByRootRequestId, "{}/{}", id, parent_request_id);
impl_display!(BlobsByRootRequestId, "{}/{}", id, parent_request_id);
impl_display!(DataColumnsByRootRequestId, "{}/{}", id, parent_request_id);
impl_display!(SingleLookupReqId, "{}/Lookup/{}", req_id, lookup_id);
impl_display!(CustodyByRootRequestId, "{}", parent_request_id);
impl_display!(SamplingId, "{}/{}", sampling_request_id, id);

impl Display for DataColumnsByRootRequester {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custody(id) => write!(f, "Custody/{id}"),
            Self::Sampling(id) => write!(f, "Sampling/{id}"),
        }
    }
}

impl Display for HeaderLookupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.0, self.1)
    }
}

impl Display for BatchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for RangeRequestId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForwardSync(id) => write!(f, "ForwardSync/{id}"),
            Self::BackfillSync(id) => write!(f, "BackfillSync/{id}"),
        }
    }
}

impl Display for BlocksByRootRequester {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(id) => write!(f, "Header/{id}"),
            Self::ForwardSync(id) => write!(f, "ForwardSync/{id}"),
        }
    }
}

impl Display for SamplingRequestId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for SamplingRequester {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImportedBlock(block) => write!(f, "ImportedBlock/{block}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_id_data_columns_by_root_custody() {
        let id = DataColumnsByRootRequestId {
            id: 123,
            parent_request_id: DataColumnsByRootRequester::Custody(CustodyByRootRequestId {
                parent_request_id: ComponentsByRootRequestId {
                    id: 121,
                    requester: RangeRequestId::ForwardSync(HeaderLookupId(Hash256::ZERO, 1)),
                },
            }),
        };
        assert_eq!(format!("{id}"), "123/Custody/121/Lookup/101");
    }

    #[test]
    fn display_id_data_columns_by_root_sampling() {
        let id = DataColumnsByRootRequestId {
            id: 123,
            parent_request_id: DataColumnsByRootRequester::Sampling(SamplingId {
                id: SamplingRequester::ImportedBlock(Hash256::ZERO),
                sampling_request_id: SamplingRequestId(101),
            }),
        };
        assert_eq!(format!("{id}"), "123/Sampling/101/ImportedBlock/0x0000000000000000000000000000000000000000000000000000000000000000");
    }
}
