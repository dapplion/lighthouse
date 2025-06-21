use crate::sync::network_context::download_request::{
    DownloadRequest, Error as DownloadRequestError,
};
use crate::sync::network_context::{
    DataColumnsByRootRequestId, RpcRequestSendError, RpcResponseError,
};
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::BeaconChainTypes;
use fnv::FnvHashMap;
use lighthouse_network::service::api_types::{CustodyByRootRequestId, DataColumnsByRootRequester};
use lighthouse_network::PeerId;
use lru_cache::LRUTimeCache;
use parking_lot::RwLock;
use rand::Rng;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use tracing::{debug, warn};
use types::{data_column_sidecar::ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Hash256};

use super::{PeerGroup, RpcResponseResult, SyncNetworkContext};

const FAILED_PEERS_CACHE_EXPIRY_SECONDS: u64 = 5;
const REQUEST_EXPIRY_SECONDS: u64 = 300;
/// TODO(das): Reconsider this retry count, it was choosen as a placeholder value. Each
/// `custody_by_*` request is already retried multiple inside of a lookup or batch
const MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS: usize = 3;

pub struct ActiveCustodyByRootRequest<T: BeaconChainTypes> {
    start_time: Instant,
    block_root: Hash256,
    custody_id: CustodyByRootRequestId,
    /// List of column indices this request needs to download to complete successfully
    #[allow(clippy::type_complexity)]
    column_requests: FnvHashMap<
        ColumnIndex,
        DownloadRequest<DataColumnsByRootRequestId, Arc<DataColumnSidecar<T::EthSpec>>>,
    >,
    /// Active requests for 1 or more columns each
    active_batch_columns_requests:
        FnvHashMap<DataColumnsByRootRequestId, ActiveBatchColumnsRequest>,
    /// Peers that have recently failed to successfully respond to a columns by root request.
    /// Having a LRUTimeCache allows this request to not have to track disconnecting peers.
    failed_peers: LRUTimeCache<PeerId>,
    /// Set of peers that claim to have imported this block and their custody columns
    lookup_peers: Arc<RwLock<HashSet<PeerId>>>,

    _phantom: PhantomData<T>,
}

#[derive(Debug)]
pub enum Error {
    InternalError(String),
    TooManyDownloadErrors(RpcResponseError),
    ExpiredNoCustodyPeers(Vec<ColumnIndex>),
}

impl From<Error> for RpcResponseError {
    fn from(e: Error) -> Self {
        match e {
            Error::InternalError(e) => RpcResponseError::InternalError(e),
            Error::TooManyDownloadErrors(e) => e,
            Error::ExpiredNoCustodyPeers(indices) => RpcResponseError::RequestExpired(format!(
                "Expired waiting for custody peers {indices:?}"
            )),
        }
    }
}

impl From<Error> for RpcRequestSendError {
    fn from(e: Error) -> Self {
        match e {
            Error::TooManyDownloadErrors(_) => {
                RpcRequestSendError::InternalError("Download error in request send".to_string())
            }
            Error::InternalError(e) => RpcRequestSendError::InternalError(e),
            Error::ExpiredNoCustodyPeers(_) => RpcRequestSendError::InternalError(
                "Request can not expire when requesting it".to_string(),
            ),
        }
    }
}

impl From<DownloadRequestError> for Error {
    fn from(e: DownloadRequestError) -> Self {
        match e {
            DownloadRequestError::InternalError(e) => Self::InternalError(e),
        }
    }
}

struct ActiveBatchColumnsRequest {
    indices: Vec<ColumnIndex>,
}

pub type CustodyByRootRequestResult<E> =
    Result<Option<(DataColumnSidecarList<E>, PeerGroup, Duration)>, Error>;

impl<T: BeaconChainTypes> ActiveCustodyByRootRequest<T> {
    pub(crate) fn new(
        block_root: Hash256,
        custody_id: CustodyByRootRequestId,
        column_indices: &[ColumnIndex],
        lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            block_root,
            custody_id,
            column_requests: HashMap::from_iter(
                column_indices
                    .iter()
                    .map(|index| (*index, DownloadRequest::new())),
            ),
            active_batch_columns_requests: <_>::default(),
            failed_peers: LRUTimeCache::new(Duration::from_secs(FAILED_PEERS_CACHE_EXPIRY_SECONDS)),
            lookup_peers,
            _phantom: PhantomData,
        }
    }

    /// Insert a downloaded column into an active custody request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Err`: Custody request has failed and will be dropped
    /// - `Ok(Some)`: Custody request has successfully completed and will be dropped
    /// - `Ok(None)`: Custody request still active
    pub(crate) fn on_data_column_downloaded(
        &mut self,
        peer_id: PeerId,
        req_id: DataColumnsByRootRequestId,
        resp: RpcResponseResult<DataColumnSidecarList<T::EthSpec>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyByRootRequestResult<T::EthSpec> {
        let Some(batch_request) = self.active_batch_columns_requests.get_mut(&req_id) else {
            warn!(
                %req_id,
                "Received custody column response for unrequested index"
            );
            return Ok(None);
        };

        match resp {
            Ok((data_columns, seen_timestamp)) => {
                debug!(
                    %req_id,
                    %peer_id,
                    count = data_columns.len(),
                    "Custody column download success"
                );

                // Map columns by index as an optimization to not loop the returned list on each
                // requested index. The worse case is 128 loops over a 128 item vec + mutation to
                // drop the consumed columns.
                let mut data_columns = HashMap::<ColumnIndex, _>::from_iter(
                    data_columns.into_iter().map(|d| (d.index, d)),
                );
                // Accumulate columns that the peer does not have to issue a single log per request
                let mut missing_column_indexes = vec![];

                for column_index in &batch_request.indices {
                    let column_request = self
                        .column_requests
                        .get_mut(column_index)
                        .ok_or(Error::InternalError("unknown column_index".to_owned()))?;

                    if let Some(data_column) = data_columns.remove(column_index) {
                        column_request.on_download_success(
                            req_id,
                            peer_id,
                            data_column,
                            seen_timestamp,
                        )?;
                    } else {
                        // Peer does not have the requested data.
                        // TODO(das) do not consider this case a success. We know for sure the block has
                        // data. However we allow the peer to return empty as we can't attribute fault.
                        // TODO(das): Should track which columns are missing and eventually give up
                        // TODO(das): If the peer is in the lookup peer set it claims to have imported
                        // the block AND its custody columns. So in this case we can downscore
                        column_request.on_download_error(req_id)?;
                        missing_column_indexes.push(column_index);
                    }
                }

                // Note: no need to check data_columns is empty, SyncNetworkContext ensures that
                // successful responses only contain requested data.

                if !missing_column_indexes.is_empty() {
                    // Note: Batch logging that columns are missing to not spam logger
                    debug!(
                        %req_id,
                        %peer_id,
                        // TODO(das): this property can become very noisy, being the full range 0..128
                        ?missing_column_indexes,
                        "Custody column peer claims to not have some data"
                    );

                    self.failed_peers.insert(peer_id);
                }
            }
            Err(err) => {
                debug!(
                    %req_id,
                    %peer_id,
                    error = ?err,
                    "Custody column download error"
                );

                // TODO(das): Should mark peer as failed and try from another peer
                for column_index in &batch_request.indices {
                    self.column_requests
                        .get_mut(column_index)
                        .ok_or(Error::InternalError("unknown column_index".to_owned()))?
                        .on_download_error_and_mark_failure(req_id, err.clone())?;
                }

                self.failed_peers.insert(peer_id);
            }
        };

        self.continue_requests(cx)
    }

    pub(crate) fn continue_requests(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> CustodyByRootRequestResult<T::EthSpec> {
        if self.column_requests.values().all(|r| r.is_downloaded()) {
            // All requests have completed successfully.
            let mut peers = HashMap::<PeerId, Vec<usize>>::new();
            let mut seen_timestamps = vec![];
            let columns = std::mem::take(&mut self.column_requests)
                .into_values()
                .map(|request| {
                    let (peer, data_column, seen_timestamp) = request.complete()?;
                    peers
                        .entry(peer)
                        .or_default()
                        .push(data_column.index as usize);
                    seen_timestamps.push(seen_timestamp);
                    Ok(data_column)
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let peer_group = PeerGroup::from_set(peers);
            let max_seen_timestamp = seen_timestamps.into_iter().max().unwrap_or(timestamp_now());
            return Ok(Some((columns, peer_group, max_seen_timestamp)));
        }

        let active_request_count_by_peer = cx.active_request_count_by_peer();
        let mut columns_to_request_by_peer = HashMap::<PeerId, Vec<ColumnIndex>>::new();
        let lookup_peers = self.lookup_peers.read();

        // Need to:
        // - track how many active requests a peer has for load balancing
        // - which peers have failures to attempt others
        // - which peer returned what to have PeerGroup attributability

        for (column_index, request) in self.column_requests.iter_mut() {
            if request.is_awaiting_download() {
                if let Some(last_error) = request.too_many_failures() {
                    return Err(Error::TooManyDownloadErrors(last_error));
                }

                // TODO(das): When is a fork and only a subset of your peers know about a block, we should
                // only query the peers on that fork. Should this case be handled? How to handle it?
                let custodial_peers = cx.get_custodial_peers(*column_index);

                // We draw from the total set of peers, but prioritize those peers who we have
                // received an attestation / status / block message claiming to have imported the
                // lookup. The frequency of those messages is low, so drawing only from lookup_peers
                // could cause many lookups to take much longer or fail as they don't have enough
                // custody peers on a given column
                let mut priorized_peers = custodial_peers
                    .iter()
                    .map(|peer| {
                        (
                            // Prioritize peers that claim to know have imported this block
                            if lookup_peers.contains(peer) { 0 } else { 1 },
                            // De-prioritize peers that have failed to successfully respond to
                            // requests recently
                            self.failed_peers.contains(peer),
                            // Prefer peers with fewer requests to load balance across peers.
                            // We batch requests to the same peer, so count existence in the
                            // `columns_to_request_by_peer` as a single 1 request.
                            active_request_count_by_peer.get(peer).copied().unwrap_or(0)
                                + columns_to_request_by_peer.get(peer).map(|_| 1).unwrap_or(0),
                            // Random factor to break ties, otherwise the PeerID breaks ties
                            rand::thread_rng().gen::<u32>(),
                            *peer,
                        )
                    })
                    .collect::<Vec<_>>();
                priorized_peers.sort_unstable();

                if let Some((_, _, _, _, peer_id)) = priorized_peers.first() {
                    columns_to_request_by_peer
                        .entry(*peer_id)
                        .or_default()
                        .push(*column_index);
                } else {
                    // Do not issue requests if there is no custody peer on this column. The request
                    // will sit idle without making progress. The only way to make to progress is:
                    // - Add a new peer that custodies the missing columns
                    // - Call `continue_requests`
                    //
                    // Otherwise this request will be dropped and failed after some time.
                }
            }
        }

        for (peer_id, indices) in columns_to_request_by_peer.into_iter() {
            let req_id = cx
                .data_columns_by_root_request(
                    DataColumnsByRootRequester::Custody(self.custody_id),
                    peer_id,
                    self.block_root,
                    indices.clone(),
                    // If peer is in the lookup peer set, it claims to have imported the block and
                    // must have its columns in custody. In that case, set `true = enforce max_requests`
                    // and downscore if data_columns_by_root does not returned the expected custody
                    // columns. For the rest of peers, don't downscore if columns are missing.
                    lookup_peers.contains(&peer_id),
                )
                .map_err(|e| {
                    Error::InternalError(format!("Send failed data_columns_by_root {e:?}"))
                })?;

            for column_index in &indices {
                let column_request = self
                    .column_requests
                    .get_mut(column_index)
                    // Should never happen: column_index is iterated from column_requests
                    .ok_or(Error::InternalError("unknown column_index".to_owned()))?;

                column_request.on_download_start(req_id)?;
            }

            self.active_batch_columns_requests
                .insert(req_id, ActiveBatchColumnsRequest { indices });
        }

        if self.start_time.elapsed() > Duration::from_secs(REQUEST_EXPIRY_SECONDS)
            && !self.column_requests.values().any(|r| r.is_downloading())
        {
            let awaiting_peers_indicies = self
                .column_requests
                .iter()
                .filter(|(_, r)| r.is_awaiting_download())
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            return Err(Error::ExpiredNoCustodyPeers(awaiting_peers_indicies));
        }

        Ok(None)
    }
}
