use crate::sync::block_lookups::Error;
use crate::sync::network_context::{
    DownloadRequest, DownloadRequestError, RpcRequestSendError, SyncNetworkContext,
};
use beacon_chain::BeaconChainTypes;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, HeaderChainId, HeaderLookupId, Id,
};
use std::collections::HashSet;
use types::{BeaconBlockHeader, Hash256};

/// Tracks a request to download a BeaconBlockHeader by block root
pub(crate) struct HeaderRequest {
    id: Option<Id>,
    chain_id: HeaderChainId,
    block_root: Hash256,
    failed_peers: HashSet<PeerId>,
    request: DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>,
}

impl HeaderRequest {
    pub fn new(block_root: Hash256, chain_id: HeaderChainId) -> Self {
        Self {
            id: None,
            chain_id,
            block_root,
            failed_peers: <_>::default(),
            request: DownloadRequest::new(),
        }
    }

    fn empty() -> Self {
        Self::new(Hash256::ZERO, HeaderChainId(0))
    }

    fn continue_request<T, I>(
        &mut self,
        peers: I,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error>
    where
        T: BeaconChainTypes,
        I: Iterator<Item = &'_ PeerId>,
    {
        if self.request.is_awaiting_download() {
            let Some(peer) = peers
                .map(|peer| {
                    (
                        // If contains -> 1 (order after), not contains -> 0 (order first)
                        self.failed_peers.contains(peer),
                        // Random factor to break ties, otherwise the PeerID breaks ties
                        rand::random::<u32>(),
                        peer,
                    )
                })
                .min()
                .map(|(_, _, peer)| *peer)
            else {
                // When a peer disconnects and is removed from the SyncingChain peer set, if the set
                // reaches zero the lookup is removed
                return Err(Error::InternalError("No peers".to_owned()));
            };

            let id = self.id.get_or_insert_with(|| cx.next_id()).clone();

            // TODO(tree-sync): send headers_by_root request if available
            let req_id = cx.send_blocks_by_root_request(
                peer,
                self.block_root,
                BlocksByRootRequester::Header(HeaderLookupId {
                    id,
                    chain_id: self.chain_id,
                }),
            )?;

            self.request.on_download_start(req_id)?;
        }
        Ok(())
    }
}
