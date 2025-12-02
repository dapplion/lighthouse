use beacon_chain::BeaconChainTypes;
use lighthouse_network::PeerId;
use lighthouse_network::service::api_types::HeaderChainId;
use std::collections::{HashMap, VecDeque};
use types::{BeaconBlockHeader, Hash256, Slot};

use crate::sync::block_lookups::Error;
use crate::sync::block_lookups::header_request::HeaderRequest;
use crate::sync::network_context::{InternalError, SyncNetworkContext};

/// Minimum data that HeaderChain needs to track for already downloaded headers
type PendingBlock = (Hash256, Slot);

#[derive(Copy, Clone, Debug)]
pub struct PeerStatusSummary {
    pub max_slot: Slot,
    pub min_slot: Slot,
}

pub(crate) struct HeaderChain {
    id: HeaderChainId,
    /// Headers descendant of `next_header_request.block_root` that are already downloaded.
    /// Does not include `next_header_request.block_root`.
    /// Sorting: tip first, oldest ancestor last
    block_roots: VecDeque<PendingBlock>,
    status: HeaderChainStatus,
    /// Peers that claim to have imported the oldest ancestor of this chain
    peers: HashMap<PeerId, PeerStatusSummary>,
}

enum HeaderChainStatus {
    Backfill {
        /// Oldest ancestor block root of this Chain.
        next_request: HeaderRequest,
    },
    WaitingParent {
        /// Parent root of the last block_root in `block_roots`
        parent_root: Hash256,
        /// True if the oldest ancestor can start downloading
        ready_to_sync: bool,
    },
}

impl HeaderChain {
    pub fn new(
        initial_block_root: Hash256,
        id: HeaderChainId,
        initial_peer: PeerId,
        initial_peer_status: PeerStatusSummary,
    ) -> Self {
        Self {
            id,
            block_roots: <_>::default(),
            status: HeaderChainStatus::Backfill {
                next_request: HeaderRequest::new(initial_block_root, id),
            },
            peers: HashMap::from_iter([(initial_peer, initial_peer_status)]),
        }
    }

    /// Continues the header or blocks requests of this chain
    pub fn continue_requests<T: BeaconChainTypes>(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        match &mut self.status {
            HeaderChainStatus::Backfill { next_request } => {
                Ok(next_request.continue_request(self.peers.keys(), cx)?)
            }
            _ => Ok(()),
        }
    }

    fn add_ancestor(&mut self, header: BeaconBlockHeader) -> Result<(), InternalError> {
        match &mut self.status {
            HeaderChainStatus::Backfill { next_request, .. } => {
                self.block_roots
                    .push_back((next_request.block_root, header.slot));
                *next_request = HeaderRequest::new(header.parent_root, self.id);
                Ok(())
            }
            _ => Err(InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn extend_with_children(&mut self, mut child_chain: Self) {
        while let Some(block) = child_chain.block_roots.pop_back() {
            // pop_back gives oldest first, pushing to front restores tip-first
            self.block_roots.push_front(block);
        }

        // All the peers of the child chain have imported the ancestors
        self.peers.extend(child_chain.peers.drain());
    }

    fn to_waiting_parent(
        &mut self,
        parent_root: Hash256,
        ready_to_sync: bool,
    ) -> Result<(), Error> {
        self.status = HeaderChainStatus::WaitingParent {
            parent_root,
            ready_to_sync,
        };
        Ok(())
    }

    fn parent_root(&self) -> Option<Hash256> {
        match &self.status {
            HeaderChainStatus::Backfill { .. } => None,
            HeaderChainStatus::WaitingParent { parent_root, .. } => Some(*parent_root),
        }
    }

    /// Returns true if the peer has been added to the map
    fn add_peer(&mut self, peer: PeerId, status: PeerStatusSummary) -> bool {
        let contains_key = self.peers.contains_key(&peer);
        self.peers.insert(peer, status);
        !contains_key
    }

    /// Returns true if a peer was removed from the map
    fn remove_peer(&mut self, peer: &PeerId) -> bool {
        self.peers.remove(peer).is_some()
    }

    fn pop_oldest_ancestor(&mut self) -> Option<PendingBlock> {
        match &mut self.status {
            HeaderChainStatus::WaitingParent {
                parent_root,
                ready_to_sync,
            } => {
                if !*ready_to_sync {
                    return None;
                }
                if let Some((block_root, block_slot)) = self.block_roots.pop_back() {
                    *parent_root = block_root;
                    Some((block_root, block_slot))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn peers_of_block_slot(&self, block_slot: Slot) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, status)| block_slot >= status.min_slot && block_slot < status.max_slot)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Returns true if this chain transitioned into ready to sync
    fn on_parent_imported(&mut self, imported_block_root: &Hash256) -> bool {
        match &mut self.status {
            HeaderChainStatus::WaitingParent {
                parent_root,
                ready_to_sync,
            } => {
                if parent_root == imported_block_root && !*ready_to_sync {
                    *ready_to_sync = true;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn block_count(&self) -> usize {
        self.block_roots.len()
    }

    fn min_slot(&self) -> Option<Slot> {
        self.block_roots.back().map(|b| b.1)
    }

    fn max_slot(&self) -> Option<Slot> {
        self.block_roots.front().map(|b| b.1)
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }
}
