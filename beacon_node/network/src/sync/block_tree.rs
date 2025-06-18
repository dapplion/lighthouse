use super::network_context::{LookupRequestResult, RpcResponseError, SyncNetworkContext};
use crate::sync::network_context::custody_by_root::ColumnRequest;
use crate::sync::network_context::{BlocksByRootSameForkRequest, RpcResponseResult};
use crate::sync::range_sync::{BatchInfo, BatchPeers};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::rpc::BlocksByRootRequest;
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, HeaderLookupId, Id, RangeRequestId,
};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::debug;
use types::{BeaconBlockHeader, Epoch, ForkName, Hash256, SignedBeaconBlock, Slot};

pub struct BlockTree<T: BeaconChainTypes> {
    blocks: HashMap<Hash256, Block>,
    batches: HashMap<Id, BatchInfo<T::EthSpec>>,
    roots: HashMap<Hash256, TreeRoot>,
    tips: HashSet<Hash256>,
    chain: Arc<BeaconChain<T>>,
}

struct TreeRoot {
    peers: HashSet<PeerId>,
    request: ColumnRequest<BlocksByRootRequestId, BeaconBlockHeader>,
}

struct Block {
    id: HeaderLookupId,
    block: BeaconBlockHeader,
    is_syncing: bool,
}

// TODO(tree-sync): Re-add the reprocessing cache, so we don't process twice a block that we got
// through gossip and sync.

impl Block {
    fn new(block_root: Hash256, block: BeaconBlockHeader) -> Self {
        Self {
            id: HeaderLookupId(block_root),
            block,
            is_syncing: false,
        }
    }

    fn start<T: BeaconChainTypes>(&mut self, cx: &mut SyncNetworkContext<T>) {
        cx.block_lookup_request(self.id, &self.peers, self.id.0);
    }

    fn on_error(&mut self, _e: RpcResponseError) {
        todo!();
    }

    fn slot(&self) -> Option<Slot> {
        if let Some(block) = self.request.peek_downloaded_data() {
            Some(block.slot)
        } else {
            None
        }
    }

    fn root(&self) -> Hash256 {
        todo!();
    }

    fn is_syncing(&self) -> bool {
        self.is_syncing
    }

    fn parent_root(&self) -> Option<Hash256> {
        if let Some(block) = self.request.peek_downloaded_data() {
            Some(block.parent_root)
        } else {
            None
        }
    }

    fn parent_root_and_slot(&self) -> Option<(Hash256, Slot)> {
        if let Some(block) = self.request.peek_downloaded_data() {
            Some((block.parent_root, block.slot))
        } else {
            None
        }
    }

    fn is_rooted(&self) -> bool {
        todo!();
    }
}

enum Error {
    A,
}

impl<T: BeaconChainTypes> BlockTree<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            blocks: <_>::default(),
            batches: <_>::default(),
            roots: <_>::default(),
            tips: <_>::default(),
            chain,
        }
    }

    pub fn pause(&mut self) {
        todo!()
    }

    pub fn remove_peer(&mut self, _peer: PeerId) {
        todo!();
    }

    pub fn search(
        &mut self,
        block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
        if self.blocks.contains_key(&block_root) {
            // `block_root` points to a known block item in the header DAG
            // Target root is the oldest known ancestor of `block_root` in the header tree
            let oldest_ancestor = self.oldest_known_ancestor(block_root);
            let Some(root) = self.roots.get_mut(&oldest_ancestor) else {
                panic!("root node should exist");
            };
            // Add peer to the root's peer set
            for peer in peers {
                if root.peers.insert(peer) {
                    debug!(block_root = ?oldest_ancestor, ?peer, "Adding peer to existing header lookup");
                }
            }
            true
        } else {
            debug!(?block_root, ?peers, "Creating new header lookup");

            let new_lookup_peers = HashSet::from_iter(peers);

            // If any root has a parent that points to `block_root` remove them from roots and don't
            // make `block_root` node a tip
            let roots_that_descend_from_new_block = self
                .roots
                .keys()
                .filter(|root| {
                    if let Some(parent_root) = self
                        .blocks
                        .get(root)
                        .expect("node must exist")
                        .parent_root()
                    {
                        parent_root == block_root
                    } else {
                        false
                    }
                })
                .copied()
                .collect::<Vec<_>>();

            // We only remove roots that have have a known parent, so they have completed download
            for block_root in roots_that_descend_from_new_block {
                let root = self.roots.remove(&block_root).expect("node must exist");
                new_lookup_peers.extend(root.peers.values());
            }

            // New nodes always become roots since we don't know their parent
            self.roots.insert(
                block_root,
                TreeRoot {
                    peers: new_lookup_peers,
                    request: ColumnRequest::new(),
                },
            );

            // If no one descends from this new node, add it to tips
            if roots_that_descend_from_new_block.is_empty() {
                self.tips.insert(block_root);
            }

            // TODO(tree-sync): have good peer selection
            let Some(peer) = lookup.peers.iter().next() else {
                todo!("no peer");
            };

            let req_id = cx
                .send_blocks_by_root_request(
                    *peer,
                    BlocksByRootRequest::new(vec![block_root], cx.spec(), ForkName::Fulu),
                    BlocksByRootRequester::Header(lookup.id),
                )
                .unwrap();

            lookup.request.on_download_start(req_id).unwrap();

            self.blocks.insert(block_root, lookup);
            true
        }
    }

    fn oldest_known_ancestor(&self, mut block_root: Hash256) -> Hash256 {
        let Some(mut parent_root) = self
            .blocks
            .get(&block_root)
            .and_then(|lookup| lookup.parent_root())
        else {
            return block_root;
        };

        loop {
            if let Some(lookup) = self.blocks.get(&parent_root) {
                if let Some(next_parent_root) = lookup.parent_root() {
                    // Continue iterating the parent chain
                    block_root = parent_root;
                    parent_root = next_parent_root;
                } else {
                    // There's an entry for parent_root but it's not downloaded yet
                    return parent_root;
                }
            } else {
                // There's no entry in the DAG for parent_root, thus block_root is the root node
                return block_root;
            }
        }
    }

    pub fn on_block(
        &mut self,
        req_id: BlocksByRootRequestId,
        lookup_id: HeaderLookupId,
        response: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let block_root = lookup_id.0;
        let Some(lookup) = self.roots.get_mut(&block_root) else {
            return Err(format!("No header lookup for root {block_root}"));
        };

        match response {
            Ok((blocks, received)) => {
                if blocks.len() != 1 {
                    return Err(format!(
                        "Lookup {block_root} returned {} blocks expecting 1",
                        blocks.len()
                    ));
                }
                let block = blocks.first().expect("blocks len == 1").clone();

                let block_header = block.message().block_header();
                let parent_root = block_header.parent_root;

                lookup
                    .request
                    .on_download_success(req_id, peer_id, block_header, received)
                    .unwrap();

                // TODO(tree-sync): Should check if node already exist to not override state
                self.blocks
                    .insert(block_root, Block::new(block_root, block_header));

                // Once we discover the parent_root of this block three things can happen
                // 1. The parent root is a known block -> stop
                // 2. We conflicts with finality -> reject
                // 3. The parent root is unknown -> continue search

                // TODO(tree-sync): should check if the block is descendant of finalized
                // TODO(tree-sync): on finalization or every interval we should drop branches that
                // conflict with finality
                let parent_imported = self.chain.block_is_known_to_fork_choice(&parent_root);
                let parent_known = self.blocks.contains_key(&parent_root);

                if parent_known {
                    self.tips.remove(&parent_root);
                }

                let finalized_slot = Slot::new(0);

                if block_header.slot <= finalized_slot {
                    panic!("Block conflicts with finality");
                }
                if parent_imported || parent_known {
                    // Stop search we reached a known block
                    self.mark_descendants_as_rooted(parent_root);
                    self.trigger_forward_sync(cx);
                } else {
                    let lookup = self.blocks.get_mut(&block_root).expect("lookup exists");
                    let peers = lookup.peers();
                    self.search(parent_root, &peers, cx);
                }
            }
            Err(e) => {
                lookup.request.on_download_error(req_id).unwrap();
                lookup.start(cx);
                todo!("error {e:?}");
            }
        }
        Ok(())
    }

    pub fn prune(&mut self) {
        // Prune blocks once imported, and once finality advances
    }

    pub fn prune_root(&mut self, _block_root: Hash256, _imported: bool) {
        todo!();
    }

    fn mark_descendants_as_rooted(&mut self, _block_root: Hash256) {
        // TODO: iterate all blocks and mark descendants of `block_root` as rooted
    }

    fn mark_as_syncing(&mut self, _blocks: &[Hash256]) {
        // TODO: mark all this block entries as syncing
    }

    fn collect_ancestors(&self, mut block_root: Hash256) -> Vec<Hash256> {
        let mut ancestors = vec![];
        while let Some(block) = self.blocks.get(&block_root) {
            ancestors.push(block_root);
            if let Some(parent_root) = block.parent_root() {
                block_root = parent_root;
            } else {
                break;
            }
        }
        ancestors
    }

    fn trigger_forward_sync(&mut self, cx: &mut SyncNetworkContext<T>) {
        // Find the block range with most peers and highest slot. This is the block
        // to be used as tip of the chain of blocks to fetch.
        let Some(block_root) = self
            .blocks
            .iter()
            .filter_map(|(root, block)| {
                // Ignore blocks that are already being forward synced
                if block.is_syncing() {
                    return None;
                }
                // Ignore block roots which header is not downloaded yet
                let Some((parent_root, slot)) = block.parent_root_and_slot() else {
                    return None;
                };
                // Check if the parent is known in the header tree
                if let Some(slot) = block.slot() {
                    // Find highest peer count, then slot
                    Some((block.peer_count(), slot, root))
                } else {
                    None
                }
            })
            .max()
            .map(|(_, _, root)| *root)
        else {
            return;
        };

        // Get the chain of ancestors of that block_root. Because they are ancestors
        // of block_root all these blocks have the same peer count as `block_root`.
        // Consider limiting the length of blocks so some sensible number to not sync
        // too much at once. There's no good reason to do a big fetch at once.
        let blocks = self.collect_ancestors(block_root);
        self.mark_as_syncing(&blocks);

        // TODO: We can sync parallel chains at once here, if we have multiple chains
        // rooted in different places
        let peers = self
            .blocks
            .get(&block_root)
            .expect("block for block_root should exist")
            .peers();

        self.forward_sync_blocks(&blocks, &peers, cx)
    }

    fn forward_sync_blocks(
        &mut self,
        blocks: &[Hash256],
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        // Create a batch with this blocks
        // Trigger batch sync

        let headers = blocks
            .iter()
            .map(|root| {
                self.blocks
                    .get(root)
                    .expect("block should exist")
                    .request
                    .peek_downloaded_data()
                    .expect("header should be downloaded")
                    .clone()
            })
            .collect::<Vec<_>>();

        // TODO(tree-sync): only choose ranges of blocks in the same fork
        let first_header = headers.first().unwrap();
        let fork = cx.spec().fork_name_at_slot::<T::EthSpec>(first_header.slot);

        // Create batch here?
        let mut batch = BatchInfo::new(blocks.to_vec());

        let request = BlocksByRootSameForkRequest {
            block_roots: batch
                .to_blocks_by_root_request(cx.spec())
                .block_roots()
                .to_vec(),
            fork,
        };
        let chain_id = cx.next_id();
        let requester = RangeRequestId::RangeSync {
            chain_id,
            batch_id: Epoch::new(0),
        };
        let peers = Arc::new(RwLock::new(HashSet::from_iter(peers.iter().copied())));
        let failed_peers = HashSet::new();

        let id =
            match cx.block_components_by_range_request(request, requester, peers, &failed_peers) {
                Ok(req_id) => {
                    // TODO: Update batch state
                    batch.start_downloading(req_id);
                    self.batches.insert(chain_id, batch);
                }
                Err(e) => {
                    // Log failed chain, mark blocks as not syncing
                }
            };
    }

    pub fn on_blocks_response(
        &mut self,
        batch_id: Id,
        blocks: Vec<RpcBlock<T::EthSpec>>,
        batch_peers: BatchPeers,
    ) {
        let Some(batch) = self.batches.get_mut(&batch_id) else {
            panic!("Unknown batch id {batch_id}");
        };

        let received = batch
            .download_completed(blocks, batch_peers)
            .map_err(|e| e.0)
            .unwrap();
        debug!(%batch_id, blocks = received, "Batch downloaded");

        // Continue batches
    }
}
