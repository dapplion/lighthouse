//! Tree sync: syncing by block root alone.
//!
//! Sync starts from any unknown block root a peer claims to hold — a `STATUS` head root, a gossip
//! block with an unknown parent, an attested root — and walks back by `parent_root` (a backfill
//! chain downloading headers) until reaching a block in fork choice, another tracked chain, or a
//! conflict with finality. Anchored chains are then promoted oldest-first into forward sync chains
//! of at most [`Config::promote_batch_roots`] roots, which download their blocks by root and import
//! them once their parent is in fork choice. Peers are adversarial: every response is verified by
//! root by the network layer, and every failure path retries or drops loudly.
//!
//! This module is a pure state machine: transitions return [`Action`]s for the caller (the future
//! `SyncManager` wiring) to execute, and the caller feeds results back via the `on_*` methods. Each
//! `Send*` action guarantees exactly one matching `on_*` callback. Requests are addressed by root
//! (headers) or root set (downloads, processing) rather than by chain, because chains split and
//! both halves keep awaiting the shared in-flight request, dispatched per root via `loc`.
//!
//! Spec: <https://github.com/sigp/lighthouse/pull/9913> (issue #7678). Differences from the spec,
//! beyond naming:
//! - `Merge` (background compaction of split chains) is not implemented; no transition requires it.
//! - `Drop` also cascades to chains anchored into the dropped chain's discovery target, and the
//!   discovery target tracks the header walk step by step so a mid-walk drop cannot leak `loc`
//!   entries.
//! - Response guarantees (contiguity, completeness) are re-validated defensively; a violation is
//!   handled as a failed request instead of corrupting the machine.

use lighthouse_network::PeerId;
use logging::crit;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use tracing::{debug, warn};
use types::{Hash256, Slot};

#[cfg(test)]
mod tests;

/// A chain identifier, internal to this module. Requests are addressed by root via `loc`, never by
/// chain id, since chains split while requests are in flight.
type ChainId = u64;

pub struct Config {
    /// Spec `B`: roots promoted into a single forward sync chain, and therefore the size of a
    /// download request (the by-root protocol caps requests at 128 post-Deneb).
    pub promote_batch_roots: usize,
    /// Spec `N`: max roots across all forward sync chains, bounding blocks held in memory.
    pub max_forward_sync_roots: usize,
    /// Spec `RETRY_MAX`: failed requests tolerated per chain before it is dropped.
    pub max_retries: u8,
    /// Spec `ROOTS_MAX`: tracked roots before the least-attested chains are pruned.
    pub max_tracked_roots: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            promote_batch_roots: 32,
            max_forward_sync_roots: 256,
            max_retries: 5,
            max_tracked_roots: 1_000_000,
        }
    }
}

/// A block header whose `root` the network layer has verified to be the hash of the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    pub root: Hash256,
    pub parent_root: Hash256,
    pub slot: Slot,
}

/// A downloaded block whose `root` the network layer has verified. Cloning must be cheap (`Arc`).
pub trait TreeSyncBlock: Clone {
    fn root(&self) -> Hash256;
}

/// Read-only view of fork choice and finality. Both grow only.
pub trait ForkChoiceView {
    fn contains_block(&self, block_root: &Hash256) -> bool;
    fn finalized(&self) -> (Hash256, Slot);
}

/// A side effect the caller must execute. `Send*` actions guarantee exactly one callback with the
/// result, echoing the request's root(s). Peer sets are a snapshot for convenience: a request
/// serviced over time (e.g. custody column fetches) should read the live peer set instead.
#[derive(Debug)]
pub enum Action<B> {
    /// Request headers walking back from `start_root` (inclusive) by `parent_root`. The caller
    /// must verify each header by root, that headers are contiguous with strictly decreasing
    /// slots, and reply via [`TreeSync::on_headers`].
    SendHeaders {
        start_root: Hash256,
        peers: Vec<PeerId>,
    },
    /// Request the blocks of exactly `roots` (oldest first). The caller must verify each block by
    /// root and reply via [`TreeSync::on_download`].
    SendDownload {
        roots: Vec<Hash256>,
        peers: Vec<PeerId>,
    },
    /// Import `blocks` (oldest first, parent of the first is in fork choice). On success all
    /// blocks must be in fork choice. Reply via [`TreeSync::on_process`].
    SendProcess { roots: Vec<Hash256>, blocks: Vec<B> },
    /// Downscore peers that served data conflicting with our view of the chain.
    ReportPeers {
        peers: Vec<PeerId>,
        reason: &'static str,
    },
}

/// A backfill (`Discovering`/`Anchored`) or forward sync (rest) chain of contiguous roots.
#[derive(Debug)]
struct Chain<B> {
    /// `(root, slot)` tip first: contiguous by `parent_root` with strictly decreasing slots
    /// (Inv 2, 4).
    roots: Vec<(Hash256, Slot)>,
    /// Peers claiming to hold the chain's tip, hence every root in it. Admission is eager: peers
    /// claiming an ancestor of the tip are pooled too, and a false claim surfaces as a failed
    /// request.
    peers: HashSet<PeerId>,
    /// Failed requests so far; exceeding [`Config::max_retries`] drops the chain. Reset on
    /// promotion to forward sync.
    errors: u8,
    state: ChainState<B>,
}

#[derive(Debug)]
enum ChainState<B> {
    /// Backfill: awaiting a headers response walking back from `next` — the parent of the oldest
    /// root, or the searched root itself while `roots` is empty.
    Discovering { next: Hash256 },
    /// Backfill complete: `parent` of the oldest root is in fork choice or tracked by another
    /// chain (Inv 6). Awaiting promotion.
    Anchored { parent: Hash256 },
    /// Forward sync: awaiting the download of all `roots`.
    Downloading { parent: Hash256 },
    /// Forward sync: `blocks` downloaded (oldest first, one per root — Inv 5), awaiting `parent`
    /// to enter fork choice.
    Ready { parent: Hash256, blocks: Vec<B> },
    /// Forward sync: awaiting the import result of `blocks`.
    Processing { parent: Hash256, blocks: Vec<B> },
}

impl<B> Chain<B> {
    fn tip(&self) -> Option<Hash256> {
        self.roots.first().map(|(root, _)| *root)
    }

    fn oldest_slot(&self) -> Option<Slot> {
        self.roots.last().map(|(_, slot)| *slot)
    }

    /// The parent of the oldest root, unknown while still discovering.
    fn parent_link(&self) -> Option<Hash256> {
        match &self.state {
            ChainState::Discovering { .. } => None,
            ChainState::Anchored { parent }
            | ChainState::Downloading { parent }
            | ChainState::Ready { parent, .. }
            | ChainState::Processing { parent, .. } => Some(*parent),
        }
    }

    fn is_forward_sync(&self) -> bool {
        matches!(
            self.state,
            ChainState::Downloading { .. }
                | ChainState::Ready { .. }
                | ChainState::Processing { .. }
        )
    }

    fn peers_vec(&self) -> Vec<PeerId> {
        self.peers.iter().copied().collect()
    }

    /// Roots in import order (oldest first).
    fn roots_oldest_first(&self) -> Vec<Hash256> {
        self.roots.iter().rev().map(|(root, _)| *root).collect()
    }
}

impl<B> ChainState<B> {
    fn name(&self) -> &'static str {
        match self {
            ChainState::Discovering { .. } => "discovering",
            ChainState::Anchored { .. } => "anchored",
            ChainState::Downloading { .. } => "downloading",
            ChainState::Ready { .. } => "ready",
            ChainState::Processing { .. } => "processing",
        }
    }
}

/// How to retry a chain after a failed request.
enum Retry {
    Headers { next: Hash256 },
    Download,
}

pub struct TreeSync<B> {
    /// All tracked chains. A `BTreeMap` so iteration (promotion, pruning) is deterministic.
    chains: BTreeMap<ChainId, Chain<B>>,
    /// Maps each root to the single chain tracking it: `loc[root] = id` iff `root` is in the
    /// chain's `roots` or is its `Discovering` target (Inv 1).
    loc: HashMap<Hash256, ChainId>,
    next_chain_id: ChainId,
    config: Config,
}

impl<B: TreeSyncBlock> TreeSync<B> {
    pub fn new(config: Config) -> Self {
        Self {
            chains: BTreeMap::new(),
            loc: HashMap::new(),
            next_chain_id: 0,
            config,
        }
    }

    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    pub fn tracked_root_count(&self) -> usize {
        self.loc.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chains.is_empty() && self.loc.is_empty()
    }

    /// Spec `Search`: a peer claimed to hold `root` (`STATUS` head root, gossip unknown parent,
    /// attested root) at `claimed_slot` or below.
    pub fn search(
        &mut self,
        root: Hash256,
        claimed_slot: Slot,
        peer: PeerId,
        fork_choice: &impl ForkChoiceView,
    ) -> Vec<Action<B>> {
        let mut actions = Vec::new();
        let (_, finalized_slot) = fork_choice.finalized();
        if fork_choice.contains_block(&root) || claimed_slot <= finalized_slot {
            return actions;
        }

        let holder_id = match self.loc.get(&root).copied() {
            // Unknown root: start discovering its ancestry.
            None => {
                let id = self.new_chain_id();
                self.chains.insert(
                    id,
                    Chain {
                        roots: Vec::new(),
                        peers: HashSet::from([peer]),
                        errors: 0,
                        state: ChainState::Discovering { next: root },
                    },
                );
                self.loc.insert(root, id);
                debug!(chain = id, %root, %claimed_slot, "Tree sync discovering new root");
                self.send_headers(id, root, &mut actions);
                id
            }
            Some(id) => {
                let Some(chain) = self.chains.get(&id) else {
                    crit!(%root, chain = id, "loc points to missing chain");
                    self.loc.remove(&root);
                    return actions;
                };
                let is_discovery_target =
                    matches!(chain.state, ChainState::Discovering { next } if next == root);
                if chain.tip() == Some(root) || is_discovery_target {
                    // Already tracked as a chain tip (or about to become its oldest root): just
                    // pool the peer.
                    id
                } else {
                    // `root` is a mid-chain root: the peer claims it but not the descendants
                    // above it, so split there and admit the peer to the older half only.
                    let Some(index) = chain.roots.iter().position(|(r, _)| *r == root) else {
                        crit!(%root, chain = id, "loc maps a root its chain does not track");
                        return actions;
                    };
                    match self.split_at_index(id, index) {
                        Some((older_id, _newer_id)) => older_id,
                        None => return actions,
                    }
                }
            }
        };

        // Admit the peer to the chain holding `root` and, since holding a block implies holding
        // its ancestors, ascend the parent links admitting it to every ancestor chain.
        let ascend_from = match self.chains.get_mut(&holder_id) {
            Some(chain) => {
                chain.peers.insert(peer);
                chain.parent_link()
            }
            None => {
                crit!(chain = holder_id, "search holder chain missing");
                None
            }
        };
        if let Some(parent) = ascend_from {
            self.add_peers_to_ancestors(parent, &[peer]);
        }

        self.prune();
        self.promote(fork_choice, &mut actions);
        actions
    }

    /// Result of a [`Action::SendHeaders`] request for `start_root`.
    pub fn on_headers(
        &mut self,
        start_root: Hash256,
        result: Result<Vec<HeaderInfo>, impl Display>,
        fork_choice: &impl ForkChoiceView,
    ) -> Vec<Action<B>> {
        let mut actions = Vec::new();
        // Dispatch via `loc`: `start_root` is the chain's discovery target until the response
        // extends it (Inv 1). A miss means the chain was dropped mid-flight.
        let Some(&id) = self.loc.get(&start_root) else {
            debug!(%start_root, "Stale headers response");
            return actions;
        };
        let Some(chain) = self.chains.get(&id) else {
            crit!(%start_root, chain = id, "loc points to missing chain");
            self.loc.remove(&start_root);
            return actions;
        };
        if !matches!(chain.state, ChainState::Discovering { next } if next == start_root) {
            debug!(%start_root, chain = id, state = chain.state.name(), "Headers response for a chain not discovering it");
            return actions;
        }
        let oldest_slot = chain.oldest_slot();

        match result {
            Err(error) => {
                debug!(chain = id, %start_root, %error, "Headers request failed");
                self.on_chain_failure(id, Retry::Headers { next: start_root }, &mut actions);
            }
            Ok(headers) => {
                if let Err(reason) = validate_headers(start_root, oldest_slot, &headers) {
                    warn!(chain = id, %start_root, reason, "Invalid headers response, SendHeaders guarantee broken");
                    self.on_chain_failure(id, Retry::Headers { next: start_root }, &mut actions);
                } else {
                    self.extend_chain_with_headers(id, headers, fork_choice, &mut actions);
                }
            }
        }

        self.prune();
        self.promote(fork_choice, &mut actions);
        actions
    }

    /// Result of a [`Action::SendDownload`] request, echoing its `roots`. `blocks` must cover
    /// exactly the requested roots, each verified by root.
    pub fn on_download(
        &mut self,
        requested_roots: &[Hash256],
        result: Result<Vec<B>, impl Display>,
        fork_choice: &impl ForkChoiceView,
    ) -> Vec<Action<B>> {
        let mut actions = Vec::new();
        // The requesting chain may have split (both halves await this response) or been dropped.
        let owners = self.owners(requested_roots);
        if owners.is_empty() {
            debug!(roots = requested_roots.len(), "Stale download response");
            return actions;
        }

        match result {
            Err(error) => {
                debug!(?owners, %error, "Download request failed");
                for id in owners {
                    match self.chains.get(&id) {
                        Some(chain) if matches!(chain.state, ChainState::Downloading { .. }) => {
                            self.on_chain_failure(id, Retry::Download, &mut actions);
                        }
                        // Dropped by a cascade from an earlier owner, or not awaiting a download.
                        _ => debug!(chain = id, "Skipping download failure"),
                    }
                }
            }
            Ok(blocks) => {
                let mut blocks_by_root: HashMap<Hash256, B> = blocks
                    .into_iter()
                    .map(|block| (block.root(), block))
                    .collect();
                for id in owners {
                    let complete = match self.chains.get_mut(&id) {
                        Some(chain) => {
                            let ChainState::Downloading { parent } = chain.state else {
                                debug!(
                                    chain = id,
                                    state = chain.state.name(),
                                    "Ignoring download response for a chain not downloading"
                                );
                                continue;
                            };
                            // Collect this chain's blocks in import order (Inv 5). Roots are
                            // unique across chains, so moving them out of the map is safe.
                            let chain_blocks: Vec<B> = chain
                                .roots
                                .iter()
                                .rev()
                                .map_while(|(root, _)| blocks_by_root.remove(root))
                                .collect();
                            if chain_blocks.len() == chain.roots.len() {
                                debug!(
                                    chain = id,
                                    blocks = chain_blocks.len(),
                                    "Tree sync chain downloaded"
                                );
                                chain.state = ChainState::Ready {
                                    parent,
                                    blocks: chain_blocks,
                                };
                                true
                            } else {
                                false
                            }
                        }
                        None => {
                            debug!(chain = id, "Skipping download response for dropped chain");
                            continue;
                        }
                    };
                    if !complete {
                        warn!(
                            chain = id,
                            "Download response missing blocks, SendDownload guarantee broken"
                        );
                        self.on_chain_failure(id, Retry::Download, &mut actions);
                    }
                }
                if !blocks_by_root.is_empty() {
                    debug!(
                        blocks = blocks_by_root.len(),
                        "Download response included no longer tracked blocks"
                    );
                }
            }
        }

        self.promote(fork_choice, &mut actions);
        actions
    }

    /// Result of a [`Action::SendProcess`] request, echoing its `roots`. `Ok` means every block is
    /// now in fork choice.
    pub fn on_process(
        &mut self,
        processed_roots: &[Hash256],
        result: Result<(), impl Display>,
        fork_choice: &impl ForkChoiceView,
    ) -> Vec<Action<B>> {
        let mut actions = Vec::new();
        let owners = self.owners(processed_roots);
        if owners.is_empty() {
            debug!(roots = processed_roots.len(), "Stale processing response");
            return actions;
        }

        match result {
            Ok(()) => {
                for id in owners {
                    let Some(chain) = self.chains.get(&id) else {
                        debug!(chain = id, "Skipping processing response for dropped chain");
                        continue;
                    };
                    if !matches!(chain.state, ChainState::Processing { .. }) {
                        debug!(
                            chain = id,
                            state = chain.state.name(),
                            "Ignoring processing response for a chain not processing"
                        );
                        continue;
                    }
                    // All blocks imported: forget the roots. Plain removal, not a cascading drop:
                    // chains anchored into this one now anchor into fork choice (Inv 6).
                    if let Some(chain) = self.chains.remove(&id) {
                        for (root, _) in &chain.roots {
                            self.loc.remove(root);
                        }
                        debug!(
                            chain = id,
                            blocks = chain.roots.len(),
                            "Tree sync chain imported"
                        );
                    }
                }
            }
            Err(error) => {
                // Import stops at the first invalid block, so only the oldest chain's peers are
                // known to be at fault (split halves share peers anyway).
                if let Some(oldest) = owners.first().and_then(|id| self.chains.get(id)) {
                    actions.push(Action::ReportPeers {
                        peers: oldest.peers_vec(),
                        reason: "served an invalid chain of blocks",
                    });
                }
                warn!(?owners, %error, "Tree sync chain failed to import");
                for id in owners {
                    match self.chains.get(&id) {
                        Some(chain) if matches!(chain.state, ChainState::Processing { .. }) => {
                            // Re-download: the blocks may have come from a bad peer.
                            self.on_chain_failure(id, Retry::Download, &mut actions);
                        }
                        _ => debug!(chain = id, "Skipping processing failure"),
                    }
                }
            }
        }

        self.promote(fork_choice, &mut actions);
        actions
    }

    /// Spec `Disconnect`: remove the peer everywhere, dropping chains left without peers.
    pub fn peer_disconnected(
        &mut self,
        peer: &PeerId,
        fork_choice: &impl ForkChoiceView,
    ) -> Vec<Action<B>> {
        let mut actions = Vec::new();
        let mut now_empty = Vec::new();
        for (id, chain) in self.chains.iter_mut() {
            if chain.peers.remove(peer) && chain.peers.is_empty() {
                now_empty.push(*id);
            }
        }
        for id in now_empty {
            self.drop_chain(id, "no peers left");
        }
        self.promote(fork_choice, &mut actions);
        actions
    }

    /// Consumes a validated headers response, walking the chain back (spec `OnHeaders`, Ok arm).
    fn extend_chain_with_headers(
        &mut self,
        id: ChainId,
        headers: Vec<HeaderInfo>,
        fork_choice: &impl ForkChoiceView,
        actions: &mut Vec<Action<B>>,
    ) {
        // Take the chain out of the map to extend it while inserting into `loc`.
        let Some(mut chain) = self.chains.remove(&id) else {
            crit!(chain = id, "extend target chain missing");
            return;
        };
        let (finalized_root, finalized_slot) = fork_choice.finalized();

        enum Halt {
            /// The walk crossed the finalized slot without passing through the finalized block:
            /// this chain is not viable and every peer claiming it is at fault.
            Conflict {
                at: Hash256,
            },
            Anchored {
                parent: Hash256,
                ascend: bool,
            },
        }
        let mut halt = None;
        let mut last_parent = None;
        for header in headers {
            if header.slot <= finalized_slot && header.root != finalized_root {
                halt = Some(Halt::Conflict { at: header.root });
                break;
            }
            // `loc[header.root] = id` already holds: it is the discovery target or was inserted
            // as the parent of the previous header.
            chain.roots.push((header.root, header.slot));
            let parent = header.parent_root;
            if fork_choice.contains_block(&parent) {
                chain.state = ChainState::Anchored { parent };
                halt = Some(Halt::Anchored {
                    parent,
                    ascend: false,
                });
                break;
            }
            if self.loc.contains_key(&parent) {
                chain.state = ChainState::Anchored { parent };
                halt = Some(Halt::Anchored {
                    parent,
                    ascend: true,
                });
                break;
            }
            // Keep walking: the parent becomes the next discovery target. Updating `loc` and the
            // state per header keeps them coherent if a later header conflicts and drops the
            // chain mid-walk.
            self.loc.insert(parent, id);
            chain.state = ChainState::Discovering { next: parent };
            last_parent = Some(parent);
        }

        match halt {
            Some(Halt::Conflict { at }) => {
                warn!(chain = id, root = %at, "Peers served a chain conflicting with finality");
                actions.push(Action::ReportPeers {
                    peers: chain.peers_vec(),
                    reason: "served a chain conflicting with finality",
                });
                self.chains.insert(id, chain);
                self.drop_chain(id, "conflicts with finality");
            }
            Some(Halt::Anchored { parent, ascend }) => {
                debug!(chain = id, %parent, roots = chain.roots.len(), "Tree sync chain anchored");
                let peers = chain.peers_vec();
                self.chains.insert(id, chain);
                if ascend {
                    // The chains this one anchored into may predate our peers' `Search` calls, so
                    // their ascents could not reach them. Peers claiming this chain hold its
                    // ancestors too.
                    self.add_peers_to_ancestors(parent, &peers);
                }
            }
            None => {
                self.chains.insert(id, chain);
                // Unresolved: request the next batch of headers, once, now that the whole
                // response is consumed.
                match last_parent {
                    Some(next) => self.send_headers(id, next, actions),
                    // Unreachable: validated responses are non-empty, so the loop either halted
                    // or advanced the target at least once.
                    None => crit!(chain = id, "headers walk made no progress"),
                }
            }
        }
    }

    /// Spec `Promote`: runs after every transition. Sends every downloaded chain whose parent is
    /// imported to processing, and fills the download pipeline with anchored backfill chains,
    /// oldest first, `promote_batch_roots` at a time.
    fn promote(&mut self, fork_choice: &impl ForkChoiceView, actions: &mut Vec<Action<B>>) {
        let ready: Vec<ChainId> = self
            .chains
            .iter()
            .filter(|(_, chain)| {
                matches!(&chain.state, ChainState::Ready { parent, .. } if fork_choice.contains_block(parent))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            self.send_process(id, actions);
        }

        let mut forward_sync_roots: usize = self
            .chains
            .values()
            .filter(|chain| chain.is_forward_sync())
            .map(|chain| chain.roots.len())
            .sum();
        while forward_sync_roots < self.config.max_forward_sync_roots {
            // A chain is promotable once everything below it is imported or forward syncing.
            let candidate = self.chains.iter().find_map(|(id, chain)| {
                let ChainState::Anchored { parent } = &chain.state else {
                    return None;
                };
                let parent_is_forward_sync = self
                    .loc
                    .get(parent)
                    .and_then(|parent_id| self.chains.get(parent_id))
                    .is_some_and(|parent_chain| parent_chain.is_forward_sync());
                (fork_choice.contains_block(parent) || parent_is_forward_sync)
                    .then_some((*id, chain.roots.len()))
            });
            let Some((id, len)) = candidate else {
                break;
            };
            if len == 0 {
                crit!(chain = id, "anchored chain with no roots");
                self.drop_chain(id, "anchored with no roots");
                continue;
            }
            // Carve off the `promote_batch_roots` oldest roots; a chain at or below that size
            // promotes whole.
            let promote_id = if len > self.config.promote_batch_roots {
                match self.split_at_index(id, len - self.config.promote_batch_roots) {
                    Some((older_id, _newer_id)) => older_id,
                    None => break,
                }
            } else {
                id
            };
            let Some(chain) = self.chains.get_mut(&promote_id) else {
                crit!(chain = promote_id, "promoted chain missing");
                break;
            };
            chain.errors = 0;
            forward_sync_roots += chain.roots.len();
            debug!(
                chain = promote_id,
                roots = chain.roots.len(),
                "Tree sync chain promoted to forward sync"
            );
            self.send_download(promote_id, actions);
        }
    }

    /// Spec `Split`: partitions a chain at `index` (0 = tip) into an older chain `roots[index..]`
    /// keeping the parent link and a newer chain `roots[..index]` anchored on the older tip. Both
    /// inherit peers and errors and keep awaiting any shared in-flight request, whose response is
    /// dispatched per root via `loc`. Returns `(older_id, newer_id)`. The smaller half takes a
    /// fresh id so re-pointing `loc` stays cheap when promotion carves batches off a long chain.
    fn split_at_index(&mut self, id: ChainId, index: usize) -> Option<(ChainId, ChainId)> {
        let Some(mut chain) = self.chains.remove(&id) else {
            crit!(chain = id, "split target chain missing");
            return None;
        };
        let Some(&(older_tip, _)) = chain.roots.get(index).filter(|_| index > 0) else {
            crit!(
                chain = id,
                index,
                len = chain.roots.len(),
                "invalid split index"
            );
            self.chains.insert(id, chain);
            return None;
        };
        let older_roots = chain.roots.split_off(index);
        let newer_roots = std::mem::take(&mut chain.roots);
        let older_len = older_roots.len();

        // Forward sync block buffers hold one block per root, oldest first (Inv 5), so they split
        // by count: the first `older_len` belong to the older half.
        let split_blocks = |mut blocks: Vec<B>| {
            debug_assert_eq!(blocks.len(), older_len + newer_roots.len());
            let newer_blocks = blocks.split_off(older_len.min(blocks.len()));
            (blocks, newer_blocks)
        };
        let (older_state, newer_state) = match chain.state {
            ChainState::Discovering { next } => (
                ChainState::Discovering { next },
                ChainState::Anchored { parent: older_tip },
            ),
            ChainState::Anchored { parent } => (
                ChainState::Anchored { parent },
                ChainState::Anchored { parent: older_tip },
            ),
            ChainState::Downloading { parent } => (
                ChainState::Downloading { parent },
                ChainState::Downloading { parent: older_tip },
            ),
            ChainState::Ready { parent, blocks } => {
                let (older_blocks, newer_blocks) = split_blocks(blocks);
                (
                    ChainState::Ready {
                        parent,
                        blocks: older_blocks,
                    },
                    ChainState::Ready {
                        parent: older_tip,
                        blocks: newer_blocks,
                    },
                )
            }
            ChainState::Processing { parent, blocks } => {
                let (older_blocks, newer_blocks) = split_blocks(blocks);
                (
                    ChainState::Processing {
                        parent,
                        blocks: older_blocks,
                    },
                    ChainState::Processing {
                        parent: older_tip,
                        blocks: newer_blocks,
                    },
                )
            }
        };

        let fresh_id = self.new_chain_id();
        let (older_id, newer_id) = if older_len <= newer_roots.len() {
            (fresh_id, id)
        } else {
            (id, fresh_id)
        };
        let older = Chain {
            roots: older_roots,
            peers: chain.peers.clone(),
            errors: chain.errors,
            state: older_state,
        };
        let newer = Chain {
            roots: newer_roots,
            peers: chain.peers,
            errors: chain.errors,
            state: newer_state,
        };

        // Re-point `loc` for the half that moved to the fresh id, including a discovery target.
        let fresh_chain = if fresh_id == older_id { &older } else { &newer };
        for (root, _) in &fresh_chain.roots {
            self.loc.insert(*root, fresh_id);
        }
        if let ChainState::Discovering { next } = &fresh_chain.state {
            self.loc.insert(*next, fresh_id);
        }
        debug!(chain = id, older = older_id, newer = newer_id, %older_tip, "Tree sync chain split");
        self.chains.insert(older_id, older);
        self.chains.insert(newer_id, newer);
        Some((older_id, newer_id))
    }

    /// Spec `Drop`: removes the chain and, transitively, every chain anchored into a root it
    /// tracked, which can no longer reach fork choice (Inv 6).
    fn drop_chain(&mut self, id: ChainId, reason: &'static str) {
        let mut queue = vec![id];
        while let Some(id) = queue.pop() {
            // May already be gone: dropped by an earlier cascade in this queue.
            let Some(chain) = self.chains.remove(&id) else {
                continue;
            };
            let mut removed_roots: HashSet<Hash256> =
                chain.roots.iter().map(|(root, _)| *root).collect();
            if let ChainState::Discovering { next } = &chain.state {
                removed_roots.insert(*next);
            }
            for root in &removed_roots {
                self.loc.remove(root);
            }
            debug!(
                chain = id,
                reason,
                roots = chain.roots.len(),
                state = chain.state.name(),
                "Dropping tree sync chain"
            );
            for (child_id, child) in &self.chains {
                if child
                    .parent_link()
                    .is_some_and(|parent| removed_roots.contains(&parent))
                {
                    queue.push(*child_id);
                }
            }
        }
    }

    /// Spec `Prune`: bounds memory, dropping the least-attested chains first.
    fn prune(&mut self) {
        while self.loc.len() > self.config.max_tracked_roots {
            let victim = self
                .chains
                .iter()
                .min_by_key(|(id, chain)| (chain.peers.len(), **id))
                .map(|(id, _)| *id);
            let Some(id) = victim else {
                crit!(tracked = self.loc.len(), "tracked roots without any chain");
                self.loc.clear();
                return;
            };
            self.drop_chain(id, "pruned, too many tracked roots");
        }
    }

    /// Registers a failed request and either retries or drops the chain (spec `Err` arms).
    fn on_chain_failure(&mut self, id: ChainId, retry: Retry, actions: &mut Vec<Action<B>>) {
        let Some(chain) = self.chains.get_mut(&id) else {
            crit!(chain = id, "failed chain missing");
            return;
        };
        chain.errors = chain.errors.saturating_add(1);
        if chain.errors > self.config.max_retries {
            self.drop_chain(id, "too many failed requests");
        } else {
            match retry {
                Retry::Headers { next } => self.send_headers(id, next, actions),
                Retry::Download => self.send_download(id, actions),
            }
        }
    }

    /// Spec `SendHeaders`. The caller must have registered `start_root` in `loc` (Inv 1).
    fn send_headers(&mut self, id: ChainId, start_root: Hash256, actions: &mut Vec<Action<B>>) {
        debug_assert_eq!(self.loc.get(&start_root), Some(&id));
        let Some(chain) = self.chains.get_mut(&id) else {
            crit!(chain = id, "headers target chain missing");
            return;
        };
        chain.state = ChainState::Discovering { next: start_root };
        actions.push(Action::SendHeaders {
            start_root,
            peers: chain.peers_vec(),
        });
    }

    /// Spec `SendDownload`.
    fn send_download(&mut self, id: ChainId, actions: &mut Vec<Action<B>>) {
        let Some(chain) = self.chains.get_mut(&id) else {
            crit!(chain = id, "download target chain missing");
            return;
        };
        let Some(parent) = chain.parent_link() else {
            crit!(chain = id, "cannot download an unanchored chain");
            return;
        };
        chain.state = ChainState::Downloading { parent };
        actions.push(Action::SendDownload {
            roots: chain.roots_oldest_first(),
            peers: chain.peers_vec(),
        });
    }

    /// Spec `SendProcess`: only `Ready` chains whose parent is in fork choice are sent.
    fn send_process(&mut self, id: ChainId, actions: &mut Vec<Action<B>>) {
        let Some(chain) = self.chains.get_mut(&id) else {
            crit!(chain = id, "processing target chain missing");
            return;
        };
        let ChainState::Ready { parent, blocks } = &chain.state else {
            crit!(
                chain = id,
                state = chain.state.name(),
                "cannot process a chain that is not ready"
            );
            return;
        };
        let (parent, blocks) = (*parent, blocks.clone());
        let roots = chain.roots_oldest_first();
        debug!(
            chain = id,
            blocks = blocks.len(),
            "Tree sync chain sent for processing"
        );
        chain.state = ChainState::Processing {
            parent,
            blocks: blocks.clone(),
        };
        actions.push(Action::SendProcess { roots, blocks });
    }

    /// The chains tracking any of `roots`, deduplicated, oldest chain first.
    fn owners(&self, roots: &[Hash256]) -> Vec<ChainId> {
        let mut seen = HashSet::new();
        let mut owners: Vec<ChainId> = roots
            .iter()
            .filter_map(|root| self.loc.get(root))
            .filter(|id| seen.insert(**id))
            .copied()
            .collect();
        owners.sort_by_key(|id| self.chains.get(id).and_then(|chain| chain.oldest_slot()));
        owners
    }

    /// Spec ascent: adds `peers` to every chain holding an ancestor, following parent links from
    /// `parent_root` until fork choice or an untracked root.
    fn add_peers_to_ancestors(&mut self, mut parent_root: Hash256, peers: &[PeerId]) {
        // Parent links strictly descend in slot (Inv 4), so the walk visits each chain at most
        // once; more iterations means a corrupt link cycle.
        for _ in 0..self.chains.len() {
            let Some(&id) = self.loc.get(&parent_root) else {
                return;
            };
            let Some(chain) = self.chains.get_mut(&id) else {
                crit!(%parent_root, chain = id, "loc points to missing chain");
                return;
            };
            chain.peers.extend(peers.iter().copied());
            let Some(next) = chain.parent_link() else {
                return;
            };
            parent_root = next;
        }
        crit!(%parent_root, "cycle in tree sync parent links");
    }

    fn new_chain_id(&mut self) -> ChainId {
        let id = self.next_chain_id;
        self.next_chain_id += 1;
        id
    }
}

/// The `SendHeaders` guarantee, re-checked so a broken caller cannot corrupt the machine: headers
/// walk back from `start_root`, contiguous by `parent_root`, with strictly decreasing slots also
/// with respect to the chain's oldest tracked root.
fn validate_headers(
    start_root: Hash256,
    oldest_slot: Option<Slot>,
    headers: &[HeaderInfo],
) -> Result<(), &'static str> {
    let Some(first) = headers.first() else {
        return Err("empty response");
    };
    if first.root != start_root {
        return Err("first header is not the requested root");
    }
    if oldest_slot.is_some_and(|slot| first.slot >= slot) {
        return Err("first header does not descend in slot");
    }
    for pair in headers.windows(2) {
        let (Some(child), Some(parent)) = (pair.first(), pair.get(1)) else {
            return Err("unreachable: windows(2) yields pairs");
        };
        if parent.root != child.parent_root {
            return Err("headers are not contiguous");
        }
        if parent.slot >= child.slot {
            return Err("header slots are not strictly decreasing");
        }
    }
    Ok(())
}
