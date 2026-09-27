//! Backfill sync: walking the chain backwards from the anchor, addressed by block root.
//!
//! A request names a block root and `blocks_by_head` (consensus-specs #5181) answers with that
//! block's parent chain, newest first. Verifying it needs only the response and the frontier we
//! already hold, so a run is accepted or rejected the instant it arrives and the peer that sent
//! it is the only suspect. Nothing has to be reconciled between adjacent responses, which is
//! why there is no window, no per-batch state machine and no retro-scoring pass here.
//!
//! The decisions live in [`backfill_core`], which is extracted to Lean and proved there; see
//! `common/backfill_core/proofs`. This file translates types, dispatches the core's actions and
//! forwards what comes back as events. It decides only the two things the core deliberately
//! cannot see: which peer to ask, and what data availability requires of a run before the store
//! will take it.

use crate::metrics;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::{
    CustodyByRootResult, LookupRequestResult, RpcRequestSendError, RpcResponseResult,
    SyncNetworkContext,
};
use backfill_core::{Action, Backfill, Config, Event, Header, PeerIdx, Root};
use beacon_chain::block_verification_types::RangeSyncBlock;
use beacon_chain::data_availability_checker::AvailableBlockData;
use beacon_chain::store::metadata::AnchorInfo;
use beacon_chain::{BeaconChain, BeaconChainTypes, WhenSlotSkipped};
use lighthouse_network::rpc::methods::BlocksByHeadRequest;
use lighthouse_network::service::api_types::{CustodyRequester, Id, SingleLookupReqId};
use lighthouse_network::types::{BackFillState, NetworkGlobals};
use lighthouse_network::{PeerAction, PeerId};
use logging::crit;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};
use types::{DataColumnSidecarList, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Ancestors asked for in one `blocks_by_head` request.
const RUN_LEN: u64 = 64;

/// `blocks_by_head` is a lookup route. Backfill has one request outstanding at a time and
/// matches responses by request id, so it needs no lookup of its own.
const BACKFILL_LOOKUP_ID: Id = 0;

/// Peers the core can name at once. See `peer_index`.
const PEER_TABLE_SIZE: usize = 16;

/// Consecutive failures tolerated before the machine parks and waits for a new peer. Spent
/// attempts are only refilled by a run that imports, so this is a budget for retrying, not a
/// budget that renews itself.
const MAX_ATTEMPTS: u8 = 10;

/// Reported to the caller so it can set the global sync state.
#[derive(Debug)]
pub enum SyncStart {
    Syncing { completed: usize, remaining: usize },
    NotSyncing,
}

#[derive(Debug)]
pub enum ProcessResult {
    Successful,
    SyncCompleted,
}

/// A verified run, while what data availability requires of it is gathered. Failing to gather
/// it is reported to the core as `Abandoned`, not `Rejected`: the peer that served the blocks
/// did not owe us the columns.
struct Staged<E: EthSpec> {
    /// Distinguishes this run from the one it replaced, so a custody request left over from an
    /// abandoned run cannot resolve this one.
    run: u32,
    /// Newest first, as they arrived, each with the root it was verified under.
    blocks: Vec<(Hash256, Arc<SignedBeaconBlock<E>>)>,
    /// Custody columns by block root, filled in as the by-root requests complete.
    columns: HashMap<Hash256, DataColumnSidecarList<E>>,
    /// Epochs whose custody request is still outstanding.
    awaiting: HashSet<Epoch>,
    /// Whether any of this run's data came from a peer other than the one that served the
    /// blocks. If it did, a store rejection has more than one suspect and penalises no one.
    columns_from_others: bool,
}

pub struct BackFillSync<T: BeaconChainTypes> {
    /// The proved state machine. Everything below it is translation.
    machine: Backfill,
    /// Peers the core has named, by index, so it cannot reach peer policy.
    peer_table: Vec<PeerId>,
    /// Next slot to mint in `peer_table`.
    peer_next: usize,
    /// The `blocks_by_head` request the core has outstanding.
    inflight: Option<InflightRequest>,
    /// Blocks of the response being handled, held only for the length of the `Run` event: if
    /// the core stages them they move into `staged`, and if it rejects them they are dropped.
    pending: Option<Vec<(Hash256, Arc<SignedBeaconBlock<T::EthSpec>>)>>,
    /// The run the core has staged, while its columns are gathered and the store works.
    staged: Option<Staged<T::EthSpec>>,
    /// Counter behind `Staged::run`.
    run_seq: u32,
    /// Where to start the next scan of candidate peers.
    peer_cursor: usize,
    /// The action to take on the core's next `Penalize`. The store picks it when it rejects a
    /// run; a run that fails the core's own check gets the default.
    penalty: PeerAction,
    /// Frontier slot when this backfill started, for the progress report.
    started_at: Slot,
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
}

struct InflightRequest {
    req_id: Id,
    peer: PeerIdx,
}

impl<T: BeaconChainTypes> BackFillSync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    ) -> Self {
        let anchor_info = beacon_chain.store.get_anchor_info();
        let machine = backfill_core::from_anchor(
            Config {
                run_len: RUN_LEN,
                max_attempts: MAX_ATTEMPTS,
            },
            frontier_of(&beacon_chain, &anchor_info),
            beacon_chain.genesis_backfill_slot.as_u64(),
        );

        let backfill = BackFillSync {
            machine,
            peer_table: vec![],
            peer_next: 0,
            inflight: None,
            pending: None,
            staged: None,
            run_seq: 0,
            peer_cursor: 0,
            penalty: PeerAction::LowToleranceError,
            started_at: anchor_info.oldest_block_slot,
            beacon_chain,
            network_globals,
        };

        let state = if backfill.machine.done {
            BackFillState::Completed
        } else {
            BackFillState::Paused
        };
        backfill.set_state(state);
        backfill
    }

    /// Stops issuing requests. The core is untouched, so resuming is just another tick.
    pub fn pause(&mut self) {
        if let BackFillState::Syncing = self.state() {
            debug!(
                frontier = self.machine.frontier.slot,
                "Backfill sync paused"
            );
            self.set_state(BackFillState::Paused);
        }
    }

    /// Starts or resumes syncing, and reports the progress the caller puts in the global
    /// sync state.
    pub fn start(&mut self, network: &mut SyncNetworkContext<T>) -> SyncStart {
        if self.machine.done {
            self.set_state(BackFillState::Completed);
            return SyncStart::NotSyncing;
        }

        match self.state() {
            BackFillState::Syncing => {}
            BackFillState::Completed => return SyncStart::NotSyncing,
            BackFillState::Paused | BackFillState::Failed => {
                self.set_state(BackFillState::Syncing);
            }
        }

        self.drive(network, Event::Tick);

        if let BackFillState::Completed = self.state() {
            return SyncStart::NotSyncing;
        }

        let frontier = Slot::new(self.machine.frontier.slot);
        SyncStart::Syncing {
            completed: self.started_at.saturating_sub(frontier).as_usize(),
            remaining: frontier
                .saturating_sub(self.beacon_chain.genesis_backfill_slot)
                .as_usize(),
        }
    }

    /// A fully synced peer has joined, which is the event a parked machine waits for. It
    /// emits no actions, so the next tick does the work.
    pub fn fully_synced_peer_joined(&mut self) {
        let actions = backfill_core::step(&mut self.machine, Event::PeerJoined);
        debug_assert!(actions.is_empty(), "PeerJoined emits no actions");
    }

    /// A `blocks_by_head` response, or the error that ended the request.
    pub fn on_blocks_by_head_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        id: SingleLookupReqId,
        peer_id: PeerId,
        response: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
    ) {
        let Some(inflight) = self.inflight.as_ref() else {
            return;
        };
        if inflight.req_id != id.req_id {
            return;
        }
        let peer = inflight.peer;
        self.inflight = None;

        match response {
            Ok(blocks) => {
                let blocks = blocks
                    .into_iter()
                    .map(|block| (block.canonical_root(), block))
                    .collect::<Vec<_>>();
                let headers = blocks
                    .iter()
                    .map(|(root, block)| to_header(*root, block))
                    .collect::<Vec<_>>();
                self.pending = Some(blocks);
                self.drive(network, Event::Run { peer, headers });
                // Whatever the core did with the run, these blocks are no longer the ones in
                // hand: a staged run has taken them, and a rejected one has no further use.
                self.pending = None;
            }
            Err(error) => {
                // No penalty here: the network context has already scored a response that
                // failed verification, and a peer that times out or honestly reports it does
                // not have the root has done nothing wrong.
                debug!(%peer_id, ?error, "Backfill run request failed");
                self.drive(network, Event::Fail { peer: Some(peer) });
            }
        }
        self.continue_backfill(network);
    }

    /// The custody columns of one epoch of a staged run have arrived, or failed to. Results of
    /// a run that has since been abandoned are ignored: its requests stay live in the network
    /// context, and one of them must not take down the run staged in its place.
    pub fn on_custody_by_root_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        run: u32,
        epoch: Epoch,
        result: CustodyByRootResult<T::EthSpec>,
    ) {
        match self.staged.as_mut() {
            Some(staged) if staged.run == run => {
                if !staged.awaiting.remove(&epoch) {
                    return;
                }
            }
            _ => return,
        }

        match result {
            Ok(download) => self.columns_arrived(network, download.value),
            Err(error) => {
                debug!(%epoch, ?error, "Backfill custody columns failed");
                // The custody machinery has already scored whoever served them, and the peer
                // that served the blocks did not owe us columns, so this blames no one.
                self.abandon(network);
            }
        }
        self.continue_backfill(network);
    }

    /// Whether a block needs data backfill cannot fetch by root yet: blob sidecars, because
    /// sync has no `blobs_by_root` consumer, and a Gloas payload envelope. Importing without
    /// either is worse than not importing — the store takes a run with no blobs silently, which
    /// would strand `oldest_blob_slot` at the checkpoint, and rejects a revealed Gloas payload
    /// with no envelope, which would charge the blocks peer for what another peer owed us.
    // TODO(gloas): fetch payload envelopes by root.
    fn sidecars_are_unfetchable(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.fork_name_unchecked().gloas_enabled()
            || self
                .beacon_chain
                .custody_context
                .blobs_required_for_block(block)
    }

    /// Fan-in for one epoch's custody columns. The run goes to the store once every epoch it
    /// touches has reported.
    fn columns_arrived(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        columns: DataColumnSidecarList<T::EthSpec>,
    ) {
        let Some(staged) = self.staged.as_mut() else {
            return;
        };
        for column in columns.iter() {
            staged
                .columns
                .entry(column.block_root())
                .or_default()
                .push(column.clone());
        }
        staged.columns_from_others = true;
        if staged.awaiting.is_empty() {
            self.send_to_processor(network);
        }
    }

    /// An event the core has resolved leaves it ready to ask for the next run, and nothing
    /// else ticks it: the sync manager only revisits backfill when the global state changes.
    /// A tick while paused is suppressed here rather than in the core, which has no notion of
    /// pausing — the next `start` ticks it instead.
    fn continue_backfill(&mut self, network: &mut SyncNetworkContext<T>) {
        if let BackFillState::Syncing = self.state() {
            self.drive(network, Event::Tick);
        }
    }

    /// Drop the staged run and tell the core to try again without blaming anyone.
    fn abandon(&mut self, network: &mut SyncNetworkContext<T>) {
        self.staged = None;
        self.drive(network, Event::Abandoned);
    }

    /// The store has finished with the run the core staged.
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        result: &BatchProcessResult,
    ) -> ProcessResult {
        // KZG is verified by the store, not by the by-root column request, so a fault in a run
        // that carried another peer's columns could be either peer's. Two suspects is not a
        // penalty: retry without blaming anyone rather than charge the blocks peer.
        let shared = self
            .staged
            .as_ref()
            .is_some_and(|staged| staged.columns_from_others);
        let penalty = match result {
            BatchProcessResult::FaultyFailure { penalty, .. } => *penalty,
            BatchProcessResult::Success { .. } | BatchProcessResult::NonFaultyFailure => {
                PeerAction::LowToleranceError
            }
        };
        self.penalty = penalty;
        self.staged = None;
        let event = match result {
            BatchProcessResult::Success { .. } => Event::Imported,
            BatchProcessResult::FaultyFailure { .. } if shared => Event::Abandoned,
            BatchProcessResult::FaultyFailure { .. } => Event::Rejected,
            BatchProcessResult::NonFaultyFailure => Event::Abandoned,
        };
        self.drive(network, event);
        self.resync_frontier();
        self.continue_backfill(network);

        if self.machine.done {
            ProcessResult::SyncCompleted
        } else {
            ProcessResult::Successful
        }
    }

    pub fn register_metrics(&self) {
        metrics::set_gauge(
            &metrics::SYNC_BACKFILL_FRONTIER_SLOT,
            self.machine.frontier.slot as i64,
        );
        metrics::set_gauge(
            &metrics::SYNC_BACKFILL_ATTEMPTS_LEFT,
            self.machine.attempts as i64,
        );
    }

    /// The core's frontier and the store's anchor are two copies of one fact, kept in step by
    /// the store confirming each import. The store is the one that matters, so when they differ
    /// the machine is rebuilt from the anchor; `inv_from_anchor` is what says the rebuilt state
    /// is a sound place to carry on from. Left to drift, the next request would name a root the
    /// store does not expect and an honest peer would be penalised for the mismatch.
    fn resync_frontier(&mut self) {
        let anchor_info = self.beacon_chain.store.get_anchor_info();
        let frontier = self.machine.frontier;
        if frontier.parent_root == to_root(anchor_info.oldest_block_parent)
            && frontier.slot == anchor_info.oldest_block_slot.as_u64()
        {
            return;
        }
        // The store stops at the block whose parent is genesis and sets the anchor to slot 0,
        // which the core cannot see coming, so this difference is the expected end and not a
        // fault.
        if anchor_info.block_backfill_complete(self.beacon_chain.genesis_backfill_slot) {
            debug!("Backfill reached the target; taking the frontier from the store");
        } else {
            warn!(
                core_slot = frontier.slot,
                anchor_slot = %anchor_info.oldest_block_slot,
                "Backfill frontier disagreed with the store; rebuilding from the anchor"
            );
        }
        self.machine = backfill_core::from_anchor(
            self.machine.cfg,
            frontier_of(&self.beacon_chain, &anchor_info),
            self.beacon_chain.genesis_backfill_slot.as_u64(),
        );
        self.staged = None;
        self.pending = None;
        self.inflight = None;
    }

    /// Feed one event to the core and carry out what it asks for. This is the only place the
    /// core is stepped, and the only place its actions are interpreted.
    fn drive(&mut self, network: &mut SyncNetworkContext<T>, event: Event) {
        for action in backfill_core::step(&mut self.machine, event) {
            match action {
                Action::Request {
                    anchor,
                    count,
                    avoid,
                } => self.send_run_request(network, anchor, count, avoid),
                Action::Store { headers } => self.make_durable(network, headers),
                Action::Penalize { peer } => {
                    if let Some(peer_id) = self.peer_table.get(peer as usize) {
                        network.report_peer(*peer_id, self.penalty, "backfill_run_rejected");
                    }
                    self.penalty = PeerAction::LowToleranceError;
                }
                Action::Complete => {
                    info!("Backfill sync completed");
                    self.set_state(BackFillState::Completed);
                }
            }
        }
    }

    fn send_run_request(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        anchor: Root,
        count: u64,
        avoid: Option<PeerIdx>,
    ) {
        let epoch = Slot::new(self.machine.frontier.slot).epoch(T::EthSpec::slots_per_epoch());
        if self
            .beacon_chain
            .custody_context
            .blobs_required_for_epoch(epoch)
            || self
                .beacon_chain
                .spec
                .fork_name_at_epoch(epoch)
                .gloas_enabled()
        {
            // `sidecars_are_unfetchable` would turn the run away after downloading it.
            warn!(%epoch, "Backfill cannot yet fetch the sidecars this epoch needs");
            self.drive(network, Event::Fail { peer: None });
            return;
        }

        let avoid_peer = avoid.and_then(|idx| self.peer_table.get(idx as usize).copied());
        let Some(peer_id) = self.choose_peer(network, avoid_peer) else {
            debug!("No peer to serve a backfill run");
            self.drive(network, Event::Fail { peer: None });
            return;
        };

        let fork = self
            .beacon_chain
            .spec
            .fork_name_at_slot::<T::EthSpec>(Slot::new(self.machine.frontier.slot));
        let request = BlocksByHeadRequest {
            beacon_root: from_root(anchor),
            // Asking for more than the peer will serve is a protocol violation.
            count: count.min(self.beacon_chain.spec.max_request_blocks(fork) as u64),
        };

        self.peer_cursor = self.peer_cursor.wrapping_add(1);
        match network.send_blocks_by_head(peer_id, BACKFILL_LOOKUP_ID, request) {
            Ok(req_id) => {
                let peer = self.peer_index(peer_id);
                self.inflight = Some(InflightRequest { req_id, peer });
            }
            Err(error) => {
                let peer = match error {
                    RpcRequestSendError::NoPeer(_) => None,
                    RpcRequestSendError::InternalError(ref e) => {
                        warn!(error = ?e, "Could not send a backfill run request");
                        Some(self.peer_index(peer_id))
                    }
                };
                self.drive(network, Event::Fail { peer });
            }
        }
    }

    /// Gather what data availability requires of the staged run, then hand it to the store.
    fn make_durable(&mut self, network: &mut SyncNetworkContext<T>, headers: Vec<Header>) {
        // The blocks in hand are the ones the core just verified: their headers are what it
        // was given, in the order it was given them. That correspondence is this adapter's
        // one obligation to the proof of S.
        let Some(blocks) = self.pending.take() else {
            self.abandon(network);
            return;
        };
        debug_assert_eq!(
            blocks.len(),
            headers.len(),
            "the staged run is the one the core verified"
        );

        if let Some((_, block)) = blocks
            .iter()
            .find(|(_, block)| self.sidecars_are_unfetchable(block))
        {
            warn!(
                slot = %block.slot(),
                "Backfill cannot yet fetch the sidecars this run needs"
            );
            self.abandon(network);
            return;
        }

        // One custody request per epoch the run touches: the sampling columns are chosen per
        // epoch, so a run that straddles a boundary needs one request on each side.
        let mut by_epoch: HashMap<Epoch, Vec<Hash256>> = HashMap::new();
        for (root, block) in blocks.iter() {
            if self
                .beacon_chain
                .custody_context
                .data_columns_required_for_block(block)
            {
                by_epoch.entry(block.epoch()).or_default().push(*root);
            }
        }

        self.run_seq = self.run_seq.wrapping_add(1);
        let run = self.run_seq;
        self.staged = Some(Staged {
            run,
            blocks,
            columns: HashMap::new(),
            awaiting: by_epoch.keys().copied().collect(),
            columns_from_others: false,
        });

        if by_epoch.is_empty() {
            self.send_to_processor(network);
            return;
        }

        let peers = Arc::new(RwLock::new(
            self.network_globals
                .peers
                .read()
                .synced_peers()
                .copied()
                .collect::<HashSet<_>>(),
        ));

        // Issue every request before handling any result, so a request that needs nothing
        // cannot complete the fan-in while later epochs are still unregistered.
        let mut ready = vec![];
        for (epoch, block_roots) in by_epoch {
            match network.custody_lookup_request(
                CustodyRequester::Backfill { run, epoch },
                &block_roots,
                epoch,
                true,
                peers.clone(),
            ) {
                Ok(LookupRequestResult::RequestSent(_)) => {}
                Ok(LookupRequestResult::NoRequestNeeded(_, columns)) => {
                    ready.push((epoch, columns))
                }
                Ok(LookupRequestResult::Pending(reason)) => {
                    debug!(reason, "Backfill custody request is pending");
                    self.abandon(network);
                    return;
                }
                Err(error) => {
                    debug!(?error, "Could not request backfill custody columns");
                    self.abandon(network);
                    return;
                }
            }
        }

        for (epoch, columns) in ready {
            if let Some(staged) = self.staged.as_mut() {
                staged.awaiting.remove(&epoch);
            }
            self.columns_arrived(network, columns);
        }
    }

    /// Hand the staged run to the beacon processor, oldest first as the store expects.
    fn send_to_processor(&mut self, network: &mut SyncNetworkContext<T>) {
        let Some(staged) = self.staged.as_mut() else {
            return;
        };

        let mut run = Vec::with_capacity(staged.blocks.len());
        for (block_root, block) in staged.blocks.iter().rev() {
            let data = match staged.columns.remove(block_root) {
                Some(columns) => AvailableBlockData::new_with_data_columns(columns),
                None => AvailableBlockData::NoData,
            };
            // Gloas runs are turned away in `make_durable`, so this is the pre-Gloas path.
            match RangeSyncBlock::new::<T>(block.clone(), data, &self.beacon_chain.custody_context)
            {
                Ok(range_block) => run.push(range_block),
                Err(error) => {
                    debug!(
                        ?block_root,
                        ?error,
                        "Backfill run is not available to store"
                    );
                    self.abandon(network);
                    return;
                }
            }
        }

        let epoch = Slot::new(self.machine.frontier.slot).epoch(T::EthSpec::slots_per_epoch());
        let process_id = ChainSegmentProcessId::BackSyncBatchId(epoch);
        if let Err(e) = network
            .beacon_processor()
            .send_chain_segment(process_id, run)
        {
            crit!(error = %e, "Failed to send a backfill run to the processor");
            self.abandon(network);
        }
    }

    /// A peer that serves `blocks_by_head` and claims to hold blocks as old as the frontier,
    /// preferring one the core has not just been failed by.
    fn choose_peer(
        &self,
        network: &SyncNetworkContext<T>,
        avoid: Option<PeerId>,
    ) -> Option<PeerId> {
        let candidates = self
            .network_globals
            .peers
            .read()
            .synced_peers_for_epoch(
                Slot::new(self.machine.frontier.slot).epoch(T::EthSpec::slots_per_epoch()),
            )
            .copied()
            .filter(|peer_id| network.peer_supports_blocks_by_head(peer_id))
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return None;
        }
        // Rotate: picking the first peer that is not the one that just failed would alternate
        // between the same two and never reach a third that can actually serve the run.
        let start = self.peer_cursor % candidates.len();
        candidates
            .iter()
            .cycle()
            .skip(start)
            .take(candidates.len())
            .find(|peer_id| Some(**peer_id) != avoid)
            .or(candidates.first())
            .copied()
    }

    /// The index the core knows a peer by. The core only ever refers to the peer of the
    /// request in flight and the peer of the run being imported, and it mints at most one
    /// index per request, so a ring this size can never be lapped between minting an index
    /// and the core using it.
    fn peer_index(&mut self, peer_id: PeerId) -> PeerIdx {
        if let Some(index) = self.peer_table.iter().position(|p| *p == peer_id) {
            return index as PeerIdx;
        }
        let index = self.peer_next % PEER_TABLE_SIZE;
        self.peer_next = self.peer_next.wrapping_add(1);
        if index < self.peer_table.len() {
            self.peer_table[index] = peer_id;
        } else {
            self.peer_table.push(peer_id);
        }
        index as PeerIdx
    }

    fn set_state(&self, state: BackFillState) {
        *self.network_globals.backfill_state.write() = state;
    }

    fn state(&self) -> BackFillState {
        self.network_globals.backfill_state.read().clone()
    }
}

/// The frontier the store is at: the oldest block it holds, whose parent backfill asks for
/// next. This is the whole of the persisted state, which is what makes a restart ordinary.
fn frontier_of<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    anchor_info: &AnchorInfo,
) -> Header {
    Header {
        // The frontier's own root is carried so that it and the headers of a run share one
        // type. The core reads the parent and the slot.
        root: to_root(
            beacon_chain
                .block_root_at_slot(anchor_info.oldest_block_slot, WhenSlotSkipped::None)
                .ok()
                .flatten()
                .unwrap_or(anchor_info.oldest_block_parent),
        ),
        parent_root: to_root(anchor_info.oldest_block_parent),
        slot: anchor_info.oldest_block_slot.as_u64(),
    }
}

fn to_root(root: Hash256) -> Root {
    let bytes = root.0;
    let word = |i: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        u64::from_le_bytes(buf)
    };
    Root {
        a: word(0),
        b: word(1),
        c: word(2),
        d: word(3),
    }
}

fn from_root(root: Root) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&root.a.to_le_bytes());
    bytes[8..16].copy_from_slice(&root.b.to_le_bytes());
    bytes[16..24].copy_from_slice(&root.c.to_le_bytes());
    bytes[24..32].copy_from_slice(&root.d.to_le_bytes());
    Hash256::from(bytes)
}

fn to_header<E: EthSpec>(root: Hash256, block: &SignedBeaconBlock<E>) -> Header {
    Header {
        root: to_root(root),
        parent_root: to_root(block.parent_root()),
        slot: block.slot().as_u64(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core compares roots for equality, so this conversion has to be injective. A byte
    /// order bug here would make every run fail to link and every honest peer be penalised.
    #[test]
    fn root_conversion_round_trips_and_separates() {
        for byte in 0..=255u8 {
            let hash = Hash256::repeat_byte(byte);
            assert_eq!(from_root(to_root(hash)), hash);
        }

        // Roots differing in one bit of each word must stay distinct.
        let mut bytes = [0u8; 32];
        for index in [0, 8, 16, 24, 31] {
            let mut other = bytes;
            other[index] = 1;
            assert!(!backfill_core::root_eq(
                to_root(Hash256::from(bytes)),
                to_root(Hash256::from(other))
            ));
            bytes[index] = 1;
        }
    }
}
