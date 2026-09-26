//! Backfill sync: walking the chain backwards from the anchor, addressed by block root.
//!
//! A checkpoint-synced client runs a forward range sync to the head so it can do its duties
//! right away, and then backfills the blocks below the anchor to restore a full history.
//!
//! Backfill asks for a run of ancestors with `blocks_by_head` (consensus-specs #5181): the
//! request names a block root and the response is that block's parent chain, newest first.
//! Verifying it needs nothing but the response and the frontier we already hold — the run
//! must start at the root we asked for and hash-link down from it — so a response is
//! accepted or rejected the instant it arrives, and the peer that sent it is the only
//! suspect. There are no seams between adjacent slot ranges to reconcile, so there is no
//! window, no per-batch state machine, and no retro-scoring pass to work out which of
//! several peers lied.
//!
//! The decisions live in [`backfill_core`], which is extracted to Lean by Charon and Aeneas
//! and proved there; see `common/backfill_core/proofs`. This file is the adapter, and it
//! holds no decisions: it translates types, dispatches the core's actions, and forwards what
//! comes back as events. The two things it decides are the two the core deliberately cannot
//! see — which peer to ask, and what data availability requires of a run before the store
//! will take it. Anything that decides *what backfill does* belongs in the core.

use crate::metrics;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::{
    CustodyByRootResult, LookupRequestResult, RpcRequestSendError, RpcResponseError,
    RpcResponseResult, SyncNetworkContext,
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

/// What a run needs beyond its blocks before the store will take it.
///
/// The core's `Store` action means "this run is verified, make it durable". What durability
/// requires is the store's business, exactly like proposer signatures and KZG, so it is
/// gathered here. A failure to gather it is reported to the core as `Abandoned` rather than
/// `Rejected`, because the peer that served the blocks did not owe us the columns.
struct Staged<E: EthSpec> {
    /// Newest first, as they arrived.
    blocks: Vec<Arc<SignedBeaconBlock<E>>>,
    /// Custody columns by block root, filled in as the by-root requests complete.
    columns: HashMap<Hash256, DataColumnSidecarList<E>>,
    /// Epochs whose custody request is still outstanding.
    awaiting: HashSet<Epoch>,
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
    pending: Option<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
    /// The run the core has staged, while its columns are gathered and the store works.
    staged: Option<Staged<T::EthSpec>>,
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
                let headers = blocks.iter().map(to_header).collect::<Vec<_>>();
                self.pending = Some(blocks);
                self.drive(network, Event::Run { peer, headers });
                // Whatever the core did with the run, these blocks are no longer the ones in
                // hand: a staged run has taken them, and a rejected one has no further use.
                self.pending = None;
            }
            Err(error) => {
                debug!(%peer_id, ?error, "Backfill run request failed");
                self.report_rpc_error(network, peer_id, &error);
                self.drive(network, Event::Fail { peer: Some(peer) });
            }
        }
    }

    /// The custody columns of one epoch of a staged run have arrived, or failed to.
    pub fn on_custody_by_root_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        epoch: Epoch,
        result: CustodyByRootResult<T::EthSpec>,
    ) {
        match result {
            Ok(download) => self.columns_arrived(network, epoch, download.value),
            Err(error) => {
                debug!(%epoch, ?error, "Backfill custody columns failed");
                // The columns peer is scored by the custody machinery that served them, so
                // the run is abandoned rather than charged to the peer that served its blocks.
                self.abandon(network);
            }
        }
    }

    /// Fan-in for one epoch's custody columns. The run goes to the store once every epoch it
    /// touches has reported.
    fn columns_arrived(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        epoch: Epoch,
        columns: DataColumnSidecarList<T::EthSpec>,
    ) {
        let Some(staged) = self.staged.as_mut() else {
            return;
        };
        if !staged.awaiting.remove(&epoch) {
            return;
        }
        for column in columns.iter() {
            staged
                .columns
                .entry(column.block_root())
                .or_default()
                .push(column.clone());
        }
        if staged.awaiting.is_empty() {
            self.send_to_processor(network);
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
        self.staged = None;
        let event = match result {
            BatchProcessResult::Success { .. } => Event::Imported,
            BatchProcessResult::FaultyFailure { .. } => Event::Rejected,
            BatchProcessResult::NonFaultyFailure => Event::Abandoned,
        };
        self.drive(network, event);
        self.resync_frontier();

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
    /// the store confirming each import. If they ever disagree the store is right, and the
    /// machine is rebuilt from it — which is exactly what `inv_from_anchor` says is safe to
    /// do at any time. Left to drift, the next request would name a root the store does not
    /// expect and an honest peer would be penalised for the mismatch.
    fn resync_frontier(&mut self) {
        let anchor_info = self.beacon_chain.store.get_anchor_info();
        let frontier = self.machine.frontier;
        if frontier.parent_root == to_root(anchor_info.oldest_block_parent)
            && frontier.slot == anchor_info.oldest_block_slot.as_u64()
        {
            return;
        }
        warn!(
            core_slot = frontier.slot,
            anchor_slot = %anchor_info.oldest_block_slot,
            "Backfill frontier disagreed with the store; rebuilding from the anchor"
        );
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
                        network.report_peer(
                            *peer_id,
                            PeerAction::LowToleranceError,
                            "backfill_run_rejected",
                        );
                    }
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
        let avoid_peer = avoid.and_then(|idx| self.peer_table.get(idx as usize).copied());
        let Some(peer_id) = self.choose_peer(network, avoid_peer) else {
            debug!("No peer to serve a backfill run");
            self.drive(network, Event::Fail { peer: None });
            return;
        };

        let request = BlocksByHeadRequest {
            beacon_root: from_root(anchor),
            count: count.min(
                self.beacon_chain.spec.max_request_blocks(
                    self.beacon_chain
                        .spec
                        .fork_name_at_slot::<T::EthSpec>(Slot::new(self.machine.frontier.slot)),
                ) as u64,
            ),
        };

        match network.send_blocks_by_head(peer_id, 0, request) {
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
        // One custody request per epoch the run touches: the sampling columns are chosen per
        // epoch, so a run that straddles a boundary needs one request on each side.
        let mut by_epoch: HashMap<Epoch, Vec<Hash256>> = HashMap::new();
        for block in blocks.iter() {
            if self
                .beacon_chain
                .custody_context
                .data_columns_required_for_block(block)
            {
                by_epoch
                    .entry(block.epoch())
                    .or_default()
                    .push(block.canonical_root());
            }
        }

        self.staged = Some(Staged {
            blocks,
            columns: HashMap::new(),
            awaiting: by_epoch.keys().copied().collect(),
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
                CustodyRequester::Backfill(epoch),
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
            self.columns_arrived(network, epoch, columns);
        }
    }

    /// Hand the staged run to the beacon processor, oldest first as the store expects.
    fn send_to_processor(&mut self, network: &mut SyncNetworkContext<T>) {
        let Some(staged) = self.staged.as_mut() else {
            return;
        };

        let mut run = Vec::with_capacity(staged.blocks.len());
        for block in staged.blocks.iter().rev() {
            let block_root = block.canonical_root();
            let data = match staged.columns.remove(&block_root) {
                Some(columns) => AvailableBlockData::new_with_data_columns(columns),
                None => AvailableBlockData::NoData,
            };
            let range_block = if block.fork_name_unchecked().gloas_enabled() {
                RangeSyncBlock::new_gloas(block.clone(), None)
                    .map_err(|e| format!("gloas block: {e}"))
            } else {
                RangeSyncBlock::new::<T>(block.clone(), data, &self.beacon_chain.custody_context)
                    .map_err(|e| format!("{e:?}"))
            };
            match range_block {
                Ok(range_block) => run.push(range_block),
                Err(reason) => {
                    debug!(
                        ?block_root,
                        reason, "Backfill run is not available to store"
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

    /// A synced peer that serves `blocks_by_head`, preferring one the core has not just been
    /// failed by.
    fn choose_peer(
        &self,
        network: &SyncNetworkContext<T>,
        avoid: Option<PeerId>,
    ) -> Option<PeerId> {
        let candidates = self
            .network_globals
            .peers
            .read()
            .synced_peers()
            .copied()
            .filter(|peer_id| network.peer_supports_blocks_by_head(peer_id))
            .collect::<Vec<_>>();

        candidates
            .iter()
            .find(|peer_id| Some(**peer_id) != avoid)
            .or_else(|| candidates.first())
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

    fn report_rpc_error(
        &self,
        network: &SyncNetworkContext<T>,
        peer_id: PeerId,
        error: &RpcResponseError,
    ) {
        network.report_peer(
            peer_id,
            PeerAction::LowToleranceError,
            "backfill_run_failed",
        );
        let _ = error;
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

fn to_header<E: EthSpec>(block: &Arc<SignedBeaconBlock<E>>) -> Header {
    Header {
        root: to_root(block.canonical_root()),
        parent_root: to_root(block.parent_root()),
        slot: block.slot().as_u64(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backfill_core::{Wait, check_run, root_eq, step};

    fn root_of(byte: u8) -> Root {
        to_root(Hash256::repeat_byte(byte))
    }

    /// `Header` has no `Debug` (the core carries no derives it does not need), so runs are
    /// compared by the fields that matter.
    fn oldest(checked: Option<Header>) -> Option<(u64, u64)> {
        checked.map(|header| (header.slot, header.root.a))
    }

    fn header(root: u8, parent: u8, slot: u64) -> Header {
        Header {
            root: root_of(root),
            parent_root: root_of(parent),
            slot,
        }
    }

    /// The core compares roots for equality, so the conversion has to be injective. A byte
    /// order bug here would make every run fail to link and every honest peer be penalised.
    #[test]
    fn root_conversion_round_trips_and_separates() {
        for byte in 0..=255u8 {
            let hash = Hash256::repeat_byte(byte);
            assert_eq!(from_root(to_root(hash)), hash);
        }

        // Two roots differing in one bit of each word must stay distinct.
        let mut bytes = [0u8; 32];
        for index in [0, 8, 16, 24, 31] {
            let mut other = bytes;
            other[index] = 1;
            assert!(!root_eq(
                to_root(Hash256::from(bytes)),
                to_root(Hash256::from(other))
            ));
            bytes[index] = 1;
        }
    }

    /// What the adapter hands the store is a run that starts at the root it asked for and
    /// links down from it. This is the Rust-level statement of `store_is_verified_descent`.
    #[test]
    fn a_run_is_only_accepted_when_it_links_to_the_frontier() {
        let run = vec![header(9, 8, 30), header(8, 7, 29), header(7, 6, 27)];

        assert_eq!(
            oldest(check_run(root_of(9), 31, &run)),
            oldest(Some(header(7, 6, 27)))
        );
        // Wrong anchor.
        assert_eq!(oldest(check_run(root_of(5), 31, &run)), None);
        // Not older than the frontier.
        assert_eq!(oldest(check_run(root_of(9), 30, &run)), None);
        // Empty runs carry no progress, so they are not a link.
        assert_eq!(oldest(check_run(root_of(9), 31, &vec![])), None);
        // A break in the middle.
        let broken = vec![header(9, 8, 30), header(4, 3, 29)];
        assert_eq!(oldest(check_run(root_of(9), 31, &broken)), None);
        // Slots that do not descend.
        let flat = vec![header(9, 8, 30), header(8, 7, 30)];
        assert_eq!(oldest(check_run(root_of(9), 31, &flat)), None);
    }

    /// The sequence the adapter has to implement, end to end: ask, verify, stage, import.
    #[test]
    fn a_landed_run_advances_the_frontier_and_refills_the_budget() {
        let cfg = Config {
            run_len: 64,
            max_attempts: 3,
        };
        let mut machine = backfill_core::from_anchor(cfg, header(9, 8, 30), 0);

        let actions = step(&mut machine, Event::Tick);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Request { anchor, count, .. } => {
                assert!(root_eq(*anchor, root_of(8)));
                assert_eq!(*count, 64);
            }
            other => panic!("expected a request, got {:?}", ActionKind::of(other)),
        }

        // A run that does not link is the sender's fault, and costs an attempt.
        let actions = step(
            &mut machine,
            Event::Run {
                peer: 1,
                headers: vec![header(4, 3, 29)],
            },
        );
        assert!(matches!(
            ActionKind::of(&actions[0]),
            ActionKind::Penalize(1)
        ));
        assert_eq!(machine.attempts, 2);
        assert_eq!(machine.frontier.slot, 30);

        // A run that links is staged, and the frontier only moves once the store confirms.
        let _ = step(&mut machine, Event::Tick);
        let run = vec![header(8, 7, 29), header(7, 6, 27)];
        let actions = step(
            &mut machine,
            Event::Run {
                peer: 2,
                headers: run,
            },
        );
        assert!(matches!(ActionKind::of(&actions[0]), ActionKind::Store));
        assert_eq!(machine.frontier.slot, 30);

        let actions = step(&mut machine, Event::Imported);
        assert!(actions.is_empty());
        assert_eq!(machine.frontier.slot, 27);
        assert_eq!(machine.attempts, 3);
    }

    /// A store rejection names the peer that served the run, not whoever is around.
    #[test]
    fn a_rejected_run_is_charged_to_the_peer_that_served_it() {
        let cfg = Config {
            run_len: 64,
            max_attempts: 3,
        };
        let mut machine = backfill_core::from_anchor(cfg, header(9, 8, 30), 0);
        let _ = step(&mut machine, Event::Tick);
        let _ = step(
            &mut machine,
            Event::Run {
                peer: 7,
                headers: vec![header(8, 7, 29)],
            },
        );

        let actions = step(&mut machine, Event::Rejected);
        assert!(matches!(
            ActionKind::of(&actions[0]),
            ActionKind::Penalize(7)
        ));

        // Whereas a run that could not be made durable blames no one.
        let _ = step(&mut machine, Event::Tick);
        let _ = step(
            &mut machine,
            Event::Run {
                peer: 7,
                headers: vec![header(8, 7, 29)],
            },
        );
        assert!(step(&mut machine, Event::Abandoned).is_empty());
    }

    /// Out of attempts, the machine parks and waits rather than spinning or dying.
    #[test]
    fn exhausted_attempts_park_until_a_peer_joins() {
        let cfg = Config {
            run_len: 64,
            max_attempts: 2,
        };
        let mut machine = backfill_core::from_anchor(cfg, header(9, 8, 30), 0);

        for _ in 0..2 {
            let _ = step(&mut machine, Event::Tick);
            let _ = step(&mut machine, Event::Fail { peer: Some(1) });
        }
        assert_eq!(machine.attempts, 0);
        match machine.wait {
            Wait::Parked => {}
            _ => panic!("expected the machine to park"),
        }
        assert!(step(&mut machine, Event::Tick).is_empty());

        let _ = step(&mut machine, Event::PeerJoined);
        assert_eq!(machine.attempts, 2);
        assert_eq!(step(&mut machine, Event::Tick).len(), 1);
    }

    /// Only for readable assertions: `Action` is plain data with no `Debug`.
    #[derive(Debug, PartialEq)]
    enum ActionKind {
        Request,
        Store,
        Penalize(PeerIdx),
        Complete,
    }

    impl ActionKind {
        fn of(action: &Action) -> Self {
            match action {
                Action::Request { .. } => ActionKind::Request,
                Action::Store { .. } => ActionKind::Store,
                Action::Penalize { peer } => ActionKind::Penalize(*peer),
                Action::Complete => ActionKind::Complete,
            }
        }
    }
}
