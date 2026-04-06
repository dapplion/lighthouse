use crate::hdiff::HDiffBuffer;
use crate::{
    Error,
    metrics::{self, HOT_METRIC},
};
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use tracing::instrument;
use typenum::Unsigned;
use types::{
    BeaconState, ChainSpec, Epoch, Eth1Data, EthSpec, Hash256, HistoricalSummary, Slot, Validator,
    execution::StatePayloadStatus,
};

/// Fraction of the LRU cache to leave intact during culling.
const CULL_EXEMPT_NUMERATOR: usize = 1;
const CULL_EXEMPT_DENOMINATOR: usize = 10;

/// States that are less than or equal to this many epochs old *could* become finalized and will not
/// be culled from the cache.
const EPOCH_FINALIZATION_LIMIT: u64 = 4;

/// Estimate the marginal memory cost of a cached state relative to the finalized base.
///
/// Uses knowledge of the consensus spec to approximate how many milhouse tree leaves were
/// copy-on-write'd since the state was rebased on finalized. No milhouse instrumentation required.
///
/// The key insight: after `rebase_on_finalized()`, all cached states share the finalized state's
/// tree as their base. Each state's COW allocations are independent, so estimates can be summed.
pub fn estimated_marginal_bytes<E: EthSpec>(state: &BeaconState<E>) -> usize {
    let n = state.validators().len();
    let is_epoch_boundary = state.slot() % E::slots_per_epoch() == 0;

    // Balances: epoch processing touches ALL validators, mid-epoch only the proposer.
    let balances_dirty = if is_epoch_boundary { n } else { 1 };
    let inactivity_dirty = if is_epoch_boundary { n } else { 0 };

    // Participation lists (u8 per validator): epoch boundary rewrites both lists,
    // mid-epoch ~committee_size attesters get flagged per slot.
    let participation_dirty = if is_epoch_boundary {
        n
    } else {
        // Approximate one committee per slot. Mainnet target is 128, minimal is 4.
        // Use 128 as a reasonable upper bound — the cost is small (u8 leaves).
        128
    };

    // Validators: effective_balance_updates at epoch boundary can mutate validators whose
    // balance crossed a threshold. In normal operation this is a very small number (0-10).
    // We don't attempt to estimate it — the cost is dominated by the large per-validator
    // Leaf<Validator> + Arc<Validator> node size, so even a few would dominate incorrectly.
    let validators_dirty: usize = 0;

    // Fixed-size vectors: 1-2 leaves per slot.
    let roots_dirty: usize = 2; // state_roots + block_roots
    let randao_dirty: usize = 1;

    // Slashings: epoch boundary resets one entry.
    let slashings_dirty: usize = if is_epoch_boundary { 1 } else { 0 };
    let slashings_cap = E::EpochsPerSlashingsVector::to_usize();

    // Eth1 data votes: accumulates 1 per slot since the last voting period reset.
    // Use the current list length as a proxy for how many leaves have changed.
    let eth1_votes_len = state.eth1_data_votes().len();
    let eth1_votes_dirty = if is_epoch_boundary && eth1_votes_len == 0 {
        // Just reset — the list is now empty so no COW cost.
        0
    } else {
        eth1_votes_len
    };
    let eth1_votes_cap = E::SlotsPerEth1VotingPeriod::to_usize();

    // Historical summaries (Capella+): 1 appended per epoch boundary.
    let historical_summaries_dirty = if is_epoch_boundary { 1 } else { 0 };
    let historical_summaries_len = state.historical_summaries().map(|s| s.len()).unwrap_or(0);
    let historical_roots_cap = E::HistoricalRootsLimit::to_usize();

    // Tree capacity for each field.
    let validator_registry_cap = E::ValidatorRegistryLimit::to_usize();
    let roots_cap = E::slots_per_historical_root();
    let randao_cap = E::epochs_per_historical_vector();

    // Container overhead: each milhouse List/Vector struct has intrinsic overhead that
    // MemoryTracker counts as differential. Count all tree-backed fields.
    const NUM_FIELDS: usize = 11; // bal, inact, 2×part, val, 2×roots, randao, slash, eth1, hist
    let container_overhead = NUM_FIELDS * std::mem::size_of::<milhouse::List<u64, typenum::U1>>();

    estimate_tree_bytes::<u64>(balances_dirty, n, validator_registry_cap)
        + estimate_tree_bytes::<u64>(inactivity_dirty, n, validator_registry_cap)
        + 2 * estimate_tree_bytes::<u8>(participation_dirty, n, validator_registry_cap)
        + estimate_tree_bytes::<Validator>(validators_dirty, n, validator_registry_cap)
        + estimate_tree_bytes::<Hash256>(roots_dirty, roots_cap, roots_cap)
        + estimate_tree_bytes::<Hash256>(randao_dirty, randao_cap, randao_cap)
        + estimate_tree_bytes::<u64>(slashings_dirty, slashings_cap, slashings_cap)
        + estimate_tree_bytes::<Eth1Data>(eth1_votes_dirty, eth1_votes_len, eth1_votes_cap)
        + estimate_tree_bytes::<HistoricalSummary>(
            historical_summaries_dirty,
            historical_summaries_len,
            historical_roots_cap,
        )
        + container_overhead
}

/// Estimate bytes consumed by COW'd nodes in a milhouse tree.
///
/// Milhouse trees pack small values into leaves (`PackedLeaf`), so the number of tree nodes
/// is less than the number of values. Each node (`Tree<T>` wrapped in `Arc`) carries overhead
/// for hashes, child pointers, and enum discriminant, which dominates for small `T`.
///
/// - `dirty`: number of values modified.
/// - `total`: current number of values in the list/vector.
/// - `capacity`: the list/vector's maximum capacity (`N` type parameter). Milhouse sizes its
///   tree for this capacity, so the root-to-leaf path length is `log₂(capacity / packing)`.
///
/// For fully-dirty trees: all leaves and internal nodes are fresh allocations, plus the
/// spine from the populated subtree to the root and Zero-node siblings along it (worst
/// case: the list is replaced entirely, so Zero nodes are distinct from the base).
/// For sparse changes: each dirty leaf COW's one root-to-leaf path of internal nodes.
/// The sparse formula overcounts for adjacent dirty values (they may share both the packed
/// leaf and internal path nodes) — intentional as an upper bound for eviction decisions.
///
/// Does NOT include the List/Vector container struct overhead — callers must add that
/// separately (see `estimated_marginal_bytes`'s `container_overhead`).
fn estimate_tree_bytes<T: milhouse::Value>(dirty: usize, total: usize, capacity: usize) -> usize {
    if dirty == 0 || total == 0 {
        return 0;
    }
    // Small types (u8, u64) are packed into 32-byte leaves. Large/composite types get 1 per leaf.
    let packing_factor = (32 / std::mem::size_of::<T>()).max(1);

    // Per-node overhead: Tree<T> enum (hash + child ptrs + discriminant) + Arc wrapper.
    let node_overhead = std::mem::size_of::<milhouse::Tree<T>>()
        + std::mem::size_of::<milhouse::Arc<milhouse::Tree<T>>>();
    // Extra data stored in each leaf. For PackedLeaf: the Vec's heap allocation.
    // For Leaf<T> (packing_factor==1): Arc<T> wrapper + T value.
    let leaf_arc_overhead = if packing_factor == 1 {
        std::mem::size_of::<milhouse::Arc<T>>()
    } else {
        0
    };
    let leaf_data = leaf_arc_overhead + packing_factor * std::mem::size_of::<T>();

    let num_leaves = total.div_ceil(packing_factor);
    // Tree depth from root to leaf is based on max capacity, not current length.
    let capacity_leaves = capacity.div_ceil(packing_factor);
    let tree_depth = if capacity_leaves <= 1 {
        0
    } else {
        usize::BITS - (capacity_leaves - 1).leading_zeros()
    } as usize;

    // Full-tree cost: all leaves + internal nodes + spine + Zero siblings.
    // This is an upper bound regardless of how many leaves are dirty.
    let populated_depth = if num_leaves <= 1 {
        0
    } else {
        usize::BITS - (num_leaves - 1).leading_zeros()
    } as usize;
    let spine = tree_depth.saturating_sub(populated_depth);
    let full_tree = num_leaves * (node_overhead + leaf_data)
        + num_leaves.saturating_sub(1) * node_overhead // internal nodes in populated subtree
        + spine * node_overhead                        // spine from populated subtree to root
        + spine * node_overhead; // Zero-node siblings along the spine

    if dirty >= total {
        full_tree
    } else {
        // Sparse: each dirty value may hit a separate packed leaf in the worst case
        // (scattered mutations). Cap at num_leaves.
        let dirty_leaves = dirty.min(num_leaves);
        // Cost per dirty path: tree_depth internal nodes + 1 leaf node.
        let sparse = dirty_leaves * (tree_depth * node_overhead + node_overhead + leaf_data);
        // The sparse formula overcounts when many leaves are dirty because it charges
        // a full root-to-leaf path per dirty leaf, ignoring shared internal nodes.
        // Cap at the full-tree cost which is always a valid upper bound.
        sparse.min(full_tree)
    }
}

#[derive(Debug)]
pub struct FinalizedState<E: EthSpec> {
    state_root: Hash256,
    state: BeaconState<E>,
}

/// Map from (block_root, payload_status) -> slot -> state_root.
#[derive(Debug, Default)]
pub struct BlockMap {
    blocks: HashMap<(Hash256, StatePayloadStatus), SlotMap>,
}

/// Map from slot -> state_root.
#[derive(Debug, Default)]
pub struct SlotMap {
    slots: BTreeMap<Slot, Hash256>,
}

#[derive(Debug)]
pub struct StateCache<E: EthSpec> {
    finalized_state: Option<FinalizedState<E>>,
    /// Stores (state_root, state) per cached state.
    states: LruCache<Hash256, (Hash256, BeaconState<E>)>,
    block_map: BlockMap,
    hdiff_buffers: HotHDiffBufferCache,
    max_epoch: Epoch,
    head_block_root: Hash256,
    headroom: NonZeroUsize,
    /// Optional byte budget. When set, eviction triggers when total COW bytes exceed this.
    max_bytes: Option<usize>,
}

/// Cache of hdiff buffers for hot states.
///
/// This cache only keeps buffers prior to the finalized state, which are required by the
/// hierarchical state diff scheme to construct newer unfinalized states.
///
/// The cache always retains the hdiff buffer for the most recent snapshot so that even if the
/// cache capacity is 1, this snapshot never needs to be loaded from disk.
#[derive(Debug)]
pub struct HotHDiffBufferCache {
    /// Cache of HDiffBuffers for states *prior* to the `finalized_state`.
    ///
    /// Maps state_root -> (slot, buffer).
    hdiff_buffers: LruCache<Hash256, (Slot, HDiffBuffer)>,
}

#[derive(Debug)]
pub enum PutStateOutcome {
    /// State is prior to the cache's finalized state (lower slot) and was cached as an HDiffBuffer.
    PreFinalizedHDiffBuffer,
    /// State is equal to the cache's finalized state and was not inserted.
    Finalized,
    /// State was already present in the cache.
    Duplicate,
    /// State is new to the cache and was inserted.
    ///
    /// Includes deleted states as a result of this insertion.
    New(Vec<Hash256>),
}

#[allow(clippy::len_without_is_empty)]
impl<E: EthSpec> StateCache<E> {
    pub fn new(
        state_capacity: NonZeroUsize,
        headroom: NonZeroUsize,
        hdiff_capacity: NonZeroUsize,
        max_bytes: Option<usize>,
    ) -> Self {
        StateCache {
            finalized_state: None,
            states: LruCache::new(state_capacity),
            block_map: BlockMap::default(),
            hdiff_buffers: HotHDiffBufferCache::new(hdiff_capacity),
            max_epoch: Epoch::new(0),
            head_block_root: Hash256::ZERO,
            headroom,
            max_bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn capacity(&self) -> usize {
        self.states.cap().get()
    }

    pub fn num_hdiff_buffers(&self) -> usize {
        self.hdiff_buffers.len()
    }

    pub fn hdiff_buffer_mem_usage(&self) -> usize {
        self.hdiff_buffers.mem_usage()
    }

    /// Total bytes consumed by cached states, computed by deduplicating shared
    /// `ApproxOwnedBytes` segments across all states (including finalized).
    pub fn cached_bytes(&self) -> usize {
        self.total_approx_owned_bytes()
    }

    /// Return all state roots currently held in the cache, including the finalized state.
    pub fn state_roots(&self) -> Vec<Hash256> {
        let mut roots: Vec<Hash256> = self
            .states
            .iter()
            .map(|(&state_root, _)| state_root)
            .collect();
        if let Some(ref finalized) = self.finalized_state {
            roots.push(finalized.state_root);
        }
        roots
    }

    pub fn update_finalized_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        mut state: BeaconState<E>,
        pre_finalized_slots_to_retain: &[Slot],
    ) -> Result<(), Error> {
        if state.slot() % E::slots_per_epoch() != 0 {
            return Err(Error::FinalizedStateUnaligned);
        }

        if self
            .finalized_state
            .as_ref()
            .is_some_and(|finalized_state| state.slot() < finalized_state.state.slot())
        {
            return Err(Error::FinalizedStateDecreasingSlot);
        }

        let payload_status = state.payload_status();

        // Add to block map.
        self.block_map
            .insert(block_root, payload_status, state.slot(), state_root);

        // Prune block map.
        let state_roots_to_prune = self.block_map.prune(state.slot());

        // Prune HDiffBuffers that are no longer required by the hdiff grid of the finalized state.
        // We need to do this prior to copying in any new hdiff buffers, because the cache
        // preferences older slots.
        // NOTE: This isn't perfect as it prunes by slot: there could be multiple buffers
        // at some slots in the case of long forks without finality.
        let new_hdiff_cache = HotHDiffBufferCache::new(self.hdiff_buffers.cap());
        let old_hdiff_cache = std::mem::replace(&mut self.hdiff_buffers, new_hdiff_cache);
        for (state_root, (slot, buffer)) in old_hdiff_cache.hdiff_buffers {
            if pre_finalized_slots_to_retain.contains(&slot) {
                self.hdiff_buffers.put(state_root, slot, buffer);
            }
        }

        // Delete states.
        for state_root in state_roots_to_prune {
            if let Some((_, state)) = self.states.pop(&state_root) {
                // Add the hdiff buffer for this state to the hdiff cache if it is now part of
                // the pre-finalized grid. The `put` method will take care of keeping the most
                // useful buffers.
                let slot = state.slot();
                if pre_finalized_slots_to_retain.contains(&slot) {
                    let hdiff_buffer = HDiffBuffer::from_state(state);
                    self.hdiff_buffers.put(state_root, slot, hdiff_buffer);
                }
            }
        }

        // Ensure the finalized state has a base size entry in its approx_owned_bytes.
        // States loaded from disk or constructed from genesis start with an empty list.
        if state.approx_owned_bytes().0.is_empty() {
            let base_bytes = types::total_state_tree_bytes(&state);
            tracing::debug!(
                base_bytes,
                slot = %state.slot(),
                validators = state.validators().len(),
                "measured finalized state base tree size"
            );
            state.approx_owned_bytes_mut().push(base_bytes);
        }

        // Update finalized state.
        self.finalized_state = Some(FinalizedState { state_root, state });
        Ok(())
    }

    /// Update the state cache's view of the enshrined head block.
    ///
    /// We never prune the unadvanced state for the head block.
    pub fn update_head_block_root(&mut self, head_block_root: Hash256) {
        self.head_block_root = head_block_root;
    }

    /// Rebase the given state on the finalized state in order to reduce its memory consumption.
    ///
    /// This function should only be called on states that are likely not to already share tree
    /// nodes with the finalized state, e.g. states loaded from disk.
    ///
    /// If the finalized state is not initialized this function is a no-op.
    pub fn rebase_on_finalized(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        // Do not attempt to rebase states prior to the finalized state. This method might be called
        // with states on the hdiff grid prior to finalization, as part of the reconstruction of
        // some later unfinalized state.
        if let Some(finalized_state) = &self.finalized_state
            && state.slot() >= finalized_state.state.slot()
        {
            state.rebase_on(&finalized_state.state, spec)?;

            // After rebase, the state shares the finalized tree. Recompute owned bytes:
            // adopt the finalized state's list + measure the remaining unique cost.
            let unique_bytes = types::cow_bytes_between(&finalized_state.state, state);
            tracing::debug!(
                unique_bytes,
                slot = %state.slot(),
                "rebased state cow_bytes vs finalized"
            );
            state
                .approx_owned_bytes_mut()
                .reset_to_base(finalized_state.state.approx_owned_bytes(), unique_bytes);
        }

        Ok(())
    }

    /// Return a status indicating whether the state already existed in the cache.
    pub fn put_state(
        &mut self,
        state_root: Hash256,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<PutStateOutcome, Error> {
        if let Some(ref finalized_state) = self.finalized_state {
            if finalized_state.state_root == state_root {
                return Ok(PutStateOutcome::Finalized);
            } else if state.slot() <= finalized_state.state.slot() {
                // We assume any state being inserted into the cache is grid-aligned (it is the
                // caller's responsibility to not feed us garbage) as we don't want to thread the
                // hierarchy config through here. So any state received is converted to an
                // HDiffBuffer and saved.
                let hdiff_buffer = HDiffBuffer::from_state(state.clone());
                self.hdiff_buffers
                    .put(state_root, state.slot(), hdiff_buffer);
                return Ok(PutStateOutcome::PreFinalizedHDiffBuffer);
            }
        }

        if self.states.peek(&state_root).is_some() {
            return Ok(PutStateOutcome::Duplicate);
        }

        // Refuse states with pending mutations: we want cached states to be as small as possible
        // i.e. stored entirely as a binary merkle tree with no updates overlaid.
        if state.has_pending_mutations() {
            return Err(Error::StateForCacheHasPendingUpdates {
                state_root,
                slot: state.slot(),
            });
        }

        // Update the cache's idea of the max epoch.
        self.max_epoch = std::cmp::max(state.current_epoch(), self.max_epoch);

        // If the cache is full (by count), use the custom cull routine to make room.
        let mut deleted_states =
            if let Some(over_capacity) = self.len().checked_sub(self.capacity()) {
                // The `over_capacity` should always be 0, but we add it here just in case.
                self.cull(over_capacity + self.headroom.get())
            } else {
                vec![]
            };

        // If adding this state would exceed the byte budget, cull until under budget.
        // total_approx_owned_bytes deduplicates shared ApproxOwnedBytes segments across
        // all cached states, so it reflects actual memory, not double-counted estimates.
        if let Some(max_bytes) = self.max_bytes {
            let total_before = self.total_approx_owned_bytes();
            let mut evicted = 0;
            while self.total_approx_owned_bytes() > max_bytes && self.len() > 0 {
                let culled = self.cull(1);
                if culled.is_empty() {
                    break;
                }
                evicted += culled.len();
                deleted_states.extend(culled);
            }
            if evicted > 0 {
                let total_after = self.total_approx_owned_bytes();
                tracing::debug!(
                    max_bytes,
                    total_before,
                    total_after,
                    evicted,
                    remaining = self.len(),
                    "state cache byte budget eviction"
                );
                metrics::inc_counter_by(
                    &metrics::STORE_BEACON_STATE_CACHE_EVICTIONS,
                    evicted as u64,
                );
            }
        }

        // Insert the full state into the cache.
        if let Some((deleted_state_root, _)) =
            self.states.put(state_root, (state_root, state.clone()))
        {
            deleted_states.push(deleted_state_root);
        }

        // Record the connection from block root and slot to this state.
        let slot = state.slot();
        let payload_status = state.payload_status();
        self.block_map
            .insert(block_root, payload_status, slot, state_root);

        Ok(PutStateOutcome::New(deleted_states))
    }

    pub fn get_by_state_root(&mut self, state_root: Hash256) -> Option<BeaconState<E>> {
        if let Some(ref finalized_state) = self.finalized_state
            && state_root == finalized_state.state_root
        {
            return Some(finalized_state.state.clone());
        }
        self.states.get(&state_root).map(|(_, state)| state.clone())
    }

    pub fn put_hdiff_buffer(&mut self, state_root: Hash256, slot: Slot, buffer: &HDiffBuffer) {
        // Only accept HDiffBuffers prior to finalization. Later states should be stored as proper
        // states, not HDiffBuffers.
        if let Some(finalized_state) = &self.finalized_state
            && slot >= finalized_state.state.slot()
        {
            return;
        }
        self.hdiff_buffers.put(state_root, slot, buffer.clone());
    }

    pub fn get_hdiff_buffer_by_state_root(&mut self, state_root: Hash256) -> Option<HDiffBuffer> {
        if let Some(buffer) = self.hdiff_buffers.get(&state_root) {
            metrics::inc_counter_vec(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_HIT, HOT_METRIC);
            let timer =
                metrics::start_timer_vec(&metrics::BEACON_HDIFF_BUFFER_CLONE_TIME, HOT_METRIC);
            let result = Some(buffer.clone());
            drop(timer);
            return result;
        }
        if let Some(buffer) = self
            .get_by_state_root(state_root)
            .map(HDiffBuffer::from_state)
        {
            metrics::inc_counter_vec(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_HIT, HOT_METRIC);
            return Some(buffer);
        }
        metrics::inc_counter_vec(&metrics::STORE_BEACON_HDIFF_BUFFER_CACHE_MISS, HOT_METRIC);
        None
    }

    #[instrument(skip_all, fields(?block_root, %slot), level = "debug")]
    pub fn get_by_block_root(
        &mut self,
        block_root: Hash256,
        payload_status: StatePayloadStatus,
        slot: Slot,
    ) -> Option<(Hash256, BeaconState<E>)> {
        let slot_map = self.block_map.blocks.get(&(block_root, payload_status))?;

        // Find the state at `slot`, or failing that the most recent ancestor.
        let state_root = slot_map
            .slots
            .iter()
            .rev()
            .find_map(|(ancestor_slot, state_root)| {
                (*ancestor_slot <= slot).then_some(*state_root)
            })?;

        let state = self.get_by_state_root(state_root)?;
        Some((state_root, state))
    }

    pub fn delete_state(&mut self, state_root: &Hash256) {
        self.states.pop(state_root);
        self.block_map.delete(state_root);
    }

    pub fn delete_block_states(&mut self, block_root: &Hash256) {
        let (pending_state_roots, full_state_roots) =
            self.block_map.delete_block_states(block_root);
        for slot_map in [pending_state_roots, full_state_roots]
            .into_iter()
            .flatten()
        {
            for state_root in slot_map.slots.values() {
                self.states.pop(state_root);
            }
        }
    }

    /// Compute the total unique COW bytes across all cached states.
    ///
    /// Iterates all states and deduplicates `CowSegment`s by `Arc` pointer identity.
    /// Shared segments (from common ancestors) are counted once.
    pub fn total_approx_owned_bytes(&self) -> usize {
        let finalized = self
            .finalized_state
            .as_ref()
            .map(|f| f.state.approx_owned_bytes());
        let cached = self
            .states
            .iter()
            .map(|(_, (_, state))| state.approx_owned_bytes());
        types::sum_approx_owned_bytes(finalized.into_iter().chain(cached))
    }

    /// Cull approximately `count` states from the cache.
    ///
    /// States are culled LRU, with the following extra order imposed:
    ///
    /// - Advanced states.
    /// - Mid-epoch unadvanced states.
    /// - Epoch-boundary states that are too old to be finalized.
    /// - Epoch-boundary states that could be finalized.
    pub fn cull(&mut self, count: usize) -> Vec<Hash256> {
        let cull_exempt = std::cmp::max(
            1,
            self.len() * CULL_EXEMPT_NUMERATOR / CULL_EXEMPT_DENOMINATOR,
        );

        // Stage 1: gather states to cull.
        let mut advanced_state_roots = vec![];
        let mut mid_epoch_state_roots = vec![];
        let mut old_boundary_state_roots = vec![];
        let mut good_boundary_state_roots = vec![];

        // Skip the `cull_exempt` most-recently used, then reverse the iterator to start at
        // least-recently used states.
        for (&state_root, (_, state)) in self.states.iter().skip(cull_exempt).rev() {
            let is_advanced = state.slot() > state.latest_block_header().slot;
            let is_boundary = state.slot() % E::slots_per_epoch() == 0;
            let could_finalize =
                (self.max_epoch - state.current_epoch()) <= EPOCH_FINALIZATION_LIMIT;

            if is_boundary {
                if could_finalize {
                    good_boundary_state_roots.push(state_root);
                } else {
                    old_boundary_state_roots.push(state_root);
                }
            } else if is_advanced {
                advanced_state_roots.push(state_root);
            } else if state.get_latest_block_root(state_root) != self.head_block_root {
                // Never prune the head state
                mid_epoch_state_roots.push(state_root);
            }

            // Terminate early in the common case where we've already found enough junk to cull.
            if advanced_state_roots.len() == count {
                break;
            }
        }

        // Stage 2: delete.
        // This could probably be more efficient in how it interacts with the block map.
        let state_roots_to_delete = advanced_state_roots
            .into_iter()
            .chain(old_boundary_state_roots)
            .chain(mid_epoch_state_roots)
            .chain(good_boundary_state_roots)
            .take(count)
            .collect::<Vec<_>>();

        for state_root in &state_roots_to_delete {
            self.delete_state(state_root);
        }

        state_roots_to_delete
    }
}

impl BlockMap {
    fn insert(
        &mut self,
        block_root: Hash256,
        payload_status: StatePayloadStatus,
        slot: Slot,
        state_root: Hash256,
    ) {
        let slot_map = self.blocks.entry((block_root, payload_status)).or_default();
        slot_map.slots.insert(slot, state_root);
    }

    fn prune(&mut self, finalized_slot: Slot) -> HashSet<Hash256> {
        let mut pruned_states = HashSet::new();

        self.blocks.retain(|_, slot_map| {
            slot_map.slots.retain(|slot, state_root| {
                let keep = *slot >= finalized_slot;
                if !keep {
                    pruned_states.insert(*state_root);
                }
                keep
            });

            !slot_map.slots.is_empty()
        });

        pruned_states
    }

    fn delete(&mut self, state_root_to_delete: &Hash256) {
        self.blocks.retain(|_, slot_map| {
            slot_map
                .slots
                .retain(|_, state_root| state_root != state_root_to_delete);
            !slot_map.slots.is_empty()
        });
    }

    fn delete_block_states(&mut self, block_root: &Hash256) -> (Option<SlotMap>, Option<SlotMap>) {
        let pending_state_roots = self
            .blocks
            .remove(&(*block_root, StatePayloadStatus::Pending));
        let full_state_roots = self.blocks.remove(&(*block_root, StatePayloadStatus::Full));
        (pending_state_roots, full_state_roots)
    }
}

impl HotHDiffBufferCache {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            hdiff_buffers: LruCache::new(capacity),
        }
    }

    pub fn get(&mut self, state_root: &Hash256) -> Option<HDiffBuffer> {
        self.hdiff_buffers
            .get(state_root)
            .map(|(_, buffer)| buffer.clone())
    }

    /// Put a value in the cache, making room for it if necessary.
    ///
    /// If the value was inserted then `true` is returned.
    pub fn put(&mut self, state_root: Hash256, slot: Slot, buffer: HDiffBuffer) -> bool {
        // If the cache is not full, simply insert the value.
        if self.hdiff_buffers.len() != self.hdiff_buffers.cap().get() {
            self.hdiff_buffers.put(state_root, (slot, buffer));
            return true;
        }

        // If the cache is full, it has room for this new entry if:
        //
        // - The capacity is greater than 1: we can retain the snapshot and the new entry, or
        // - The capacity is 1 and the slot of the new entry is older than the min_slot in the
        //   cache. This is a simplified way of retaining the snapshot in the cache. We don't need
        //   to worry about inserting/retaining states older than the snapshot because these are
        //   pruned on finalization and never reinserted.
        let Some(min_slot) = self.hdiff_buffers.iter().map(|(_, (slot, _))| *slot).min() else {
            // Unreachable: cache is full so should have >0 entries.
            return false;
        };

        if self.hdiff_buffers.cap().get() > 1 || slot < min_slot {
            // Remove LRU value. Cache is now at size `cap - 1`.
            let Some((removed_state_root, (removed_slot, removed_buffer))) =
                self.hdiff_buffers.pop_lru()
            else {
                // Unreachable: cache is full so should have at least one entry to pop.
                return false;
            };

            // Insert new value. Cache size is now at size `cap`.
            self.hdiff_buffers.put(state_root, (slot, buffer));

            // If the removed value had the min slot and we didn't intend to replace it (cap=1)
            // then we reinsert it.
            if removed_slot == min_slot && slot >= min_slot {
                self.hdiff_buffers
                    .put(removed_state_root, (removed_slot, removed_buffer));
            }
            true
        } else {
            // No room.
            false
        }
    }

    pub fn cap(&self) -> NonZeroUsize {
        self.hdiff_buffers.cap()
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.hdiff_buffers.len()
    }

    pub fn mem_usage(&self) -> usize {
        self.hdiff_buffers
            .iter()
            .map(|(_, (_, buffer))| buffer.size())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixed_bytes::FixedBytesExtended;
    use milhouse::mem::MemoryTracker;
    use milhouse::{List, Vector};
    use ssz_types::BitVector;
    use std::sync::Arc;
    use types::state::ProgressiveBalancesCache;
    use types::{
        BeaconBlockHeader, BeaconStateAltair, Checkpoint, CommitteeCache, EpochCache, Eth1Data,
        ExitCache, Fork, MinimalEthSpec, ParticipationFlags, PubkeyCache, SlashingsCache, Slot,
        SyncCommittee,
    };

    type E = MinimalEthSpec;

    fn make_test_validator() -> Validator {
        Validator {
            pubkey: bls::PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::zero(),
            effective_balance: 32_000_000_000,
            slashed: false,
            activation_eligibility_epoch: Epoch::new(0),
            activation_epoch: Epoch::new(0),
            exit_epoch: Epoch::new(u64::MAX),
            withdrawable_epoch: Epoch::new(u64::MAX),
        }
    }

    /// Create an Altair state with `n` validators at the given `slot`.
    fn make_altair_state(n: usize, slot: Slot) -> BeaconState<E> {
        let validators = List::new(vec![make_test_validator(); n]).unwrap();
        let balances = List::new(vec![32_000_000_000u64; n]).unwrap();
        let inactivity_scores = List::new(vec![0u64; n]).unwrap();
        let participation = List::new(vec![ParticipationFlags::default(); n]).unwrap();
        let default_committee_cache = Arc::new(CommitteeCache::default());
        let sync_committee = Arc::new(SyncCommittee::temporary());

        BeaconState::Altair(BeaconStateAltair {
            genesis_time: 0,
            genesis_validators_root: Hash256::zero(),
            slot,
            fork: Fork::default(),
            latest_block_header: BeaconBlockHeader::empty(),
            block_roots: Vector::default(),
            state_roots: Vector::default(),
            historical_roots: List::default(),
            eth1_data: Eth1Data::default(),
            eth1_data_votes: List::default(),
            eth1_deposit_index: 0,
            validators,
            balances,
            randao_mixes: Vector::default(),
            slashings: Vector::default(),
            previous_epoch_participation: participation.clone(),
            current_epoch_participation: participation,
            justification_bits: BitVector::new(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            inactivity_scores,
            current_sync_committee: sync_committee.clone(),
            next_sync_committee: sync_committee,
            total_active_balance: None,
            progressive_balances_cache: ProgressiveBalancesCache::default(),
            committee_caches: [
                default_committee_cache.clone(),
                default_committee_cache.clone(),
                default_committee_cache,
            ],
            pubkey_cache: PubkeyCache::default(),
            exit_cache: ExitCache::default(),
            slashings_cache: SlashingsCache::default(),
            epoch_cache: EpochCache::default(),
            approx_owned_bytes: types::ApproxOwnedBytesList::default(),
        })
    }

    /// Measure actual differential bytes for all milhouse fields between base and derived state.
    ///
    /// Tracks base fields first (marking shared nodes as seen), then derived fields.
    /// The differential_size of each derived field is the actual COW memory cost.
    fn measure_actual_differential_bytes(base: &BeaconState<E>, derived: &BeaconState<E>) -> usize {
        let mut tracker = MemoryTracker::default();

        // Track base fields — marks shared tree nodes as "seen"
        tracker.track_item(base.validators());
        tracker.track_item(base.balances());
        tracker.track_item(base.inactivity_scores().unwrap());
        tracker.track_item(base.previous_epoch_participation().unwrap());
        tracker.track_item(base.current_epoch_participation().unwrap());
        tracker.track_item(base.state_roots());
        tracker.track_item(base.block_roots());
        tracker.track_item(base.randao_mixes());
        tracker.track_item(base.slashings());
        tracker.track_item(base.eth1_data_votes());

        // Track derived fields — differential_size captures new COW'd allocations
        let mut total = 0;
        total += tracker.track_item(derived.validators()).differential_size;
        total += tracker.track_item(derived.balances()).differential_size;
        total += tracker
            .track_item(derived.inactivity_scores().unwrap())
            .differential_size;
        total += tracker
            .track_item(derived.previous_epoch_participation().unwrap())
            .differential_size;
        total += tracker
            .track_item(derived.current_epoch_participation().unwrap())
            .differential_size;
        total += tracker.track_item(derived.state_roots()).differential_size;
        total += tracker.track_item(derived.block_roots()).differential_size;
        total += tracker.track_item(derived.randao_mixes()).differential_size;
        total += tracker.track_item(derived.slashings()).differential_size;
        total += tracker
            .track_item(derived.eth1_data_votes())
            .differential_size;
        total
    }

    // ── estimate_tree_bytes: sparse mutations ──────────────────────────────

    /// The capacity for test lists (List<_, U1048576>).
    const TEST_CAP: usize = 1048576;

    /// Assert estimate is an upper bound within the given max ratio.
    fn assert_upper_bound(label: &str, estimated: usize, actual: usize, max_ratio: f64) {
        let ratio = estimated as f64 / actual as f64;
        eprintln!("{label}: estimated={estimated}, actual={actual}, ratio={ratio:.2}");
        assert!(
            estimated >= actual,
            "{label}: estimate ({estimated}) must be >= actual ({actual})"
        );
        assert!(
            ratio <= max_ratio,
            "{label}: ratio {ratio:.2} exceeds max {max_ratio:.1}"
        );
    }

    #[test]
    fn estimate_tree_bytes_sparse_single() {
        // Mutate 1 out of 1024 leaves in a List<u64>
        let total = 1024;
        let base = List::<u64, typenum::U1048576>::new(vec![0u64; total]).unwrap();
        let mut derived = base.clone();
        *derived.get_mut(0).unwrap() = 1;
        derived.apply_updates().unwrap();

        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        // MemoryTracker includes the List struct overhead; estimate_tree_bytes only covers tree
        // nodes, so add the container size for a fair comparison.
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<u64>(1, total, TEST_CAP) + container;
        assert_upper_bound("sparse(1/1024)", estimated, actual, 1.5);
    }

    #[test]
    fn estimate_tree_bytes_sparse_many() {
        // Mutate 100 scattered leaves out of 4096
        let total = 4096;
        let base = List::<u64, typenum::U1048576>::new(vec![0u64; total]).unwrap();
        let mut derived = base.clone();
        // Spread mutations across the tree to minimize path sharing
        for i in (0..total).step_by(total / 100) {
            *derived.get_mut(i).unwrap() = 1;
        }
        derived.apply_updates().unwrap();

        let dirty = 100;
        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<u64>(dirty, total, TEST_CAP) + container;
        assert_upper_bound("sparse(100/4096)", estimated, actual, 4.0);
    }

    #[test]
    fn estimate_tree_bytes_sparse_adjacent() {
        // Mutate 100 adjacent leaves — worst case for overcounting (shared paths).
        // Adjacent mutations share nearly all internal nodes, but the sparse formula
        // charges each a full path. The full-tree cap limits the damage but it's still
        // a significant overcount for this pathological layout.
        let total = 4096;
        let base = List::<u64, typenum::U1048576>::new(vec![0u64; total]).unwrap();
        let mut derived = base.clone();
        for i in 0..100 {
            *derived.get_mut(i).unwrap() = 1;
        }
        derived.apply_updates().unwrap();

        let dirty = 100;
        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<u64>(dirty, total, TEST_CAP) + container;
        // Adjacent is the worst case for the sparse formula — allow more headroom.
        assert_upper_bound("adjacent(100/4096)", estimated, actual, 30.0);
    }

    #[test]
    fn estimate_tree_bytes_full() {
        let total = 1024;
        let base = List::<u64, typenum::U1048576>::new(vec![0u64; total]).unwrap();
        let mut derived = base.clone();
        for i in 0..total {
            *derived.get_mut(i).unwrap() = 1;
        }
        derived.apply_updates().unwrap();

        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<u64>(total, total, TEST_CAP) + container;
        assert_upper_bound("full(1024/1024)", estimated, actual, 1.5);
    }

    // ── estimated_marginal_bytes: epoch boundary ───────────────────────────

    #[test]
    fn estimated_marginal_bytes_epoch_boundary() {
        let n = 1024;
        let slots_per_epoch = E::slots_per_epoch();
        let slot = Slot::new(slots_per_epoch); // epoch boundary
        let base = make_altair_state(n, slot);
        let mut derived = base.clone();

        // Simulate epoch processing: all balances rewritten
        for i in 0..n {
            *derived.balances_mut().get_mut(i).unwrap() += 1;
        }
        // All inactivity scores rewritten
        for i in 0..n {
            *derived.inactivity_scores_mut().unwrap().get_mut(i).unwrap() += 1;
        }
        // Both participation lists replaced (epoch rotation creates new lists)
        *derived.previous_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        *derived.current_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        // Roots and randao
        *derived.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x01);
        *derived.block_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x02);
        *derived.randao_mixes_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x03);

        derived.apply_pending_mutations().unwrap();

        let actual = measure_actual_differential_bytes(&base, &derived);
        let estimated = estimated_marginal_bytes::<E>(&derived);

        assert_upper_bound("epoch_boundary(n=1024)", estimated, actual, 1.5);
    }

    // ── estimated_marginal_bytes: mid-epoch ────────────────────────────────

    #[test]
    fn estimated_marginal_bytes_mid_epoch() {
        let n = 1024;
        let slot = Slot::new(1); // mid-epoch
        let base = make_altair_state(n, slot);
        let mut derived = base.clone();

        // Simulate mid-epoch: 1 proposer reward
        *derived.balances_mut().get_mut(0).unwrap() += 1;
        // ~128 attesters update participation flags
        for i in 0..128.min(n) {
            derived
                .current_epoch_participation_mut()
                .unwrap()
                .get_mut(i)
                .unwrap()
                .add_flag(0)
                .unwrap();
        }
        // Roots and randao
        *derived.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x01);
        *derived.block_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x02);
        *derived.randao_mixes_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x03);

        derived.apply_pending_mutations().unwrap();

        let actual = measure_actual_differential_bytes(&base, &derived);
        let estimated = estimated_marginal_bytes::<E>(&derived);

        assert_upper_bound("mid_epoch(n=1024)", estimated, actual, 4.0);
    }

    // ── estimate_tree_bytes: u8 (participation) ────────────────────────────

    #[test]
    fn estimate_tree_bytes_u8_full() {
        // ParticipationFlags are u8-sized — test with a u8 list
        let total = 1024;
        let base = List::<u8, typenum::U1048576>::new(vec![0u8; total]).unwrap();
        let mut derived = base.clone();
        for i in 0..total {
            *derived.get_mut(i).unwrap() = 1;
        }
        derived.apply_updates().unwrap();

        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<u8>(total, total, TEST_CAP) + container;
        assert_upper_bound("u8_full(1024/1024)", estimated, actual, 1.5);
    }

    #[test]
    fn estimate_tree_bytes_hash256_sparse() {
        // Vectors like state_roots / block_roots use Hash256
        let total = 64; // MinimalEthSpec::SlotsPerHistoricalRoot
        let base = Vector::<Hash256, typenum::U64>::default();
        let mut derived = base.clone();
        *derived.get_mut(0).unwrap() = Hash256::repeat_byte(0x01);
        *derived.get_mut(1).unwrap() = Hash256::repeat_byte(0x02);
        derived.apply_updates().unwrap();

        let dirty = 2;
        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        // For vectors, capacity == total (fixed size)
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<Hash256>(dirty, total, total) + container;

        assert_upper_bound("hash256_sparse(2/64)", estimated, actual, 2.0);
    }

    // ── estimate_tree_bytes: additional type coverage ──────────────────────

    #[test]
    fn estimate_tree_bytes_hash256_full() {
        let total = 64;
        let base = Vector::<Hash256, typenum::U64>::default();
        let mut derived = base.clone();
        for i in 0..total {
            *derived.get_mut(i).unwrap() = Hash256::repeat_byte(i as u8);
        }
        derived.apply_updates().unwrap();

        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<Hash256>(total, total, total) + container;
        assert_upper_bound("hash256_full(64/64)", estimated, actual, 1.5);
    }

    #[test]
    fn estimate_tree_bytes_slashings_single() {
        let total = 64;
        let base = Vector::<u64, typenum::U64>::default();
        let mut derived = base.clone();
        *derived.get_mut(0).unwrap() = 1_000_000;
        derived.apply_updates().unwrap();

        let mut tracker = MemoryTracker::default();
        tracker.track_item(&base);
        let actual = tracker.track_item(&derived).differential_size;
        let container = std::mem::size_of_val(&derived);
        let estimated = estimate_tree_bytes::<u64>(1, total, total) + container;

        assert_upper_bound("slashings(1/64)", estimated, actual, 1.5);
    }

    // ── Per-field differential tests ──────────────────────────────────────

    /// Track a single milhouse field's differential between base and derived states.
    fn field_differential<T: milhouse::mem::MemorySize>(
        base_field: &T,
        derived_field: &T,
    ) -> usize {
        let mut tracker = MemoryTracker::default();
        tracker.track_item(base_field);
        tracker.track_item(derived_field).differential_size
    }

    /// Helper: mutate `dirty` scattered balance entries out of `n`, measure estimate vs actual.
    fn check_balances_estimate(n: usize, dirty: usize, max_ratio: f64) {
        let base = make_altair_state(n, Slot::new(1));
        let mut derived = base.clone();
        // Spread mutations evenly across the list
        let step = if dirty >= n { 1 } else { n / dirty };
        for i in (0..n).step_by(step).take(dirty) {
            *derived.balances_mut().get_mut(i).unwrap() += 1;
        }
        derived.apply_pending_mutations().unwrap();

        let actual = field_differential(base.balances(), derived.balances());
        let container = std::mem::size_of_val(derived.balances());
        let cap = <E as types::EthSpec>::ValidatorRegistryLimit::to_usize();
        let estimated = estimate_tree_bytes::<u64>(dirty, n, cap) + container;
        assert_upper_bound(
            &format!("balances({dirty}/{n})"),
            estimated,
            actual,
            max_ratio,
        );
    }

    #[test]
    fn per_field_balances_single() {
        check_balances_estimate(1024, 1, 1.5);
    }

    #[test]
    fn per_field_balances_10pct() {
        check_balances_estimate(1024, 102, 3.0);
    }

    #[test]
    fn per_field_balances_50pct() {
        check_balances_estimate(1024, 512, 2.0);
    }

    #[test]
    fn per_field_balances_all() {
        check_balances_estimate(1024, 1024, 1.5);
    }

    #[test]
    fn per_field_participation_committee() {
        let n = 1024;
        let base = make_altair_state(n, Slot::new(1));
        let mut derived = base.clone();
        // ~128 attesters update current participation
        for i in 0..128.min(n) {
            derived
                .current_epoch_participation_mut()
                .unwrap()
                .get_mut(i)
                .unwrap()
                .add_flag(0)
                .unwrap();
        }
        derived.apply_pending_mutations().unwrap();

        let actual = field_differential(
            base.current_epoch_participation().unwrap(),
            derived.current_epoch_participation().unwrap(),
        );
        let container = std::mem::size_of_val(derived.current_epoch_participation().unwrap());
        let cap = <E as types::EthSpec>::ValidatorRegistryLimit::to_usize();
        let estimated = estimate_tree_bytes::<u8>(128, n, cap) + container;
        assert_upper_bound("participation(128/1024)", estimated, actual, 4.0);
    }

    #[test]
    fn per_field_state_roots_single() {
        let n = 1024;
        let base = make_altair_state(n, Slot::new(1));
        let mut derived = base.clone();
        *derived.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0xAA);
        derived.apply_pending_mutations().unwrap();

        let actual = field_differential(base.state_roots(), derived.state_roots());
        let container = std::mem::size_of_val(derived.state_roots());
        let cap = E::slots_per_historical_root();
        let estimated = estimate_tree_bytes::<Hash256>(1, cap, cap) + container;
        assert_upper_bound("state_roots(1/64)", estimated, actual, 1.5);
    }

    #[test]
    fn per_field_randao_single() {
        let n = 1024;
        let base = make_altair_state(n, Slot::new(1));
        let mut derived = base.clone();
        *derived.randao_mixes_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0xBB);
        derived.apply_pending_mutations().unwrap();

        let actual = field_differential(base.randao_mixes(), derived.randao_mixes());
        let container = std::mem::size_of_val(derived.randao_mixes());
        let cap = E::epochs_per_historical_vector();
        let estimated = estimate_tree_bytes::<Hash256>(1, cap, cap) + container;
        assert_upper_bound("randao(1/64)", estimated, actual, 1.5);
    }

    #[test]
    fn per_field_inactivity_all() {
        let n = 1024;
        let base = make_altair_state(n, Slot::new(8));
        let mut derived = base.clone();
        for i in 0..n {
            *derived.inactivity_scores_mut().unwrap().get_mut(i).unwrap() += 1;
        }
        derived.apply_pending_mutations().unwrap();

        let actual = field_differential(
            base.inactivity_scores().unwrap(),
            derived.inactivity_scores().unwrap(),
        );
        let container = std::mem::size_of_val(derived.inactivity_scores().unwrap());
        let cap = <E as types::EthSpec>::ValidatorRegistryLimit::to_usize();
        let estimated = estimate_tree_bytes::<u64>(n, n, cap) + container;
        assert_upper_bound("inactivity(1024/1024)", estimated, actual, 1.5);
    }

    #[test]
    fn per_field_participation_replaced() {
        let n = 1024;
        let base = make_altair_state(n, Slot::new(8));
        let mut derived = base.clone();
        *derived.previous_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        derived.apply_pending_mutations().unwrap();

        let actual = field_differential(
            base.previous_epoch_participation().unwrap(),
            derived.previous_epoch_participation().unwrap(),
        );
        let container = std::mem::size_of_val(derived.previous_epoch_participation().unwrap());
        let cap = <E as types::EthSpec>::ValidatorRegistryLimit::to_usize();
        let estimated = estimate_tree_bytes::<u8>(n, n, cap) + container;
        assert_upper_bound("participation_replaced(1024/1024)", estimated, actual, 1.5);
    }

    // ── Clone chain / shared COW tests ────────────────────────────────────

    #[test]
    fn clone_chain_shared_cow() {
        // State A cloned from base, mutated.
        // State B cloned from A, mutated further.
        // Verify that B's differential relative to base includes both A's and B's mutations.
        let n = 512;
        let base = make_altair_state(n, Slot::new(1));

        // State A: modify first half of balances
        let mut state_a = base.clone();
        for i in 0..n / 2 {
            *state_a.balances_mut().get_mut(i).unwrap() += 1;
        }
        state_a.apply_pending_mutations().unwrap();

        // State B: clone A, modify second half of balances
        let mut state_b = state_a.clone();
        for i in n / 2..n {
            *state_b.balances_mut().get_mut(i).unwrap() += 1;
        }
        state_b.apply_pending_mutations().unwrap();

        // B's cost relative to base should be ~full (all balances dirty)
        let b_vs_base = field_differential(base.balances(), state_b.balances());
        // B's cost relative to A should be ~half (only second half dirty)
        let b_vs_a = field_differential(state_a.balances(), state_b.balances());
        // A's cost relative to base should be ~half
        let a_vs_base = field_differential(base.balances(), state_a.balances());

        eprintln!("clone_chain: a_vs_base={a_vs_base}, b_vs_a={b_vs_a}, b_vs_base={b_vs_base}");
        // B vs base should be >= A vs base (B has all A's mutations plus its own)
        assert!(
            b_vs_base >= a_vs_base,
            "B's cost vs base ({b_vs_base}) should be >= A's cost vs base ({a_vs_base})"
        );
        // The key property: B's cost vs base < A's + B_vs_A because they share COW nodes
        // (A's mutations are shared, not duplicated)
        assert!(
            b_vs_base <= a_vs_base + b_vs_a,
            "B vs base shouldn't exceed sum of parts"
        );
    }

    #[test]
    fn prune_intermediate_state() {
        // After dropping state A, state B's total_size (not differential) should remain the same.
        // The MemoryTracker sees all of B's nodes regardless of whether A exists.
        let n = 512;
        let base = make_altair_state(n, Slot::new(1));

        let mut state_a = base.clone();
        for i in 0..n / 2 {
            *state_a.balances_mut().get_mut(i).unwrap() += 1;
        }
        state_a.apply_pending_mutations().unwrap();

        let mut state_b = state_a.clone();
        for i in n / 2..n {
            *state_b.balances_mut().get_mut(i).unwrap() += 1;
        }
        state_b.apply_pending_mutations().unwrap();

        // Measure B's total size while A is alive
        let b_total_with_a = {
            let mut t = MemoryTracker::default();
            t.track_item(state_b.balances()).total_size
        };

        // Drop A
        drop(state_a);

        // Measure B's total size after A is dropped — should be identical
        let b_total_without_a = {
            let mut t = MemoryTracker::default();
            t.track_item(state_b.balances()).total_size
        };

        eprintln!("prune: b_total_with_a={b_total_with_a}, b_total_without_a={b_total_without_a}");
        assert_eq!(
            b_total_with_a, b_total_without_a,
            "B's total_size should not change when A is dropped"
        );
    }

    #[test]
    fn prune_shared_base_differential_increases() {
        // When base is dropped, derived's differential relative to nothing is its full size.
        // This demonstrates the "pruning hazard": if the only state sharing nodes with B is
        // the finalized state, and we measure B's differential against finalized, it's small.
        // But if finalized is updated (rebased), B's differential could be large.
        let n = 512;
        let base = make_altair_state(n, Slot::new(1));

        let mut derived = base.clone();
        *derived.balances_mut().get_mut(0).unwrap() += 1;
        derived.apply_pending_mutations().unwrap();

        // Differential with base tracked = small (only 1 dirty path)
        let diff_with_base = field_differential(base.balances(), derived.balances());

        // Total size = everything (no sharing baseline)
        let total = {
            let mut t = MemoryTracker::default();
            t.track_item(derived.balances()).total_size
        };

        eprintln!(
            "prune_hazard: diff_with_base={diff_with_base}, total={total}, ratio={:.1}x",
            total as f64 / diff_with_base as f64
        );
        // Total should be much larger than the marginal differential
        assert!(
            total > diff_with_base * 5,
            "total ({total}) should be much larger than marginal diff ({diff_with_base})"
        );
    }

    #[test]
    fn two_states_same_slot_independent_cow() {
        // Two states at the same slot (e.g. pending vs full payload) independently cloned from
        // base. Both mutate the same indices but with different values. Their COW'd nodes are
        // completely independent — no sharing between A and B.
        //
        // When measured together (track base, then A, then B), B's differential is 0 for the
        // shared base but full for its own COW'd paths (same as A's).
        //
        // estimated_marginal_bytes counts each independently = 2x cost. This is correct
        // because each state independently owns its COW'd nodes.
        let n = 1024;
        let base = make_altair_state(n, Slot::new(1));

        let mut state_a = base.clone();
        *state_a.balances_mut().get_mut(0).unwrap() += 1;
        *state_a.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x01);
        state_a.apply_pending_mutations().unwrap();

        let mut state_b = base.clone();
        *state_b.balances_mut().get_mut(0).unwrap() += 2;
        *state_b.state_roots_mut().get_mut(0).unwrap() = Hash256::repeat_byte(0x02);
        state_b.apply_pending_mutations().unwrap();

        // Measure combined: track base, then A, then B
        let mut tracker = MemoryTracker::default();
        tracker.track_item(base.balances());
        tracker.track_item(base.state_roots());
        tracker.track_item(base.block_roots());
        tracker.track_item(base.randao_mixes());
        let a_bal = tracker.track_item(state_a.balances()).differential_size;
        tracker.track_item(state_a.state_roots());
        let b_bal = tracker.track_item(state_b.balances()).differential_size;
        tracker.track_item(state_b.state_roots());

        eprintln!("same_slot: a_bal_diff={a_bal}, b_bal_diff={b_bal}");
        // Both should have non-zero differential (independent COW'd paths)
        assert!(a_bal > 0, "A should have non-zero balance diff");
        assert!(b_bal > 0, "B should have non-zero balance diff");
        // Both get the same estimate (same slot position)
        let est_a = estimated_marginal_bytes::<E>(&state_a);
        let est_b = estimated_marginal_bytes::<E>(&state_b);
        assert_eq!(est_a, est_b, "same-slot states get identical estimates");
    }

    // ── Multi-slot accumulation ───────────────────────────────────────────

    #[test]
    fn multi_slot_accumulation() {
        // Simulate several mid-epoch slots accumulating mutations.
        // The estimate for a later slot should be >= actual (even with accumulated changes).
        let n = 512;
        let slots_per_epoch = E::slots_per_epoch();
        let base = make_altair_state(n, Slot::new(0));
        let mut state = base.clone();

        // Simulate 4 mid-epoch slots
        for s in 0..4.min(slots_per_epoch) {
            // Each slot: 1 proposer reward, ~128 participation, 1 root, 1 randao
            *state.balances_mut().get_mut(s as usize).unwrap() += 1;
            for i in 0..128.min(n) {
                state
                    .current_epoch_participation_mut()
                    .unwrap()
                    .get_mut(i)
                    .unwrap()
                    .add_flag(0)
                    .ok(); // ok if flag already set
            }
            let root_idx = s as usize % E::slots_per_historical_root();
            *state.state_roots_mut().get_mut(root_idx).unwrap() = Hash256::repeat_byte(s as u8 + 1);
            *state.block_roots_mut().get_mut(root_idx).unwrap() =
                Hash256::repeat_byte(s as u8 + 0x10);
            let randao_idx = s as usize % E::epochs_per_historical_vector();
            *state.randao_mixes_mut().get_mut(randao_idx).unwrap() =
                Hash256::repeat_byte(s as u8 + 0x20);
        }
        state.apply_pending_mutations().unwrap();

        let actual = measure_actual_differential_bytes(&base, &state);
        let estimated = estimated_marginal_bytes::<E>(&state);
        assert_upper_bound("multi_slot(4 slots)", estimated, actual, 8.0);
    }

    // ── Real epoch transition ─────────────────────────────────────────────

    #[test]
    fn real_epoch_transition() {
        use state_processing::per_slot_processing;
        use types::ChainSpec;

        let mut spec = ChainSpec::minimal();
        // Start at Altair so we have participation lists and inactivity scores.
        spec.altair_fork_epoch = Some(Epoch::new(0));
        let n = 64;
        let slots_per_epoch = E::slots_per_epoch();

        // Build a valid genesis state with committee caches.
        let keypairs = types::test_utils::generate_deterministic_keypairs(n);
        let mut state = genesis::interop_genesis_state::<E>(
            &keypairs,
            1_567_552_690,
            Hash256::repeat_byte(0x42),
            None,
            &spec,
        )
        .unwrap();
        state.build_caches(&spec).unwrap();
        state.apply_pending_mutations().unwrap();

        let base = state.clone();

        // Advance through a full epoch to the epoch boundary.
        for _ in 0..slots_per_epoch {
            per_slot_processing(&mut state, None, &spec).unwrap();
        }
        state.apply_pending_mutations().unwrap();

        assert_eq!(
            state.slot() % slots_per_epoch,
            0,
            "should be at epoch boundary"
        );

        let actual = measure_actual_differential_bytes(&base, &state);
        let estimated = estimated_marginal_bytes::<E>(&state);
        // The ratio is higher than the simulated epoch_boundary test because
        // per_slot_processing without blocks produces no attestation rewards, so
        // balances and inactivity scores are unchanged — but the estimate assumes
        // they're all dirty (the normal case with active validators).
        assert_upper_bound("real_epoch_transition", estimated, actual, 3.5);
    }
}
