use crate::hdiff::HDiffBuffer;
use crate::{
    Error,
    metrics::{self, HOT_METRIC},
};
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use tracing::instrument;
use types::{
    BeaconState, ChainSpec, Epoch, EthSpec, Hash256, Slot, Validator, execution::StatePayloadStatus,
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

    // Validators: only mutated on activation/exit (rare). Negligible for estimation.
    let validators_dirty: usize = 0;

    // Fixed-size vectors: 1-2 leaves per slot, negligible but included for completeness.
    let roots_dirty: usize = 2; // state_roots + block_roots
    let randao_dirty: usize = 1;

    estimate_tree_bytes::<u64>(balances_dirty, n)
        + estimate_tree_bytes::<u64>(inactivity_dirty, n)
        // Two participation lists (previous + current), each List<u8, N>
        + 2 * estimate_tree_bytes::<u8>(participation_dirty, n)
        + estimate_tree_bytes::<Validator>(validators_dirty, n)
        + estimate_tree_bytes::<Hash256>(roots_dirty, E::slots_per_historical_root())
        + estimate_tree_bytes::<Hash256>(randao_dirty, E::epochs_per_historical_vector())
}

/// Estimate bytes consumed by COW'd nodes in a milhouse tree.
///
/// For sparse changes: each dirty leaf creates ~log2(total) new internal nodes along its path.
/// For fully-dirty trees: the entire tree is a fresh allocation (~2*total nodes).
/// The sparse formula overcounts for adjacent dirty leaves (shared internal paths) — this is
/// intentional as an upper bound (safe direction for eviction decisions).
fn estimate_tree_bytes<T>(dirty: usize, total: usize) -> usize {
    if dirty == 0 || total == 0 {
        return 0;
    }
    let node_size = std::mem::size_of::<T>();
    if dirty >= total {
        // Full tree copy: all leaves + all internal nodes ≈ 2*total
        2 * total * node_size
    } else {
        // Sparse: each dirty leaf COW's ~log2(total) internal nodes
        let depth = usize::BITS as u32 - total.leading_zeros();
        dirty * depth as usize * node_size
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
    /// Stores (state_root, state, estimated_marginal_bytes) per cached state.
    states: LruCache<Hash256, (Hash256, BeaconState<E>, usize)>,
    block_map: BlockMap,
    hdiff_buffers: HotHDiffBufferCache,
    max_epoch: Epoch,
    head_block_root: Hash256,
    headroom: NonZeroUsize,
    /// Sum of `estimated_marginal_bytes` across all cached states.
    cached_bytes: usize,
    /// Optional byte budget. When set, eviction triggers when `cached_bytes` exceeds this.
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
            cached_bytes: 0,
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

    /// Total estimated bytes consumed by cached states.
    pub fn cached_bytes(&self) -> usize {
        self.cached_bytes
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
        state: BeaconState<E>,
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
            if let Some((_, state, cost)) = self.states.pop(&state_root) {
                self.cached_bytes = self.cached_bytes.saturating_sub(cost);
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

        let cost = estimated_marginal_bytes::<E>(state);

        // If the cache is full (by count), use the custom cull routine to make room.
        let mut deleted_states =
            if let Some(over_capacity) = self.len().checked_sub(self.capacity()) {
                // The `over_capacity` should always be 0, but we add it here just in case.
                self.cull(over_capacity + self.headroom.get())
            } else {
                vec![]
            };

        // If adding this state would exceed the byte budget, cull until under budget.
        if let Some(max_bytes) = self.max_bytes {
            while self.cached_bytes.saturating_add(cost) > max_bytes && self.len() > 0 {
                let culled = self.cull(1);
                if culled.is_empty() {
                    // Nothing left to cull (all states are exempt).
                    break;
                }
                deleted_states.extend(culled);
            }
        }

        // Insert the full state into the cache.
        if let Some((deleted_state_root, _, old_cost)) = self
            .states
            .put(state_root, (state_root, state.clone(), cost))
        {
            self.cached_bytes = self.cached_bytes.saturating_sub(old_cost);
            deleted_states.push(deleted_state_root);
        }
        self.cached_bytes = self.cached_bytes.saturating_add(cost);

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
        self.states
            .get(&state_root)
            .map(|(_, state, _)| state.clone())
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
        if let Some((_, _, cost)) = self.states.pop(state_root) {
            self.cached_bytes = self.cached_bytes.saturating_sub(cost);
        }
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
                if let Some((_, _, cost)) = self.states.pop(state_root) {
                    self.cached_bytes = self.cached_bytes.saturating_sub(cost);
                }
            }
        }
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
        for (&state_root, (_, state, _)) in self.states.iter().skip(cull_exempt).rev() {
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
