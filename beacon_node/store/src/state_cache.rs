use crate::hdiff::HDiffBuffer;
use crate::{
    Error,
    metrics::{self, HOT_METRIC},
};
use lru::LruCache;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use tracing::instrument;
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, Slot, execution::StatePayloadStatus};

/// Fraction of the LRU cache to leave intact during culling.
const CULL_EXEMPT_NUMERATOR: usize = 1;
const CULL_EXEMPT_DENOMINATOR: usize = 10;

/// States that are less than or equal to this many epochs old *could* become finalized and will not
/// be culled from the cache.
const EPOCH_FINALIZATION_LIMIT: u64 = 4;

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

        // Measure base size for states loaded from disk or genesis (empty list).
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

        // NOTE: we do NOT recompute exact costs here because cached states still share
        // tree nodes with the OLD finalized state, not this new one. cow_bytes_between
        // against the new finalized would see completely different trees and overcount
        // massively. The slow-path recomputation needs a mechanism to know which base
        // each cached state actually shares with — a future improvement.

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

        // Fast path: check byte budget using approximate segment-based total.
        // This may overcount (segments accumulate from repeated mutations to the same
        // path), but overcounting is safe — it triggers eviction earlier, never too late.
        // The slow path in update_finalized_state corrects the overcount periodically.
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
        // Record segment counts per state for observability.
        if let Some(ref fin) = self.finalized_state {
            metrics::observe(
                &metrics::STORE_BEACON_STATE_CACHE_SEGMENT_COUNT,
                fin.state.approx_owned_bytes().0.len() as f64,
            );
        }
        for (_, (_, state)) in self.states.iter() {
            metrics::observe(
                &metrics::STORE_BEACON_STATE_CACHE_SEGMENT_COUNT,
                state.approx_owned_bytes().0.len() as f64,
            );
        }

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
    use milhouse::List;
    use ssz_types::BitVector;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use types::state::*;
    use types::*;

    type E = MinimalEthSpec;

    fn make_test_validator() -> Validator {
        Validator {
            pubkey: bls::PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::ZERO,
            effective_balance: 32_000_000_000,
            slashed: false,
            activation_eligibility_epoch: Epoch::new(0),
            activation_epoch: Epoch::new(0),
            exit_epoch: Epoch::new(u64::MAX),
            withdrawable_epoch: Epoch::new(u64::MAX),
        }
    }

    fn make_altair_state(n: usize, slot: Slot) -> BeaconState<E> {
        let validators = List::new(vec![make_test_validator(); n]).unwrap();
        let balances = List::new(vec![32_000_000_000u64; n]).unwrap();
        let inactivity_scores = List::new(vec![0u64; n]).unwrap();
        let participation = List::new(vec![ParticipationFlags::default(); n]).unwrap();
        let default_cc = Arc::new(CommitteeCache::default());
        let sync = Arc::new(SyncCommittee::temporary());

        BeaconState::Altair(BeaconStateAltair {
            genesis_time: 0,
            genesis_validators_root: Hash256::ZERO,
            slot,
            fork: Fork::default(),
            latest_block_header: BeaconBlockHeader::empty(),
            block_roots: milhouse::Vector::default(),
            state_roots: milhouse::Vector::default(),
            historical_roots: List::default(),
            eth1_data: Eth1Data::default(),
            eth1_data_votes: List::default(),
            eth1_deposit_index: 0,
            validators,
            balances,
            randao_mixes: milhouse::Vector::default(),
            slashings: milhouse::Vector::default(),
            previous_epoch_participation: participation.clone(),
            current_epoch_participation: participation,
            justification_bits: BitVector::new(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            inactivity_scores,
            current_sync_committee: sync.clone(),
            next_sync_committee: sync,
            total_active_balance: None,
            progressive_balances_cache: ProgressiveBalancesCache::default(),
            committee_caches: [default_cc.clone(), default_cc.clone(), default_cc],
            pubkey_cache: PubkeyCache::default(),
            exit_cache: ExitCache::default(),
            slashings_cache: SlashingsCache::default(),
            epoch_cache: EpochCache::default(),
            approx_owned_bytes: ApproxOwnedBytesList::default(),
        })
    }

    fn hash(byte: u8) -> Hash256 {
        Hash256::repeat_byte(byte)
    }

    fn new_cache(capacity: usize, max_bytes: Option<usize>) -> StateCache<E> {
        StateCache::new(
            NonZeroUsize::new(capacity).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            max_bytes,
        )
    }
    // ── cow_bytes_between tests ──────────────────────────────────────────

    #[test]
    fn cow_bytes_clone_is_zero() {
        let state = make_altair_state(256, Slot::new(1));
        let clone = state.clone();
        assert_eq!(cow_bytes_between(&state, &clone), 0);
    }

    #[test]
    fn cow_bytes_single_mutation() {
        let base = make_altair_state(256, Slot::new(1));
        let mut derived = base.clone();
        *derived.balances_mut().get_mut(0).unwrap() += 1;
        derived.apply_pending_mutations().unwrap();

        let cow = cow_bytes_between(&base, &derived);
        assert!(cow > 0, "single mutation should produce non-zero cow_bytes");
    }

    #[test]
    fn cow_bytes_epoch_boundary_mutations() {
        let n = 256;
        let base = make_altair_state(n, Slot::new(8));
        let mut derived = base.clone();

        // Simulate epoch: all balances + inactivity + participation replaced
        for i in 0..n {
            *derived.balances_mut().get_mut(i).unwrap() += 1;
        }
        for i in 0..n {
            *derived.inactivity_scores_mut().unwrap().get_mut(i).unwrap() += 1;
        }
        *derived.previous_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        *derived.current_epoch_participation_mut().unwrap() =
            List::new(vec![ParticipationFlags::default(); n]).unwrap();
        derived.apply_pending_mutations().unwrap();

        let cow = cow_bytes_between(&base, &derived);
        // Should be substantial — most of the tree is dirty
        assert!(
            cow > 10_000,
            "epoch boundary should produce significant cow_bytes: {cow}"
        );
    }

    // ── total_state_tree_bytes tests ──────────────────────────────────────

    #[test]
    fn total_tree_bytes_nonzero() {
        let state = make_altair_state(256, Slot::new(0));
        let total = total_state_tree_bytes(&state);
        // 256 validators × various fields, should be in the tens of KB
        assert!(total > 10_000, "total tree bytes should be > 10KB: {total}");
    }

    #[test]
    fn total_tree_bytes_scales_with_validators() {
        let small = total_state_tree_bytes(&make_altair_state(64, Slot::new(0)));
        let large = total_state_tree_bytes(&make_altair_state(1024, Slot::new(0)));
        assert!(
            large > small * 4,
            "1024 validators should be > 4x of 64: small={small}, large={large}"
        );
    }

    // ── ApproxOwnedBytesList deduplication tests ──────────────────────────

    #[test]
    fn approx_owned_bytes_dedup_across_clones() {
        let mut base = ApproxOwnedBytesList::default();
        base.push(1000);

        let mut s1 = base.clone();
        s1.push(100);

        let mut s2 = base.clone();
        s2.push(200);

        // Unique segments: base(1000) + s1(100) + s2(200) = 1300
        let total = sum_approx_owned_bytes([&base, &s1, &s2].into_iter());
        assert_eq!(total, 1300);
    }

    // ── StateCache integration tests ──────────────────────────────────────

    #[test]
    fn finalized_state_gets_base_size() {
        let mut cache = new_cache(10, None);
        let state = make_altair_state(256, Slot::new(0));
        let state_root = hash(1);

        cache
            .update_finalized_state(state_root, hash(2), state, &[])
            .unwrap();

        let total = cache.total_approx_owned_bytes();
        assert!(
            total > 0,
            "finalized state should have non-zero total: {total}"
        );
    }

    #[test]
    fn put_state_adds_to_total() {
        let mut cache = new_cache(10, None);

        // Set finalized
        let fin = make_altair_state(64, Slot::new(0));
        cache
            .update_finalized_state(hash(1), hash(2), fin, &[])
            .unwrap();
        cache.update_head_block_root(hash(10));

        let total_before = cache.total_approx_owned_bytes();

        // Insert a state with some COW mutations
        let mut state = cache.get_by_state_root(hash(1)).unwrap();
        *state.slot_mut() = Slot::new(1);
        *state.balances_mut().get_mut(0).unwrap() += 1;
        state.apply_pending_mutations().unwrap();
        // Push a cow segment to simulate what per_slot_processing does
        let cow = cow_bytes_between(&cache.get_by_state_root(hash(1)).unwrap(), &state);
        state.approx_owned_bytes_mut().push(cow);

        cache.put_state(hash(3), hash(10), &state).unwrap();

        let total_after = cache.total_approx_owned_bytes();
        assert!(
            total_after >= total_before,
            "total should not decrease after adding state: before={total_before}, after={total_after}"
        );
    }

    #[test]
    fn byte_budget_eviction() {
        let fin = make_altair_state(64, Slot::new(0));
        let base_size = total_state_tree_bytes(&fin);

        // Set a very tight budget: just the finalized base. Any inserted state should
        // trigger eviction attempts.
        let mut cache = new_cache(10, Some(base_size));
        cache
            .update_finalized_state(hash(1), hash(2), fin, &[])
            .unwrap();
        cache.update_head_block_root(hash(99));

        // Insert 5 states with different block roots (not head, so evictable)
        for i in 0u8..5 {
            let mut state = cache.get_by_state_root(hash(1)).unwrap();
            *state.slot_mut() = Slot::new(i as u64 + 1);
            *state.balances_mut().get_mut(i as usize).unwrap() += 1;
            state.apply_pending_mutations().unwrap();
            let cow = cow_bytes_between(&cache.get_by_state_root(hash(1)).unwrap(), &state);
            state.approx_owned_bytes_mut().push(cow);

            cache
                .put_state(hash(100 + i), hash(10 + i), &state)
                .unwrap();
        }

        // With a budget equal to base_size, the cache should have evicted most states.
        // It may keep 1-2 (exempt), but not all 5.
        assert!(
            cache.len() < 5,
            "eviction should have removed some states, but cache has {} states",
            cache.len()
        );
    }
}
