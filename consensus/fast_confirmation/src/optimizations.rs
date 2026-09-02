//! Performance optimizations for the Fast Confirmation Rule.
//!
//! Nothing here is a spec function; each item computes a spec-defined quantity (e.g. the
//! per-block `get_attestation_score`) via a faster algorithm. They are deliberately kept out of
//! `lib.rs` so that module reads as the spec algorithm.

use crate::primitives::{Checkpoint, Epoch, Hash256, SafeArith, Slot, Votes};
use crate::store::ForkChoiceStore;
use crate::{BalanceSourceData, Error};
use alloc::collections::BTreeSet;
use alloc::vec;
use core::cell::OnceCell;
use hashbrown::HashMap;

/// An observed-justified checkpoint paired with the balance snapshot anchored to it.
///
/// The fields are private and can only be set together through [`Self::new`], so the spec tracking
/// variable and its `get_*_balance_source` data cannot drift apart by accident. The balances carry
/// their own `checkpoint` (the one they were built for); [`Self::is_stale`] reports when that lags
/// the tracked `checkpoint` and a rebuild is due.
#[derive(Clone, Debug)]
pub struct CheckpointAndBalance {
    checkpoint: Checkpoint,
    balances: BalanceSourceData,
}

impl CheckpointAndBalance {
    #[inline]
    pub fn new(checkpoint: Checkpoint, balances: BalanceSourceData) -> Self {
        Self {
            checkpoint,
            balances,
        }
    }

    #[inline]
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    #[inline]
    pub fn balances(&self) -> &BalanceSourceData {
        &self.balances
    }
}

/// Cached implementation of the spec's `get_attestation_score`.
///
/// The Python spec computes `get_attestation_score(store, node, balance_source)` independently
/// for each candidate block. Lighthouse computes the same scores for a canonical chain segment in
/// one pass and then serves individual `get_attestation_score` calls from this cache.
pub(crate) struct AttestationScoreCache {
    scores: RootBalanceMap<Hash256>,
}

impl AttestationScoreCache {
    pub(crate) fn for_chain<V: Votes + ?Sized>(
        proto_array: &dyn ForkChoiceStore,
        chain: &[Hash256],
        terminal_slot: Slot,
        balance_source: &BalanceSourceData,
        votes: &V,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            scores: precompute_chain_attestation_scores(
                proto_array,
                chain,
                terminal_slot,
                balance_source,
                votes,
                equivocating_indices,
            )?,
        })
    }

    #[inline]
    pub(crate) fn get_attestation_score(&self, block_root: Hash256) -> Option<u64> {
        self.scores.get(&block_root)
    }
}

/// Memoizes one O(V) `compute_honest_ffg_support` sweep so both FFG predicates can share it within
/// a single `get_latest_confirmed` call. The cache owns no FCR logic; callers provide the spec
/// computation as a closure.
pub(crate) struct HonestFfgSupportCache {
    support: OnceCell<u64>,
}

impl HonestFfgSupportCache {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            support: OnceCell::new(),
        }
    }

    #[inline]
    pub(crate) fn get_or_compute(
        &self,
        compute: impl FnOnce() -> Result<u64, Error>,
    ) -> Result<u64, Error> {
        if let Some(support) = self.support.get() {
            return Ok(*support);
        }
        let support = compute()?;
        let _ = self.support.set(support);
        Ok(support)
    }
}

/// Identity hasher for `u64` keys derived from block-root byte prefixes.
///
/// The aggregation and projection maps below already store/compare the full key, so the prefix only
/// chooses a bucket. Avoiding SipHash over 32-byte roots matters in the same per-validator loops that
/// dominate the 1M-validator FCR benchmarks.
#[derive(Default)]
pub struct IdentityU64Hasher(u64);
impl core::hash::Hasher for IdentityU64Hasher {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline(always)]
    fn write(&mut self, _: &[u8]) {}
    #[inline(always)]
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

/// First 8 bytes of a block root as a `u64` (roots are uniformly distributed, so this is a good
/// hash). The stored full key disambiguates the (2⁻⁶⁴) prefix collision.
fn root_prefix(root: &Hash256) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&root.as_slice()[..8]);
    u64::from_le_bytes(bytes)
}

/// A key that can be hashed cheaply from the block root it contains.
pub trait RootKey: Copy + Eq {
    fn prefix_hash(&self) -> u64;
}

impl RootKey for Hash256 {
    fn prefix_hash(&self) -> u64 {
        root_prefix(self)
    }
}

impl RootKey for (Hash256, Epoch) {
    fn prefix_hash(&self) -> u64 {
        root_prefix(&self.0) ^ self.1.as_u64()
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PrefixKey<K: RootKey>(K);

impl<K: RootKey> core::hash::Hash for PrefixKey<K> {
    #[inline(always)]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.0.prefix_hash());
    }
}

/// Aggregates validator balances by vote key before running expensive per-key work.
///
/// This intentionally changes the shape of the spec's per-validator loops, but not the result:
/// summing balances before projection/checkpoint lookup is equivalent to summing matching
/// validators after lookup, and avoids repeating the same ancestor walk for every validator with
/// the same latest message.
pub struct RootBalanceMap<K: RootKey> {
    map: HashMap<PrefixKey<K>, u64, core::hash::BuildHasherDefault<IdentityU64Hasher>>,
}

impl<K: RootKey> Default for RootBalanceMap<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: RootKey> RootBalanceMap<K> {
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }

    pub fn add(&mut self, key: K, balance: u64) -> Result<(), Error> {
        self.map
            .entry(PrefixKey(key))
            .or_insert(0)
            .safe_add_assign(balance)?;
        Ok(())
    }

    pub fn insert(&mut self, key: K, value: u64) {
        self.map.insert(PrefixKey(key), value);
    }

    pub fn get(&self, key: &K) -> Option<u64> {
        self.map.get(&PrefixKey(*key)).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (K, u64)> + '_ {
        self.map.iter().map(|(key, &balance)| (key.0, balance))
    }
}

/// Projects a vote root onto the canonical chain segment: the deepest segment position the vote
/// descends from (the deepest block it "covers"). An off-segment vote walks up its ancestors until
/// it rejoins the segment; a vote deeper than the tip resolves to the tip; a vote touching only
/// blocks at/below the terminal resolves to `None`.
///
/// ```text
///   segment (terminal T excluded), positions A=0, B=1, C=2 (C = tip):
///
///       Z ── T ── [ A ── B ── C ] ── D
///                        \
///                         X ── Y   (X ── Y = side branch off B; D = child of tip C)
///
///   project(C) -> 2     C is on the segment
///   project(Y) -> 1     walk Y → X → B; B is the deepest on-segment ancestor
///   project(D) -> 2     D (deeper than the tip) walks up to the tip C
///   project(Z) -> None  Z is below the terminal T; covers nothing on the segment
/// ```
struct ChainProjector<'a> {
    proto_array: &'a dyn ForkChoiceStore,
    /// block root → position on the canonical chain segment.
    root_to_position: RootBalanceMap<Hash256>,
    terminal_slot: Slot,
}

impl<'a> ChainProjector<'a> {
    fn new(proto_array: &'a dyn ForkChoiceStore, chain: &[Hash256], terminal_slot: Slot) -> Self {
        let mut root_to_position = RootBalanceMap::new();
        for (pos, root) in chain.iter().enumerate() {
            root_to_position.insert(*root, pos as u64);
        }
        Self {
            proto_array,
            root_to_position,
            terminal_slot,
        }
    }

    /// The deepest canonical position `vote_root` descends from, or `None` if it covers no block
    /// on the segment.
    #[inline]
    fn project(&self, vote_root: Hash256) -> Option<usize> {
        let mut root = vote_root;
        loop {
            if let Some(pos) = self.root_to_position.get(&root) {
                return Some(pos as usize);
            }
            let (slot, parent) = self.proto_array.slot_and_parent(root)?;
            if slot <= self.terminal_slot {
                break;
            }
            root = parent?;
        }
        None
    }
}

/// Precompute the per-block attestation score (spec's `get_attestation_score`) for every block on
/// `chain`, ordered `terminal_root`-exclusive .. `chain_tip`-inclusive, with `terminal_slot` the
/// terminal's slot.
///
/// One pass in place of B separate O(V × depth) `get_attestation_score` calls. Pure optimization —
/// not a spec function.
pub fn precompute_chain_attestation_scores<V: Votes + ?Sized>(
    proto_array: &dyn ForkChoiceStore,
    chain: &[Hash256],
    terminal_slot: Slot,
    balance_source: &BalanceSourceData,
    votes: &V,
    equivocating_indices: &BTreeSet<u64>,
) -> Result<RootBalanceMap<Hash256>, Error> {
    let vote_balances = aggregate_vote_balances(balance_source, votes, equivocating_indices)?;

    // Charge each vote root's balance to the deepest chain block it covers, then suffix-sum so every
    // block inherits its descendants' weight — one O(V × depth) pass instead of B ancestor walks.
    let chain_len = chain.len();
    let mut score_at_position = vec![0u64; chain_len];
    let projector = ChainProjector::new(proto_array, chain, terminal_slot);

    for (vote_root, balance) in vote_balances.iter() {
        let Some(pos) = projector.project(vote_root) else {
            continue;
        };
        let score = score_at_position
            .get_mut(pos)
            .ok_or(Error::IndexOutOfBounds(pos))?;
        *score = score.safe_add(balance)?;
    }

    // Suffix sum: a vote covering position j also covers all ancestors at positions 0..j.
    let mut scores = RootBalanceMap::new();
    let mut running = 0u64;
    for i in (0..chain_len).rev() {
        running = running.safe_add(score_at_position[i])?;
        scores.insert(chain[i], running);
    }
    Ok(scores)
}

/// Sum unslashed balances by LMD vote root (skipping zero and equivocating votes), so the ancestor
/// projection runs once per distinct root rather than once per validator.
pub(crate) fn aggregate_vote_balances<V: Votes + ?Sized>(
    balance_source: &BalanceSourceData,
    votes: &V,
    equivocating_indices: &BTreeSet<u64>,
) -> Result<RootBalanceMap<Hash256>, Error> {
    let mut balance_by_vote_root = RootBalanceMap::<Hash256>::new();

    // Walk the active set and read a vote only for a validator that can count:
    // `Votes::get` copies the vote out of the host's storage.
    for (val_idx, balance) in balance_source.unslashed_and_active_indices() {
        if equivocating_indices.contains(&(val_idx as u64)) {
            continue;
        }
        let Some(vote_root) = votes.current_root(val_idx) else {
            continue;
        };
        if vote_root.is_zero() {
            continue;
        }
        balance_by_vote_root.add(vote_root, balance)?;
    }

    Ok(balance_by_vote_root)
}
