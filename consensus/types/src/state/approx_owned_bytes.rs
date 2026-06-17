use crate::core::EthSpec;
use crate::state::BeaconState;
use std::collections::HashSet;
use std::sync::Arc;

/// Approximate bytes of tree memory owned by a group of states at a specific point —
/// either the base tree of a state loaded from disk, or the new COW nodes produced
/// by a state transition.
///
/// Identity is by `Arc` pointer — states sharing the same `Arc<ApproxOwnedBytes>`
/// inherited it from a common ancestor via clone.
#[derive(Debug)]
pub struct ApproxOwnedBytes {
    pub bytes: usize,
}

/// List of `ApproxOwnedBytes` carried on each `BeaconState`.
///
/// Each entry is a chunk of tree memory: the base tree (for states loaded from disk)
/// or new nodes from a transition. States that share ancestry share the same `Arc`
/// entries — clone copies the `Vec` but shares all `Arc` pointers.
///
/// `PartialEq` always returns true — memory tracking is not consensus-relevant.
#[derive(Clone, Debug, Default)]
pub struct ApproxOwnedBytesList(pub Vec<Arc<ApproxOwnedBytes>>);

impl PartialEq for ApproxOwnedBytesList {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl ApproxOwnedBytesList {
    pub fn push(&mut self, bytes: usize) {
        if bytes > 0 {
            self.0.push(Arc::new(ApproxOwnedBytes { bytes }));
        }
    }

    /// Replace with a base state's list plus an optional entry for unique bytes.
    ///
    /// Used after `rebase_on` to adopt the finalized state's entries and add the
    /// remaining unique cost.
    pub fn reset_to_base(&mut self, base: &ApproxOwnedBytesList, unique_bytes: usize) {
        self.0 = base.0.clone();
        if unique_bytes > 0 {
            self.0.push(Arc::new(ApproxOwnedBytes {
                bytes: unique_bytes,
            }));
        }
    }
}

/// Sum the unique `ApproxOwnedBytes` across multiple states.
///
/// Deduplicates by `Arc` pointer identity — shared entries are counted once.
pub fn sum_approx_owned_bytes<'a>(states: impl Iterator<Item = &'a ApproxOwnedBytesList>) -> usize {
    let mut seen = HashSet::new();
    let mut total: usize = 0;
    for list in states {
        for entry in &list.0 {
            if seen.insert(Arc::as_ptr(entry)) {
                total = total.saturating_add(entry.bytes);
            }
        }
    }
    total
}

/// Compute the COW bytes between two states across all tree-backed fields and caches.
///
/// IMPORTANT: this list must be kept in sync with `BeaconState::rebase_on` which uses
/// `bimap_beacon_state_*_tree_list_fields!` macros. When a new fork adds a tree-backed
/// field, add it here too.
///
/// NOTE: milhouse's `cow_bytes` uses `size_of::<T>()` for leaf data, which only counts
/// stack size. If a future leaf type has heap allocations (Vec, String, etc.), they won't
/// be counted. All current beacon state leaf types are fully inline, so this is correct today.
#[allow(clippy::arithmetic_side_effects)]
pub fn cow_bytes_between<E: EthSpec>(base: &BeaconState<E>, derived: &BeaconState<E>) -> usize {
    let mut total: usize = 0;

    // Tree-backed fields (common to all forks).
    total = total.saturating_add(derived.validators().cow_bytes(base.validators()));
    total = total.saturating_add(derived.balances().cow_bytes(base.balances()));
    total = total.saturating_add(derived.state_roots().cow_bytes(base.state_roots()));
    total = total.saturating_add(derived.block_roots().cow_bytes(base.block_roots()));
    total = total.saturating_add(derived.randao_mixes().cow_bytes(base.randao_mixes()));
    total = total.saturating_add(derived.slashings().cow_bytes(base.slashings()));
    total = total.saturating_add(derived.eth1_data_votes().cow_bytes(base.eth1_data_votes()));
    total = total.saturating_add(
        derived
            .historical_roots()
            .cow_bytes(base.historical_roots()),
    );

    // Altair+ fields.
    if let (Ok(d), Ok(b)) = (derived.inactivity_scores(), base.inactivity_scores()) {
        total = total.saturating_add(d.cow_bytes(b));
    }
    if let (Ok(d), Ok(b)) = (
        derived.previous_epoch_participation(),
        base.previous_epoch_participation(),
    ) {
        total = total.saturating_add(d.cow_bytes(b));
    }
    if let (Ok(d), Ok(b)) = (
        derived.current_epoch_participation(),
        base.current_epoch_participation(),
    ) {
        total = total.saturating_add(d.cow_bytes(b));
    }

    // Capella+ fields.
    if let (Ok(d), Ok(b)) = (derived.historical_summaries(), base.historical_summaries()) {
        total = total.saturating_add(d.cow_bytes(b));
    }

    // Electra+ fields.
    if let (Ok(d), Ok(b)) = (derived.pending_deposits(), base.pending_deposits()) {
        total = total.saturating_add(d.cow_bytes(b));
    }
    if let (Ok(d), Ok(b)) = (
        derived.pending_partial_withdrawals(),
        base.pending_partial_withdrawals(),
    ) {
        total = total.saturating_add(d.cow_bytes(b));
    }
    if let (Ok(d), Ok(b)) = (
        derived.pending_consolidations(),
        base.pending_consolidations(),
    ) {
        total = total.saturating_add(d.cow_bytes(b));
    }

    // Caches: count as COW if they point to different Arc allocations.
    for (d, b) in derived
        .committee_caches()
        .iter()
        .zip(base.committee_caches())
    {
        if !Arc::ptr_eq(d, b) {
            total = total.saturating_add(d.approx_heap_bytes());
        }
    }
    if let (Ok(d), Ok(b)) = (
        derived.current_sync_committee(),
        base.current_sync_committee(),
    ) && !Arc::ptr_eq(d, b)
    {
        total = total.saturating_add(std::mem::size_of_val(&**d));
    }
    if let (Ok(d), Ok(b)) = (derived.next_sync_committee(), base.next_sync_committee())
        && !Arc::ptr_eq(d, b)
    {
        total = total.saturating_add(std::mem::size_of_val(&**d));
    }

    total
}

/// Compute the total bytes for a state's tree-backed fields and caches (no sharing).
///
/// IMPORTANT: must be kept in sync with `cow_bytes_between`.
#[allow(clippy::arithmetic_side_effects)]
pub fn total_state_tree_bytes<E: EthSpec>(state: &BeaconState<E>) -> usize {
    let mut total: usize = 0;

    // Tree-backed fields.
    total = total.saturating_add(state.validators().total_tree_bytes());
    total = total.saturating_add(state.balances().total_tree_bytes());
    total = total.saturating_add(state.state_roots().total_tree_bytes());
    total = total.saturating_add(state.block_roots().total_tree_bytes());
    total = total.saturating_add(state.randao_mixes().total_tree_bytes());
    total = total.saturating_add(state.slashings().total_tree_bytes());
    total = total.saturating_add(state.eth1_data_votes().total_tree_bytes());
    total = total.saturating_add(state.historical_roots().total_tree_bytes());

    if let Ok(f) = state.inactivity_scores() {
        total = total.saturating_add(f.total_tree_bytes());
    }
    if let Ok(f) = state.previous_epoch_participation() {
        total = total.saturating_add(f.total_tree_bytes());
    }
    if let Ok(f) = state.current_epoch_participation() {
        total = total.saturating_add(f.total_tree_bytes());
    }
    if let Ok(f) = state.historical_summaries() {
        total = total.saturating_add(f.total_tree_bytes());
    }
    if let Ok(f) = state.pending_deposits() {
        total = total.saturating_add(f.total_tree_bytes());
    }
    if let Ok(f) = state.pending_partial_withdrawals() {
        total = total.saturating_add(f.total_tree_bytes());
    }
    if let Ok(f) = state.pending_consolidations() {
        total = total.saturating_add(f.total_tree_bytes());
    }

    // Caches.
    for cc in state.committee_caches() {
        total = total.saturating_add(cc.approx_heap_bytes());
    }
    if let Ok(sc) = state.current_sync_committee() {
        total = total.saturating_add(std::mem::size_of_val(&**sc));
    }
    if let Ok(sc) = state.next_sync_committee() {
        total = total.saturating_add(std::mem::size_of_val(&**sc));
    }

    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_topology() {
        let mut base = ApproxOwnedBytesList::default();
        base.push(500);

        let mut s1 = base.clone();
        s1.push(50);

        let mut s2 = base.clone();
        s2.push(80);

        assert_eq!(sum_approx_owned_bytes([&base, &s1, &s2].into_iter()), 630);
        assert_eq!(sum_approx_owned_bytes([&s1, &s2].into_iter()), 630);
    }

    #[test]
    fn chain_topology() {
        let mut f = ApproxOwnedBytesList::default();
        f.push(500);

        let mut a = f.clone();
        a.push(50);

        let mut b = a.clone();
        b.push(30);

        assert_eq!(sum_approx_owned_bytes([&f, &a, &b].into_iter()), 580);
        assert_eq!(sum_approx_owned_bytes([&b].into_iter()), 580);
    }

    #[test]
    fn rebase_resets() {
        let mut f = ApproxOwnedBytesList::default();
        f.push(500);

        let mut s = ApproxOwnedBytesList::default();
        s.push(999);
        s.push(10);

        s.reset_to_base(&f, 80);

        assert_eq!(sum_approx_owned_bytes([&f, &s].into_iter()), 580);
    }

    #[test]
    fn zero_bytes_not_pushed() {
        let mut s = ApproxOwnedBytesList::default();
        s.push(0);
        assert!(s.0.is_empty());
    }
}
