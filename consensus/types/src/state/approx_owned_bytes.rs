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
    let mut total = 0;
    for list in states {
        for entry in &list.0 {
            if seen.insert(Arc::as_ptr(entry)) {
                total += entry.bytes;
            }
        }
    }
    total
}

/// Snapshot of a `BeaconState`'s tree roots before a transition.
///
/// Used to measure the bytes of new tree nodes produced by a slot or block transition.
/// After the transition, call `approx_owned_bytes` to get the delta.
///
/// TODO: implement actual pairwise tree walk in milhouse. Currently returns 0.
pub struct TreeSnapshot {
    _private: (),
}

impl TreeSnapshot {
    /// Capture tree root pointers from the pre-transition state.
    pub fn new<E: EthSpec>(_state: &BeaconState<E>) -> Self {
        // TODO: capture Arc<Tree<T>> root pointers for each tree-backed field.
        // When milhouse exposes a pairwise diff, store the roots here.
        TreeSnapshot { _private: () }
    }

    /// Measure the bytes of new tree nodes produced since the snapshot was taken.
    pub fn approx_owned_bytes<E: EthSpec>(self, _state: &BeaconState<E>) -> usize {
        // TODO: for each tree-backed field, compare old root vs new root using
        // milhouse's pairwise tree walk. Sum the divergent node bytes.
        0
    }
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
