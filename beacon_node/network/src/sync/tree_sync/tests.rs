//! Property tests for the one part of the forest that is pure: cutting a chain in two.
//!
//! `Chain::split_at` touches only `roots`, `state` and `peers` — no network, no fork
//! choice, no clock — so it can be driven directly over generated inputs. Every property
//! here is one the rest of the module assumes without checking.

use super::*;
use proptest::prelude::*;
use types::MainnetEthSpec;

type E = MainnetEthSpec;

/// Roots are only ever compared, so any distinct values will do.
fn root_at(index: usize) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    Hash256::from(bytes)
}

/// A run of ancestors tip first with strictly decreasing slots, which is the shape
/// `extend_chain` builds and every invariant downstream assumes. `gaps` makes the slots
/// non-contiguous, since skipped slots are normal.
fn ancestors(len: usize, gaps: &[u64]) -> VecDeque<BlockSummary> {
    let mut slot = 1_000_000u64;
    (0..len)
        .map(|index| {
            slot -= gaps.get(index).copied().unwrap_or(1).max(1);
            BlockSummary {
                block_root: root_at(index),
                slot: Slot::new(slot),
                has_data: index % 3 == 0,
                has_payload: index % 2 == 0,
            }
        })
        .collect()
}

fn chain(roots: VecDeque<BlockSummary>, state: ChainState<E>) -> Chain<E> {
    Chain {
        roots,
        failed_batches: 0,
        peers: Arc::new(RwLock::new(HashSet::from([PeerId::random()]))),
        state,
        last_progress: Instant::now(),
    }
}

/// The states that hold no block data. `AwaitingProcessing` needs real blocks and is
/// covered separately.
fn states(anchor: Hash256, next: Hash256) -> Vec<ChainState<E>> {
    vec![
        ChainState::Discovering {
            next,
            request: DownloadRequest::new(),
        },
        ChainState::Anchored(anchor),
        ChainState::ForwardSync(
            anchor,
            ForwardSyncState::Downloading(DownloadRequest::new()),
        ),
        ChainState::ForwardSync(anchor, ForwardSyncState::Processing),
    ]
}

fn slots_strictly_decrease(roots: &VecDeque<BlockSummary>) -> bool {
    roots
        .iter()
        .zip(roots.iter().skip(1))
        .all(|(newer, older)| older.slot < newer.slot)
}

proptest! {
    /// The halves partition the roots exactly, in order: `roots` is tip first, the newer
    /// half keeps `[tip..pivot)` and the older half `[pivot..oldest]`.
    #[test]
    fn split_partitions_roots_in_order(
        len in 2usize..40,
        pivot_index in 1usize..40,
        gaps in prop::collection::vec(1u64..5, 40),
    ) {
        prop_assume!(pivot_index < len);
        for state in states(root_at(len + 1), root_at(len + 2)) {
            let before = ancestors(len, &gaps);
            let mut older = chain(before.clone(), state);
            let newer = older.split_at(root_at(pivot_index)).unwrap().unwrap();

            let rejoined: VecDeque<BlockSummary> =
                newer.roots.iter().chain(older.roots.iter()).cloned().collect();
            prop_assert_eq!(&rejoined, &before, "halves must rejoin into the original");
            prop_assert_eq!(newer.roots.len(), pivot_index);
            prop_assert_eq!(older.roots.len(), len - pivot_index);
        }
    }

    /// Inv 3 survives the cut: `extend_chain` enforces decreasing slots on the way in, so
    /// splitting must not produce a half that breaks them.
    #[test]
    fn split_preserves_decreasing_slots(
        len in 2usize..40,
        pivot_index in 1usize..40,
        gaps in prop::collection::vec(1u64..5, 40),
    ) {
        prop_assume!(pivot_index < len);
        for state in states(root_at(len + 1), root_at(len + 2)) {
            let mut older = chain(ancestors(len, &gaps), state);
            let newer = older.split_at(root_at(pivot_index)).unwrap().unwrap();
            prop_assert!(slots_strictly_decrease(&newer.roots));
            prop_assert!(slots_strictly_decrease(&older.roots));
        }
    }

    /// The newer half waits on the pivot, whatever state it was cut from. A half anchored
    /// anywhere else waits on a root nothing will fetch.
    #[test]
    fn newer_half_anchors_on_the_pivot(
        len in 2usize..40,
        pivot_index in 1usize..40,
        gaps in prop::collection::vec(1u64..5, 40),
    ) {
        prop_assume!(pivot_index < len);
        for state in states(root_at(len + 1), root_at(len + 2)) {
            let mut older = chain(ancestors(len, &gaps), state);
            let newer = older.split_at(root_at(pivot_index)).unwrap().unwrap();
            prop_assert_eq!(newer.parent(), Some(root_at(pivot_index)));
        }
    }

    /// Cutting at the tip has nothing above it to cut off, and must leave the chain alone.
    #[test]
    fn split_at_the_tip_is_a_no_op(
        len in 1usize..40,
        gaps in prop::collection::vec(1u64..5, 40),
    ) {
        for state in states(root_at(len + 1), root_at(len + 2)) {
            let before = ancestors(len, &gaps);
            let mut chain = chain(before.clone(), state);
            prop_assert!(chain.split_at(root_at(0)).unwrap().is_none());
            prop_assert_eq!(&chain.roots, &before, "a no-op split must not mutate");
        }
    }

    /// A root the chain does not own is an internal error, and must not half-apply.
    #[test]
    fn split_at_an_unowned_root_errors_without_mutating(
        len in 1usize..40,
        gaps in prop::collection::vec(1u64..5, 40),
    ) {
        for state in states(root_at(len + 1), root_at(len + 2)) {
            let before = ancestors(len, &gaps);
            let mut chain = chain(before.clone(), state);
            prop_assert!(chain.split_at(Hash256::repeat_byte(0xff)).is_err());
            prop_assert_eq!(&chain.roots, &before, "a failed split must not mutate");
        }
    }

    /// Splitting repeatedly at arbitrary pivots never loses or duplicates a root. This is
    /// what `advance` does to a long chain, one batch at a time.
    #[test]
    fn repeated_splits_conserve_roots(
        len in 2usize..40,
        pivots in prop::collection::vec(1usize..40, 1..8),
        gaps in prop::collection::vec(1u64..5, 40),
    ) {
        let before = ancestors(len, &gaps);
        let mut halves = vec![chain(before.clone(), ChainState::Anchored(root_at(len + 1)))];

        for pivot_index in pivots {
            let mut split_off = vec![];
            for half in halves.iter_mut() {
                let owns = half.roots.iter().any(|b| b.block_root == root_at(pivot_index));
                if owns && let Some(newer) = half.split_at(root_at(pivot_index)).unwrap() {
                    split_off.push(newer);
                }
            }
            halves.extend(split_off);
        }

        let mut seen: Vec<Hash256> = halves
            .iter()
            .flat_map(|half| half.roots.iter().map(|b| b.block_root))
            .collect();
        let unique: HashSet<Hash256> = seen.iter().copied().collect();
        prop_assert_eq!(seen.len(), unique.len(), "a root ended up in two halves");
        seen.sort();
        let mut expected: Vec<Hash256> = before.iter().map(|b| b.block_root).collect();
        expected.sort();
        prop_assert_eq!(seen, expected, "roots lost or invented across splits");
        for half in &halves {
            prop_assert!(slots_strictly_decrease(&half.roots));
        }
    }
}
