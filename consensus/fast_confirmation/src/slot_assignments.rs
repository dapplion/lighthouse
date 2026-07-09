//! Committee slot assignments for the Fast Confirmation Rule, resolved on demand from the
//! committee-cache shufflings covering the `[current-2 ..= current+1]` epoch window.

use crate::Error;
use safe_arith::SafeArith;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use types::{BeaconState, CommitteeCache, Epoch, EthSpec, Hash256, RelativeEpoch, Slot};

/// Epochs covered, oldest to newest: `[current-2, current-1, current, current+1]`.
const WINDOW: usize = 4;

/// Committee assignments over the FCR epoch window. Shufflings are keyed by their dependent root,
/// so a rebuild reuses the ones already held (notably `current-2`, which was `current-1` last
/// epoch) instead of recomputing them.
#[derive(Clone, Debug)]
pub(crate) struct SlotAssignments {
    /// Shufflings for the readable window epochs, keyed by dependent root so a rebuild reuses them.
    cache: HashMap<Hash256, Arc<CommitteeCache>>,
    /// `(shuffling, epoch_start_slot)` per window epoch; `None` when the shuffling isn't yet held
    /// (e.g. `current-2` right after a cold start).
    window: [(Option<Arc<CommitteeCache>>, Slot); WINDOW],
    dependent_root: Hash256,
}

impl SlotAssignments {
    pub(crate) fn new<E: EthSpec>(state: &BeaconState<E>) -> Result<Self, Error> {
        let mut assignments = Self {
            cache: HashMap::new(),
            window: std::array::from_fn(|_| (None, Slot::new(0))),
            dependent_root: Hash256::ZERO,
        };
        assignments.rebuild(state)?;
        Ok(assignments)
    }

    /// Refresh the window for `state`'s current epoch, fetching only shufflings not already held.
    pub(crate) fn rebuild<E: EthSpec>(&mut self, state: &BeaconState<E>) -> Result<(), Error> {
        let spe = E::slots_per_epoch();
        let current = state.current_epoch();

        // The previous/current shufflings have readable dependent roots; cache them for reuse.
        for relative in [RelativeEpoch::Previous, RelativeEpoch::Current] {
            let root = crate::dependent_root::<E>(state, relative.into_epoch(current))?;
            if let Entry::Vacant(entry) = self.cache.entry(root) {
                entry.insert(committee_cache(state, relative)?);
            }
        }
        // The next epoch's decision root isn't readable yet, so fetch it fresh each rebuild.
        let next = committee_cache(state, RelativeEpoch::Next)?;

        let mut window: [(Option<Arc<CommitteeCache>>, Slot); WINDOW] =
            std::array::from_fn(|_| (None, Slot::new(0)));
        let mut live = HashSet::new();
        for (slot, epoch) in window.iter_mut().zip([
            current.saturating_sub(Epoch::new(2)),
            current.saturating_sub(Epoch::new(1)),
            current,
        ]) {
            let root = crate::dependent_root::<E>(state, epoch)?;
            live.insert(root);
            *slot = (self.cache.get(&root).cloned(), epoch.start_slot(spe));
        }
        window[WINDOW - 1] = (Some(next), current.safe_add(1)?.start_slot(spe));

        self.window = window;
        self.dependent_root = crate::dependent_root::<E>(state, current)?;
        self.cache.retain(|root, _| live.contains(root));
        Ok(())
    }

    pub(crate) fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    /// True if `val_idx` attests in any window epoch at a slot within `[start, end]`.
    pub(crate) fn is_in_range(
        &self,
        val_idx: usize,
        start: Slot,
        end: Slot,
    ) -> Result<bool, Error> {
        for (cache, epoch_start) in &self.window {
            let Some(cache) = cache else { continue };
            if assigned_slot(cache, *epoch_start, val_idx)?
                .is_some_and(|slot| slot >= start && slot <= end)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn committee_cache<E: EthSpec>(
    state: &BeaconState<E>,
    relative: RelativeEpoch,
) -> Result<Arc<CommitteeCache>, Error> {
    Ok(state
        .committee_cache(relative)
        .map_err(|e| Error::CommitteeCacheUninitialized(format!("{e:?}")))?
        .clone())
}

/// The committee slot `val_idx` attests in for `cache`'s epoch, or `None` if it has no duty.
/// Inverts the spec's `compute_committee` position ranges: the committee for shuffled position `p`
/// is `(p * count + count - 1) / len`, mapped to a slot via `committees_per_slot`.
fn assigned_slot(
    cache: &CommitteeCache,
    epoch_start: Slot,
    val_idx: usize,
) -> Result<Option<Slot>, Error> {
    let Some(position) = cache.shuffled_position(val_idx) else {
        return Ok(None);
    };
    let total = cache.epoch_committee_count()?;
    let committee = position
        .safe_mul(total)?
        .safe_add(total.safe_sub(1)?)?
        .safe_div(cache.active_validator_count())?;
    let offset = committee.safe_div(cache.committees_per_slot() as usize)?;
    Ok(Some(epoch_start.safe_add(offset as u64)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use state_processing::per_slot_processing;
    use types::{MinimalEthSpec, Validator};

    type E = MinimalEthSpec;

    fn genesis_state(n: usize) -> (BeaconState<E>, types::ChainSpec) {
        let spec = E::default_spec();
        let mut state = BeaconState::new(0, Default::default(), &spec);
        for _ in 0..n {
            state
                .validators_mut()
                .push(Validator {
                    effective_balance: spec.max_effective_balance,
                    activation_epoch: Epoch::new(0),
                    exit_epoch: spec.far_future_epoch,
                    withdrawable_epoch: spec.far_future_epoch,
                    ..Default::default()
                })
                .expect("push validator");
            state
                .balances_mut()
                .push(spec.max_effective_balance)
                .expect("push balance");
        }
        state
            .build_all_committee_caches(&spec)
            .expect("committee caches");
        (state, spec)
    }

    fn advance_state(state: &mut BeaconState<E>, target: Slot, spec: &types::ChainSpec) {
        while state.slot() < target {
            per_slot_processing(state, None, spec).expect("advance slot");
        }
        state
            .build_all_committee_caches(spec)
            .expect("committee caches");
    }

    #[test]
    fn builds_from_genesis_state() {
        let (state, _) = genesis_state(64);
        SlotAssignments::new::<E>(&state).expect("builds from genesis state");
    }

    #[test]
    fn every_validator_attests_once_in_current_epoch() {
        let (mut state, spec) = genesis_state(64);
        let spe = E::slots_per_epoch();
        let start = Slot::new(spe * 2);
        advance_state(&mut state, start, &spec);
        let sa = SlotAssignments::new::<E>(&state).expect("build");

        let end = Slot::new(spe * 2 + spe - 1);
        for val_idx in 0..state.validators().len() {
            assert!(
                sa.is_in_range(val_idx, start, end).unwrap(),
                "validator {val_idx} missing epoch 2 assignment"
            );
        }
    }

    #[test]
    fn is_in_range_returns_false_for_uncovered_epochs() {
        let (state, _) = genesis_state(64);
        let sa = SlotAssignments::new::<E>(&state).expect("build");
        let far = Slot::new(E::slots_per_epoch() * 5);
        for val_idx in 0..state.validators().len() {
            assert!(!sa.is_in_range(val_idx, far, far).unwrap());
        }
    }
}
