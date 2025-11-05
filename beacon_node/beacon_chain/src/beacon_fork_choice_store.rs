//! Defines the `BeaconForkChoiceStore` which provides the persistent storage for the `ForkChoice`
//! struct.
//!
//! Additionally, the `BalancesCache` struct is defined; a cache designed to avoid database
//! reads when fork choice requires the validator balances of the justified state.

use crate::BeaconSnapshot;
use derivative::Derivative;
use fork_choice::{BalancesGetter, Error as ForkChoiceError};
use proto_array::JustifiedBalances;
use safe_arith::ArithError;
use ssz_derive::{Decode, Encode};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{Error as StoreError, HotColdDB, ItemStore};
use superstruct::superstruct;
use types::{
    BeaconState, BeaconStateError, Checkpoint, Epoch, EthSpec, FixedBytesExtended, Hash256, Slot,
};

#[derive(Debug)]
pub enum Error {
    FailedToReadBlock(StoreError),
    MissingBlock(Hash256),
    FailedToReadState(StoreError),
    MissingState(Hash256),
    BeaconStateError(BeaconStateError),
    UnalignedCheckpoint { block_slot: Slot, state_slot: Slot },
    Arith(ArithError),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::Arith(e)
    }
}

/// The number of validator balance sets that are cached within `BalancesCache`.
const MAX_BALANCE_CACHE_SIZE: usize = 4;

#[superstruct(
    variants(V8),
    variant_attributes(derive(PartialEq, Clone, Debug, Encode, Decode)),
    no_enum
)]
pub(crate) struct CacheItem {
    pub(crate) block_root: Hash256,
    pub(crate) epoch: Epoch,
    pub(crate) balances: Vec<u64>,
}

pub(crate) type CacheItem = CacheItemV8;

#[superstruct(
    variants(V8),
    variant_attributes(derive(PartialEq, Clone, Default, Debug, Encode, Decode)),
    no_enum
)]
pub struct BalancesCacheInner {
    pub(crate) items: Vec<CacheItemV8>,
}

pub type BalancesCacheInner = BalancesCacheInnerV8;

pub struct BalancesCache<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    pub(crate) cache: BalancesCacheInner,
    pub(crate) store: Arc<HotColdDB<E, Hot, Cold>>,
}

impl BalancesCacheInner {
    /// Inspect the given `state` and determine the root of the block at the first slot of
    /// `state.current_epoch`. If there is not already some entry for the given block root, then
    /// add the effective balances from the `state` to the cache.
    fn process_state<E: EthSpec>(
        &mut self,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        let epoch = state.current_epoch();
        let epoch_boundary_slot = epoch.start_slot(E::slots_per_epoch());
        let epoch_boundary_root = if epoch_boundary_slot == state.slot() {
            block_root
        } else {
            // This call remains sensible as long as `state.block_roots` is larger than a single
            // epoch.
            *state.get_block_root(epoch_boundary_slot)?
        };

        // Check if there already exists a cache entry for the epoch boundary block of the current
        // epoch. We rely on the invariant that effective balances do not change for the duration
        // of a single epoch, so even if the block on the epoch boundary itself is skipped we can
        // still update its cache entry from any subsequent state in that epoch.
        if self.position(epoch_boundary_root, epoch).is_none() {
            let item = CacheItem {
                block_root: epoch_boundary_root,
                epoch,
                balances: JustifiedBalances::from_justified_state(state)?.effective_balances,
            };

            if self.items.len() == MAX_BALANCE_CACHE_SIZE {
                self.items.remove(0);
            }

            self.items.push(item);
        }

        Ok(())
    }

    fn position(&self, block_root: Hash256, epoch: Epoch) -> Option<usize> {
        self.items
            .iter()
            .position(|item| item.block_root == block_root && item.epoch == epoch)
    }

    /// Get the balances for the given `block_root`, if any.
    ///
    /// If some balances are found, they are cloned from the cache.
    fn get(&self, block_root: Hash256, epoch: Epoch) -> Option<Vec<u64>> {
        let i = self.position(block_root, epoch)?;
        Some(self.items[i].balances.clone())
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> BalancesCache<E, Hot, Cold> {
    pub fn new(store: Arc<HotColdDB<E, Hot, Cold>>) -> Self {
        Self {
            store,
            cache: <_>::default(),
        }
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> BalancesGetter
    for BalancesCache<E, Hot, Cold>
{
    fn get_balances(
        &self,
        state_root: Hash256,
        checkpoint: Checkpoint,
    ) -> Result<JustifiedBalances, ForkChoiceError> {
        if let Some(balances) = self.cache.get(checkpoint.root, checkpoint.epoch) {
            return Ok(JustifiedBalances::from_effective_balances(balances)
                .map_err(|e| format!("Invalid cached balances {e:?}"))?);
        }

        let state_slot = checkpoint.epoch.start_slot(E::slots_per_epoch());
        let state = self
            .store
            .get_state(&state_root, Some(state_slot), false)
            .map_err(|e| format!("Error getting state {state_root:?} {e:?}"))?
            .ok_or_else(|| {
                ForkChoiceError::BalancesGetterError(format!("Missing state {state_root:?}"))
            })?;
        let balances = JustifiedBalances::from_justified_state(&state)
            .map_err(|e| format!("Invalid state balances {e:?}"))?;
        return Ok(balances);
    }
}

/// Implements `fork_choice::ForkChoiceStore` in order to provide a persistent backing to the
/// `fork_choice::ForkChoice` struct.
#[derive(Debug, Derivative)]
#[derivative(PartialEq(bound = "E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>"))]
pub struct BeaconForkChoiceStore<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    #[derivative(PartialEq = "ignore")]
    store: Arc<HotColdDB<E, Hot, Cold>>,
    balances_cache: BalancesCacheInner,
    time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: JustifiedBalances,
    justified_state_root: Hash256,
    unrealized_justified_checkpoint: Checkpoint,
    unrealized_justified_state_root: Hash256,
    unrealized_finalized_checkpoint: Checkpoint,
    proposer_boost_root: Hash256,
    equivocating_indices: BTreeSet<u64>,
    _phantom: PhantomData<E>,
}

impl<E, Hot, Cold> BeaconForkChoiceStore<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// Initialize `Self` from some `anchor` checkpoint which may or may not be the genesis state.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#get_forkchoice_store
    ///
    /// ## Notes:
    ///
    /// It is assumed that `anchor` is already persisted in `store`.
    pub fn get_forkchoice_store(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        anchor: BeaconSnapshot<E>,
    ) -> Result<Self, Error> {
        let unadvanced_state_root = anchor.beacon_state_root();
        let mut anchor_state = anchor.beacon_state;
        let mut anchor_block_header = anchor_state.latest_block_header().clone();

        // The anchor state MUST be on an epoch boundary (it should be advanced by the caller).
        if !anchor_state
            .slot()
            .as_u64()
            .is_multiple_of(E::slots_per_epoch())
        {
            return Err(Error::UnalignedCheckpoint {
                block_slot: anchor_block_header.slot,
                state_slot: anchor_state.slot(),
            });
        }

        // Compute the accurate block root for the checkpoint block.
        if anchor_block_header.state_root.is_zero() {
            anchor_block_header.state_root = unadvanced_state_root;
        }
        let anchor_block_root = anchor_block_header.canonical_root();
        let anchor_epoch = anchor_state.current_epoch();
        let justified_checkpoint = Checkpoint {
            epoch: anchor_epoch,
            root: anchor_block_root,
        };
        let finalized_checkpoint = justified_checkpoint;
        let justified_balances = JustifiedBalances::from_justified_state(&anchor_state)?;
        let justified_state_root = anchor_state.canonical_root()?;

        Ok(Self {
            store,
            balances_cache: <_>::default(),
            time: anchor_state.slot(),
            justified_checkpoint,
            justified_balances,
            justified_state_root,
            finalized_checkpoint,
            unrealized_justified_checkpoint: justified_checkpoint,
            unrealized_justified_state_root: justified_state_root,
            unrealized_finalized_checkpoint: finalized_checkpoint,
            proposer_boost_root: Hash256::zero(),
            equivocating_indices: BTreeSet::new(),
            _phantom: PhantomData,
        })
    }

    /// Save the current state of `Self` to a `PersistedForkChoiceStore` which can be stored to the
    /// on-disk database.
    pub fn to_persisted(&self) -> PersistedForkChoiceStore {
        PersistedForkChoiceStore {
            time: self.time,
            finalized_checkpoint: self.finalized_checkpoint,
            justified_checkpoint: self.justified_checkpoint,
            justified_state_root: self.justified_state_root,
            unrealized_justified_checkpoint: self.unrealized_justified_checkpoint,
            unrealized_justified_state_root: self.unrealized_justified_state_root,
            unrealized_finalized_checkpoint: self.unrealized_finalized_checkpoint,
            proposer_boost_root: self.proposer_boost_root,
            equivocating_indices: self.equivocating_indices.clone(),
        }
    }

    /// Restore `Self` from a previously-generated `PersistedForkChoiceStore`.
    ///
    /// DEPRECATED. Can be deleted once migrations no longer require it.
    pub fn from_persisted_v17(
        persisted: PersistedForkChoiceStoreV17,
        justified_state_root: Hash256,
        unrealized_justified_state_root: Hash256,
        store: Arc<HotColdDB<E, Hot, Cold>>,
    ) -> Result<Self, Error> {
        let justified_balances =
            JustifiedBalances::from_effective_balances(persisted.justified_balances)?;

        Ok(Self {
            store,
            balances_cache: <_>::default(),
            time: persisted.time,
            finalized_checkpoint: persisted.finalized_checkpoint,
            justified_checkpoint: persisted.justified_checkpoint,
            justified_balances,
            justified_state_root,
            unrealized_justified_checkpoint: persisted.unrealized_justified_checkpoint,
            unrealized_justified_state_root,
            unrealized_finalized_checkpoint: persisted.unrealized_finalized_checkpoint,
            proposer_boost_root: persisted.proposer_boost_root,
            equivocating_indices: persisted.equivocating_indices,
            _phantom: PhantomData,
        })
    }

    /// Restore `Self` from a previously-generated `PersistedForkChoiceStore`.
    pub fn from_persisted(
        persisted: PersistedForkChoiceStore,
        store: Arc<HotColdDB<E, Hot, Cold>>,
    ) -> Result<Self, Error> {
        let justified_checkpoint = persisted.justified_checkpoint;
        let justified_state_root = persisted.justified_state_root;

        let update_cache = true;
        let justified_state = store
            .get_hot_state(&justified_state_root, update_cache)
            .map_err(Error::FailedToReadState)?
            .ok_or(Error::MissingState(justified_state_root))?;

        let justified_balances = JustifiedBalances::from_justified_state(&justified_state)?;
        Ok(Self {
            store,
            balances_cache: <_>::default(),
            time: persisted.time,
            finalized_checkpoint: persisted.finalized_checkpoint,
            justified_checkpoint,
            justified_balances,
            justified_state_root,
            unrealized_justified_checkpoint: persisted.unrealized_justified_checkpoint,
            unrealized_justified_state_root: persisted.unrealized_justified_state_root,
            unrealized_finalized_checkpoint: persisted.unrealized_finalized_checkpoint,
            proposer_boost_root: persisted.proposer_boost_root,
            equivocating_indices: persisted.equivocating_indices,
            _phantom: PhantomData,
        })
    }
}

pub type PersistedForkChoiceStore = PersistedForkChoiceStoreV28;

/// A container which allows persisting the `BeaconForkChoiceStore` to the on-disk database.
#[superstruct(
    variants(V17, V28),
    variant_attributes(derive(Encode, Decode)),
    no_enum
)]
pub struct PersistedForkChoiceStore {
    /// The balances cache was removed from disk storage in schema V28.
    #[superstruct(only(V17))]
    pub balances_cache: BalancesCacheInnerV8,
    pub time: Slot,
    pub finalized_checkpoint: Checkpoint,
    pub justified_checkpoint: Checkpoint,
    /// The justified balances were removed from disk storage in schema V28.
    #[superstruct(only(V17))]
    pub justified_balances: Vec<u64>,
    /// The justified state root is stored so that it can be used to load the justified balances.
    #[superstruct(only(V28))]
    pub justified_state_root: Hash256,
    pub unrealized_justified_checkpoint: Checkpoint,
    #[superstruct(only(V28))]
    pub unrealized_justified_state_root: Hash256,
    pub unrealized_finalized_checkpoint: Checkpoint,
    pub proposer_boost_root: Hash256,
    pub equivocating_indices: BTreeSet<u64>,
}

// Convert V28 to V17 by adding balances and removing justified state roots.
impl From<(PersistedForkChoiceStoreV28, JustifiedBalances)> for PersistedForkChoiceStoreV17 {
    fn from((v28, balances): (PersistedForkChoiceStoreV28, JustifiedBalances)) -> Self {
        Self {
            balances_cache: Default::default(),
            time: v28.time,
            finalized_checkpoint: v28.finalized_checkpoint,
            justified_checkpoint: v28.justified_checkpoint,
            justified_balances: balances.effective_balances,
            unrealized_justified_checkpoint: v28.unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint: v28.unrealized_finalized_checkpoint,
            proposer_boost_root: v28.proposer_boost_root,
            equivocating_indices: v28.equivocating_indices,
        }
    }
}
