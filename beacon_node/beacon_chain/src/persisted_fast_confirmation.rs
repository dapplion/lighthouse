//! Fast Confirmation Rule state carried across restarts. Stored under its own key next to fork
//! choice; absent, the rule is seeded from the justified checkpoint.

use fast_confirmation::FastConfirmationRule;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::{Checkpoint, Hash256, Slot};

pub const FAST_CONFIRMATION_DB_KEY: Hash256 = Hash256::with_last_byte(1);

const NO_UPDATE_SLOT: u64 = u64::MAX;

/// The spec's `FastConfirmationStore` fields; balance snapshots are rebuilt on load.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct PersistedFastConfirmation {
    pub confirmed_root: Hash256,
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Hash256,
    pub current_slot_head: Hash256,
    previous_update_slot: u64,
    current_update_slot: u64,
}

impl PersistedFastConfirmation {
    pub fn from_rule(rule: &FastConfirmationRule) -> Self {
        Self {
            confirmed_root: rule.confirmed_root,
            previous_epoch_observed_justified_checkpoint: rule
                .previous_epoch_observed_justified
                .checkpoint(),
            current_epoch_observed_justified_checkpoint: rule
                .current_epoch_observed_justified
                .checkpoint(),
            previous_epoch_greatest_unrealized_checkpoint: rule
                .previous_epoch_greatest_unrealized_checkpoint,
            previous_slot_head: rule.previous_slot_head,
            current_slot_head: rule.current_slot_head,
            previous_update_slot: Self::raw_slot(rule.previous_update_slot()),
            current_update_slot: Self::raw_slot(rule.last_update_slot()),
        }
    }

    fn raw_slot(slot: Option<Slot>) -> u64 {
        slot.map_or(NO_UPDATE_SLOT, |slot| slot.as_u64())
    }

    fn slot(raw: u64) -> Option<Slot> {
        (raw != NO_UPDATE_SLOT).then(|| Slot::new(raw))
    }

    pub fn previous_update_slot(&self) -> Option<Slot> {
        Self::slot(self.previous_update_slot)
    }

    pub fn current_update_slot(&self) -> Option<Slot> {
        Self::slot(self.current_update_slot)
    }
}

impl StoreItem for PersistedFastConfirmation {
    fn db_column() -> DBColumn {
        DBColumn::ForkChoice
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
