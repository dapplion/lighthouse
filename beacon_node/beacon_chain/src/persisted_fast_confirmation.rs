//! State that lets the Fast Confirmation Rule carry on across a restart instead of starting over.
//!
//! Nothing here changes the database schema: both items live under their own keys in
//! `DBColumn::ForkChoice`, are written in the same batch as fork choice, and a database without
//! them (an older version, a fresh sync) simply boots the way it always did.

use fast_confirmation::FastConfirmationRule;
use fork_choice::QueuedAttestation;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::{Checkpoint, Hash256, Slot};

pub const FAST_CONFIRMATION_DB_KEY: Hash256 = Hash256::with_last_byte(1);
pub const QUEUED_ATTESTATIONS_DB_KEY: Hash256 = Hash256::with_last_byte(2);

/// Marks `last_update_slot` as unset: the rule had not run yet when it was persisted.
const NO_UPDATE_SLOT: u64 = u64::MAX;

/// The FCR tracking variables (spec: the `FastConfirmationStore` fields) plus the slot of the
/// rule's last per-slot update. Balance snapshots are rebuilt from the checkpoint states on load.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct PersistedFastConfirmation {
    pub confirmed_root: Hash256,
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Hash256,
    pub current_slot_head: Hash256,
    last_update_slot: u64,
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
            last_update_slot: rule
                .last_update_slot()
                .map_or(NO_UPDATE_SLOT, |slot| slot.as_u64()),
        }
    }

    pub fn last_update_slot(&self) -> Option<Slot> {
        (self.last_update_slot != NO_UPDATE_SLOT).then(|| Slot::new(self.last_update_slot))
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

/// Attestations fork choice was holding for the next slot when it was persisted.
///
/// `PersistedForkChoice` stopped carrying these in V29. Without them a node that shuts down in
/// slot N comes back without any of slot N's votes until block N+1 delivers them, and the Fast
/// Confirmation Rule, which re-confirms the recent chain at every epoch boundary, can fall a
/// committee short of the safety threshold and drop its confirmed root for no reason a node that
/// stayed up would have.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct PersistedQueuedAttestations {
    pub attestations: Vec<QueuedAttestation>,
}

impl StoreItem for PersistedQueuedAttestations {
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
