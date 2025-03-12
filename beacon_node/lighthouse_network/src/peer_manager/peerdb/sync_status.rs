//! Handles individual sync status for peers.

use crate::rpc::{methods::epoch_of_ancestor_root_offset, StatusMessage};
use serde::Serialize;
use types::{ChainSpec, Epoch, EthSpec, Hash256, Slot};

#[derive(Clone, Debug, Serialize)]
/// The current sync status of the peer.
pub enum SyncStatus {
    /// At the current state as our node or ahead of us.
    Synced { info: SyncInfo },
    /// The peer has greater knowledge about the canonical chain than we do.
    Advanced { info: SyncInfo },
    /// Is behind our current head and not useful for block downloads.
    Behind { info: SyncInfo },
    /// This peer is in an incompatible network.
    IrrelevantPeer,
    /// Not currently known as a STATUS handshake has not occurred.
    Unknown,
}

/// A relevant peer's sync information.
#[derive(Clone, Debug, Serialize)]
pub struct SyncInfo {
    pub head_slot: Slot,
    pub head_root: Hash256,
    pub finalized_epoch: Epoch,
    pub finalized_root: Hash256,
    pub ancestor_roots: Option<Vec<Hash256>>,
}

impl SyncInfo {
    pub fn from_status<E: EthSpec>(status: StatusMessage<E>) -> Self {
        Self {
            head_slot: *status.head_slot(),
            head_root: *status.head_root(),
            finalized_epoch: *status.finalized_epoch(),
            finalized_root: *status.finalized_root(),
            ancestor_roots: Some(status.ancestor_roots().to_vec()),
        }
    }

    pub fn is_same_finalized_checkpoint(&self, other: &Self) -> bool {
        self.finalized_epoch == other.finalized_epoch && self.finalized_root == other.finalized_root
    }

    pub fn last_known_ancestor_root(
        &self,
        other: &Self,
        spec: &ChainSpec,
    ) -> Option<(Epoch, Hash256)> {
        if !self.is_same_finalized_checkpoint(other) {
            return None;
        }

        let (Some(self_ancestor_roots), Some(remote_ancestor_roots)) =
            (self.ancestor_roots.as_ref(), other.ancestor_roots.as_ref())
        else {
            return Some((self.finalized_epoch, self.finalized_root));
        };

        for (i, (self_root, other_root)) in self_ancestor_roots
            .iter()
            .zip(remote_ancestor_roots.iter())
            .enumerate()
        {
            if self_root != other_root {
                // Found the first unknown root
                return if i == 0 {
                    // If the root at the first index is unknown return the common
                    // finalized checkpoint
                    Some((self.finalized_epoch, self.finalized_root))
                } else {
                    // The prior index is the last known root
                    let last_known_index = i - 1;
                    let root = self_ancestor_roots
                        .get(last_known_index)
                        .expect("get within bounds of self_ancestor_roots len");
                    let epoch =
                        epoch_of_ancestor_root_offset(self.finalized_epoch, last_known_index, spec);
                    Some((epoch, *root))
                };
            }
        }

        // Case `local.len() < remote.len()`
        // local  [a,b,c]   <- last known is `c`
        // remote [a,b,c,d]
        //
        // Case `local.len() == remote.len()`
        // local  [a,b,c]   <- last known is `c`
        // remote [a,b,c]
        //
        // Case `local.len() > remote.len()`
        // > Note this case should not happen as then this peer is not advanced and we won't
        // sync from it. For sanity we return None
        // local  [a,b,c,d]
        // remote [a,b,c]

        // If reach here the common section of both ancestor roots arrays are the same.
        if self_ancestor_roots.len() <= remote_ancestor_roots.len() {
            if self_ancestor_roots.is_empty() {
                Some((self.finalized_epoch, self.finalized_root))
            } else {
                let last_item_index = self_ancestor_roots.len();
                let root = remote_ancestor_roots
                    .get(last_item_index)
                    .expect("remote_ancestor_roots len is > self_ancestor_roots len");
                let epoch =
                    epoch_of_ancestor_root_offset(self.finalized_epoch, last_item_index, spec);
                Some((epoch, *root))
            }
        } else {
            None
        }
    }
}

impl std::cmp::PartialEq for SyncStatus {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (SyncStatus::Synced { .. }, SyncStatus::Synced { .. })
                | (SyncStatus::Advanced { .. }, SyncStatus::Advanced { .. })
                | (SyncStatus::Behind { .. }, SyncStatus::Behind { .. })
                | (SyncStatus::IrrelevantPeer, SyncStatus::IrrelevantPeer)
                | (SyncStatus::Unknown, SyncStatus::Unknown)
        )
    }
}

impl SyncStatus {
    /// Returns true if the peer has advanced knowledge of the chain.
    pub fn is_advanced(&self) -> bool {
        matches!(self, SyncStatus::Advanced { .. })
    }

    /// Returns true if the peer is up to date with the current chain.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncStatus::Synced { .. })
    }

    /// Returns true if the peer is behind the current chain.
    pub fn is_behind(&self) -> bool {
        matches!(self, SyncStatus::Behind { .. })
    }

    /// Updates the peer's sync status, returning whether the status transitioned.
    ///
    /// E.g. returns `true` if the state changed from `Synced` to `Advanced`, but not if
    /// the status remained `Synced` with different `SyncInfo` within.
    pub fn update(&mut self, new_state: SyncStatus) -> bool {
        let changed_status = *self != new_state;
        *self = new_state;
        changed_status
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::Advanced { .. } => "Advanced",
            SyncStatus::Behind { .. } => "Behind",
            SyncStatus::Synced { .. } => "Synced",
            SyncStatus::Unknown => "Unknown",
            SyncStatus::IrrelevantPeer => "Irrelevant",
        }
    }
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
