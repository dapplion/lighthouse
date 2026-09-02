//! The types the rule is written against, with the same surface the Lighthouse
//! originals expose.
//!
//! `types` and `proto_array` are not `no_std` and drag in most of the client, so
//! the rule cannot use them directly. Rather than rewrite it against `u64`, this
//! provides `Slot`, `Epoch`, `Root` and `Checkpoint` with the same methods --
//! `epoch()`, `as_u64()`, `start_slot()`, `safe_add()` -- so the ported bodies
//! read as the originals do and diff against them cleanly. That is the whole
//! design goal: a reviewer should be able to put the two side by side.

use crate::{ArithError, Result};

/// A block root. `types::Hash256` in Lighthouse.
pub type Root = [u8; 32];

/// The zero root, which the rule uses for "no block".
pub const ZERO_ROOT: Root = [0u8; 32];

macro_rules! scalar {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
        pub struct $name(pub u64);

        impl $name {
            pub const fn new(v: u64) -> Self {
                Self(v)
            }
            pub const fn as_u64(self) -> u64 {
                self.0
            }
            pub fn safe_add(self, other: impl Into<u64>) -> Result<Self> {
                Ok(Self(self.0.checked_add(other.into()).ok_or(ArithError)?))
            }
            pub fn safe_sub(self, other: impl Into<u64>) -> Result<Self> {
                Ok(Self(self.0.checked_sub(other.into()).ok_or(ArithError)?))
            }
            pub fn saturating_add(self, other: impl Into<u64>) -> Self {
                Self(self.0.saturating_add(other.into()))
            }
            pub fn saturating_sub(self, other: impl Into<u64>) -> Self {
                Self(self.0.saturating_sub(other.into()))
            }
        }

        impl From<$name> for u64 {
            fn from(v: $name) -> u64 {
                v.0
            }
        }
    };
}

scalar!(Slot);
scalar!(Epoch);

impl Slot {
    /// Spec: `compute_epoch_at_slot`.
    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        Epoch(self.0 / slots_per_epoch)
    }
}

impl Epoch {
    /// Spec: `compute_start_slot_at_epoch`.
    pub fn start_slot(self, slots_per_epoch: u64) -> Slot {
        Slot(self.0.saturating_mul(slots_per_epoch))
    }
}

/// `types::Checkpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

/// Whether a block's execution payload is usable. The rule only ever asks
/// whether it is optimistic or invalid, so that is all this carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Valid,
    OptimisticOrInvalid,
    /// Pre-merge. Treated as not optimistic, as the spec's MUST is post-merge.
    Irrelevant,
}

impl ExecutionStatus {
    pub fn is_optimistic_or_invalid(self) -> bool {
        matches!(self, ExecutionStatus::OptimisticOrInvalid)
    }
}

/// One validator's latest vote. `proto_array::VoteTracker`, at the two fields
/// the rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Vote {
    pub current_root: Root,
    pub current_slot: Slot,
}

impl Vote {
    pub fn current_root(&self) -> Root {
        self.current_root
    }
    pub fn current_slot(&self) -> Slot {
        self.current_slot
    }
}
