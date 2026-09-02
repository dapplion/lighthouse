//! The handful of `types` the rule reads, without `types`.

use core::fmt;

/// Checked arithmetic overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArithError;

/// `safe_arith::SafeArith`, for the types the rule does arithmetic on.
pub trait SafeArith<Rhs = Self>: Sized {
    fn safe_add(self, other: Rhs) -> Result<Self, ArithError>;
    fn safe_sub(self, other: Rhs) -> Result<Self, ArithError>;
    fn safe_mul(self, other: Rhs) -> Result<Self, ArithError>;
    fn safe_div(self, other: Rhs) -> Result<Self, ArithError>;
    fn safe_rem(self, other: Rhs) -> Result<Self, ArithError>;

    #[inline]
    fn safe_add_assign(&mut self, other: Rhs) -> Result<(), ArithError>
    where
        Self: Copy,
    {
        *self = self.safe_add(other)?;
        Ok(())
    }
}

impl SafeArith for u64 {
    #[inline]
    fn safe_add(self, other: Self) -> Result<Self, ArithError> {
        self.checked_add(other).ok_or(ArithError)
    }
    #[inline]
    fn safe_sub(self, other: Self) -> Result<Self, ArithError> {
        self.checked_sub(other).ok_or(ArithError)
    }
    #[inline]
    fn safe_mul(self, other: Self) -> Result<Self, ArithError> {
        self.checked_mul(other).ok_or(ArithError)
    }
    #[inline]
    fn safe_div(self, other: Self) -> Result<Self, ArithError> {
        self.checked_div(other).ok_or(ArithError)
    }
    #[inline]
    fn safe_rem(self, other: Self) -> Result<Self, ArithError> {
        self.checked_rem(other).ok_or(ArithError)
    }
}

/// A block root.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

macro_rules! scalar {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(v: u64) -> Self {
                Self(v)
            }
            pub const fn as_u64(&self) -> u64 {
                self.0
            }
            #[inline]
            pub fn saturating_add(self, other: u64) -> Self {
                Self(self.0.saturating_add(other))
            }
            #[inline]
            pub fn saturating_sub(self, other: u64) -> Self {
                Self(self.0.saturating_sub(other))
            }
        }

        impl SafeArith<u64> for $name {
            #[inline]
            fn safe_add(self, other: u64) -> Result<Self, ArithError> {
                self.0.safe_add(other).map(Self)
            }
            #[inline]
            fn safe_sub(self, other: u64) -> Result<Self, ArithError> {
                self.0.safe_sub(other).map(Self)
            }
            #[inline]
            fn safe_mul(self, other: u64) -> Result<Self, ArithError> {
                self.0.safe_mul(other).map(Self)
            }
            #[inline]
            fn safe_div(self, other: u64) -> Result<Self, ArithError> {
                self.0.safe_div(other).map(Self)
            }
            #[inline]
            fn safe_rem(self, other: u64) -> Result<Self, ArithError> {
                self.0.safe_rem(other).map(Self)
            }
        }

        impl From<u64> for $name {
            #[inline]
            fn from(v: u64) -> Self {
                Self(v)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

scalar!(Slot);
scalar!(Epoch);

impl Slot {
    #[inline]
    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        Epoch(self.0 / slots_per_epoch)
    }
}

impl Epoch {
    #[inline]
    pub fn start_slot(self, slots_per_epoch: u64) -> Slot {
        Slot(self.0.saturating_mul(slots_per_epoch))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Hash256,
}

/// The one thing the rule reads off the chain spec.
pub trait EthSpec {
    fn slots_per_epoch() -> u64;
}

/// A spec known at compile time, for a caller with no `types` to hand.
pub struct SlotsPerEpoch<const N: u64>;

impl<const N: u64> EthSpec for SlotsPerEpoch<N> {
    #[inline]
    fn slots_per_epoch() -> u64 {
        N
    }
}

/// Failure to answer a committee membership question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotAssignmentsError;

/// `types::SlotAssignments`, at the one question the rule asks of it.
pub trait SlotAssignments {
    fn is_in_range(
        &self,
        validator_index: usize,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<bool, SlotAssignmentsError>;
}

/// One validator's latest vote: `proto_array::VoteTracker`, at the two fields
/// the rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VoteTracker {
    pub current_root: Hash256,
    pub current_slot: Slot,
}

impl VoteTracker {
    #[inline]
    pub fn current_root(&self) -> Hash256 {
        self.current_root
    }
    #[inline]
    pub fn current_slot(&self) -> Slot {
        self.current_slot
    }
}

/// The latest vote of each validator, by index, read in place.
///
/// Lighthouse keeps votes as `proto_array::VoteTracker` and would otherwise
/// copy the whole set -- tens of megabytes at mainnet size -- on every call.
pub trait Votes {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, index: usize) -> Option<VoteTracker>;

    /// Only the root. The loops that count support read nothing else, and a
    /// host's vote record can keep the root and the slot on different cache
    /// lines, so this is the read they make once per validator.
    #[inline]
    fn current_root(&self, index: usize) -> Option<Hash256> {
        self.get(index).map(|vote| vote.current_root)
    }

    /// Every vote, in index order. `get` is total on `0..len`, so nothing is skipped.
    fn iter(&self) -> impl Iterator<Item = VoteTracker> + '_ {
        (0..self.len()).map(|i| self.get(i).unwrap_or_default())
    }
}

impl Votes for [VoteTracker] {
    fn len(&self) -> usize {
        <[VoteTracker]>::len(self)
    }

    fn get(&self, index: usize) -> Option<VoteTracker> {
        <[VoteTracker]>::get(self, index).copied()
    }
}
