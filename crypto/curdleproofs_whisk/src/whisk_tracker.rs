use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::BLSG1Point;

#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Default,
)]
pub struct WhiskTracker {
    pub r_g: BLSG1Point,   // r * G
    pub k_r_g: BLSG1Point, // k * r * G
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for WhiskTracker {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(WhiskTracker {
            r_g: BLSG1Point::arbitrary(u)?,
            k_r_g: BLSG1Point::arbitrary(u)?,
        })
    }
}

impl Into<curdleproofs::whisk::WhiskTracker> for &WhiskTracker {
    fn into(self) -> curdleproofs::whisk::WhiskTracker {
        curdleproofs::whisk::WhiskTracker {
            r_G: self.r_g.0,
            k_r_G: self.k_r_g.0,
        }
    }
}

impl From<&curdleproofs::whisk::WhiskTracker> for WhiskTracker {
    fn from(value: &curdleproofs::whisk::WhiskTracker) -> Self {
        Self {
            r_g: BLSG1Point(value.r_G),
            k_r_g: BLSG1Point(value.k_r_G),
        }
    }
}
