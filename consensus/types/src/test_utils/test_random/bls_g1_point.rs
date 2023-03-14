use super::*;
use bls::SecretKey;
use curdleproofs_whisk::BLSG1Point;

impl TestRandom for BLSG1Point {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        BLSG1Point(SecretKey::random_for_test(rng).public_key().serialize())
    }
}
