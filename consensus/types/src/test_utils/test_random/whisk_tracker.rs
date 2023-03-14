use super::*;
use curdleproofs_whisk::WhiskTracker;

impl TestRandom for WhiskTracker {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        WhiskTracker {
            r_g: BLSG1Point::random_for_test(rng),
            k_r_g: BLSG1Point::random_for_test(rng),
        }
    }
}
