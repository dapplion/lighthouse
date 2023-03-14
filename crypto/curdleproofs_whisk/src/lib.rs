mod bls_g1_point;
mod whisk_tracker;

pub use crate::{bls_g1_point::BLSG1Point, whisk_tracker::WhiskTracker};
pub use curdleproofs::{
    curdleproofs::SerializationError,
    whisk::{
        bls_g1_scalar_multiply, bytes_to_bls_field, deserialize_fr, serialize_fr,
        FieldElementBytes, Fr, G1Affine, TrackerProofBytes, WhiskShuffleProofBytes,
        TRACKER_PROOF_SIZE, WHISK_SHUFFLE_PROOF_SIZE,
    },
};
use curdleproofs::{
    curdleproofs::{generate_crs, CanonicalDeserialize, CanonicalSerialize, CurdleproofsCrs},
    whisk::{from_g1_compressed, g1_generator, rand_scalar, to_g1_compressed},
    N_BLINDERS,
};
use lazy_static::lazy_static;
use rand::{rngs::StdRng, SeedableRng};
use std::io::{Cursor, Read};

pub type BLSFieldElement = [u8; 32];

const N: usize = 128;
pub const WHISK_SHUFFLE_ELL: usize = N - N_BLINDERS;

pub const TRUSTED_SETUP: &[u8] = include_bytes!("trusted_setup/curdleproofs_crs.rand.bin");

lazy_static! {
    pub static ref WHISK: Whisk =
        Whisk::new_from_trusted_setup(Cursor::new(TRUSTED_SETUP)).unwrap();
    pub static ref BLS_G1_GENERATOR: G1Affine = g1_generator();
    pub static ref BLS_G1_GENERATOR_BYTES: BLSG1Point =
        BLSG1Point(to_g1_compressed(&g1_generator()).unwrap());
}

pub struct Whisk {
    crs: CurdleproofsCrs,
}

impl Whisk {
    /// Load Whisk trusted setup from serialized reader.
    /// Expectes a `CurdleproofsCrs` instance serialized with `ark_serialize::CanonicalSerialize`
    pub fn new_from_trusted_setup<R: Read>(trusted_setup: R) -> Result<Self, SerializationError> {
        Ok(Self {
            crs: CurdleproofsCrs::deserialize(trusted_setup)?,
        })
    }

    pub fn new_from_random_setup() -> Self {
        Self {
            crs: generate_crs(WHISK_SHUFFLE_ELL),
        }
    }

    pub fn serialize_trusted_setup(&self) -> Result<Vec<u8>, SerializationError> {
        let mut out: Vec<u8> = vec![];
        self.crs.serialize(&mut out)?;
        Ok(out)
    }

    /// Verify `post_shuffle_trackers` is a permutation of `pre_shuffle_trackers`.
    /// Defined in https://github.com/nalinbhardwaj/curdleproofs.pie/blob/59eb1d54fe193f063a718fc3bdded4734e66bddc/curdleproofs/curdleproofs/whisk_interface.py#L18-L42
    pub fn is_valid_whisk_shuffle_proof(
        &self,
        pre_shuffle_trackers: &[WhiskTracker],
        post_shuffle_trackers: &[WhiskTracker],
        shuffle_proof: &WhiskShuffleProofBytes,
    ) -> Result<bool, SerializationError> {
        // TODO: Where to instantiate RNG?
        let mut rng = StdRng::seed_from_u64(0u64);

        curdleproofs::whisk::is_valid_whisk_shuffle_proof(
            &mut rng,
            &self.crs,
            &deserialize_shuffle_trackers(pre_shuffle_trackers),
            &deserialize_shuffle_trackers(post_shuffle_trackers),
            shuffle_proof,
        )
    }

    pub fn generate_whisk_shuffle_proof(
        &self,
        pre_shuffle_trackers: &[WhiskTracker],
    ) -> Result<(Vec<WhiskTracker>, WhiskShuffleProofBytes), SerializationError> {
        // TODO: Where to instantiate RNG?
        let mut rng = StdRng::seed_from_u64(0u64);

        let pre_shuffle_trackers = deserialize_shuffle_trackers(pre_shuffle_trackers);

        let (post_shuffle_trackers, shuffle_proof) =
            curdleproofs::whisk::generate_whisk_shuffle_proof(
                &mut rng,
                &self.crs,
                &pre_shuffle_trackers,
            )?;

        Ok((
            serialize_shuffle_trackers(&post_shuffle_trackers),
            shuffle_proof,
        ))
    }
}

/// Verify knowledge of `k` such that `tracker.k_r_g == k * tracker.r_g` and `k_commitment == k * BLS_G1_GENERATOR`.
/// Defined in https://github.com/nalinbhardwaj/curdleproofs.pie/blob/59eb1d54fe193f063a718fc3bdded4734e66bddc/curdleproofs/curdleproofs/whisk_interface.py#L48-L68
///
/// # Arguments
///
/// * `tracker` - Retrieved from the state
///
pub fn is_valid_whisk_tracker_proof(
    tracker: &WhiskTracker,
    k_commitment: &BLSG1Point,
    tracker_proof: &TrackerProofBytes,
) -> Result<bool, SerializationError> {
    curdleproofs::whisk::is_valid_whisk_tracker_proof(
        &tracker.into(),
        &k_commitment.0,
        tracker_proof,
    )
}

/// Generate whisk opening proof to pass `is_valid_whisk_tracker_proof`
pub fn generate_whisk_tracker_proof(
    tracker: &WhiskTracker,
    k: &Fr,
) -> Result<TrackerProofBytes, SerializationError> {
    // TODO: Where to instantiate RNG?
    let mut rng = StdRng::seed_from_u64(0u64);
    curdleproofs::whisk::generate_whisk_tracker_proof(&mut rng, &tracker.into(), k)
}

pub fn is_g1_generator(g1_point: &BLSG1Point) -> bool {
    g1_point == &*BLS_G1_GENERATOR_BYTES
}

pub fn bls_g1_scalar_multiply_generator(scalar: &Fr) -> G1Affine {
    bls_g1_scalar_multiply(&BLS_G1_GENERATOR, scalar)
}

/// Returns Tracker where r is known and equal to 1
pub fn compute_initial_tracker(k: &Fr) -> Result<(BLSG1Point, WhiskTracker), SerializationError> {
    let k_g = bls_g1_scalar_multiply(&BLS_G1_GENERATOR, k);
    let tracker = curdleproofs::whisk::WhiskTracker {
        r_G: to_g1_compressed(&BLS_G1_GENERATOR)?,
        k_r_G: to_g1_compressed(&k_g)?,
    };
    Ok(((&k_g).try_into()?, (&tracker).into()))
}

/// Returns Tracker where r is random, and forgotten
pub fn compute_tracker(k: &Fr) -> Result<(G1Affine, WhiskTracker), SerializationError> {
    let mut rng = StdRng::seed_from_u64(0u64);
    let r = rand_scalar(&mut rng);
    let k_g = bls_g1_scalar_multiply(&BLS_G1_GENERATOR, k);
    let tracker = curdleproofs::whisk::WhiskTracker {
        r_G: to_g1_compressed(&bls_g1_scalar_multiply(&BLS_G1_GENERATOR, &r))?,
        k_r_G: to_g1_compressed(&bls_g1_scalar_multiply(&k_g, &r))?,
    };
    Ok((k_g, (&tracker).into()))
}

fn deserialize_shuffle_trackers(
    shuffle_trackers: &[WhiskTracker],
) -> Vec<curdleproofs::whisk::WhiskTracker> {
    shuffle_trackers
        .iter()
        .map(|tracker| tracker.into())
        .collect::<Vec<_>>()
}

fn serialize_shuffle_trackers(
    shuffle_trackers: &[curdleproofs::whisk::WhiskTracker],
) -> Vec<WhiskTracker> {
    shuffle_trackers
        .iter()
        .map(|tracker| tracker.into())
        .collect::<Vec<_>>()
}

pub struct WhiskTrackerG1Affine {
    r_g: G1Affine,
    k_r_g: G1Affine,
}

impl TryFrom<&WhiskTracker> for WhiskTrackerG1Affine {
    type Error = SerializationError;
    fn try_from(value: &WhiskTracker) -> Result<Self, Self::Error> {
        deserialize_tracker(&value.into())
    }
}

impl TryFrom<&curdleproofs::whisk::WhiskTracker> for WhiskTrackerG1Affine {
    type Error = SerializationError;
    fn try_from(value: &curdleproofs::whisk::WhiskTracker) -> Result<Self, Self::Error> {
        deserialize_tracker(value)
    }
}

pub fn deserialize_tracker(
    tracker: &curdleproofs::whisk::WhiskTracker,
) -> Result<WhiskTrackerG1Affine, SerializationError> {
    Ok(WhiskTrackerG1Affine {
        r_g: from_g1_compressed(&tracker.r_G)?,
        k_r_g: from_g1_compressed(&tracker.k_r_G)?,
    })
}

pub fn is_matching_tracker(tracker: &WhiskTrackerG1Affine, k: &Fr) -> bool {
    bls_g1_scalar_multiply(&tracker.r_g, k) == tracker.k_r_g
}

#[cfg(test)]
mod tests {
    use super::*;
    use curdleproofs::whisk::TRACKER_PROOF_SIZE;

    #[test]
    fn serdes_fr_low_val() {
        let k_bytes = [0x02; 32]; // some rand value < mod
        let k = deserialize_fr(&k_bytes);
        assert_eq!(k.serialized_size(), 32);
        assert_eq!(serialize_fr(&k), k_bytes);
    }

    #[test]
    fn serdes_fr_high_val() {
        let k_bytes = [0xff; 32]; // some rand value > mod
        let k = deserialize_fr(&k_bytes);
        assert_eq!(k.serialized_size(), 32);
        assert_eq!(
            hex::encode(serialize_fr(&k)),
            "fdffffff0100000002480300fab78458f54fbcecef4f8c996f05c5ac59b12418"
        );
    }

    #[test]
    fn serdes_g1generator() {
        assert_eq!(hex::encode(BLS_G1_GENERATOR_BYTES.0), "bbc622db0af03afbef1a7af93fe8556c58ac1b173f3a4ea105b974974f8c68c30faca94f8c63952694d79731a7d3f117");
        let g1: G1Affine = (&*BLS_G1_GENERATOR_BYTES).try_into().unwrap();
        assert_eq!(g1, *BLS_G1_GENERATOR);
    }

    /// Compute k for validator at `index` for its first proposal after Whisk
    pub fn compute_initial_k(index: u64) -> Fr {
        deserialize_fr(&index.to_be_bytes())
    }

    #[test]
    fn tracker_proof() {
        let k = compute_initial_k(12345678);
        let (k_commitment, tracker) = compute_tracker(&k).unwrap();
        let tracker_proof = generate_whisk_tracker_proof(&tracker, &k).unwrap();
        assert!(is_valid_whisk_tracker_proof(
            &tracker,
            &k_commitment.try_into().unwrap(),
            &tracker_proof
        )
        .unwrap());
    }

    #[test]
    fn shuffle_proof() {
        // Initial tracker in state
        let pre_shuffled_trackers: Vec<WhiskTracker> = (0..WHISK_SHUFFLE_ELL as u64)
            .map(|i| compute_tracker(&compute_initial_k(1 + i)).unwrap().1)
            .collect();

        let (whisk_post_shuffle_trackers, whisk_shuffle_proof) = WHISK
            .generate_whisk_shuffle_proof(&pre_shuffled_trackers)
            .unwrap();
        assert!(
            WHISK
                .is_valid_whisk_shuffle_proof(
                    &pre_shuffled_trackers,
                    &whisk_post_shuffle_trackers,
                    &whisk_shuffle_proof
                )
                .unwrap(),
            "invalid whisk_shuffle_proof"
        );
    }

    // Construct the CRS

    struct Block {
        pub whisk_opening_proof: TrackerProofBytes,
        pub whisk_post_shuffle_trackers: Vec<WhiskTracker>,
        pub whisk_shuffle_proof: WhiskShuffleProofBytes,
        pub whisk_registration_proof: TrackerProofBytes,
        pub whisk_tracker: WhiskTracker,
        pub whisk_k_commitment: BLSG1Point,
    }

    struct State {
        pub proposer_tracker: WhiskTracker,
        pub proposer_k_commitment: BLSG1Point,
        pub shuffled_trackers: Vec<WhiskTracker>,
    }

    fn process_block(state: &mut State, block: &Block) {
        // process_whisk_opening_proof
        assert!(
            is_valid_whisk_tracker_proof(
                &state.proposer_tracker,
                &state.proposer_k_commitment,
                &block.whisk_opening_proof,
            )
            .unwrap(),
            "invalid whisk_opening_proof"
        );

        // whisk_process_shuffled_trackers
        assert!(
            WHISK
                .is_valid_whisk_shuffle_proof(
                    &state.shuffled_trackers,
                    &block.whisk_post_shuffle_trackers,
                    &block.whisk_shuffle_proof
                )
                .unwrap(),
            "invalid whisk_shuffle_proof"
        );

        // whisk_process_tracker_registration
        if is_g1_generator(&state.proposer_tracker.r_g) {
            // First proposal
            assert!(
                is_valid_whisk_tracker_proof(
                    &block.whisk_tracker,
                    &block.whisk_k_commitment,
                    &block.whisk_registration_proof,
                )
                .unwrap(),
                "invalid whisk_registration_proof"
            );
            state.proposer_tracker = block.whisk_tracker.clone();
            state.proposer_k_commitment = block.whisk_k_commitment.clone();
        } else {
            // Next proposals, registration data not used
        }
    }

    fn produce_block(state: &State, proposer_k: &Fr, proposer_index: u64) -> Block {
        let (whisk_post_shuffle_trackers, whisk_shuffle_proof) = WHISK
            .generate_whisk_shuffle_proof(&state.shuffled_trackers)
            .unwrap();

        let is_first_proposal = is_g1_generator(&state.proposer_tracker.r_g);

        let (whisk_registration_proof, whisk_tracker, whisk_k_commitment) = if is_first_proposal {
            // First proposal, validator creates tracker for registering
            let (whisk_k_commitment, whisk_tracker) = compute_tracker(proposer_k).unwrap();
            let whisk_registration_proof =
                generate_whisk_tracker_proof(&whisk_tracker, proposer_k).unwrap();
            (
                whisk_registration_proof,
                whisk_tracker,
                whisk_k_commitment.try_into().unwrap(),
            )
        } else {
            // And subsequent proposals leave registration fields empty
            let whisk_registration_proof = [0u8; TRACKER_PROOF_SIZE];
            let whisk_tracker = WhiskTracker {
                r_g: BLS_G1_GENERATOR_BYTES.clone(),
                k_r_g: BLS_G1_GENERATOR_BYTES.clone(),
            };
            let whisk_k_commitment = BLS_G1_GENERATOR_BYTES.clone();
            (whisk_registration_proof, whisk_tracker, whisk_k_commitment)
        };

        let k_prev_proposal = if is_first_proposal {
            // On first proposal the k is computed deterministically and known to all
            compute_initial_k(proposer_index)
        } else {
            // Subsequent proposals use same k for registered tracker
            *proposer_k
        };

        let whisk_opening_proof =
            generate_whisk_tracker_proof(&state.proposer_tracker, &k_prev_proposal).unwrap();

        Block {
            whisk_opening_proof,
            whisk_post_shuffle_trackers,
            whisk_shuffle_proof,
            whisk_registration_proof,
            whisk_tracker,
            whisk_k_commitment,
        }
    }

    #[test]
    fn whisk_lifecycle() {
        // Initial tracker in state
        let shuffled_trackers: Vec<WhiskTracker> = (0..WHISK_SHUFFLE_ELL as u64)
            .map(|i| compute_tracker(&compute_initial_k(1 + i)).unwrap().1)
            .collect();

        let proposer_index = 12345678;
        let proposer_initial_k = compute_initial_k(proposer_index);

        // Initial dummy values, r = 1
        let (proposer_k_commitment, proposer_tracker) =
            compute_initial_tracker(&proposer_initial_k).unwrap();
        let mut state = State {
            proposer_tracker,
            proposer_k_commitment,
            shuffled_trackers,
        };

        // k must be kept
        let proposer_k = deserialize_fr([1; 32].as_slice());

        // On first proposal, validator creates tracker for registering
        let block_0 = produce_block(&state, &proposer_k, proposer_index);
        // Block is valid
        process_block(&mut state, &block_0);

        // On second proposal, validator opens previously submited tracker
        let block_1 = produce_block(&state, &proposer_k, proposer_index);
        // Block is valid
        process_block(&mut state, &block_1);
    }
}
