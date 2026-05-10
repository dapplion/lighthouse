//! Direct-byte SSZ blinder for the ERA importer's hot path.
//!
//! `clone_as_blinded` + `as_ssz_bytes` requires a full typed parse of the
//! `SignedBeaconBlock`, which dominates per-block CPU because it allocates the
//! attestations / deposits / sync committee bits / etc. — all of which we then
//! immediately discard. For the ERA-import case we already know we're going
//! to throw the typed body away after writing the blinded SSZ to cold, so we
//! skip the parse and walk SSZ container offsets directly.
//!
//! Supported forks (mainnet ERA range eras 0..1260):
//! - **Phase 0 / Altair** — `FullPayload` and `BlindedPayload` SSZ-encodings
//!   are identical (no `execution_payload` field); the snappy-decompressed
//!   bytes from the ERA file *are* already the blinded encoding. Returned as-is.
//! - **Capella** — full custom byte walker; output verified byte-identical
//!   against `clone_as_blinded().as_ssz_bytes()` in `examples/blinder_bench.rs`.
//! - **Deneb** — same shape with the extra `blob_kzg_commitments` body offset
//!   and `blob_gas_used` / `excess_blob_gas` payload fields.
//!
//! Bellatrix and Electra+ are not implemented here; callers fall back to the
//! typed `clone_as_blinded` + `as_ssz_bytes` path for those.

use ssz::Decode;
use tree_hash::TreeHash;
use types::{EthSpec, Slot, Transactions, Withdrawals};

// SignedBeaconBlock outer layout: { msg_offset(4), signature(96), msg_bytes }.
const SBB_HEADER_LEN: usize = 100;
// BeaconBlock layout: { slot(8), proposer(8), parent_root(32), state_root(32),
// body_offset(4), body_bytes }.
const BB_HEADER_LEN: usize = 84;

// BeaconBlockBody fixed-part offsets common to Bellatrix..Deneb.
const BODY_OFF_EXEC_PAYLOAD: usize = 380;
const BODY_OFF_BLS_CHANGES: usize = 384; // Capella+
const BODY_OFF_BLOB_KZG: usize = 388; // Deneb+
const CAPELLA_BODY_FIXED_LEN: usize = 388;
const DENEB_BODY_FIXED_LEN: usize = 392;

// ExecutionPayload Bellatrix..Deneb shared layout up to byte 504.
const PAYLOAD_OFF_EXTRA_DATA: usize = 436;
const PAYLOAD_OFF_TRANSACTIONS: usize = 504;
const PAYLOAD_OFF_WITHDRAWALS: usize = 508; // Capella+

// ExecutionPayloadHeader fixed sizes (transactions_root + withdrawals_root
// replace 4-byte offsets with 32-byte hashes; +28 each).
const CAPELLA_HEADER_FIXED_LEN: usize = 568;
const DENEB_HEADER_FIXED_LEN: usize = 584;

/// Read the `slot` field from the start of a `SignedBeaconBlock` SSZ encoding.
/// Layout: 4 (msg_offset) + 96 (signature) = 100 bytes header, then the
/// `BeaconBlock` whose first field is `slot: u64` (8 bytes little-endian).
pub fn slot_from_ssz_bytes(bytes: &[u8]) -> Slot {
    let raw = u64::from_le_bytes(
        bytes[SBB_HEADER_LEN..SBB_HEADER_LEN + 8]
            .try_into()
            .expect("SignedBeaconBlock too short"),
    );
    Slot::new(raw)
}

fn read_u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("u32 slice"))
}

/// Sliced outer fields of a `SignedBeaconBlock` SSZ encoding, ready to splice
/// back into a new `SignedBeaconBlock` whose only difference is the body's
/// execution payload.
struct OuterFields<'a> {
    signature: &'a [u8],
    slot: &'a [u8],
    proposer_index: &'a [u8],
    parent_root: &'a [u8],
    state_root: &'a [u8],
    body: &'a [u8],
}

fn split_outer(signed: &[u8]) -> OuterFields<'_> {
    let signature = &signed[4..SBB_HEADER_LEN];
    let bb = &signed[SBB_HEADER_LEN..];
    OuterFields {
        signature,
        slot: &bb[0..8],
        proposer_index: &bb[8..16],
        parent_root: &bb[16..48],
        state_root: &bb[48..80],
        body: &bb[BB_HEADER_LEN..],
    }
}

fn assemble_signed_block(
    signature: &[u8],
    slot: &[u8],
    proposer_index: &[u8],
    parent_root: &[u8],
    state_root: &[u8],
    new_body: &[u8],
) -> Vec<u8> {
    let mut new_bb = Vec::with_capacity(BB_HEADER_LEN + new_body.len());
    new_bb.extend_from_slice(slot);
    new_bb.extend_from_slice(proposer_index);
    new_bb.extend_from_slice(parent_root);
    new_bb.extend_from_slice(state_root);
    new_bb.extend_from_slice(&(BB_HEADER_LEN as u32).to_le_bytes());
    new_bb.extend_from_slice(new_body);

    let mut new_sbb = Vec::with_capacity(SBB_HEADER_LEN + new_bb.len());
    new_sbb.extend_from_slice(&(SBB_HEADER_LEN as u32).to_le_bytes());
    new_sbb.extend_from_slice(signature);
    new_sbb.extend_from_slice(&new_bb);
    new_sbb
}

fn build_capella_payload_header(
    exec_bytes: &[u8],
    transactions_root: &[u8],
    withdrawals_root: &[u8],
    extra_data_bytes: &[u8],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(CAPELLA_HEADER_FIXED_LEN + extra_data_bytes.len());
    header.extend_from_slice(&exec_bytes[0..PAYLOAD_OFF_EXTRA_DATA]);
    header.extend_from_slice(&(CAPELLA_HEADER_FIXED_LEN as u32).to_le_bytes());
    header.extend_from_slice(&exec_bytes[PAYLOAD_OFF_EXTRA_DATA + 4..PAYLOAD_OFF_TRANSACTIONS]);
    header.extend_from_slice(transactions_root);
    header.extend_from_slice(withdrawals_root);
    header.extend_from_slice(extra_data_bytes);
    header
}

fn build_deneb_payload_header(
    exec_bytes: &[u8],
    transactions_root: &[u8],
    withdrawals_root: &[u8],
    blob_gas_used: &[u8],
    excess_blob_gas: &[u8],
    extra_data_bytes: &[u8],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(DENEB_HEADER_FIXED_LEN + extra_data_bytes.len());
    header.extend_from_slice(&exec_bytes[0..PAYLOAD_OFF_EXTRA_DATA]);
    header.extend_from_slice(&(DENEB_HEADER_FIXED_LEN as u32).to_le_bytes());
    header.extend_from_slice(&exec_bytes[PAYLOAD_OFF_EXTRA_DATA + 4..PAYLOAD_OFF_TRANSACTIONS]);
    header.extend_from_slice(transactions_root);
    header.extend_from_slice(withdrawals_root);
    header.extend_from_slice(blob_gas_used);
    header.extend_from_slice(excess_blob_gas);
    header.extend_from_slice(extra_data_bytes);
    header
}

/// Fast direct-byte blinder for Capella `SignedBeaconBlock`.
pub fn custom_blind_capella<E: EthSpec>(signed: &[u8]) -> Result<Vec<u8>, ssz::DecodeError> {
    let OuterFields {
        signature,
        slot,
        proposer_index,
        parent_root,
        state_root,
        body,
    } = split_outer(signed);

    let off_exec = read_u32_le(body, BODY_OFF_EXEC_PAYLOAD) as usize;
    let off_bls = read_u32_le(body, BODY_OFF_BLS_CHANGES) as usize;
    let exec_bytes = &body[off_exec..off_bls];
    let bls_bytes = &body[off_bls..];

    let off_extra = read_u32_le(exec_bytes, PAYLOAD_OFF_EXTRA_DATA) as usize;
    let off_txs = read_u32_le(exec_bytes, PAYLOAD_OFF_TRANSACTIONS) as usize;
    let off_with = read_u32_le(exec_bytes, PAYLOAD_OFF_WITHDRAWALS) as usize;
    let extra = &exec_bytes[off_extra..off_txs];
    let txs = &exec_bytes[off_txs..off_with];
    let withs = &exec_bytes[off_with..];

    let transactions_root = Transactions::<E>::from_ssz_bytes(txs)?.tree_hash_root();
    let withdrawals_root = Withdrawals::<E>::from_ssz_bytes(withs)?.tree_hash_root();

    let header = build_capella_payload_header(
        exec_bytes,
        transactions_root.as_slice(),
        withdrawals_root.as_slice(),
        extra,
    );

    let new_off_bls: u32 = (off_exec as u32) + (header.len() as u32);
    let mut new_body = Vec::with_capacity(
        CAPELLA_BODY_FIXED_LEN
            + (off_exec - CAPELLA_BODY_FIXED_LEN)
            + header.len()
            + bls_bytes.len(),
    );
    new_body.extend_from_slice(&body[0..BODY_OFF_BLS_CHANGES]);
    new_body.extend_from_slice(&new_off_bls.to_le_bytes());
    new_body.extend_from_slice(&body[CAPELLA_BODY_FIXED_LEN..off_exec]);
    new_body.extend_from_slice(&header);
    new_body.extend_from_slice(bls_bytes);

    Ok(assemble_signed_block(
        signature,
        slot,
        proposer_index,
        parent_root,
        state_root,
        &new_body,
    ))
}

/// Fast direct-byte blinder for Deneb `SignedBeaconBlock`.
pub fn custom_blind_deneb<E: EthSpec>(signed: &[u8]) -> Result<Vec<u8>, ssz::DecodeError> {
    let OuterFields {
        signature,
        slot,
        proposer_index,
        parent_root,
        state_root,
        body,
    } = split_outer(signed);

    let off_exec = read_u32_le(body, BODY_OFF_EXEC_PAYLOAD) as usize;
    let off_bls = read_u32_le(body, BODY_OFF_BLS_CHANGES) as usize;
    let off_blob_kzg = read_u32_le(body, BODY_OFF_BLOB_KZG) as usize;
    let exec_bytes = &body[off_exec..off_bls];
    let bls_bytes = &body[off_bls..off_blob_kzg];
    let blob_kzg_bytes = &body[off_blob_kzg..];

    let off_extra = read_u32_le(exec_bytes, PAYLOAD_OFF_EXTRA_DATA) as usize;
    let off_txs = read_u32_le(exec_bytes, PAYLOAD_OFF_TRANSACTIONS) as usize;
    let off_with = read_u32_le(exec_bytes, PAYLOAD_OFF_WITHDRAWALS) as usize;
    let blob_gas_used = &exec_bytes[512..520];
    let excess_blob_gas = &exec_bytes[520..528];
    let extra = &exec_bytes[off_extra..off_txs];
    let txs = &exec_bytes[off_txs..off_with];
    let withs = &exec_bytes[off_with..];

    let transactions_root = Transactions::<E>::from_ssz_bytes(txs)?.tree_hash_root();
    let withdrawals_root = Withdrawals::<E>::from_ssz_bytes(withs)?.tree_hash_root();

    let header = build_deneb_payload_header(
        exec_bytes,
        transactions_root.as_slice(),
        withdrawals_root.as_slice(),
        blob_gas_used,
        excess_blob_gas,
        extra,
    );

    let new_off_bls: u32 = (off_exec as u32) + (header.len() as u32);
    let new_off_blob_kzg: u32 = new_off_bls + bls_bytes.len() as u32;
    let mut new_body = Vec::with_capacity(
        DENEB_BODY_FIXED_LEN
            + (off_exec - DENEB_BODY_FIXED_LEN)
            + header.len()
            + bls_bytes.len()
            + blob_kzg_bytes.len(),
    );
    new_body.extend_from_slice(&body[0..BODY_OFF_BLS_CHANGES]);
    new_body.extend_from_slice(&new_off_bls.to_le_bytes());
    new_body.extend_from_slice(&new_off_blob_kzg.to_le_bytes());
    new_body.extend_from_slice(&body[DENEB_BODY_FIXED_LEN..off_exec]);
    new_body.extend_from_slice(&header);
    new_body.extend_from_slice(bls_bytes);
    new_body.extend_from_slice(blob_kzg_bytes);

    Ok(assemble_signed_block(
        signature,
        slot,
        proposer_index,
        parent_root,
        state_root,
        &new_body,
    ))
}
