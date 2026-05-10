//! Microbenchmark: full SSZ-parse-then-blind-then-encode vs a custom
//! direct-byte blinder for a single Capella SignedBeaconBlock.
//!
//! Input: `/tmp/sample_block.ssz` (extracted via `extract_block`).
//!
//! Method A (current ERA-import path):
//!   `SignedBeaconBlock::from_ssz_bytes` -> `clone_as_blinded` -> `as_ssz_bytes`
//!
//! Method B (custom):
//!   walk SSZ container offsets directly, locate `execution_payload`'s
//!   transactions and withdrawals byte slices, parse only those into typed
//!   `VariableList`s, compute their `tree_hash_root`, then assemble a
//!   blinded SignedBeaconBlock SSZ output by splicing scalars + the new
//!   ExecutionPayloadHeader bytes.
//!
//! Run:
//!     cargo run --release --example blinder_bench -p beacon_chain -- [iters]

use ssz::{Decode, Encode};
use std::env;
use std::time::Instant;
use tree_hash::TreeHash;
use types::{ChainSpec, EthSpec, MainnetEthSpec, SignedBeaconBlock};
use types::{Transactions, Withdrawals};

const SAMPLE_PATH: &str = "/tmp/sample_block.ssz";
const SAMPLE_PATH_DENEB: &str = "/tmp/sample_block_deneb.ssz";

// Deneb additions vs Capella:
//
// BeaconBlockBody Deneb fixed part = 392 bytes (Capella 388 + blob_kzg_commitments offset).
//   off_blob_kzg_commitments: 4   [388 .. 392]
const DENEB_BODY_FIXED_LEN: usize = 392;
const BODY_OFF_BLOB_KZG: usize = 388;
//
// ExecutionPayload Deneb adds blob_gas_used(8) + excess_blob_gas(8) at the end of the
// fixed part. New layout (bytes 0..512 same as Capella, then):
//   blob_gas_used:   8   [512 .. 520]
//   excess_blob_gas: 8   [520 .. 528]
const DENEB_PAYLOAD_FIXED_LEN: usize = 528;
//
// ExecutionPayloadHeader Deneb fixed = 584 bytes (header Capella 568 + 16 for blob_gas_used + excess_blob_gas).
const DENEB_HEADER_FIXED_LEN: usize = 584;

// Capella BeaconBlockBody fixed-part layout (bytes from start of body):
//   randao_reveal:                96    [0   .. 96]
//   eth1_data:                    72    [96  .. 168]
//   graffiti:                     32    [168 .. 200]
//   off_proposer_slashings:        4    [200 .. 204]
//   off_attester_slashings:        4    [204 .. 208]
//   off_attestations:              4    [208 .. 212]
//   off_deposits:                  4    [212 .. 216]
//   off_voluntary_exits:           4    [216 .. 220]
//   sync_aggregate:              160    [220 .. 380]
//   off_execution_payload:         4    [380 .. 384]
//   off_bls_to_execution_changes:  4    [384 .. 388]
//   <variable region>                  [388 ..]
const CAPELLA_BODY_FIXED_LEN: usize = 388;
const BODY_OFF_EXEC_PAYLOAD: usize = 380;
const BODY_OFF_BLS_CHANGES: usize = 384;

// Capella ExecutionPayload fixed-part layout (bytes from start of payload):
//   parent_hash:        32   [0   .. 32]
//   fee_recipient:      20   [32  .. 52]
//   state_root:         32   [52  .. 84]
//   receipts_root:      32   [84  .. 116]
//   logs_bloom:        256   [116 .. 372]
//   prev_randao:        32   [372 .. 404]
//   block_number:        8   [404 .. 412]
//   gas_limit:           8   [412 .. 420]
//   gas_used:            8   [420 .. 428]
//   timestamp:           8   [428 .. 436]
//   off_extra_data:      4   [436 .. 440]
//   base_fee_per_gas:   32   [440 .. 472]
//   block_hash:         32   [472 .. 504]
//   off_transactions:    4   [504 .. 508]
//   off_withdrawals:     4   [508 .. 512]
const PAYLOAD_FIXED_LEN: usize = 512;
const PAYLOAD_OFF_EXTRA_DATA: usize = 436;
const PAYLOAD_OFF_TRANSACTIONS: usize = 504;
const PAYLOAD_OFF_WITHDRAWALS: usize = 508;

// Capella ExecutionPayloadHeader fixed-part layout (bytes from start of header):
//   ... same scalars / logs_bloom (436 bytes) ...
//   off_extra_data:      4   [436 .. 440]
//   base_fee_per_gas:   32   [440 .. 472]
//   block_hash:         32   [472 .. 504]
//   transactions_root:  32   [504 .. 536]      (was a 4-byte offset in payload)
//   withdrawals_root:   32   [536 .. 568]      (was a 4-byte offset in payload)
const HEADER_FIXED_LEN: usize = 568;

fn read_u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn custom_blind_capella<E: EthSpec>(signed_block: &[u8]) -> Vec<u8> {
    // Outer SignedBeaconBlock: { msg_offset(4), signature(96), msg_bytes... }
    // msg_offset must be 100 (4 + 96).
    let signature = &signed_block[4..100];
    let bb = &signed_block[100..];

    // Inner BeaconBlock: { slot(8), proposer_index(8), parent_root(32),
    //                     state_root(32), body_offset(4), body_bytes... }
    let slot = &bb[0..8];
    let proposer_index = &bb[8..16];
    let parent_root = &bb[16..48];
    let state_root = &bb[48..80];
    // body_offset must be 84 (80 + 4).
    let body = &bb[84..];

    // Capella body fixed part + offset table.
    let off_exec = read_u32_le(body, BODY_OFF_EXEC_PAYLOAD) as usize;
    let off_bls = read_u32_le(body, BODY_OFF_BLS_CHANGES) as usize;
    let exec_bytes = &body[off_exec..off_bls];
    let bls_bytes = &body[off_bls..];

    // Capella ExecutionPayload fixed part + offset table.
    let off_extra_data = read_u32_le(exec_bytes, PAYLOAD_OFF_EXTRA_DATA) as usize;
    let off_transactions = read_u32_le(exec_bytes, PAYLOAD_OFF_TRANSACTIONS) as usize;
    let off_withdrawals = read_u32_le(exec_bytes, PAYLOAD_OFF_WITHDRAWALS) as usize;
    let extra_data_bytes = &exec_bytes[off_extra_data..off_transactions];
    let transactions_bytes = &exec_bytes[off_transactions..off_withdrawals];
    let withdrawals_bytes = &exec_bytes[off_withdrawals..];

    // Parse JUST the transactions / withdrawals slices. Skips the rest of the
    // typed BeaconBlock parse (attestations, sync committee bits, deposits, …)
    // which is where most of the allocation cost lives. Tree-hashing the
    // transactions list is the irreducible part of producing the header.
    let transactions =
        Transactions::<E>::from_ssz_bytes(transactions_bytes).expect("transactions decode");
    let transactions_root = transactions.tree_hash_root();
    let withdrawals =
        Withdrawals::<E>::from_ssz_bytes(withdrawals_bytes).expect("withdrawals decode");
    let withdrawals_root = withdrawals.tree_hash_root();

    // Build the new ExecutionPayloadHeader (Capella) bytes.
    let mut header = Vec::with_capacity(HEADER_FIXED_LEN + extra_data_bytes.len());
    // Scalars + logs_bloom carried verbatim from the payload (bytes 0..436).
    header.extend_from_slice(&exec_bytes[0..PAYLOAD_OFF_EXTRA_DATA]);
    // The header has only one variable field (extra_data), which sits right
    // after the fixed part.
    let header_extra_data_off: u32 = HEADER_FIXED_LEN as u32;
    header.extend_from_slice(&header_extra_data_off.to_le_bytes()); // 4 bytes
    header.extend_from_slice(&exec_bytes[PAYLOAD_OFF_EXTRA_DATA + 4..PAYLOAD_OFF_TRANSACTIONS]); // base_fee + block_hash
    header.extend_from_slice(transactions_root.as_slice()); // 32
    header.extend_from_slice(withdrawals_root.as_slice()); // 32
    header.extend_from_slice(extra_data_bytes); // variable

    // New body bytes: copy fixed part (388 bytes), then bytes between body
    // fixed part and exec_payload (the prefix variable fields), then the
    // header bytes, then bls_to_execution_changes bytes. The exec_payload
    // offset stays the same (variable region position unchanged); the
    // bls_changes offset shifts by the size delta.
    let new_off_bls: u32 = (off_exec as u32) + (header.len() as u32);
    let mut new_body = Vec::with_capacity(
        CAPELLA_BODY_FIXED_LEN
            + (off_exec - CAPELLA_BODY_FIXED_LEN)
            + header.len()
            + bls_bytes.len(),
    );
    // Fixed part with patched bls_changes offset.
    new_body.extend_from_slice(&body[0..BODY_OFF_BLS_CHANGES]); // 0..384 (incl. exec offset still at 380..384)
    new_body.extend_from_slice(&new_off_bls.to_le_bytes()); // 384..388
    new_body.extend_from_slice(&body[CAPELLA_BODY_FIXED_LEN..off_exec]); // prefix variable
    new_body.extend_from_slice(&header);
    new_body.extend_from_slice(bls_bytes);

    // New BeaconBlock bytes.
    let mut new_bb = Vec::with_capacity(84 + new_body.len());
    new_bb.extend_from_slice(slot);
    new_bb.extend_from_slice(proposer_index);
    new_bb.extend_from_slice(parent_root);
    new_bb.extend_from_slice(state_root);
    new_bb.extend_from_slice(&84u32.to_le_bytes());
    new_bb.extend_from_slice(&new_body);

    // New SignedBeaconBlock bytes.
    let mut new_sbb = Vec::with_capacity(100 + new_bb.len());
    new_sbb.extend_from_slice(&100u32.to_le_bytes());
    new_sbb.extend_from_slice(signature);
    new_sbb.extend_from_slice(&new_bb);
    new_sbb
}

fn custom_blind_deneb<E: EthSpec>(signed_block: &[u8]) -> Vec<u8> {
    let signature = &signed_block[4..100];
    let bb = &signed_block[100..];
    let slot = &bb[0..8];
    let proposer_index = &bb[8..16];
    let parent_root = &bb[16..48];
    let state_root = &bb[48..80];
    let body = &bb[84..];

    // Deneb body has three trailing variable offsets: execution_payload,
    // bls_to_execution_changes, blob_kzg_commitments.
    let off_exec = read_u32_le(body, BODY_OFF_EXEC_PAYLOAD) as usize;
    let off_bls = read_u32_le(body, BODY_OFF_BLS_CHANGES) as usize;
    let off_blob_kzg = read_u32_le(body, BODY_OFF_BLOB_KZG) as usize;
    let exec_bytes = &body[off_exec..off_bls];
    let bls_bytes = &body[off_bls..off_blob_kzg];
    let blob_kzg_bytes = &body[off_blob_kzg..];

    // Deneb ExecutionPayload: same scalars+offset table as Capella, plus
    // blob_gas_used (8) + excess_blob_gas (8) at the end.
    let off_extra_data = read_u32_le(exec_bytes, PAYLOAD_OFF_EXTRA_DATA) as usize;
    let off_transactions = read_u32_le(exec_bytes, PAYLOAD_OFF_TRANSACTIONS) as usize;
    let off_withdrawals = read_u32_le(exec_bytes, PAYLOAD_OFF_WITHDRAWALS) as usize;
    let blob_gas_used = &exec_bytes[512..520];
    let excess_blob_gas = &exec_bytes[520..528];
    let extra_data_bytes = &exec_bytes[off_extra_data..off_transactions];
    let transactions_bytes = &exec_bytes[off_transactions..off_withdrawals];
    let withdrawals_bytes = &exec_bytes[off_withdrawals..];

    let transactions =
        Transactions::<E>::from_ssz_bytes(transactions_bytes).expect("transactions decode");
    let transactions_root = transactions.tree_hash_root();
    let withdrawals =
        Withdrawals::<E>::from_ssz_bytes(withdrawals_bytes).expect("withdrawals decode");
    let withdrawals_root = withdrawals.tree_hash_root();

    // Build Deneb ExecutionPayloadHeader: fixed scalars (0..436) + extra_data offset
    // (4) + base_fee_per_gas (32) + block_hash (32) + transactions_root (32) +
    // withdrawals_root (32) + blob_gas_used (8) + excess_blob_gas (8) + extra_data.
    let mut header = Vec::with_capacity(DENEB_HEADER_FIXED_LEN + extra_data_bytes.len());
    header.extend_from_slice(&exec_bytes[0..PAYLOAD_OFF_EXTRA_DATA]); // 0..436
    let header_extra_data_off: u32 = DENEB_HEADER_FIXED_LEN as u32;
    header.extend_from_slice(&header_extra_data_off.to_le_bytes()); // 4 bytes
    header.extend_from_slice(&exec_bytes[PAYLOAD_OFF_EXTRA_DATA + 4..PAYLOAD_OFF_TRANSACTIONS]); // base_fee + block_hash
    header.extend_from_slice(transactions_root.as_slice());
    header.extend_from_slice(withdrawals_root.as_slice());
    header.extend_from_slice(blob_gas_used);
    header.extend_from_slice(excess_blob_gas);
    header.extend_from_slice(extra_data_bytes);

    // Body: 392-byte fixed part with patched bls + blob_kzg offsets, then
    // [388..off_exec] prefix variable, then header bytes, then bls_bytes, then
    // blob_kzg_bytes.
    let new_off_bls: u32 = (off_exec as u32) + (header.len() as u32);
    let new_off_blob_kzg: u32 = new_off_bls + bls_bytes.len() as u32;
    let mut new_body = Vec::with_capacity(
        DENEB_BODY_FIXED_LEN
            + (off_exec - DENEB_BODY_FIXED_LEN)
            + header.len()
            + bls_bytes.len()
            + blob_kzg_bytes.len(),
    );
    new_body.extend_from_slice(&body[0..BODY_OFF_BLS_CHANGES]); // 0..384 (incl. exec offset)
    new_body.extend_from_slice(&new_off_bls.to_le_bytes()); // 384..388
    new_body.extend_from_slice(&new_off_blob_kzg.to_le_bytes()); // 388..392
    new_body.extend_from_slice(&body[DENEB_BODY_FIXED_LEN..off_exec]); // prefix variable
    new_body.extend_from_slice(&header);
    new_body.extend_from_slice(bls_bytes);
    new_body.extend_from_slice(blob_kzg_bytes);

    // Wrap in BeaconBlock + SignedBeaconBlock.
    let mut new_bb = Vec::with_capacity(84 + new_body.len());
    new_bb.extend_from_slice(slot);
    new_bb.extend_from_slice(proposer_index);
    new_bb.extend_from_slice(parent_root);
    new_bb.extend_from_slice(state_root);
    new_bb.extend_from_slice(&84u32.to_le_bytes());
    new_bb.extend_from_slice(&new_body);

    let mut new_sbb = Vec::with_capacity(100 + new_bb.len());
    new_sbb.extend_from_slice(&100u32.to_le_bytes());
    new_sbb.extend_from_slice(signature);
    new_sbb.extend_from_slice(&new_bb);
    new_sbb
}

fn run_one(label: &str, path: &str, custom: fn(&[u8]) -> Vec<u8>, iters: usize, spec: &ChainSpec) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("# skipping {label}: failed to read {path}: {e}");
            return;
        }
    };
    println!(
        "\n=== {label} ===  input {} bytes, {iters} iters",
        bytes.len()
    );

    let block: SignedBeaconBlock<MainnetEthSpec> =
        SignedBeaconBlock::from_ssz_bytes(&bytes, spec).expect("parse");
    let canonical = block.clone_as_blinded().as_ssz_bytes();
    let custom_out = custom(&bytes);
    println!(
        "canonical blinded len = {}, custom blinded len = {}, equal = {}",
        canonical.len(),
        custom_out.len(),
        canonical == custom_out
    );

    let usper = |dt: std::time::Duration| dt.as_secs_f64() * 1e6 / iters as f64;

    let t = Instant::now();
    for _ in 0..iters {
        let _b: SignedBeaconBlock<MainnetEthSpec> =
            SignedBeaconBlock::from_ssz_bytes(&bytes, spec).unwrap();
    }
    let dt_a1 = t.elapsed();

    let t = Instant::now();
    for _ in 0..iters {
        let b: SignedBeaconBlock<MainnetEthSpec> =
            SignedBeaconBlock::from_ssz_bytes(&bytes, spec).unwrap();
        let bl = b.clone_as_blinded();
        let _bytes = bl.as_ssz_bytes();
    }
    let dt_a3 = t.elapsed();

    let t = Instant::now();
    for _ in 0..iters {
        let _ = custom(&bytes);
    }
    let dt_b = t.elapsed();

    println!("{:<48} {:>12.1} us/iter", "A1: parse only", usper(dt_a1));
    println!(
        "{:<48} {:>12.1} us/iter",
        "A3: parse + clone_as_blinded + as_ssz_bytes",
        usper(dt_a3)
    );
    println!(
        "{:<48} {:>12.1} us/iter",
        "B:  custom direct-byte blinder",
        usper(dt_b)
    );
    println!(
        "speedup B vs A3: {:.2}x",
        dt_a3.as_secs_f64() / dt_b.as_secs_f64()
    );
}

fn main() {
    let iters: usize = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let spec = ChainSpec::mainnet();
    run_one(
        "Capella",
        SAMPLE_PATH,
        custom_blind_capella::<MainnetEthSpec>,
        iters,
        &spec,
    );
    run_one(
        "Deneb",
        SAMPLE_PATH_DENEB,
        custom_blind_deneb::<MainnetEthSpec>,
        iters,
        &spec,
    );
}

fn _main_old() {
    let iters: usize = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let bytes = std::fs::read(SAMPLE_PATH).expect("read sample block");
    println!("# input size: {} bytes", bytes.len());
    println!("# iters: {iters}");
    let spec = ChainSpec::mainnet();

    // Sanity check: parse once and report block size info.
    let block: SignedBeaconBlock<MainnetEthSpec> =
        SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).expect("parse");
    let blinded = block.clone_as_blinded();
    let canonical_blinded = blinded.as_ssz_bytes();
    let custom_blinded = custom_blind_capella::<MainnetEthSpec>(&bytes);
    println!(
        "# canonical blinded len = {}, custom blinded len = {}, equal = {}",
        canonical_blinded.len(),
        custom_blinded.len(),
        canonical_blinded == custom_blinded
    );

    // ---- Method A1: parse only ----
    let t = Instant::now();
    for _ in 0..iters {
        let _b: SignedBeaconBlock<MainnetEthSpec> =
            SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).unwrap();
    }
    let dt_a1 = t.elapsed();

    // ---- Method A2: parse + clone_as_blinded ----
    let t = Instant::now();
    for _ in 0..iters {
        let b: SignedBeaconBlock<MainnetEthSpec> =
            SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).unwrap();
        let _bl = b.clone_as_blinded();
    }
    let dt_a2 = t.elapsed();

    // ---- Method A3: full path = parse + clone_as_blinded + as_ssz_bytes ----
    let t = Instant::now();
    for _ in 0..iters {
        let b: SignedBeaconBlock<MainnetEthSpec> =
            SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).unwrap();
        let bl = b.clone_as_blinded();
        let _bytes = bl.as_ssz_bytes();
    }
    let dt_a3 = t.elapsed();

    // ---- Method B: custom direct-byte blinder ----
    let t = Instant::now();
    for _ in 0..iters {
        let _ = custom_blind_capella::<MainnetEthSpec>(&bytes);
    }
    let dt_b = t.elapsed();

    let usper = |dt: std::time::Duration| dt.as_secs_f64() * 1e6 / iters as f64;
    println!();
    println!("{:<48} {:>12} {:>14}", "method", "us/iter", "blocks/s");
    println!(
        "{:<48} {:>12.1} {:>14.1}",
        "A1: from_ssz_bytes (parse only)",
        usper(dt_a1),
        iters as f64 / dt_a1.as_secs_f64()
    );
    println!(
        "{:<48} {:>12.1} {:>14.1}",
        "A2: parse + clone_as_blinded",
        usper(dt_a2),
        iters as f64 / dt_a2.as_secs_f64()
    );
    println!(
        "{:<48} {:>12.1} {:>14.1}",
        "A3: parse + clone_as_blinded + as_ssz_bytes (current)",
        usper(dt_a3),
        iters as f64 / dt_a3.as_secs_f64()
    );
    println!(
        "{:<48} {:>12.1} {:>14.1}",
        "B:  custom direct-byte blinder",
        usper(dt_b),
        iters as f64 / dt_b.as_secs_f64()
    );
    println!(
        "speedup B vs A3: {:.2}x",
        dt_a3.as_secs_f64() / dt_b.as_secs_f64()
    );
}
