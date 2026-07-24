//! Minimal era-file tool for hdiff benchmarking.
//!
//! Subcommands:
//!   extract-state <era-file> <out.ssz>
//!       Extract the CompressedBeaconState from an era file.
//!   replay <pre.ssz> <blocks-era-file|none> <checkpoints> <out-dir>
//!       Load a state, apply real blocks from the era file (or none, for
//!       skip-slot inactivity-leak simulation), dumping post-block states at
//!       each checkpoint offset (in slots, relative to the pre-state slot).
//!       Offset 0 means "apply the block at the pre-state's own slot".
use ssz::Encode;
use state_processing::{
    AllCaches, BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, per_block_processing,
    state_advance::complete_state_advance,
};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Instant;
use types::{BeaconState, ChainSpec, MainnetEthSpec, SignedBeaconBlock};

type E = MainnetEthSpec;

const TYPE_BLOCK: [u8; 2] = [0x01, 0x00];
const TYPE_STATE: [u8; 2] = [0x02, 0x00];

fn e2store_entries(bytes: &[u8]) -> Vec<([u8; 2], &[u8])> {
    let mut entries = vec![];
    let mut pos = 0;
    while pos + 8 <= bytes.len() {
        let typ = [bytes[pos], bytes[pos + 1]];
        let len = u32::from_le_bytes(bytes[pos + 2..pos + 6].try_into().unwrap()) as usize;
        let start = pos + 8;
        if start + len > bytes.len() {
            break;
        }
        entries.push((typ, &bytes[start..start + len]));
        pos = start + len;
    }
    entries
}

fn snappy_decode(data: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    snap::read::FrameDecoder::new(data)
        .read_to_end(&mut out)
        .expect("snappy decode failed");
    out
}

fn extract_state(era_path: &str, out_path: &str) {
    let bytes = std::fs::read(era_path).expect("read era file");
    for (typ, payload) in e2store_entries(&bytes) {
        if typ == TYPE_STATE {
            let state_bytes = snappy_decode(payload);
            std::fs::write(out_path, &state_bytes).expect("write state");
            println!("wrote {} bytes to {out_path}", state_bytes.len());
            return;
        }
    }
    panic!("no state entry found in {era_path}");
}

fn load_blocks(
    era_path: &str,
    min_slot: u64,
    max_slot: u64,
    spec: &ChainSpec,
) -> BTreeMap<u64, SignedBeaconBlock<E>> {
    let bytes = std::fs::read(era_path).expect("read era file");
    let mut blocks = BTreeMap::new();
    for (typ, payload) in e2store_entries(&bytes) {
        if typ == TYPE_BLOCK {
            let block_bytes = snappy_decode(payload);
            // SignedBeaconBlock SSZ: offset(4) | signature(96) | message(slot u64 first)
            let slot = u64::from_le_bytes(block_bytes[100..108].try_into().unwrap());
            if slot < min_slot || slot > max_slot {
                continue;
            }
            let block =
                SignedBeaconBlock::<E>::from_ssz_bytes(&block_bytes, spec).expect("decode block");
            blocks.insert(slot, block);
        }
    }
    blocks
}

fn replay(pre_path: &str, era_path: &str, checkpoints_arg: &str, out_dir: &str) {
    let spec = ChainSpec::mainnet();
    let checkpoints: Vec<u64> = checkpoints_arg
        .split(',')
        .map(|s| s.parse().expect("bad checkpoint"))
        .collect();
    let max_offset = *checkpoints.iter().max().expect("no checkpoints");

    let t = Instant::now();
    let state_bytes = std::fs::read(pre_path).expect("read state");
    let mut state = BeaconState::<E>::from_ssz_bytes(&state_bytes, &spec).expect("decode state");
    drop(state_bytes);
    let base_slot = state.slot().as_u64();
    println!(
        "loaded state at slot {base_slot} ({:?}) in {:?}",
        state.fork_name_unchecked(),
        t.elapsed()
    );

    let blocks = if era_path == "none" {
        BTreeMap::new()
    } else {
        let t = Instant::now();
        let blocks = load_blocks(era_path, base_slot, base_slot + max_offset, &spec);
        println!("loaded {} blocks in {:?}", blocks.len(), t.elapsed());
        blocks
    };

    let t = Instant::now();
    state.build_all_caches(&spec).expect("build caches");
    println!("built caches in {:?}", t.elapsed());

    let dump = |state: &BeaconState<E>, offset: u64| {
        let out = format!("{out_dir}/state_{}.ssz", state.slot().as_u64());
        let t = Instant::now();
        let bytes = state.as_ssz_bytes();
        std::fs::write(&out, &bytes).expect("write state");
        println!(
            "checkpoint +{offset}: wrote {} bytes to {out} in {:?}",
            bytes.len(),
            t.elapsed()
        );
    };

    let apply_block = |state: &mut BeaconState<E>, block: &SignedBeaconBlock<E>| {
        let mut ctxt = ConsensusContext::new(block.slot());
        per_block_processing(
            state,
            block,
            BlockSignatureStrategy::NoVerification,
            VerifyBlockRoot::True,
            &mut ctxt,
            &spec,
        )
        .unwrap_or_else(|e| panic!("block processing failed at slot {}: {e:?}", block.slot()));
    };

    // Nimbus era states are post-block states: latest_block_header.slot == state.slot when a
    // block existed at the boundary slot. Only apply the base-slot block if it isn't in yet.
    if let Some(block) = blocks.get(&base_slot) {
        if state.latest_block_header().slot < base_slot {
            apply_block(&mut state, block);
            println!("applied block at base slot {base_slot}");
        } else {
            println!("base slot block already applied (post-block era state)");
        }
    }
    if checkpoints.contains(&0) {
        dump(&state, 0);
    }

    let t_all = Instant::now();
    for offset in 1..=max_offset {
        let slot = base_slot + offset;
        complete_state_advance(&mut state, None, slot.into(), &spec)
            .unwrap_or_else(|e| panic!("state advance failed at slot {slot}: {e:?}"));
        if let Some(block) = blocks.get(&slot) {
            apply_block(&mut state, block);
        }
        if checkpoints.contains(&offset) {
            dump(&state, offset);
        }
        if offset % 320 == 0 {
            println!("... slot {slot} (+{offset}) elapsed {:?}", t_all.elapsed());
        }
    }
    println!("replay done in {:?}", t_all.elapsed());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("extract-state") => extract_state(&args[2], &args[3]),
        Some("replay") => replay(&args[2], &args[3], &args[4], &args[5]),
        _ => {
            eprintln!("usage: era_tool extract-state <era> <out.ssz>");
            eprintln!("       era_tool replay <pre.ssz> <blocks-era|none> <cp1,cp2,...> <out-dir>");
            std::process::exit(1);
        }
    }
}
