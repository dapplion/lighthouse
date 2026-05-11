//! Pull a single SignedBeaconBlock SSZ payload out of a Nimbus-format ERA file and
//! write it to disk. Used to prepare a fixture for `blinder_bench.rs`.
//!
//!     cargo run --release --example extract_block -p store -- <era_file> <slot> <out>

use reth_era::common::file_ops::StreamReader;
use reth_era::era::file::EraReader;
use std::env;
use std::fs::File;
use std::path::PathBuf;

fn main() {
    let era_path: PathBuf = env::args().nth(1).expect("era_file path").into();
    let target_slot: u64 = env::args()
        .nth(2)
        .expect("target slot")
        .parse()
        .expect("slot must be u64");
    let out_path: PathBuf = env::args().nth(3).expect("out path").into();

    let file = File::open(&era_path).expect("open era file");
    let network = "mainnet".to_string();
    let era_file = EraReader::new(file)
        .read_and_assemble(network)
        .expect("read era");

    let mut closest: Option<(u64, Vec<u8>)> = None;
    for compressed in era_file.group.blocks {
        let bytes = compressed.decompress().expect("decompress");
        if bytes.len() < 108 {
            continue;
        }
        let slot = u64::from_le_bytes(bytes[100..108].try_into().expect("slice"));
        if slot == target_slot {
            std::fs::write(&out_path, &bytes).expect("write");
            println!(
                "wrote {} bytes for slot {} -> {}",
                bytes.len(),
                slot,
                out_path.display()
            );
            return;
        }
        // Track block whose slot is >= target (helps when caller picked a skipped slot).
        if slot >= target_slot && closest.as_ref().is_none_or(|(s, _)| slot < *s) {
            closest = Some((slot, bytes));
        }
    }
    if let Some((slot, bytes)) = closest {
        std::fs::write(&out_path, &bytes).expect("write");
        println!(
            "exact slot {target_slot} skipped; wrote next non-skip slot {} ({} bytes) -> {}",
            slot,
            bytes.len(),
            out_path.display()
        );
        return;
    }
    panic!(
        "no block at or after slot {target_slot} in {}",
        era_path.display()
    );
}
