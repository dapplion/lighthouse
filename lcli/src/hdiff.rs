//! Compute and apply hierarchical state diffs (hdiffs) for testing and benchmarking.
use crate::transition_blocks::load_from_ssz_with;
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use eth2_network_config::Eth2NetworkConfig;
use ssz::{Decode, Encode};
use std::path::PathBuf;
use std::time::Instant;
use store::StoreConfig;
use store::hdiff::{HDiff, HDiffBuffer};
use types::{BeaconState, EthSpec};

pub fn run_compute<E: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config.chain_spec::<E>()?;

    let pre_state_path: PathBuf = parse_required(matches, "pre-state")?;
    let post_state_path: PathBuf = parse_required(matches, "post-state")?;
    let output_path: PathBuf = parse_required(matches, "output")?;
    let runs: usize = parse_required(matches, "runs")?;

    let config = StoreConfig::default();

    let pre_state = load_from_ssz_with(&pre_state_path, spec, BeaconState::<E>::from_ssz_bytes)?;
    let post_state = load_from_ssz_with(&post_state_path, spec, BeaconState::<E>::from_ssz_bytes)?;

    println!(
        "Pre-state: slot {} ({})",
        pre_state.slot(),
        pre_state.fork_name_unchecked()
    );
    println!(
        "Post-state: slot {} ({})",
        post_state.slot(),
        post_state.fork_name_unchecked()
    );

    let t = Instant::now();
    let pre_buffer = HDiffBuffer::from_state(pre_state);
    println!("Pre-state buffer creation: {:?}", t.elapsed());

    let t = Instant::now();
    let post_buffer = HDiffBuffer::from_state(post_state);
    println!("Post-state buffer creation: {:?}", t.elapsed());

    println!(
        "Buffer sizes: pre {} bytes, post {} bytes",
        pre_buffer.size(),
        post_buffer.size()
    );

    let mut diff = None;
    for i in 0..runs {
        let t = Instant::now();
        diff = Some(
            HDiff::compute(&pre_buffer, &post_buffer, &config)
                .map_err(|e| format!("failed to compute diff: {e:?}"))?,
        );
        println!("Run {i}: compute time {:?}", t.elapsed());
    }
    let diff = diff.ok_or("runs must be greater than 0")?;

    println!(
        "Component sizes (state, balances, inactivity, validators, historical roots, \
         historical summaries, pending deposits, pending partial withdrawals, pending \
         consolidations): {:?}",
        diff.sizes()
    );

    let diff_bytes = diff.as_ssz_bytes();
    println!("Diff size: {} bytes", diff_bytes.len());

    std::fs::write(&output_path, &diff_bytes)
        .map_err(|e| format!("failed to write diff to {}: {e}", output_path.display()))?;
    println!("Wrote diff to {}", output_path.display());

    Ok(())
}

pub fn run_apply<E: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config.chain_spec::<E>()?;

    let pre_state_path: PathBuf = parse_required(matches, "pre-state")?;
    let diff_path: PathBuf = parse_required(matches, "diff")?;
    let output_path: Option<PathBuf> = parse_optional(matches, "output")?;
    let expected_post_state_path: Option<PathBuf> = parse_optional(matches, "post-state")?;
    let runs: usize = parse_required(matches, "runs")?;

    let diff_bytes = std::fs::read(&diff_path)
        .map_err(|e| format!("failed to read diff from {}: {e}", diff_path.display()))?;
    let diff =
        HDiff::from_ssz_bytes(&diff_bytes).map_err(|e| format!("failed to decode diff: {e:?}"))?;

    let config = StoreConfig::default();

    let pre_state = load_from_ssz_with(&pre_state_path, spec, BeaconState::<E>::from_ssz_bytes)?;
    println!(
        "Pre-state: slot {} ({})",
        pre_state.slot(),
        pre_state.fork_name_unchecked()
    );

    let t = Instant::now();
    let pre_buffer = HDiffBuffer::from_state(pre_state);
    println!("Pre-state buffer creation: {:?}", t.elapsed());

    let mut applied_buffer = None;
    for i in 0..runs {
        let mut buffer = pre_buffer.clone();
        let t = Instant::now();
        diff.apply(&mut buffer, &config)
            .map_err(|e| format!("failed to apply diff: {e:?}"))?;
        println!("Run {i}: apply time {:?}", t.elapsed());
        applied_buffer = Some(buffer);
    }
    let buffer = applied_buffer.ok_or("runs must be greater than 0")?;

    let t = Instant::now();
    let post_state = buffer
        .as_state(spec)
        .map_err(|e| format!("failed to convert buffer to state: {e:?}"))?;
    println!("Buffer to state conversion: {:?}", t.elapsed());
    println!(
        "Post-state: slot {} ({})",
        post_state.slot(),
        post_state.fork_name_unchecked()
    );

    let post_state_bytes = post_state.as_ssz_bytes();

    if let Some(expected_path) = expected_post_state_path {
        let expected_bytes = std::fs::read(&expected_path)
            .map_err(|e| format!("failed to read {}: {e}", expected_path.display()))?;
        if post_state_bytes == expected_bytes {
            println!(
                "Verification OK: applied state matches {}",
                expected_path.display()
            );
        } else {
            return Err(format!(
                "verification FAILED: applied state does not match {}",
                expected_path.display()
            ));
        }
    }

    if let Some(output_path) = output_path {
        std::fs::write(&output_path, &post_state_bytes)
            .map_err(|e| format!("failed to write state to {}: {e}", output_path.display()))?;
        println!("Wrote post-state to {}", output_path.display());
    }

    Ok(())
}
