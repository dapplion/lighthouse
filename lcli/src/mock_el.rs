use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use execution_layer::{
    auth::{JwtKey, strip_prefix},
    test_utils::{Config, DEFAULT_JWT_SECRET, MockExecutionConfig, MockServer},
};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use types::*;

pub fn run<E: EthSpec>(mut env: Environment<E>, matches: &ArgMatches) -> Result<(), String> {
    let jwt_output_path: Option<PathBuf> = parse_optional(matches, "jwt-output-path")?;
    let jwt_secret_path: Option<PathBuf> = parse_optional(matches, "jwt-secret-path")?;
    let listen_addr: Ipv4Addr = parse_required(matches, "listen-address")?;
    let listen_port: u16 = parse_required(matches, "listen-port")?;
    let all_payloads_valid: bool = parse_required(matches, "all-payloads-valid")?;
    let all_payloads_invalid: bool = matches.get_flag("all-payloads-invalid");
    let latest_valid_hash: ExecutionBlockHash = parse_required(matches, "latest-valid-hash")?;
    let all_payloads_syncing: bool = matches.get_flag("all-payloads-syncing");
    let invalid_after_secs: Option<u64> = parse_optional(matches, "invalid-after-secs")?;
    let invalid_once: bool = matches.get_flag("invalid-once");
    let shanghai_time = parse_required(matches, "shanghai-time")?;
    let cancun_time = parse_optional(matches, "cancun-time")?;
    let prague_time = parse_optional(matches, "prague-time")?;
    let osaka_time = parse_optional(matches, "osaka-time")?;
    let amsterdam_time = parse_optional(matches, "amsterdam-time")?;
    let heze_time = parse_optional(matches, "heze-time")?;

    let handle = env.core_context().executor.handle().unwrap();

    let jwt_key = if let Some(secret_path) = jwt_secret_path {
        let hex_str = std::fs::read_to_string(&secret_path)
            .map_err(|e| format!("Failed to read JWT secret file: {}", e))?;
        let secret_bytes = hex::decode(strip_prefix(hex_str.trim()))
            .map_err(|e| format!("Invalid hex in JWT secret file: {}", e))?;
        JwtKey::from_slice(&secret_bytes)
            .map_err(|e| format!("Invalid JWT secret length (expected 32 bytes): {}", e))?
    } else if let Some(jwt_path) = jwt_output_path {
        let jwt_key = JwtKey::from_slice(&DEFAULT_JWT_SECRET)
            .map_err(|e| format!("Default JWT secret invalid: {}", e))?;
        std::fs::write(jwt_path, hex::encode(jwt_key.as_bytes()))
            .map_err(|e| format!("Failed to write JWT secret to output path: {}", e))?;
        jwt_key
    } else {
        return Err("either --jwt-secret-path or --jwt-output-path must be provided".to_string());
    };

    let config = MockExecutionConfig {
        server_config: Config {
            listen_addr,
            listen_port,
        },
        jwt_key,
        shanghai_time: Some(shanghai_time),
        cancun_time,
        prague_time,
        osaka_time,
        amsterdam_time,
        heze_time,
    };
    let kzg = None;
    let server: MockServer<E> = MockServer::new_with_config(&handle, config, kzg);

    if all_payloads_invalid {
        eprintln!(
            "Returning INVALID for all payloads (latest_valid_hash={:?}). \
            For testing payload invalidation only.",
            latest_valid_hash
        );
        server.all_payloads_invalid(latest_valid_hash);
    } else if all_payloads_syncing {
        eprintln!("Returning SYNCING for all payloads: blocks import optimistically.");
        server.all_payloads_syncing(true);
    } else if all_payloads_valid {
        eprintln!(
            "Using --all-payloads-valid=true can be dangerous. \
            Never use this flag when operating validators."
        );
        // Indicate that all payloads are valid.
        server.all_payloads_valid();
    }

    if let Some(secs) = invalid_after_secs {
        let revert_after = invalid_once.then(|| std::time::Duration::from_secs(6));
        eprintln!(
            "forkchoiceUpdated will return INVALID after {}s (latest_valid_hash={:?}, once={}).",
            secs, latest_valid_hash, invalid_once
        );
        server.invalidate_on_forkchoice_updated_after(
            &handle,
            std::time::Duration::from_secs(secs),
            latest_valid_hash,
            revert_after,
        );
    }

    eprintln!(
        "This tool is for TESTING PURPOSES ONLY. Do not use in production or on mainnet. \
        It cannot perform validator duties. It may cause nodes to follow an invalid chain."
    );
    eprintln!("Server listening on {}:{}", listen_addr, listen_port);

    let shutdown_reason = env.block_until_shutdown_requested()?;

    eprintln!("Shutting down: {:?}", shutdown_reason);

    Ok(())
}
