//! Keeps asking this node's proof engine about payloads nobody has proven yet.
//!
//! A payload is seeded when its envelope is imported, but a proving service has not proven it by
//! then: Ethproofs serves a block's first proof around five minutes later. So one ask per payload
//! seeds almost nothing, and this sweeps the window once a slot instead. The engine answers from
//! its own cache, so a sweep that finds nothing is cheap.
use crate::network_beacon_processor::NetworkBeaconProcessor;
use beacon_chain::BeaconChainTypes;
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::debug;

/// Spawns the sweep, unless this node has no proof engine to ask.
pub fn spawn_execution_proof_seeding_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    processor: Arc<NetworkBeaconProcessor<T>>,
) {
    if !processor.chain.execution_proofs_enabled() {
        return;
    }

    executor.clone().spawn(
        async move {
            loop {
                match processor.chain.slot_clock.duration_to_next_slot() {
                    Some(duration) => sleep(duration).await,
                    None => {
                        sleep(processor.chain.slot_clock.slot_duration()).await;
                        continue;
                    }
                }

                let block_roots = processor.chain.unproven_payload_block_roots();
                if block_roots.is_empty() {
                    continue;
                }

                debug!(
                    payloads = block_roots.len(),
                    "Seeding execution proofs for unproven payloads"
                );
                for block_root in block_roots {
                    processor.publish_execution_proofs(block_root).await;
                }
            }
        },
        "execution_proof_seeding",
    );
}
