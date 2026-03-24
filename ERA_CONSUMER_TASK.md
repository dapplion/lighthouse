# Task: Port crash-resume progress tracking and parallel state reconstruction to ERA consumer

## Context
Working in `/root/.openclaw/workspace/lighthouse-pr-69` on branch `era-lcli-test`.
This is a Lighthouse (Ethereum consensus client) PR for ERA file import/export.

The consumer at `beacon_node/beacon_chain/src/era/consumer.rs` is missing two critical features
that exist in a reference implementation (PR #65's `builder.rs`). Port them.

## What to add

### 1. ERA import pointer (crash resume)

Add store methods to `beacon_node/store/src/hot_cold_store.rs` for tracking import progress:

```rust
// Add these two helper functions near the top of the file (after struct definition):
fn era_import_pointer_key() -> &'static [u8] {
    b"era_import_ptr"
}

fn era_reconstruction_key(era_number: u64) -> Vec<u8> {
    let mut key = b"era_recon:".to_vec();
    key.extend_from_slice(&era_number.to_be_bytes());
    key
}

// Add these methods to the impl block for HotColdDB:

pub fn get_era_import_pointer(&self) -> Result<Option<u64>, Error> {
    let Some(bytes) = self
        .hot_db
        .get_bytes(DBColumn::BeaconMeta, era_import_pointer_key())?
    else {
        return Ok(None);
    };
    let bytes: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBytes)?;
    Ok(Some(u64::from_be_bytes(bytes)))
}

pub fn set_era_import_pointer(&self, era_number: u64) -> Result<(), Error> {
    self.hot_db.put_bytes(
        DBColumn::BeaconMeta,
        era_import_pointer_key(),
        &era_number.to_be_bytes(),
    )
}

pub fn era_reconstruction_done(&self, era_number: u64) -> Result<bool, Error> {
    self.hot_db
        .key_exists(DBColumn::BeaconMeta, &era_reconstruction_key(era_number))
}

pub fn set_era_reconstruction_done(&self, era_number: u64) -> Result<(), Error> {
    self.hot_db.put_bytes(
        DBColumn::BeaconMeta,
        &era_reconstruction_key(era_number),
        &[1u8],
    )
}
```

**IMPORTANT:** Check if `Error::InvalidBytes` exists in the store's Error enum. If not, add it.
Look at `beacon_node/store/src/errors.rs` or wherever the Error enum is defined.

### 2. Update import_all in consumer.rs

Modify `import_all` in `beacon_node/beacon_chain/src/era/consumer.rs`:

```rust
pub fn import_all<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    &self,
    store: &Arc<HotColdDB<E, Hot, Cold>>,
    spec: &ChainSpec,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let max_era = self.max_era;
    let slots_per_historical_root = E::slots_per_historical_root() as u64;

    // Resume from last successfully imported ERA
    let imported_pointer = store
        .get_era_import_pointer()
        .map_err(|e| format!("ERA import pointer read failed: {e:?}"))?
        .unwrap_or(0);

    info!(
        max_era,
        resume_from = imported_pointer + 1,
        "Importing ERA files"
    );

    let mut last_log = std::time::Instant::now();
    for era_number in imported_pointer + 1..=max_era {
        self.import_era_file(store, era_number, spec)?;

        // Persist progress pointer after each ERA
        store
            .set_era_import_pointer(era_number)
            .map_err(|e| format!("ERA import pointer write failed: {e:?}"))?;

        // Rate-limited progress logging (every 5 seconds)
        let now = std::time::Instant::now();
        if now.duration_since(last_log) >= std::time::Duration::from_secs(5) {
            last_log = now;
            let done_slots = era_number * slots_per_historical_root;
            let total_slots = max_era * slots_per_historical_root;
            info!(
                completed_era_files = era_number,
                total_era_files = max_era,
                completed_slots = done_slots,
                total_slots,
                "Importing ERA files"
            );
        }
    }

    info!(max_era, "ERA file import complete, starting state reconstruction");

    // Parallel state reconstruction using rayon
    self.reconstruct_states_parallel(store, max_era, slots_per_historical_root)?;

    // Advance the store metadata from genesis to the latest ERA boundary.
    self.advance_store_to_era::<E, Hot, Cold>(store, spec)?;

    info!(
        max_era,
        elapsed = ?start.elapsed(),
        "ERA file import and reconstruction complete"
    );

    Ok(())
}
```

### 3. Add parallel state reconstruction method to consumer.rs

Add this method to `EraFileDir`:

```rust
/// Reconstruct all intermediate states in parallel using rayon.
///
/// Each ERA's states are reconstructed independently by replaying blocks from the
/// ERA boundary state. Progress is tracked per-ERA so reconstruction can resume
/// after a crash.
fn reconstruct_states_parallel<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    &self,
    store: &Arc<HotColdDB<E, Hot, Cold>>,
    max_era: u64,
    slots_per_historical_root: u64,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use rayon::prelude::*;

    let total_era_files = max_era;
    let completed = Arc::new(AtomicU64::new(0));
    let progress = Arc::new(parking_lot::Mutex::new(std::time::Instant::now()));

    (1..=max_era).into_par_iter().try_for_each(|era_number| {
        let already_done = store
            .era_reconstruction_done(era_number)
            .map_err(|e| format!("ERA reconstruction marker read failed: {e:?}"))?;

        if !already_done {
            let start_slot = Slot::new((era_number - 1) * slots_per_historical_root);
            let end_slot = Slot::new(era_number * slots_per_historical_root);
            store
                .reconstruct_historic_states_on_range(
                    start_slot,
                    start_slot + Slot::new(1),
                    end_slot,
                )
                .map_err(|e| {
                    format!("ERA reconstruction failed for era {era_number}: {e:?}")
                })?;

            store
                .set_era_reconstruction_done(era_number)
                .map_err(|e| {
                    format!("ERA reconstruction marker write failed: {e:?}")
                })?;
        }

        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
        let now = std::time::Instant::now();
        let mut last_log = progress.lock();
        if now.duration_since(*last_log) >= std::time::Duration::from_secs(5) {
            *last_log = now;
            info!(
                completed_era_files = done,
                total_era_files,
                "Reconstructing states from ERA files"
            );
        }

        Ok::<(), String>(())
    })?;

    Ok(())
}
```

### 4. Add `reconstruct_historic_states_on_range` to store

This method needs to be added to `beacon_node/store/src/reconstruct.rs`. It replays blocks
on a given slot range to reconstruct and store intermediate states. Here's the implementation
from PR #65:

```rust
pub fn reconstruct_historic_states_on_range(
    self: &Arc<Self>,
    with_state_at_slot: Slot,
    from_slot: Slot,
    to_slot: Slot,
) -> Result<(), Error> {
    debug!(
        %from_slot,
        %to_slot,
        "Starting state reconstruction batch"
    );

    let _t = metrics::start_timer(&metrics::STORE_BEACON_RECONSTRUCTION_TIME);

    let block_root_iter =
        FrozenForwardsIterator::new(self, DBColumn::BeaconBlockRoots, from_slot, to_slot)?;

    // The state to be advanced.
    let mut state = self.load_cold_state_by_slot(with_state_at_slot)?;
    state.build_caches(&self.spec)?;

    process_results(block_root_iter, |iter| -> Result<(), Error> {
        let mut io_batch = vec![];
        let mut prev_state_root = None;

        for (block_root, slot) in iter {
            io_batch.push(KeyValueStoreOp::PutKeyValue(
                DBColumn::BeaconBlockRoots,
                slot.as_u64().to_be_bytes().to_vec(),
                block_root.as_slice().to_vec(),
            ));

            let block = {
                let block = self
                    .get_blinded_block(&block_root)?
                    .ok_or(Error::BlockNotFound(block_root))?;
                if block.slot() == slot && block.slot() > self.spec.genesis_slot {
                    Some(block)
                } else {
                    None
                }
            };

            // Advance state to slot.
            while state.slot() < slot {
                per_slot_processing(&mut state, prev_state_root.take(), &self.spec)
                    .map_err(HotColdDBError::BlockReplaySlotError)?;
            }

            // Apply block.
            if let Some(block) = block {
                let mut ctxt = ConsensusContext::new(block.slot())
                    .set_current_block_root(block_root)
                    .set_proposer_index(block.message().proposer_index());

                per_block_processing(
                    &mut state,
                    &block,
                    BlockSignatureStrategy::NoVerification,
                    VerifyBlockRoot::True,
                    &mut ctxt,
                    &self.spec,
                )
                .map_err(|e| HotColdDBError::BlockReplayBlockError(block.slot(), e))?;

                prev_state_root = Some(block.state_root());
            }

            let state_root = prev_state_root
                .ok_or(())
                .or_else(|_| state.update_tree_hash_cache())?;

            // Stage state for storage in freezer DB.
            self.store_cold_state(&state_root, &state, &mut io_batch)?;

            let batch_complete = slot + 1 == to_slot;

            if self.hierarchy.should_commit_immediately(slot)? || batch_complete {
                self.cold_db.do_atomically(std::mem::take(&mut io_batch))?;

                if batch_complete {
                    debug!(
                        start_slot = %from_slot,
                        end_slot = %slot,
                        "Finished state reconstruction batch"
                    );
                    return Ok(());
                }
            }
        }

        Ok(())
    })??;

    Ok(())
}
```

Check the existing imports in `reconstruct.rs` and add any missing ones (like `FrozenForwardsIterator`,
`ConsensusContext`, `per_block_processing`, `BlockSignatureStrategy`, `VerifyBlockRoot`,
`KeyValueStoreOp`, `DBColumn`). Many should already be imported by the existing `reconstruct_historic_states`.

### 5. Update advance_store_to_era anchor info

In `advance_store_to_era`, after reconstruction is done, the anchor should reflect that ALL
states are now available. Update the anchor so `state_lower_limit` equals `state_upper_limit`
(both should indicate all historic states are stored):

```rust
// In advance_store_to_era, update the anchor to mark reconstruction complete
{
    let old_anchor = store.get_anchor_info();
    let mut new_anchor = old_anchor.clone();
    new_anchor.anchor_slot = head_slot;
    new_anchor.state_lower_limit = Slot::new(0);
    new_anchor.state_upper_limit = Slot::new(0);
    new_anchor.oldest_block_slot = Slot::new(0);
    store
        .compare_and_set_anchor_info_with_write(old_anchor, new_anchor)
        .map_err(|e| format!("failed to update anchor: {e:?}"))?;
}
```

## Build instructions

- `.cargo/config.toml` already exists with `target-dir = "/mnt/ssd/builds/lighthouse-pr-69"`
- After all changes: run `cargo fmt --all` then `cargo check`
- Do NOT run tests, just ensure it compiles

## Important notes

- Do NOT modify any files outside the listed ones
- The store uses the `store::Error` enum - check where it lives and if `InvalidBytes` variant exists
- `FrozenForwardsIterator` should exist in the store crate - search for it
- `parking_lot::Mutex` is already a dependency
- `rayon` is already a dependency (used in consumer.rs)
- `Arc` is already imported in consumer.rs
- The `import_all` signature changes to take `&Arc<HotColdDB<...>>` instead of `&HotColdDB<...>` because `reconstruct_historic_states_on_range` takes `self: &Arc<Self>`
