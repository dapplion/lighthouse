# Plan: combine PR #9273 + PR #75 for ERA-file load benchmark

Worktree: `/root/.openclaw/workspace/lighthouse-claude-lh-era-files-static`
Branch: `claude-lh-era-files-static`
Base (merge base of both PRs): `31e5f308c3` ("Generalise reconstruct_historic_states for ranged replay" — sigp/lighthouse#9222, already on `unstable`).

ERA files: `/mnt/ssd/era-files-mainnet/` — Nimbus mainnet, ~1741 files (≈ slots 0 .. 1741 × 8192 ≈ 14.26M).

## End goal

Benchmark a Lighthouse beacon node booted purely from ERA files:

1. **Load speed** — wall-clock time to ingest the ~1741 ERA files into the cold DB and produce a startable node.
2. **Write amplification** — bytes written to disk by the cold backend ÷ logical ERA bytes consumed. We want this comparison across at least:
   - Current LevelDB cold backend (baseline).
   - The new static-archive cold backend introduced in #75.

The two PRs are required together because:
- #9273 (`era-lcli-upstream`) provides the ERA → store ingestion path and the boot-from-ERA-imported-store wiring.
- #75 (`static-files-generalization-spec`) provides the `ColdStore` trait, `StaticColdStore`, and the `--cold-backend` flag we want to benchmark against LevelDB.

Without #75, we cannot select the static backend; without #9273, we have no fast bulk-import path to feed it.

## What each PR contains (high-level)

### PR #9273 — ERA consumer/producer via LCLI (14 commits)
Adds:
- `beacon_chain/src/era/{consumer,producer,store_init,tests}.rs` — bulk import/export logic.
- `lcli` subcommands `consume_era_files` and `produce_era_files`.
- `EraImportTrust` enum + `--era-trusted-state` CLI flag.
- `BeaconChain` boot from ERA-imported store via `resume_from_db`.
- `historical_summary` SSZ helper.
- Touches `store/src/hot_cold_store.rs` for `store_cold_state_summary` and reconstruction fixes.
- Touches `beacon_chain/src/test_utils.rs`, `beacon_chain/src/lib.rs`.

### PR #75 — ColdStore trait + slot-keyed static archive (17 commits)
Adds:
- Specs: `specs/{era-storage,static-blocks,static-cold-backend}.md`.
- `store/src/static_cold.rs` — slot-keyed static archive backend.
- `ColdStore` trait, `StaticColdStore`, blanket `ColdStore` impl over `KeyValueStore`.
- `ColdBackend` enum + `--cold-backend` flag (wired through `database_manager` and beacon_node CLI).
- `ColdBatch` for bundled cold writes; `iter_index`; tightened column types (`DBColumnCold`).
- `store_tests` parameterized by `COLD_BACKEND` env var.
- Refactors `hot_cold_store.rs` heavily; touches `migrate.rs`, `historical_blocks.rs`, `forwards_iter.rs`, `reconstruct.rs`, `client/src/builder.rs`, etc.

## Conflict surface

Files touched by both PRs (off the shared base `31e5f308c3`):

| File | #9273 | #75 | Risk |
|------|-------|-----|------|
| `beacon_node/store/src/hot_cold_store.rs` | 2 commits (reconstruction + summary writes) | 8 commits (trait extraction, ColdBatch, backend split) | **High** — heavy structural refactor in #75 may rename or relocate the symbols #9273's reconstruction code calls. |
| `beacon_node/beacon_chain/src/test_utils.rs` | 1 commit | 2 commits | Low–medium — likely independent additions. |
| `Cargo.lock` | both | both | Trivial — regenerate. |

Outside the overlap, the two PRs are largely orthogonal: #9273 is mostly in `era/` + `lcli/`, and #75 is mostly in `store/` + spec docs.

## Combination strategy (proposed)

**Base on #75, layer #9273 on top.**

Reasons:
- #75 is the larger storage-layer refactor. Rebasing #75 onto #9273 would force re-resolving every `hot_cold_store.rs` move under #9273's smaller delta — more error-prone.
- #9273's ERA-ingest code calls store APIs that #75 reshapes (`store_cold_state_summary`, cold-state writes). It is easier to port a fresh ERA import call site onto the new `ColdStore` trait than to retrofit the new trait through pre-existing ERA code.

Concrete steps (each step ends with `cargo check`):

1. **Reset branch** `claude-lh-era-files-static` → tip of `dapplion/static-files-generalization-spec` (PR #75).
2. **Cherry-pick #9273 commits** in order onto that base. Expect conflicts only in:
   - `beacon_node/store/src/hot_cold_store.rs` — reconcile #9273's reconstruction/summary edits with #75's `ColdStore` trait split. Likely move calls behind the new trait.
   - `beacon_node/beacon_chain/src/test_utils.rs` — straightforward merge.
   - `Cargo.lock` — accept #75's, re-run `cargo check`.
3. **Keep cherry-picks small** — squash only if a commit is purely a fix to an earlier one in the series.
4. **`cargo check` + `make lint-full`** after each meaningful step (uses shared `CARGO_TARGET_DIR=/root/.openclaw/workspace/.lighthouse-target`, never per-worktree `target/`).
5. **Smoke-test** with `lcli consume-era-files` against a small subset of `/mnt/ssd/era-files-mainnet/` (e.g. first 16 eras) on **both** cold backends to verify both produce a bootable store before running the full benchmark.

Fallback if cherry-pick conflicts get gnarly: `git merge dapplion/static-files-generalization-spec` into `pr-9273-sigp` (or vice versa) producing a single merge commit with conflicts resolved in one place — sacrifices history clarity but localizes resolution.

## Benchmark plan (after combination compiles)

**Inputs are read-only.** `/mnt/ssd/era-files-mainnet/` is shared input — never modified, never moved.

**My output root** (mine alone — safe to create, write, and wipe inside): `/mnt/ssd/lh-bench/claude-lh-era-files-static/`. Anything outside this root may belong to another agent or test and must not be touched.

Per-backend layout under that root:
- `/mnt/ssd/lh-bench/claude-lh-era-files-static/leveldb/`
- `/mnt/ssd/lh-bench/claude-lh-era-files-static/static-cold/`

For each backend:
1. Pre-flight: `du -sb /mnt/ssd/era-files-mainnet/` for logical ERA byte total (read-only stat).
2. `rm -rf` the per-backend dir under my root, then `mkdir -p` it. (Only paths under my root — never elsewhere.)
3. Capture pre-import disk stats (`/proc/diskstats` for the SSD device, plus `du -sb` of the new empty output dir).
4. Run `lcli consume-era-files --datadir <my-dir> --cold-backend <leveldb|static> /mnt/ssd/era-files-mainnet/*.era` under `/usr/bin/time -v`.
5. Capture post-import disk stats and `du -sb` of the output dir.
6. Record: wall-clock, peak RSS, sectors written delta × 512, on-disk footprint, write-amp = sectors_written / logical_era_bytes.
7. (Optional) `iostat -x 1` capture during run for backend-internal write-amp shape.

Repeat each backend at least twice; report median across runs.

Disk-stat caveat: `/proc/diskstats` is whole-device and shared with every other process on the box. While other benchmarks run in parallel, the sectors-written delta is contaminated. Mitigation: prefer per-process write counters (`/usr/bin/time -v` "File system outputs", or `cat /proc/<pid>/io` `write_bytes` after the run) for the primary write-amp number; treat `/proc/diskstats` as a sanity cross-check only.

Variables to vary later (out of scope for v1): batch size, slot range (e.g. only post-Capella), parallel reconstruction toggle.

## Open questions

- Does #75's `--cold-backend static` accept a path layout compatible with what #9273's importer writes? — needs verification while resolving the `hot_cold_store.rs` conflict.
- Does the ERA importer respect `ColdBatch` semantics, or does it bypass batching? Bypassing would skew the write-amp comparison.
- Is `EraImportTrust::TrustedStateRoot` required for benchmark runs, or is the default trust mode acceptable? Default is preferable for reproducibility.

## Status

- [x] Worktree created, both PR branches fetched (`pr-9273-sigp`, `dapplion/static-files-generalization-spec`).
- [ ] Reset branch onto #75 tip.
- [ ] Cherry-pick #9273 commits.
- [ ] Resolve `hot_cold_store.rs` conflict.
- [ ] `cargo check` clean.
- [ ] `make lint-full` clean.
- [ ] Smoke-test 16-era ingest on both backends.
- [ ] Full benchmark run with metrics captured.
