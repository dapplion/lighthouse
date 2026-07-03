# Lighthouse FCR Audit Report

Target: `dapplion/lighthouse` `origin/fcr` at `1cffab49ae7ad56afac60b2b17073486fd081364`

Specs: `/root/.openclaw/workspace/consensus-specs-main` at `aff96a1`

Method reference: Mythos-style broad candidate generation followed by a separate proof-only triage pass: <https://red.anthropic.com/2026/mythos-preview/>

## Method

Independent agents reviewed different layers:

- Spec equivalence and FCR algorithm behavior.
- Gloas and execution-layer integration.
- Lifecycle, persistence, and timing.
- Adversarial performance and DoS surfaces.
- Validator lifecycle, migration, persistence, HTTP/import signaling, and test coverage.

A final triage agent then classified candidates as confirmed, rejected, informational, or requiring a targeted test/benchmark. This report only promotes triaged items.

## Confirmed Issues

| ID | Severity | Finding | Status |
|---|---|---|---|
| FCR-01 | High | Gloas FCR safe hash uses bid `block_hash`; spec requires bid `parent_block_hash`. | Confirmed |
| FCR-02 | Medium | Ahead-of-slot fork-choice lookahead can consume FCR once-per-slot rotation early. | Confirmed |
| FCR-03 | Medium | Observed balance sources are rebuilt from pulled-up head state, not checkpoint states. | Confirmed |
| FCR-04 | Medium | Head-derived caches only refresh on head-root change, leaving same-head epoch transitions stale. | Confirmed |
| FCR-05 | Low | `SlotAssignments` omits `current_epoch - 2`, which reconfirmation can need. | Confirmed |
| FCR-06 | Low | Unknown/pruned `confirmed_root` errors before fallback to finalized. | Confirmed |
| FCR-07 | Medium | `SlotAssignments` inverse committee mapping is wrong at uneven committee boundaries. | Confirmed |
| FCR-08 | Medium | Invalidated latest-message roots can be counted in LMD and FFG support. | Confirmed |
| FCR-09 | Low | V28-to-V29 vote migration zeroes latest-message slot data used by FCR. | Confirmed |
| CHAIN-01 | Medium | Async EL forkchoice update tasks can be sent out of recompute order. | Confirmed |
| CHAIN-02 | Low | Block import emits `head` SSE before DB commit and canonical/FCR/EL updates. | Confirmed |
| CHAIN-03 | Low | Block-import DB rollback restores fork choice, cached head, and FCR non-atomically. | Confirmed |
| CHAIN-04 | Medium | Same-head finalization can prune DB ahead of persisted fork choice. | Confirmed |
| GLOAS-01 | Medium | Envelope import can leave fork choice `Full` after DB persistence failure. | Confirmed |
| GLOAS-02 | Medium | `--reset-payload-statuses` does not clear V29 `payload_received`. | Confirmed |
| GLOAS-03 | Medium | Successful envelope DB import is not durably reconciled into fork choice. | Confirmed |
| GLOAS-04 | Medium | PTC DA vote derives from `payload_received` instead of local data availability. | Confirmed |
| GLOAS-05 | Medium | HTTP envelope import does not notify payload-attestation reprocessing. | Confirmed |

### FCR-01: Gloas FCR Safe Hash

`run_fcr` resolves the confirmed block hash via `execution_status.block_hash().or(execution_payload_block_hash)` and writes it into `ForkchoiceUpdateParameters.justified_hash`, which is sent to EL as `safe_block_hash`.

Refs:
- `beacon_node/beacon_chain/src/canonical_head.rs:770`
- `beacon_node/beacon_chain/src/canonical_head.rs:1039`
- `consensus/fork_choice/src/fork_choice.rs:595`
- `specs/gloas/fast-confirmation.md:38`
- `specs/gloas/fork-choice.md:95`

Spec requires the safe hash for a confirmed Gloas beacon block to be the bid `parent_block_hash`, not the bid `block_hash`.

Fix direction: for post-Gloas/V29 FCR safe hash, prefer `confirmed_node.execution_payload_parent_hash`. Keep pre-Gloas behavior on `execution_status.block_hash()`.

### FCR-02: Ahead-Of-Slot Rotation

`state_advance_timer` calls `recompute_head_at_slot(next_slot)` before the slot boundary. FCR then runs `update_fast_confirmation_variables` for `next_slot` and sets `last_update_slot`, so later recomputes in the actual slot cannot rotate `previous_slot_head/current_slot_head`.

Refs:
- `beacon_node/beacon_chain/src/state_advance_timer.rs:197`
- `beacon_node/beacon_chain/src/canonical_head.rs:741`
- `consensus/fast_confirmation/src/lib.rs:266`
- `specs/phase0/fast-confirmation.md:1039`

Fix direction: do not run FCR from pre-slot lookahead recomputes, or pass an explicit production/FCR eligibility flag into recompute.

### FCR-03: Balance Source Checkpoint State

Spec `get_previous_balance_source` and `get_current_balance_source` return `store.checkpoint_states[...]`. Current code stores the observed checkpoint but pairs it with `BalanceSourceData::for_epoch(state, epoch)` from the pulled-up head state.

Refs:
- `consensus/fast_confirmation/src/lib.rs:147`
- `consensus/fast_confirmation/src/lib.rs:281`
- `consensus/fast_confirmation/src/balance_source.rs:27`
- `specs/phase0/fast-confirmation.md:264`

Fix direction: source observed balances from the checkpoint state matching the observed checkpoint, or prove the pulled-up head state is equivalent in every validator lifecycle edge.

### FCR-04: Same-Head Cache Staleness

Head-derived cache rebuilds are inside `if self.current_slot_head != head_root`, but epoch-dependent roots can change while the head root stays the same.

Refs:
- `consensus/fast_confirmation/src/lib.rs:248`
- `consensus/fast_confirmation/src/lib.rs:255`
- `consensus/fast_confirmation/src/lib.rs:260`

Fix direction: compute dependent roots independently of head-root change and rebuild each cache when its own dependent root changes.

### FCR-05: Missing `current_epoch - 2`

`SlotAssignments` stores only previous/current/next columns. Spec notes reconfirmation may compute empty-slot discount for `current_epoch - 2`.

Refs:
- `consensus/fast_confirmation/src/slot_assignments.rs:7`
- `consensus/fast_confirmation/src/slot_assignments.rs:51`
- `specs/phase0/fast-confirmation.md:520`

Fix direction: extend assignment coverage to include `current_epoch - 2`, or add a narrower reconfirmation fallback.

### FCR-06: Pruned Confirmed Root

`get_latest_confirmed` calls `get_block_epoch(confirmed_root, proto_array)?` before deciding whether to revert to finalized. If `confirmed_root` was pruned or is unknown, the function errors and never reaches fallback.

Refs:
- `consensus/fast_confirmation/src/lib.rs:314`
- `specs/phase0/fast-confirmation.md:976`

Fix direction: treat unknown/pruned `confirmed_root` as a fallback-to-finalized reason.

### FCR-07: Committee Inverse Mapping

`SlotAssignments` maps shuffled position to committee with:

```text
position * total_committees / shuffling_len
```

Spec committee ranges are:

```text
start = len(indices) * index // count
end = len(indices) * (index + 1) // count
```

At uneven boundaries this inverse is wrong. Example: `len=65`, `count=16`, `position=4`; spec places position 4 in committee 1, current inverse returns committee 0.

Refs:
- `consensus/fast_confirmation/src/slot_assignments.rs:81`
- `consensus/types/src/state/committee_cache.rs:403`
- `specs/phase0/beacon-chain.md:887`

Fix direction: use the same range logic as `compute_committee_range_in_epoch`, or a proven inverse of those floor boundaries.

### FCR-08: Invalidated Vote Roots Counted

FCR support aggregation accepts any non-zero `VoteTracker.current_root()` and projects it to the canonical segment. `get_current_target_score` similarly maps vote roots to checkpoints and counts current-target FFG support without rejecting invalidated vote roots. Invalidated blocks remain addressable in proto-array, so votes on invalidated descendants can be counted toward valid ancestors or valid current targets. Optimistic sync says weights from invalidated blocks must not be applied to valid or non-validated ancestors.

Refs:
- `consensus/fast_confirmation/src/optimizations.rs:225`
- `consensus/fast_confirmation/src/optimizations.rs:286`
- `consensus/fast_confirmation/src/lib.rs:1000`
- `consensus/fast_confirmation/src/lib.rs:1016`
- `consensus/proto_array/src/proto_array.rs:477`
- `sync/optimistic.md:263`

Fix direction: filter invalidated vote roots/subtrees before all FCR latest-message consumers, including LMD support precompute and FFG current-target support. Do not accidentally drop merely optimistic roots unless the FCR spec requires it for that specific check.

### FCR-09: V28-To-V29 Vote Migration

`VoteTrackerV28` stores `next_epoch`, but the V29 conversion preserves roots while setting both `current_slot` and `next_slot` to zero. FCR derives latest-message epoch from `VoteTracker.current_slot()`, so migrated vote roots cannot contribute to current-target support until fresh attestations rewrite the slot.

Refs:
- `consensus/proto_array/src/proto_array_fork_choice.rs:38`
- `consensus/proto_array/src/proto_array_fork_choice.rs:58`
- `consensus/proto_array/src/ssz_container.rs:78`
- `beacon_node/beacon_chain/src/schema_change/migration_schema_v29.rs:60`
- `consensus/fast_confirmation/src/lib.rs:1004`

Fix direction: migrate an approximate latest-message slot from the stored epoch, or explicitly clear migrated roots for FCR so they are not silently mis-epoch'd.

### CHAIN-01: Out-Of-Order EL Forkchoice Updates

`recompute_head_at_slot_internal` spawns an async EL update task and later drops `recompute_head_lock`. A later recompute can spawn a newer task before the older task acquires `execution_engine_forkchoice_lock`; that lock orders acquisition, not recompute creation. The EL cache is updated before the RPC call, so a stale task can overwrite the latest FCU state.

Refs:
- `beacon_node/beacon_chain/src/canonical_head.rs:965`
- `beacon_node/beacon_chain/src/canonical_head.rs:973`
- `beacon_node/beacon_chain/src/beacon_chain.rs:6613`
- `beacon_node/beacon_chain/src/beacon_chain.rs:6638`
- `beacon_node/execution_layer/src/lib.rs:1569`

Fix direction: sequence-number FCUs or enqueue/send under an ordering mechanism tied to recompute order.

### CHAIN-02: Pre-Commit Head SSE

Block import can emit `head` SSE while the block is only in fork choice and early-attester state, before DB write, canonical recompute, FCR, and EL update. If the DB write fails, restore happens after an already-emitted event.

Refs:
- `beacon_node/beacon_chain/src/beacon_chain.rs:4389`
- `beacon_node/beacon_chain/src/beacon_chain.rs:4414`
- `beacon_node/beacon_chain/src/beacon_chain.rs:4492`

Fix direction: delay public head SSE until after durable import, or emit a distinct pre-commit/attestable signal.

### CHAIN-03: Non-Atomic Block-Import Rollback

On block DB write failure, `restore_from_store` replaces fork choice, drops the fork-choice lock, then updates cached head and resets FCR without taking `recompute_head_lock`. A recompute can observe restored fork choice with stale cached/FCR state.

Refs:
- `beacon_node/beacon_chain/src/canonical_head.rs:392`
- `beacon_node/beacon_chain/src/canonical_head.rs:395`
- `beacon_node/beacon_chain/src/canonical_head.rs:398`

Fix direction: perform restore under recompute serialization or update fork choice, cached head, and FCR as one serialized recovery section.

### CHAIN-04: Same-Head Finalization Persistence

Same-head finalization skips `after_new_head`, where fork choice persistence normally happens. `after_finalization` can migrate/prune DB and then prune in-memory fork choice without persisting the updated fork choice. A crash before later persistence can leave persisted fork choice pointing at pruned hot data.

Refs:
- `beacon_node/beacon_chain/src/canonical_head.rs:936`
- `beacon_node/beacon_chain/src/canonical_head.rs:1134`
- `beacon_node/beacon_chain/src/canonical_head.rs:1278`
- `beacon_node/beacon_chain/src/canonical_head.rs:1291`

Fix direction: persist fork choice before or atomically with finalization pruning on same-head finalization.

### GLOAS-01: `Full` Without Envelope Persistence

Envelope import sets `payload_received = true` in fork choice before the DB write. If `do_atomically_with_block_and_blobs_cache` fails, the function returns with a rollback TODO commented out.

Refs:
- `beacon_node/beacon_chain/src/payload_envelope_verification/import.rs:247`
- `beacon_node/beacon_chain/src/payload_envelope_verification/import.rs:285`
- `consensus/proto_array/src/proto_array.rs:799`

Fix direction: persist before mutating fork choice, or implement rollback/reload on DB failure.

### GLOAS-02: Reset Does Not Clear V29 `payload_received`

Startup reset calls `set_all_blocks_to_optimistic`, which resets V17 execution statuses but leaves V29 `payload_received` unchanged. That preserves `Full` virtual children despite `--reset-payload-statuses`.

Refs:
- `consensus/fork_choice/src/fork_choice.rs:1836`
- `consensus/fork_choice/src/fork_choice.rs:1862`
- `consensus/proto_array/src/proto_array_fork_choice.rs:846`
- `consensus/proto_array/src/proto_array_fork_choice.rs:976`

Fix direction: extend reset handling to V29 `payload_received`, including any required weight/virtual-node consistency work.

### GLOAS-03: Successful Envelope Import Not Reconciled

Envelope import sets `payload_received = true` in memory and stores the envelope in DB, but a successful import does not also persist fork choice. Startup only loads an envelope if persisted fork choice already selects `PayloadStatus::Full`. A crash after envelope DB success but before fork-choice persistence can restart with the envelope present but `payload_received = false`.

Refs:
- `beacon_node/beacon_chain/src/payload_envelope_verification/import.rs:247`
- `beacon_node/beacon_chain/src/payload_envelope_verification/import.rs:278`
- `beacon_node/beacon_chain/src/payload_envelope_verification/import.rs:301`
- `beacon_node/beacon_chain/src/builder.rs:773`

Fix direction: persist fork choice with successful envelope import or reconstruct `payload_received` from stored envelopes on startup.

### GLOAS-04: PTC DA Uses `payload_received`

Validator PTC data sets `blob_data_available` from fork-choice `is_payload_received` rather than local data availability. Spec says the value should come from `is_data_available(root)`. A node can have data available before envelope execution/import completes and still vote DA false.

Refs:
- `beacon_node/beacon_chain/src/beacon_chain.rs:2178`
- `beacon_node/beacon_chain/src/beacon_chain.rs:2195`
- `specs/gloas/validator.md:421`

Fix direction: derive DA from local data availability/pending payload/data-column caches, not from envelope import completion.

### GLOAS-05: HTTP Envelope Import Does Not Reprocess Attestations

HTTP envelope import recomputes head but does not send the `PayloadEnvelopeImported` signal that gossip/RPC paths send. The reprocessing queue releases `UnknownPayloadEnvelope` attestations on that signal, so HTTP-published or queued payload-present attestations may not be reprocessed after HTTP envelope import.

Refs:
- `beacon_node/http_api/src/beacon/execution_payload_envelopes.rs:156`
- `beacon_node/http_api/src/beacon/execution_payload_envelopes.rs:228`
- `beacon_node/network/src/network_beacon_processor/gossip_methods.rs:3921`
- `beacon_node/beacon_processor/src/scheduler/work_reprocessing_queue.rs:119`
- `beacon_node/beacon_processor/src/scheduler/work_reprocessing_queue.rs:919`

Fix direction: send the same reprocessing notification after successful HTTP envelope import.

## Needs Targeted Test

| ID | Finding | Why not promoted |
|---|---|---|
| TEST-01 | FCR safe hash may be non-ancestor during pre-Gloas proposer-reorg override. | Plausible from parameter preservation, but needs a focused reachability test. |
| TEST-02 | FCR event can be visible before cached head and EL safe hash are committed. | Plausible interleaving; needs a focused race/order test. |
| TEST-03 | Late first FCR update can snapshot epoch-boundary state after the spec deadline. | Needs a test with first-run FCR failure and later changed unrealized justification. |

Refs:
- `beacon_node/beacon_chain/src/beacon_chain.rs:5230`
- `beacon_node/beacon_chain/src/beacon_chain.rs:5374`
- `beacon_node/beacon_chain/src/canonical_head.rs:792`
- `beacon_node/beacon_chain/src/canonical_head.rs:919`
- `beacon_node/beacon_chain/src/canonical_head.rs:997`
- `consensus/fast_confirmation/src/lib.rs:267`

## Needs Targeted Benchmark

| ID | Finding | Benchmark shape |
|---|---|---|
| PERF-01 | Production FCR clones/advances/builds caches under fork-choice read lock and FCR mutex. | Benchmark `run_fcr`/`recompute_head` with mainnet-sized state and measure lock hold time. |
| PERF-02 | Sparse skipped-slot support scans validators per candidate block. | Sparse chain with skipped parents and enough votes to avoid early exits. |
| PERF-03 | Side-branch vote projection walks ancestors per distinct vote root. | Many distinct side-branch vote roots at controlled depth. |
| PERF-04 | Historical equivocator set has recurring unbounded cost. | Populate large historical `equivocating_indices` sets and measure `get_latest_confirmed`. |
| PERF-05 | Invalid vote roots cost the same as valid side roots before filtering. | Side-branch invalidation variants for LMD projection and current-target FFG support. |

Refs:
- `beacon_node/beacon_chain/src/canonical_head.rs:741`
- `beacon_node/beacon_chain/src/canonical_head.rs:997`
- `consensus/fast_confirmation/src/lib.rs:684`
- `consensus/fast_confirmation/src/optimizations.rs:225`
- `consensus/fast_confirmation/src/lib.rs:901`

Suggested benchmark names:
- `prod_run_fcr_lock_hold`
- `sparse_skipped_slot_discount_scan`
- `side_branch_vote_projection_depth`
- `historical_equivocating_indices_cost`
- `invalid_vote_roots_projection_cost`

## Regression Test Plan

- `gloas_fcr_safe_hash_uses_bid_parent_block_hash`
- `lookahead_recompute_does_not_consume_fcr_slot_rotation`
- `observed_justified_balances_come_from_checkpoint_state`
- `same_head_epoch_transition_rebuilds_head_dependent_caches`
- `slot_assignments_cover_epoch_minus_two_for_reconfirmation`
- `unknown_confirmed_root_falls_back_to_finalized`
- `slot_assignments_match_committee_cache_on_uneven_boundaries`
- `attestation_score_ignores_votes_from_invalid_descendants`
- `current_target_score_ignores_invalidated_vote_roots`
- `payload_envelope_db_write_failure_rolls_back_payload_received`
- `reset_payload_statuses_clears_v29_payload_received`
- `v28_vote_migration_preserves_or_clears_latest_message_epoch`
- `http_envelope_import_releases_payload_attestations`

## Informational / Coverage

- Cache-only head-state failure degrades FCR availability, but errors are isolated from consensus and safe falls back.
- `fast_confirmation` SSE has no explicit fallback/error event; this is an observability gap, not a direct safety issue.
- EF/spec test harness gaps remain: production mutation path, timing behavior, Gloas oracle, EL safe hash assertion, and SSE behavior need coverage.
- Gloas FCR EF vectors remain blocked by handler support and lack of EL `safe_block_hash` checks.

## Rejected

- Missed epoch-boundary snapshot on startup/checkpoint was not promoted. Spec initializes FCR from finalized checkpoint, and the current conservative startup behavior matches that shape.
- Block PTC aggregation with duplicate PTC positions was not promoted. A one-bit block remains valid and fork-choice block processing expands the validator index to all PTC positions.

## Suggested Fix Order

1. FCR-01, FCR-07, FCR-08: direct safety/spec-equivalence issues with concrete local fixes.
2. FCR-02, FCR-03, FCR-04, FCR-09: lifecycle, state-source, and migration correctness.
3. GLOAS-01 through GLOAS-05: execution persistence, reset, DA, and import signaling.
4. CHAIN-01 through CHAIN-04: ordering, rollback, and persistence hardening.
5. FCR-05, FCR-06: edge-case correctness and robustness.
6. Add targeted benchmarks for PERF-01 through PERF-05 before optimizing further.
