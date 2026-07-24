# hdiff time goals: what to measure and why it matters

## Goals and relevance (call sites verified on this branch)

1. **Diff compute under the fork-choice write lock** — EVERY node, once per epoch: the hot DB
   stores the full hierarchy grid, so `import_block` → `store_hot_state` →
   `store_hot_state_as_diff` runs inside the lock (`beacon_chain.rs` DB-write section,
   `hot_cold_store.rs`). Leaf spans (32..480) in 15/16 epochs; a 2^9..2^18 diff otherwise.
   This is a **latency-spike** goal: total kernel CPU is <1 min/day.
2. **Diff apply** — hot state-cache miss (rare; reorgs/API bursts), archive historical queries
   (snapshot + ~4.9 layer applies + replay, in expectation), and the archive **background
   migration** (`migrate_database` recomputes the grid into the freezer; regular
   checkpoint-synced nodes skip it: `slot < state_upper_limit`).
3. **Flatten/rebuild** — `HDiffBuffer::from_state` (~0.95 s) brackets every compute and
   `as_state` (0.6–0.8 s) every load. They dominate both paths for any diff algorithm:
   measure them first; kernel savings are bounded by them.

## Measure

```
# kernels: per-layer spans; leaf 32..480 in 32-slot steps is MANDATORY (both algos have a
# compute/apply/size cliff between spans 128 and 192); then 512,1536,2048,6144 + era pairs.
LCLI=... BENCH_DIR=... ./run_bench.sh "span32:pre.ssz:post.ssz" ...   # states: see README.md
./parse_results.sh          # medians; logs also print from_state ("buffer creation")
                            # and as_state ("Buffer to state conversion")
time zstd -1 -c state.ssz >/dev/null   # snapshot compress; zstd -d for decompress
# block replay: ~40 ms/block (no sig verify, roots from summaries); confirm with
# lcli transition-blocks --exclude-post-block-thc
```

## Model

Edit the `MS` table + constants in `compute_model.py` with your medians, then run it. Prints:
per-epoch lock-held cost (typical / mean / worst 2^18 tail), expected archive query latency
with per-component breakdown and kernel share, and archive migration cost per epoch.

## Validate against prod

Grafana: `store_hdiff_compute_seconds`, `store_beacon_hdiff_buffer_from_state_time`,
`store_beacon_hdiff_buffer_into_state_time`, hdiff buffer cache hit/miss counters — the
bench `from_state` constant comes from freshly-decoded states; live nodes may differ.

Reference (2026-07, 2.19M validators): lock-held epoch cost 1137 ms (xdelta3) vs 1032 ms
(eth-state-diff), worst tail 2382 vs 1284 ms; archive query 2.40 vs 1.93 s (kernel share
40% vs 15%). Flatten/rebuild + replay bound both algorithms — biggest levers are moving
compute off the lock and shrinking from_state/as_state, not the diff kernel.
