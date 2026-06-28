# TODO: research Lighthouse archive read patterns

Open research question for the static cold backend (`common/static_file_storage`, PR #75).

## Why this matters

The library's bench plan currently focuses on **writes** during ERA load (large
state snapshots / diffs through `put_batch`), because that's the dominant
operation we have measurements for — PR #76's 42× number is a write-path
number (mainnet ERA import 51.27 h → 1.22 h).

But once an archive is loaded, the node's *job* is to serve reads. We have no
data on which read paths are performance-critical and therefore no informed
basis for read-bench design, read-side data layout decisions, or any future
caching layer above the static files.

Without that data we're guessing about:
- Whether `read(slot)` random-access latency matters or only sequential
  throughput matters
- Whether to add per-column read caches, and what their hit profile would be
- Whether iter-from-slot should be a first-class library API or a caller
  concern built on top of `read(slot)`
- Whether large-state reads dominate, or many-small-block reads dominate

## Questions to answer

1. **Who uses Lighthouse as an archive?** Block explorers, analytics services,
   validator monitoring, MEV bots, researchers? Each has a different access
   pattern.

2. **Per consumer class, what does the HTTP API call mix look like?**
   - `/eth/v2/beacon/blocks/{block_id}` — slot or root keyed
   - `/eth/v2/debug/beacon/states/{state_id}` — full state at any slot
   - `/eth/v1/beacon/states/{state_id}/validators` — validator subset queries
   - `/eth/v1/beacon/states/{state_id}/finality_checkpoints`
   - `/eth/v1/beacon/headers/{block_id}`
   - State-by-state_root vs state-by-slot ratio
   - Random-slot vs sequential-slot ratio
   - Recent-history vs deep-history ratio (last 100 epochs vs > 1 year ago)

3. **What's the in-memory hot-state cache hit rate** above the cold backend in
   real archive deployments? If most reads land in the existing
   `state_cache` / `historic_state_cache` (see
   `beacon_node/store/src/hot_cold_store.rs:318` and surrounding), the
   library's read perf matters less than its cache-miss path.

4. **Where can we get the data?** Candidates:
   - sigp / dapplion's own Grafana dashboards if any are public
   - Block-explorer operators (BeaconScan, beaconcha.in, etc.) — what HTTP API
     endpoints do they hit and at what rate
   - Lighthouse logs from a running archive node — instrument `http_api` to
     histogram endpoint calls by slot-age bucket
   - PR / issue history on sigp/lighthouse — any past archive perf
     discussions
   - Public datasets: era-snapshot services, beacon API mirrors

## Out of scope for this TODO

This is research, not design. It does NOT propose adding caches, changing the
on-disk format, or extending the library API. It only commits us to producing
the data that should drive those decisions.

## Disposition

Until this is answered, the library's read API stays minimal — `read(slot)`,
`contains(slot)`, `highest_written_slot()`. No iter, no caching, no
prefetching, no read benches beyond a single ad-hoc baseline. When the data
arrives, revisit.
