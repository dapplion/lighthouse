# Lighthouse audit against “Principles for fast Tokio applications”

## Executive assessment

Lighthouse does exhibit several of the anti-patterns described in Russell Cohen’s “Principles for fast Tokio applications.”[^1] The most important are not spread uniformly across the project: they cluster in metrics collection, data-column processing, validator signing, and a few shared-state/control-plane paths.

The strongest findings are:

1. **High — metrics scrapes execute blocking and potentially contended work on Tokio workers.** Both metrics servers synchronously gather and encode metrics inside async Warp handlers. The beacon-node path also performs filesystem metadata calls and holds a `std::sync::Mutex<Registry>` while encoding gossipsub metrics. The optional remote-monitoring task repeats synchronous system, registry, and filesystem collection inside a Tokio task every 60 seconds.
2. **High — data-column gossip can perform disk reads and KZG work inside async tasks.** The beacon processor deliberately dispatches gossip data columns and partial columns as async work, but their verification paths are synchronous. A source comment already acknowledges that the Gloas payload-bid fallback can read the database from an async gossip/RPC path. This is capable of producing long polls under a column burst.
3. **High at large validator counts — signing fan-out is unconstrained and too fine-grained.** Multiple duty paths build one future per validator and run all of them with `join_all` or `FuturesUnordered`, without a semaphore or chunking. A local key creates one Rayon job per signature; a Web3Signer key can create one concurrent HTTP request per signature. The input is the configured validator set, not a small protocol constant.
4. **Medium — several locks are intentionally held across `.await`.** Some cases are defensible single-flight or serialization mechanisms, but they still match the article’s warning and can amplify tail latency. One production use is explicitly exempted from Clippy’s `await_holding_lock` lint.
5. **Medium/conditional — one Tokio runtime competes with several other pools and threads.** The main runtime defaults to one worker per available core, while Lighthouse also creates Rayon pools sized to about 25% and 80% of cores, can use Rayon’s global pool, uses Tokio’s global blocking pool, and runs dedicated migration/logging threads. There is no CPU affinity or priority isolation in the application.
6. **Low-to-medium — several custom `poll` implementations drain all immediately-ready work.** The work per item is generally small and other bounds exist, so these are candidates for profiling rather than proven production problems.

This is not a diagnosis that Tokio is currently Lighthouse’s performance bottleneck. The article’s first principle is to start from a real latency/throughput symptom, and this audit is static: it identifies credible mechanisms, not observed scheduling delay. Lighthouse currently exposes task-lifetime and blocking-task metrics, but not Tokio schedule-latency, poll-time, global-queue-depth, or blocking-queue metrics, so the most important hypotheses cannot be accepted or rejected from existing telemetry.

## Scope and method

The audit is based on checkout `6d0d15831a9f824d8e5710566d9279942adee791` (2026-09-14), which resolves Tokio to `1.52.3`. It covered:

- all 895 tracked Rust source files, including tests and tools;
- a production-oriented subset of approximately 797 files after excluding conventional test, benchmark, example, and build-script paths;
- Cargo manifests and the lockfile for runtime and dependency configuration;
- all direct uses of task spawning, blocking offload, Rayon, async and blocking mutexes/RwLocks, join/fan-out combinators, filesystem APIs, runtime construction, and hand-written polling loops;
- call-path inspection for every high-risk class rather than treating search matches as findings;
- a full `cargo clippy --workspace --all-targets` run with `clippy::await_holding_lock` and `clippy::await_holding_refcell_ref` elevated to warnings. It completed successfully. The known production lock case is suppressed locally, and Tokio mutex guards are outside that lint’s purpose.

No runtime workload, flamegraph, `tokio-console`, dial9 trace, or schedule-latency histogram was available. Consequently, findings are labeled **confirmed pattern** when the source directly implements the article’s anti-pattern, and **conditional risk** when impact depends on load, cardinality, or timing.

## Article-to-code matrix

| Principle from the article | Lighthouse result | Confidence | Main evidence |
|---|---|---:|---|
| Start from a measured problem | Observability gap | High | Task duration is measured; Tokio scheduling/poll/queue behavior is not |
| Yield for fairness | Several drain-until-pending polls; no production `yield_now` | Medium | RPC handler, discovery, peer manager, inbound limiter |
| Batch blocking/filesystem work | Mixed; good in migrations, weak in per-key work and metrics | High | migration coalescing vs. per-signature jobs and inline scrapes |
| Beware global resources | Conditional exposure | High | shared Tokio blocking pool, global task queue, global Prometheus registry |
| Keep mutex critical sections short; do not await/I/O while locked | Several direct matches | High | metrics registry, EL caches/state, validator store, fallback list |
| Constrain parallelism | Strong in beacon processor/network; weak in validator signing | High | bounded processor/RPC vs. `join_all`/`FuturesUnordered` over validators |
| Isolate Tokio workers from other threads | Not implemented | High | single default runtime plus Rayon, blocking, migration, and logger threads |
| Multiple runtimes by priority | Not implemented | High | one production runtime in `environment` |
| Blocking executor may be acceptable when measured | Used deliberately, but largely unmeasured at scheduler level | Medium | broad `spawn_blocking` use and workload queues |
| Spin for microsecond latency | Not used | High | no relevant busy-spin path found |

## Detailed findings

### 1. Metrics collection blocks Tokio and can serialize workers

**Severity: High. Status: confirmed pattern.**

The beacon-node metrics route calls `gather_prometheus_metrics` directly from an async `and_then` handler (`beacon_node/http_metrics/src/lib.rs:110-131`). That synchronous function:

- scrapes chain metrics;
- calls `store::scrape_for_metrics` (`beacon_node/http_metrics/src/metrics.rs:30-38`), which performs `read_dir` and `metadata` calls for the hot and freezer database paths (`beacon_node/store/src/metrics.rs:406-411`, `common/directory/src/lib.rs:69-81`);
- collects and text-encodes the global Prometheus registry (`beacon_node/http_metrics/src/metrics.rs:49-52`);
- locks `std::sync::Mutex<Registry>` and encodes the gossipsub registry while holding the guard (`beacon_node/http_metrics/src/metrics.rs:53-58`).

The validator-client metrics server uses the same shape: its async route directly calls a synchronous collector (`validator_client/http_metrics/src/lib.rs:119-140`). The collector reads shared state, scrapes allocator/health data, gathers the global registry, and encodes it (`validator_client/http_metrics/src/lib.rs:162-225`).

This is especially close to the article’s concrete warning about a metrics registry behind a blocking mutex during an expensive flush. Concurrent scrapes can place multiple runtime workers in the same path: one encodes under the gossipsub registry lock while another blocks in `std::sync::Mutex::lock`. Even without contention, filesystem syscalls and registry encoding extend a Tokio poll.

The optional remote monitoring client repeats the issue on a timer. `auto_update` runs `send_metrics` in an async task (`common/monitoring_api/src/lib.rs:105-132`); `send_metrics` calls synchronous metric/system gathering before its first network await (`common/monitoring_api/src/lib.rs:168-199`). The default period is 60 seconds. This is a plausible source of the article’s “P99 spikes at predictable intervals” signature.

Two API constructors also refresh `sysinfo::System` synchronously inside Warp `.map` filters while holding `parking_lot::RwLock` write guards (`beacon_node/http_api/src/lib.rs:528-548`, `validator_client/http_api/src/lib.rs:265-285`). These filters run before the downstream handler’s `blocking_json_task`, so the expensive refresh itself remains on a Tokio worker.

**Recommendation.** Move the entire snapshot-and-encode operation into one coarse `spawn_blocking` call per scrape, including sysinfo refreshes and database-size sampling. Add a small concurrency gate or single-flight cache so simultaneous scrapes do not multiply the work. Prefer producing a snapshot before locking the gossipsub registry, or ensure registry encoding occurs only on the blocking pool. This is the first change worth benchmarking.

### 2. Data-column work can create long Tokio polls

**Severity: High under PeerDAS/Gloas traffic. Status: confirmed pattern.**

The beacon processor was designed to protect the core runtime: its queues are bounded and its default maximum worker count is one per CPU (`beacon_node/beacon_processor/src/lib.rs:14-36`, `:118-131`, `:678-717`). Most expensive consensus work is sent to `spawn_blocking`.

Data-column work is an exception. `Work::GossipDataColumnSidecar` and `Work::GossipPartialDataColumnSidecar` are dispatched with `spawn_async` (`beacon_node/beacon_processor/src/lib.rs:1551-1567`). Their async handlers synchronously call data-column verification before reaching another await (`beacon_node/network/src/network_beacon_processor/gossip_methods.rs:681-716`, `:1017-1037`). Verification includes KZG work (`beacon_node/beacon_chain/src/data_column_verification.rs:914-1007`) and, for Gloas, can synchronously load a payload bid from the on-disk store.

The code documents the disk problem explicitly at `beacon_node/beacon_chain/src/data_column_verification.rs:1339-1350`: the store fallback is a synchronous disk read and callers include async gossip/RPC validation paths. Because the processor may run up to `max_workers` such async jobs, a burst can occupy multiple or all Tokio workers with synchronous verification, defeating the processor’s normal isolation strategy.

A related HTTP path reconstructs blobs synchronously after reading data columns (`beacon_node/http_api/src/block_id.rs:469-509`). `reconstruct_blobs` deliberately avoids Rayon and may call KZG recovery (`beacon_node/beacon_chain/src/kzg_utils.rs:656-739`). Whether the enclosing route already places every caller on the blocking pool should be made explicit at this boundary; the function is hazardous in any direct async caller.

Invalid-block capture is another optional case. After async gossip block processing, `maybe_store_invalid_block` performs `exists`, file creation, SSZ serialization, and `write_all` synchronously (`beacon_node/network/src/network_beacon_processor/gossip_methods.rs:1928-1935`, `:3610-3662`). It is disabled by default, but adversarial invalid traffic plus `invalid_block_storage` can turn it into repeated blocking I/O on runtime workers.

**Recommendation.** Split data-column processing into a short async orchestration phase and a blocking/CPU phase. Batch verification where the KZG API allows it, fetch the Gloas bid before entering async validation or via a blocking job, and keep the existing beacon-processor admission control around the whole operation. Move invalid-block serialization and both file writes into one blocking task, with a bounded queue to prevent attacker-controlled disk backlog.

### 3. Validator signing has unbounded fan-out and one job per signature

**Severity: High at large validator counts; Medium otherwise. Status: confirmed pattern.**

The validator store constructs all signing futures and waits on them together for:

- attestations (`validator_client/lighthouse_validator_store/src/lib.rs:1001-1031`);
- aggregate-and-proofs (`:1181-1213`);
- sync committee signatures (`:1232-1264`);
- sync committee contributions (`:1293-1326`).

Duty computation also uses unconstrained `FuturesUnordered` for beacon committee selection proofs (`validator_client/validator_services/src/duties_service.rs:170-197`) and for parallel selection-proof production (`:1538-1560`). Sync committee proof generation creates a future for each relevant validator/subnet combination (`validator_client/validator_services/src/sync.rs:617-648`). No semaphore, `buffer_unordered(n)`, or chunk limit protects these paths.

For local keystores, each individual signature calls `spawn_blocking_with_rayon_async`, which submits a separate job to the high-priority Rayon pool and awaits a oneshot (`validator_client/signing_method/src/lib.rs:188-201`, `common/task_executor/src/lib.rs:241-260`). For remote signers, each future can become a separate HTTP request. Therefore `join_all` does not merely allocate many dormant futures: it can enqueue one CPU job or initiate one remote request per validator at once.

This matches two article warnings simultaneously: tiny work units pay scheduler/coordination overhead, and unconstrained fan-out can overwhelm the downstream service. The high-priority Rayon pool bounds simultaneous local execution, but does not bound its queue or the number of live futures. The remote path has no equivalent pool bound visible at this layer.

**Recommendation.** Add explicit concurrency limits separately for local and remote signing. For local keys, introduce a batch-signing blocking operation that signs a chunk inside one Rayon job; choose chunk size from benchmarks. For Web3Signer, use `stream::iter(...).buffer_unordered(configured_limit)` or a semaphore, ideally per endpoint, and expose queue depth/wait time. Preserve deadline priority so block and attestation signatures are not trapped behind lower-priority bulk work.

### 4. Locks span awaits and expensive work

**Severity: Medium overall. Status: confirmed pattern, with some intentional serialization.**

Not every await-under-lock is a bug. An async mutex is appropriate when serialization is the requirement, and several Lighthouse cases implement single-flight cache refreshes. They should still be treated as latency-sensitive coordination points.

The main instances are:

- Execution-engine capability and version caches retain a Tokio mutex guard while making JSON-RPC requests (`beacon_node/execution_layer/src/engine_api/http.rs:1275-1294`, `:1330-1357`). This prevents duplicate refreshes but makes every reader queue behind network latency.
- `Engine::upcheck` holds the async `state` write lock while `send_latest_forkchoice_state().await` performs an execution-engine request (`beacon_node/execution_layer/src/engines.rs:231-244`, `:193-215`). State readers are blocked for the request duration.
- `BeaconNodeFallback::num_available` and `get_notifier_info` retain the candidates read guard while awaiting each candidate’s health lock (`validator_client/beacon_node_fallback/src/lib.rs:465-515`). `update_candidates_list` retains its candidates write guard while awaiting a separate cache purge (`:519-550`), and `update_all_candidates` retains a write guard while asynchronously sorting by health (`:598-606`, `:801-813`). These operations can delay reconfiguration and other readers.
- Attestation production keeps `latest_attested_slot` locked across `spawn_attestation_tasks().await`, a path containing sleeps, HTTP requests, signing, and publication (`validator_client/validator_services/src/attestation_service.rs:198-216`, `:248-430`). This appears intentional to enforce one attempt per slot, but is a long-lived FutureLock-style critical section.
- Validator insertion holds a `parking_lot::RwLock` write guard across async initialization (`validator_client/lighthouse_validator_store/src/lib.rs:188-216`). The source explicitly suppresses `clippy::await_holding_lock`. This is more dangerous than the Tokio-lock cases because a concurrent task that calls a synchronous read can block an OS/Tokio worker. The authenticated HTTP management routes run their outer work on Tokio’s blocking pool, which reduces but does not eliminate cross-task contention.

**Recommendation.** For caches, use a single-flight state machine that does not retain the data mutex during I/O (for example, cached value plus a refresh notification). For EL state, finish network I/O before acquiring the state write lock. Clone the fallback candidate vector before awaits, as `update_all_candidates` already does on its read side. Replace the validator-store await-under-`parking_lot` pattern with an async-aware ownership/update protocol; do not merely change it to a Tokio RwLock without measuring read-path cost.

### 5. Runtime and CPU-pool isolation is incomplete

**Severity: Medium/conditional. Status: architectural risk, not a demonstrated bottleneck.**

Production constructs one default multi-threaded Tokio runtime with `.enable_all()` and no explicit worker count or thread hooks (`lighthouse/environment/src/lib.rs:165-180`). Tokio therefore selects its normal worker count, while Lighthouse separately creates:

- a low-priority Rayon pool at roughly 25% of CPUs;
- a high-priority Rayon pool at roughly 80% of CPUs (`common/task_executor/src/rayon_pool_provider.rs:4-43`);
- uses of Rayon’s global pool in production KZG/state-processing/operation-pool code;
- Tokio’s blocking pool through at least 73 production-oriented source occurrences of Lighthouse/Tokio blocking-spawn APIs;
- dedicated migration and non-blocking logging threads.

The scoped Rayon pools are a meaningful improvement over indiscriminate global Rayon use, and the low-priority pool directly limits backfill impact. However, Tokio can still believe it owns all cores while high-priority Rayon work also tries to use most cores. Under simultaneous gossip, signing, KZG, migration, and logging pressure, the kernel—not Lighthouse—decides latency priority. That is precisely the scenario the article’s isolation section addresses.

**Recommendation.** First measure kernel wakeup delay and Tokio schedule latency under realistic sync and validator workloads. If contention is visible, reserve explicit cores for the Tokio runtime and cap/pin Rayon and background pools to the remainder, or separate latency-critical networking from bulk sync/maintenance with a second runtime. Make worker counts configurable and log the resulting CPU budget at startup. A second runtime is not justified solely by this static finding.

### 6. Drain-until-pending polling may reduce fairness

**Severity: Low-to-medium. Status: candidate for measurement.**

Several hand-written polling paths process every immediately-ready item in one call:

- RPC handler expired inbound/outbound streams and per-substream state loops (`beacon_node/lighthouse_network/src/rpc/handler.rs:416-481`);
- inbound limiter expirations and queued requests (`beacon_node/lighthouse_network/src/rpc/inbound_limiter.rs:263-328`);
- discovery query completions and discv5 events (`beacon_node/lighthouse_network/src/discovery/mod.rs:989-1002`, `:1067-1090`);
- peer-manager heartbeat, ping, and status timers (`beacon_node/lighthouse_network/src/peer_manager/network_behaviour.rs:43-105`).

These resemble the pipelined-ready-loop example in the article: if the underlying stream stays ready, the future can do work proportional to the backlog without yielding. The risk is moderated by peer limits (default target 200), request rate/concurrency limits, and the fact that most per-item operations are short. `SubnetService` demonstrates a fairer local pattern: it processes one ready expiration and explicitly re-wakes itself (`beacon_node/network/src/subnet_service/mod.rs:604-680`).

**Recommendation.** Instrument poll duration before changing behavior. If long tails appear, impose a small per-poll budget (item count or elapsed time), call `wake_by_ref`, and return `Pending`/one event after the budget. Preserve batching by choosing the budget empirically rather than yielding after every item.

### 7. Periodic fire-and-forget tasks can overlap

**Severity: Low-to-medium. Status: conditional risk.**

The execution-layer watchdog spawns a new `upcheck` task each slot and then sleeps, without awaiting or checking whether the previous task finished (`beacon_node/execution_layer/src/lib.rs:695-710`). The proposer preparation service has the same fire-and-forget shape (`beacon_node/beacon_chain/src/proposer_prep_service.rs:31-62`). The attestation simulator spawns synchronous attestation production on the Tokio runtime each slot (`beacon_node/beacon_chain/src/attestation_simulator.rs:27-51`).

Normal request timeouts and a 12-second slot make sustained overlap unlikely, but slow or stuck downstream work can accumulate tasks. `TaskExecutor::spawn` also creates a separate monitor task for each spawned task (`common/task_executor/src/lib.rs:126-176`), doubling task objects for these events.

**Recommendation.** Use an in-flight guard or await each periodic unit when overlap provides no benefit. Track skipped/overlapped runs. Move the simulator’s synchronous state/committee production to a blocking worker if profiling shows a material poll.

## Positive patterns already present

Lighthouse already follows much of the article’s advice:

- **Bounded admission control:** beacon-processor work and reprocessing channels have explicit capacities, and active processor workers are capped (`beacon_node/beacon_processor/src/lib.rs:75-91`, `:678-717`, `:811`).
- **Network request constraints:** inbound RPC processing limits a peer/protocol to two concurrent requests and rejects work that cannot start within five seconds (`beacon_node/lighthouse_network/src/rpc/inbound_limiter.rs:20-24`, `:104-193`). Discovery also limits query concurrency.
- **Blocking offload is pervasive:** block verification, chain-segment filtering/signature verification, head recomputation, database pruning, slashing-protection work, and expensive keystore decryption are deliberately kept off core workers.
- **Batching exists where it matters:** the store migrator drains and coalesces notifications before doing finalization, pruning, reconstruction, or compaction (`beacon_node/beacon_chain/src/migrate.rs:450-497`). Attestation gossip processing has batch variants, and chain sync verifies same-epoch block signatures together.
- **Scoped CPU pools:** low- and high-priority Rayon pools reduce some global-pool interference (`common/task_executor/src/rayon_pool_provider.rs:4-56`).
- **No `tokio::fs` churn:** no Rust source use of `tokio::fs` was found, avoiding the article’s concern about turning each small filesystem operation into separate blocking-pool work.
- **Lock awareness:** many paths clone data or explicitly drop guards before awaits; lock ordering is documented in canonical-head code. The fallback updater itself comments on cloning candidates to release its read lock.
- **No busy spinning:** the article’s advanced spin tactic is not used.

These controls explain why many superficial search hits are not findings. For example, numerous `std::fs` uses occur during CLI/startup or inside blocking HTTP wrappers; Rayon in genesis creation is startup-only; test runtimes and test locks do not affect production scheduling.

## Prioritized action plan

### Priority 0: add evidence before broad refactoring

1. Enable Tokio runtime metrics needed to observe schedule-latency histograms, worker busy time, global queue depth, and blocking-thread/queue behavior. Existing `async_tasks_time_histogram` measures whole task lifetime—including sleeps and I/O—not poll time or schedule latency (`common/task_executor/src/metrics.rs:40-46`).
2. Add named metrics around: `/metrics` gather/encode time; gossipsub registry lock wait/hold time; data-column verification CPU/disk time; signature fan-out size and queue wait; EL cache/state lock wait; and periodic-task overlap.
3. Reproduce with realistic profiles: PeerDAS column bursts, large local-validator sets, large Web3Signer sets, concurrent Prometheus scrapes, range sync plus metrics, and degraded execution/beacon-node endpoints.

### Priority 1: low-risk structural fixes

1. Put each full metrics scrape in one coarse blocking task and single-flight concurrent scrapes.
2. Move sysinfo refresh filters to blocking tasks.
3. Clone fallback candidates and release list locks before awaiting health/cache operations.
4. Move invalid-block capture into a bounded blocking writer.
5. Prevent watchdog/proposer-prep overlap with a simple in-flight guard.

### Priority 2: hot-path changes requiring benchmarks

1. Reclassify data-column verification as blocking/CPU work while retaining beacon-processor limits.
2. Batch local signatures and bound remote-signer concurrency per endpoint.
3. Add poll budgets to network drain loops only where traces show long polls.
4. Tune Tokio/Rayon worker budgets or introduce runtime/core isolation only after scheduler and kernel-delay measurements demonstrate contention.

## Bottom line

Lighthouse is already unusually deliberate about separating expensive consensus work from its Tokio runtime, and its beacon processor implements bounded queues and concurrency well. The audit nevertheless finds three credible production hazards that map directly to the article: inline metrics work with a blocking registry lock, async data-column verification containing synchronous disk/cryptographic work, and unconstrained per-validator signing fan-out.

The metrics path is the clearest first fix because it is structurally wrong for async execution, externally triggerable when enabled, and easy to isolate. Data-column verification is the most important latency-sensitive hot-path candidate. Signing concurrency is the highest scalability risk for large validator installations. Runtime splitting, CPU pinning, and poll-budget changes should follow measurements rather than precede them.

## Sources

[^1]: Russell Cohen, [“Principles for fast Tokio applications”](https://dial9-rs.github.io/blog/principles-for-fast-tokio-applications/), dial9-rs, 2026-09-13. The article supplies the evaluation framework: schedule latency, fairness versus batching, global queues/pools, mutex contention, constrained parallelism, worker isolation, and multiple runtimes.

2. Lighthouse source checkout `6d0d15831a9f824d8e5710566d9279942adee791`, 2026-09-14. File-and-line references throughout are to this local revision.
3. Tokio project, [`spawn_blocking` documentation](https://docs.rs/tokio/1.52.0/tokio/task/fn.spawn_blocking.html), version 1.52.0.
4. Tokio project, [`tokio::sync::Mutex` documentation](https://docs.rs/tokio/1.52.0/tokio/sync/struct.Mutex.html), version 1.52.0.
5. Tokio project, [`RuntimeMetrics` documentation](https://docs.rs/tokio/1.52.0/tokio/runtime/struct.RuntimeMetrics.html), version 1.52.0.
