# hdiff benchmark & archive DB-size estimation

Benchmarks HDiff algorithms (`xdelta3` vs `eth-state-diff`) on real mainnet states at the exact
spans the hierarchy produces, then projects archive DB growth per year.

## 1. Build

```
cargo build --release -p lcli   # builds lcli (compute-hdiff / apply-hdiff) and era_tool
```

## 2. States (mainnet era files, ~800 MB each, from https://mainnet.era.nimbus.team)

Era states are post-block epoch-boundary states at slot `8192 * era` — exactly the hdiff grid.
Pick a base era `E` divisible by 8 (ideally by 32); pairs of era states give spans `8192 * k`.

```
era_tool extract-state mainnet-<E>-*.era era_E.ssz
# sub-8192 spans: replay real blocks from era file E+1, dumping states at each offset
era_tool replay era_E.ssz mainnet-<E+1>-*.era 32,64,96,128,192,256,320,384,448,480,512,1536,2048,6144 out/
# inactivity-leak worst case: replay with no blocks (leak activates after 4 epochs)
era_tool replay era_E.ssz none 512,544,1024,2560,8192 leak/
```

## 3. Benchmark

```
LCLI=<path>/lcli BENCH_DIR=<dir> ./run_bench.sh "span32:era_E.ssz:out/state_<8192E+32>.ssz" ...
./parse_results.sh   # medians + sizes; every run verifies apply(compute(pre)) == post byte-for-byte
```

## 4. DB size per year

Layer math (exponents `[5,9,11,13,16,18,21]`): each slot divisible by 2^5 stores one item on the
largest layer 2^n dividing it, diffed from the previous 2^m grid point (m = next larger layer),
so spans are `2^n * k, k = 1..(2^m / 2^n - 1)`. Per 2^21-slot period (24.3 days): 1 snapshot,
7 / 24 / 224 / 768 / 3072 diffs on layers 2^18..2^9, and 61440 leaf diffs (spans 32..480).

```
# put measured leaf sizes in leaf_sizes.txt ("span algo bytes" per line); update size_points /
# SNAPSHOT_BYTES (zstd -1 -c era_E.ssz | wc -c) in the script when the cost model gets stale
SLOT=<current_slot> ./archive_census.py leaf_sizes.txt
```

Prints exact per-layer counts/spans plus GB per period and per year for each algorithm.
The leaf layer is ~94% of items and >85% of bytes: always measure the full 32..480 leaf curve,
never interpolate it (eth-state-diff sizes cliff ~14x between spans 128 and 192).

Reference (2026-07, slot 14.84M, 2.19M validators): xdelta3 ≈ 72 GB/yr, eth-state-diff ≈ 427 GB/yr,
snapshot 136.7 MB. Both algorithms verified byte-for-byte on all pairs incl. Electra→Fulu cross-fork.
