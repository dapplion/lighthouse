#!/bin/bash
# Benchmark hdiff on state pairs. Usage: run_bench.sh <name:pre.ssz:post.ssz> ...
# Env: LCLI (path to lcli), BENCH_DIR (output root; diffs/ and results/ created inside).
LCLI=${LCLI:-$CARGO_TARGET_DIR/release/lcli}
BENCH_DIR=${BENCH_DIR:-.}
D=$BENCH_DIR/diffs
R=$BENCH_DIR/results
mkdir -p "$D" "$R"

for spec in "$@"; do
    name=$(echo "$spec" | cut -d: -f1)
    pre=$(echo "$spec" | cut -d: -f2)
    post=$(echo "$spec" | cut -d: -f3)
    log="$R/${name}.log"
    echo "=== $name compute ===" | tee "$log"
    $LCLI compute-hdiff --pre-state "$pre" --post-state "$post" \
        --runs 3 --output "$D/${name}.bin" >> "$log" 2>&1 \
        || { echo "COMPUTE FAILED: $name" | tee -a "$log"; continue; }
    echo "=== $name apply ===" >> "$log"
    $LCLI apply-hdiff --pre-state "$pre" --diff "$D/${name}.bin" \
        --post-state "$post" --runs 3 >> "$log" 2>&1 \
        || echo "APPLY FAILED: $name" | tee -a "$log"
    echo "done: $name"
done
echo "ALL DONE"
