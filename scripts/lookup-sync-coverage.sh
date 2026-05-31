#!/bin/bash
# Aggregate lookup sync test coverage for a single fork.
# Modeled on scripts/range-sync-coverage.sh, but the lookup-sync tests run as a
# single fork (gloas by default) rather than the full fork matrix, so no lcov
# merge step is needed.
#
# Usage: ./scripts/lookup-sync-coverage.sh [--html]
# Env:   FORK_NAME=gloas (override to run under a different fork)
#        CARGO_TARGET_DIR=... (override target dir; large, ~tens of GB)
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_DIR="${CARGO_TARGET_DIR:-/mnt/ssd/builds/lighthouse-lookup-sync-tests}"
FORK_NAME="${FORK_NAME:-gloas}"
LCOV_OUT="/tmp/lookup-cov-${FORK_NAME}.lcov"

echo "=== Running lookup sync coverage (fork=$FORK_NAME) ==="
CARGO_TARGET_DIR="$TARGET_DIR" FORK_NAME="$FORK_NAME" \
    cargo llvm-cov --features "network/fake_crypto,network/fork_from_env" \
    -p network --lib --lcov --output-path "$LCOV_OUT" \
    -- "sync::tests::lookups" 2>&1 | grep -E "test result|running"

echo ""
echo "=== Lookup sync coverage ==="

python3 - "$LCOV_OUT" << 'PYEOF'
import sys
from collections import defaultdict

current_sf = None
lines = defaultdict(dict)

with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if line.startswith("SF:"):
            current_sf = line[3:]
        elif line.startswith("DA:") and current_sf:
            parts = line[3:].split(",")
            lineno, hits = int(parts[0]), int(parts[1])
            lines[current_sf][lineno] = hits

# Files touched by PR #9155 — keep in sync with the lookup-sync surface area.
targets = [
    "block_lookups/single_block_lookup.rs",
    "block_lookups/mod.rs",
    "block_lookups/parent_chain.rs",
    "sync/manager.rs",
    "sync/network_context.rs",
    "requests/payload_envelopes_by_root.rs",
]

print(f"{'File':<55} {'Lines':>6} {'Covered':>8} {'Missed':>7} {'Coverage':>9}")
print("-" * 90)

total_all = 0
covered_all = 0

for sf in sorted(lines.keys()):
    if not any(t in sf for t in targets):
        continue
    short = sf.split("sync/")[-1] if "sync/" in sf else sf.split("/")[-1]
    total = len(lines[sf])
    covered = sum(1 for h in lines[sf].values() if h > 0)
    missed = total - covered
    pct = covered / total * 100 if total > 0 else 0
    total_all += total
    covered_all += covered
    print(f"{short:<55} {total:>6} {covered:>8} {missed:>7} {pct:>8.1f}%")

print("-" * 90)
pct_all = covered_all / total_all * 100 if total_all > 0 else 0
print(f"{'TOTAL':<55} {total_all:>6} {covered_all:>8} {total_all - covered_all:>7} {pct_all:>8.1f}%")
PYEOF

if [ "$1" = "--html" ]; then
    echo ""
    echo "=== Generating HTML report ==="
    genhtml "$LCOV_OUT" -o /tmp/lookup-cov-html --ignore-errors source 2>/dev/null
    echo "HTML report: /tmp/lookup-cov-html/index.html"
fi
