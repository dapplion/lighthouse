#!/usr/bin/env python3
"""Compute/apply time model for hdiff on mainnet, per node type and algorithm.

Event model (verified in code, branch eth-state-diff @ 8bdf194):
- Hot DB (ALL nodes): full hierarchy grid from anchor; one diff compute per 32-slot
  grid point (store_hot_state_as_diff), executed while holding the fork-choice write
  lock during import_block. Snapshot (zstd) once per 2^21 slots.
- Cold DB (ARCHIVE only): migrate_database recomputes the same grid in the background
  migrator as finalization advances (regular checkpoint-synced nodes skip: slot <
  state_upper_limit). => archive = 2x grid compute.
- Apply: hot state-cache miss (rare) and archive historical queries: snapshot decompress
  + one diff per layer present in the slot's decomposition + block replay.
"""
import bisect

MS = {  # span -> (x3_compute, esd_compute, x3_apply, esd_apply), medians, ms
    32: (172, 56, 34, 11), 64: (201, 57, 40, 13), 96: (203, 57, 38, 13),
    128: (188, 61, 36, 13), 192: (183, 91, 185, 35), 256: (179, 91, 185, 34),
    320: (186, 92, 184, 34), 384: (191, 91, 182, 33), 448: (187, 93, 185, 34),
    480: (185, 93, 194, 35), 512: (192, 91, 185, 35), 1536: (201, 95, 189, 37),
    2048: (209, 107, 186, 38), 6144: (253, 106, 189, 39), 8192: (293, 105, 193, 40),
    57344: (384, 131, 201, 42), 65536: (441, 163, 208, 53), 196608: (708, 178, 204, 51),
    262144: (611, 182, 202, 56), 1835008: (1432, 334, 303, 266),
}
FROM_STATE = 950   # ms, HDiffBuffer::from_state (both algos)
AS_STATE = {"x3": 614, "esd": 810}  # ms, buffer -> BeaconState
SNAP_COMPRESS, SNAP_DECOMPRESS = 730, 200  # ms, zstd-1, 332MB state
BLOCK_REPLAY = 40  # ms per block (no sig verify, no tree hash; state roots from summaries)

def interp(span, idx):
    xs = sorted(MS)
    if span in MS:
        return MS[span][idx]
    i = bisect.bisect_left(xs, span)
    x0, x1 = xs[i - 1], xs[i]
    y0, y1 = MS[x0][idx], MS[x1][idx]
    return y0 + (y1 - y0) * (span - x0) / (x1 - x0)

# (layer_exp, [spans], count_per_span) per 2^21 period
LAYERS = [
    (5, [32 * k for k in range(1, 16)], 4096),
    (9, [512 * k for k in range(1, 4)], 1024),
    (11, [2048 * k for k in range(1, 4)], 256),
    (13, [8192 * k for k in range(1, 8)], 32),
    (16, [65536 * k for k in range(1, 4)], 8),
    (18, [262144 * k for k in range(1, 8)], 1),
]
GRID = 65536  # grid slots per period (incl. 1 snapshot)
EPOCHS_PER_DAY = 225

def expected_compute(idx):
    tot = sum(interp(s, idx) * c for _, spans, c in LAYERS for s in spans)
    return tot  # ms per period, diffs only

print("== Grid compute per 2^21 period (diff kernels only) ==")
for name, idx in (("x3", 0), ("esd", 1)):
    tot = expected_compute(idx)
    print(f"{name}: {tot/1000:8.0f}s/period  = {tot/GRID:6.0f}ms per grid slot (per epoch)"
          f"  + from_state {FROM_STATE}ms + snapshot {SNAP_COMPRESS}ms/period")

print("\n== Per-epoch import-path cost under fork-choice write lock (hot, ALL nodes) ==")
for name, idx in (("x3", 0), ("esd", 1)):
    leaf = sum(interp(32 * k, idx) for k in range(1, 16)) / 15
    diffs = expected_compute(idx) / GRID
    print(f"{name}: typical (leaf) {FROM_STATE}+{leaf:.0f} = {FROM_STATE+leaf:.0f}ms"
          f" | mean {FROM_STATE+diffs:.0f}ms"
          f" | worst 2^18 tail {FROM_STATE+interp(1835008, idx):.0f}ms (1/2^21 slots)")

print("\n== Archive random historical state query (expected, ms) ==")
for name, cidx, aidx in (("x3", 0, 2), ("esd", 1, 3)):
    e_applies = 0.0
    for exp, spans, _ in LAYERS:
        n_big = {5: 9, 9: 11, 11: 13, 13: 16, 16: 18, 18: 21}[exp]
        p_present = 1 - (1 << exp) / (1 << n_big)
        mean_apply = sum(interp(s, aidx) for s in spans) / len(spans)
        e_applies += p_present * mean_apply
    replay = 15.5 * BLOCK_REPLAY
    total = SNAP_DECOMPRESS + e_applies + AS_STATE[name if name != "x3" else "x3"] + replay
    print(f"{name}: snap {SNAP_DECOMPRESS} + applies {e_applies:.0f} + as_state "
          f"{AS_STATE[name]} + replay {replay:.0f} = {total:.0f}ms"
          f"  (diff kernel share {100*e_applies/total:.0f}%)")

print("\n== Archive migration (background, per epoch: 1 grid slot) ==")
for name, idx in (("x3", 0), ("esd", 1)):
    diffs = expected_compute(idx) / GRID
    print(f"{name}: from_state {FROM_STATE} + E[compute] {diffs:.0f} = {FROM_STATE+diffs:.0f}ms/epoch"
          f" (+ base-buffer reconstruction on cold-cache miss)")
