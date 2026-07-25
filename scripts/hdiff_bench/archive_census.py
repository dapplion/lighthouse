#!/usr/bin/env python3
"""Exact census of hdiff archive items at a given slot + size model per algorithm."""
import bisect, os, sys

CURRENT_SLOT = int(os.environ.get("SLOT", 14_839_427))
EXPONENTS = [5, 9, 11, 13, 16, 18, 21]
MODULI = [1 << e for e in EXPONENTS]
SNAP = MODULI[-1]
SLOTS_PER_YEAR = 365.25 * 86400 / 12

# Measured diff sizes (bytes) at spans, mainnet ~2.19M validators (Fulu),
# 2^18-layer points measured on ~2.06M-validator Electra states.
# size_points[algo] = {span: bytes}
size_points = {
    "xdelta3": {
        32: 540_380, 64: None, 96: None, 128: None, 192: None, 256: None,
        320: None, 384: None, 448: None, 480: 959_675, 512: 974_284,
        1536: 1_365_685, 2048: 1_556_561, 6144: 2_576_443, 8192: 3_060_843,
        57344: 4_568_735, 65536: 4_798_328, 196608: 7_426_270,
        262144: 9_206_379, 1835008: 24_161_774,
    },
    "eth-state-diff": {
        32: 293_335, 64: None, 96: None, 128: None, 192: None, 256: None,
        320: None, 384: None, 448: None, 480: 7_082_816, 512: 7_091_434,
        1536: 7_390_805, 2048: 7_552_705, 6144: 8_614_524, 8192: 8_958_204,
        57344: 9_970_611, 65536: 10_628_775, 196608: 10_106_911,
        262144: 9_136_832, 1835008: 23_401_097,
    },
}
SNAPSHOT_BYTES = 136_727_209

def load_extra(path):
    # lines: span algo bytes
    for line in open(path):
        span, algo, b = line.split()
        size_points[algo][int(span)] = int(b)

def interp(points, span):
    xs = sorted(s for s, v in points.items() if v is not None)
    ys = [points[s] for s in xs]
    if span <= xs[0]:
        return ys[0]
    if span >= xs[-1]:
        return ys[-1]
    i = bisect.bisect_left(xs, span)
    if xs[i] == span:
        return ys[i]
    x0, x1, y0, y1 = xs[i - 1], xs[i], ys[i - 1], ys[i]
    return y0 + (y1 - y0) * (span - x0) / (x1 - x0)

def layer_of(slot):
    """Return (layer_exponent, diff_span) per HierarchyModuli::storage_strategy, or None."""
    if slot % SNAP == 0:
        return (21, 0)
    for n_big, n_small in zip(MODULI[::-1], MODULI[-2::-1]):
        if slot % n_small == 0:
            return (n_small.bit_length() - 1, slot - slot // n_big * n_big)
    return None

def census(max_slot):
    layers = {}  # exp -> {span: count}
    for slot in range(0, max_slot + 1, 32):
        r = layer_of(slot)
        if r is None:
            continue
        exp, span = r
        layers.setdefault(exp, {}).setdefault(span, 0)
        layers[exp][span] += 1
    return layers

def report(layers, title):
    print(f"\n=== {title} ===")
    print(f"{'layer':>7} {'count':>8} {'spans':>22} {'mean span':>10} "
          f"{'xdelta3':>12} {'eth-state-diff':>15}")
    totals = {a: 0 for a in size_points}
    total_count = 0
    for exp in sorted(layers, reverse=True):
        spans = layers[exp]
        count = sum(spans.values())
        total_count += count
        tot_span = sum(s * c for s, c in spans.items())
        mean_span = tot_span / count
        row_bytes = {}
        for algo in size_points:
            if exp == 21:
                b = count * SNAPSHOT_BYTES
            else:
                b = sum(c * interp(size_points[algo], s) for s, c in spans.items())
            row_bytes[algo] = b
            totals[algo] += b
        span_range = f"{min(spans)}..{max(spans)}" if exp != 21 else "snapshot"
        print(f"2^{exp:<5} {count:>8} {span_range:>22} {mean_span:>10.0f} "
              f"{row_bytes['xdelta3']/1e9:>10.2f}GB {row_bytes['eth-state-diff']/1e9:>13.2f}GB")
    print(f"{'TOTAL':>7} {total_count:>8} {'':>22} {'':>10} "
          f"{totals['xdelta3']/1e9:>10.2f}GB {totals['eth-state-diff']/1e9:>13.2f}GB")
    return totals

if __name__ == "__main__":
    if len(sys.argv) > 1:
        load_extra(sys.argv[1])
    print(f"current slot: {CURRENT_SLOT} (period {CURRENT_SLOT / SNAP:.3f})")
    layers = census(CURRENT_SLOT)
    report(layers, f"Full archive at slot {CURRENT_SLOT} (sizes = today's cost model)")

    # steady-state: one full 2^21 period, scaled to a year
    period = census(SNAP - 1)  # slots 0..2^21-1 => one snapshot + all diffs of one period
    tot = report(period, "Per 2^21-slot period (24.3 days), steady state")
    per_year = SLOTS_PER_YEAR / SNAP
    print(f"\n=== Per year ({per_year:.3f} periods) ===")
    for algo, b in tot.items():
        print(f"{algo:>15}: {b * per_year / 1e9:.1f} GB/year")
