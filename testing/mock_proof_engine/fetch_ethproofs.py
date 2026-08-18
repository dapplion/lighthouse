#!/usr/bin/env python3
"""Fetch real zkEVM proof artifacts from the Ethproofs public API.

No authentication and no third-party packages are required: the two endpoints
used here are the ones the Ethproofs OpenAPI spec marks as unauthenticated.

    GET https://ethproofs.org/api/v0/blocks/{block_number}
        -> JSON metadata, including the canonical block "hash".

    GET https://ethproofs.org/api/v0/proofs/download/block/{block_hash}
        -> application/zip containing every proved proof for that block,
           one entry per proof named "<team>_<cluster_uuid>_<proof_id>.bin".

Ethproofs runs its full cohort against every 100th mainnet block, so this
script snaps the starting block down to a multiple of BLOCK_STRIDE and walks
backwards in the same stride. Blocks that are not a multiple of 100 are proved
by only a handful of teams.

Proofs are opaque binary blobs. Each proving team uses its own encoding
(zstd frames, gzip, or bare bincode-style serialization), which is exactly
what we want when feeding realistic bytes through gossip.

Usage:
    fetch_ethproofs.py --list
    fetch_ethproofs.py --count 4 --out ./proofs
    fetch_ethproofs.py --block 25700000 --count 12 --out ./proofs
"""

import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile

BASE_URL = "https://ethproofs.org/api/v0"

# Ethproofs rate-limits the ZIP download endpoint to ~10 requests/minute.
DEFAULT_SLEEP = 7.0

# Block number known to exist in the Ethproofs index; used as the lower bound
# when auto-discovering the newest indexed block.
ANCHOR_BLOCK = 25_000_000

# The full Ethproofs cohort proves every 100th block.
BLOCK_STRIDE = 100

# Canonical ordering of proving teams, so that a given team keeps a stable
# position in --list output across runs. Teams not listed here sort after these,
# alphabetically. The team slug is the closest thing the public API exposes to a
# "proving system" identifier.
KNOWN_TEAMS = (
    "antchain-openlabs",
    "axiom",
    "brevis",
    "cysic",
    "gattaca",
    "lambdaclass",
    "matter-labs",
    "pico",
    "scroll",
    "succinct",
    "zilkworm",
    "zisk",
    "zkm",
)

# Lighthouse EIP-8025 caps a single execution proof at 4 MiB.
MAX_PROOF_SIZE = 4 * 1024 * 1024


def _http_get(url, timeout=120):
    """GET a URL, returning (status, body_bytes). Never raises on 4xx/5xx."""
    req = urllib.request.Request(url, headers={"User-Agent": "fetch_ethproofs/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def _team_sort_key(team):
    if team in KNOWN_TEAMS:
        return (0, KNOWN_TEAMS.index(team), team)
    return (1, 0, team)


def get_block(block_number):
    """Return the Ethproofs metadata dict for a block, or None if not indexed."""
    status, body = _http_get(f"{BASE_URL}/blocks/{block_number}")
    if status != 200:
        return None
    return json.loads(body)


def find_latest_block(anchor=ANCHOR_BLOCK):
    """Binary-search the newest block number the Ethproofs index knows about."""
    if get_block(anchor) is None:
        raise SystemExit(f"anchor block {anchor} is not indexed by Ethproofs")

    low, step = anchor, 100_000
    while get_block(low + step) is not None:
        low += step
        step *= 2

    high = low + step
    while high - low > BLOCK_STRIDE:
        mid = ((low + high) // 2 // BLOCK_STRIDE) * BLOCK_STRIDE
        if mid <= low:
            break
        if get_block(mid) is not None:
            low = mid
        else:
            high = mid
    return (low // BLOCK_STRIDE) * BLOCK_STRIDE


def download_block_proofs(block_hash):
    """Download and unpack every proved proof for a block hash.

    Returns a list of (team, cluster_uuid, proof_id, data) tuples.
    """
    status, body = _http_get(f"{BASE_URL}/proofs/download/block/{block_hash}")
    if status == 429:
        raise RuntimeError("rate limited by Ethproofs (HTTP 429); retry in a minute")
    if status != 200:
        raise RuntimeError(f"HTTP {status} downloading proofs for {block_hash}")

    proofs = []
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        for info in archive.infolist():
            stem = os.path.basename(info.filename)
            if stem.endswith(".bin"):
                stem = stem[: -len(".bin")]
            parts = stem.split("_")
            team = parts[0]
            cluster = parts[1] if len(parts) > 1 else ""
            proof_id = parts[2] if len(parts) > 2 else ""
            proofs.append((team, cluster, proof_id, archive.read(info)))
    return proofs


def collect(count, block_number, sleep_secs, verbose=True):
    """Gather one proof per distinct proving team, walking back over blocks."""
    collected = {}
    block = (block_number // BLOCK_STRIDE) * BLOCK_STRIDE
    attempts = 0

    while len(collected) < count and attempts < 8:
        meta = get_block(block)
        if meta is None:
            block -= BLOCK_STRIDE
            attempts += 1
            continue

        if verbose:
            print(
                f"block {meta['block_number']} {meta['hash']}", file=sys.stderr
            )
        for team, cluster, proof_id, data in download_block_proofs(meta["hash"]):
            if team not in collected:
                collected[team] = {
                    "team": team,
                    "cluster_id": cluster,
                    "proof_id": proof_id,
                    "block_number": meta["block_number"],
                    "block_hash": meta["hash"],
                    "data": data,
                }

        attempts += 1
        if len(collected) < count:
            block -= BLOCK_STRIDE * 1000
            if sleep_secs:
                time.sleep(sleep_secs)

    ordered = sorted(collected.values(), key=lambda p: _team_sort_key(p["team"]))
    return ordered[:count]


def cmd_list(block_number, sleep_secs):
    proofs = collect(count=999, block_number=block_number, sleep_secs=sleep_secs)
    print(f"{'idx':>3}  {'proving system':<20} {'block':>10} {'bytes':>10}  over 4MiB")
    for index, proof in enumerate(proofs):
        size = len(proof["data"])
        flag = "YES" if size > MAX_PROOF_SIZE else ""
        print(
            f"{index:>3}  {proof['team']:<20} {proof['block_number']:>10} "
            f"{size:>10}  {flag}"
        )
    print(f"\n{len(proofs)} proving systems available", file=sys.stderr)
    return 0


def cmd_fetch(count, block_number, out_dir, sleep_secs):
    proofs = collect(count=count, block_number=block_number, sleep_secs=sleep_secs)
    if not proofs:
        print("no proofs retrieved", file=sys.stderr)
        return 1

    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    for index, proof in enumerate(proofs):
        path = os.path.join(out_dir, f"{index}.bin")
        with open(path, "wb") as handle:
            handle.write(proof["data"])

        size = len(proof["data"])
        manifest.append(
            {
                "proof_type": index,
                "file": f"{index}.bin",
                "proving_system": proof["team"],
                "cluster_id": proof["cluster_id"],
                "proof_id": proof["proof_id"],
                "block_number": proof["block_number"],
                "block_hash": proof["block_hash"],
                "size_bytes": size,
            }
        )
        warning = "  WARNING: exceeds 4 MiB" if size > MAX_PROOF_SIZE else ""
        print(f"{path}  {proof['team']:<20} block {proof['block_number']} "
              f"{size} bytes{warning}")

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, indent=2)
    print(f"{manifest_path}  ({len(manifest)} proofs)")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--list", action="store_true", help="print available proving systems and exit"
    )
    parser.add_argument(
        "--count", type=int, default=4, help="number of proofs to fetch (default: 4)"
    )
    parser.add_argument(
        "--out", default="./ethproofs", help="output directory (default: ./ethproofs)"
    )
    parser.add_argument(
        "--block",
        type=int,
        default=None,
        help="starting block number (default: newest block Ethproofs has indexed)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=DEFAULT_SLEEP,
        help=f"seconds between block downloads (default: {DEFAULT_SLEEP})",
    )
    args = parser.parse_args()

    block = args.block if args.block is not None else find_latest_block()

    if args.list:
        return cmd_list(block, args.sleep)
    return cmd_fetch(args.count, block, args.out, args.sleep)


if __name__ == "__main__":
    sys.exit(main())
