#!/usr/bin/env bash
#
# Regenerate the Lean model of this crate from its Rust source, so the theorems in
# `proofs/Backfill/Properties.lean` are about the code that ships and not a transcription of
# it. Run after any change to `src/lib.rs`, then `cd proofs && lake build`.
#
# Needs `charon` and `aeneas` on PATH, or CHARON and AENEAS pointing at them. See
# `proofs/README.md` for the versions this was built against.

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHARON="${CHARON:-charon}"
AENEAS="${AENEAS:-aeneas}"

# A target dir of its own: Charon builds with its own pinned nightly, which would otherwise
# invalidate the workspace's build cache on every extraction.
export CARGO_TARGET_DIR="${CHARON_TARGET_DIR:-$CRATE_DIR/target}"

cd "$CRATE_DIR"
# `--dest` is needed because Charon resolves a relative destination against the workspace
# root, not the crate.
"$CHARON" cargo --preset=aeneas --dest "$CRATE_DIR"
# `-loops-to-rec` extracts loops as recursive functions rather than as applications of the
# `loop` combinator, so a loop spec is proved by the ordinary unfold-and-recurse idiom.
"$AENEAS" -backend lean -loops-to-rec -dest "$CRATE_DIR/proofs" "$CRATE_DIR/backfill_core.llbc"
mv proofs/BackfillCore.lean proofs/Backfill/Core.lean
