import Lake
open Lake DSL

require aeneas from "../../../../aeneas/backends/lean"

package «backfillProofs» where

@[default_target] lean_lib «Backfill» where
  globs := #[.submodules `Backfill]
