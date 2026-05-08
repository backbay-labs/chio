# Per-crate cargo-mutants config overrides

cargo-mutants 25.x reads its base config from the workspace
`.cargo/mutants.toml`. That config sets
`additional_cargo_test_args = ["--workspace", "--exclude",
"chio-cpp-kernel-ffi"]` so mutants are tested against the full
workspace, matching the CI hosted-nightly invocation.

Some crates need to override that workspace scope for measurement
fidelity reasons (typically: a pre-existing unrelated test failure in
a different crate that would mask the per-mutant signal). The override
is per-run, applied via cargo-mutants' `--config <FILE>` flag:

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/<crate>.toml \
  -p <crate> --in-place \
  --output audits/evidence/mutants/<crate>
```

Each override file in this directory:
- Repeats the workspace `examine_globs` for that crate (so the same
  trust-boundary surface is measured), or enumerates a per-crate
  surface for crates not present in the workspace examine list.
- Repeats the workspace `exclude_globs` (test/build/fuzz scaffolding).
- Repeats `timeout_multiplier` and `minimum_test_timeout`.
- Replaces `additional_cargo_test_args` with a per-package scope.
- Records the *reason* the override is necessary in the file header.

The per-crate JSON summary
(`audits/evidence/mutants/<crate>/<date>.json`) records the actual
test scope used (workspace vs package-only).

## Files

- `chio-weights.toml`: package-only scope to avoid the pre-existing
  chio-acp-proxy test failure that would otherwise mask every
  per-mutant signal. chio-weights is the M10 phase 4 model-card
  surface and is not in the canonical six trust-boundary crates per
  `releases.toml [trust_boundary_crates]`, but is treated as
  trust-boundary for TRJ5-A1 because malformed cards must cause the
  kernel to refuse bind. examine_globs covers all four logic-bearing
  source files (bundle, card, error, lineage); lib.rs is re-export
  only.
