# Mutation testing evidence

This directory holds per-crate cargo-mutants evidence for the seven
trust-boundary crates measured in the Chio mutation baseline.

## What is committed here

Each per-crate subdirectory contains:

- A dated JSON summary (`YYYY-MM-DD.json`) - the authoritative
  machine-readable result consumed by `audits/mutation/aggregate.sh`.
- `mutants.out/caught.txt`, `missed.txt`, `timeout.txt`, `unviable.txt` -
  one line per outcome, used by the aggregation and summary scripts.
- `README.md` - human-readable run narrative with methodology notes.

`banner.json` at this level records the overall mutation program status
across all seven crates.

## What is NOT committed here

The raw per-run cargo-mutants output - `mutants.out/diff/` (per-mutant
source patches) and `mutants.out/mutants.json` (full mutant catalogue) -
is produced by each cargo-mutants invocation and published as release
artifacts rather than tracked in the repository. These files were
previously committed but were removed because 891 machine-generated diff
blobs (~4.6 MB) belong in release archives, not in the working tree.

The `.gitignore` in this directory excludes `diff/` and `mutants.json`
so that regenerated run output is not accidentally committed.

To regenerate the diff corpus locally, re-run cargo-mutants using the
per-crate config in `audits/mutation/per-crate-configs/`. The resulting
counts should match the corresponding dated JSON summary.

## Aggregate and summary scripts

`audits/mutation/aggregate.sh` reads `caught.txt`, `missed.txt`,
`timeout.txt`, and `unviable.txt` from each `mutants.out/` directory and
emits a markdown kill-rate table. It also reads the dated JSON summaries
for partial-run labels. It does NOT require `diff/` or `mutants.json` to
produce accurate kill-rate output.

`audits/mutation/summary.sh` writes dated JSON summaries from a live
`mutants.out/` directory. It reads `mutants.json` when present to derive
`total_discovered`, but treats its absence gracefully.
