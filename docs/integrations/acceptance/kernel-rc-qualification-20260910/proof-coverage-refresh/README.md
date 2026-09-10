# Proof coverage input metadata refresh

The source CI job for `0599e9fa3ee337719986f6fd88466f75ba0290dd` passed the
structural and formal-mirror gates, then refused stale generated coverage input
hashes. The existing generator reproduced the exact hosted expected digest.
Regeneration changes only eight added and seven removed lines in the Generation
section of `docs/formal/COVERAGE.md`. The proof table before that section is
byte-identical; its 58 rows and 166 declared artifacts are unchanged.

The refreshed inputs include the selected lockfile, prior generated wire and
governed-intent changes, receipt persistence, and the Rust file inventory.
The existing `cargo xtask gen proof-coverage --check` now passes. Its generator
and gate were not edited. This does not declare new formal proof success or
close the interrupted release qualifier or six-host acceptance requirements.

[The record](manifest.json) preserves the original hosted failure, local failing
control, regeneration output, generated JSON and final checked result. The
standalone xtask build used one worker and its own target directory; no kernel
build checkout or target was changed. Confidence: high in the reproduced drift
and generated metadata repair.
