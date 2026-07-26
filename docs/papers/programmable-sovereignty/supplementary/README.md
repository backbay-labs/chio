# Supplementary Artifact

Paper: "Proof-Carrying Bilateral Admission for Cross-Organization Agent Tool
Calls"

Target: USENIX Security 2027, Cycle 1

Snapshot date: 2026-07-25

This package records the exact boundary of the paper's formal, implementation,
and experimental claims. The artifact manifest pins the source snapshot,
production symbols, behavioral tests, theorem declarations and axiom lists,
positive and negative corpora, benchmark scripts and outputs, and the
submission page limit. It also records every surface that the paper withholds
or treats as an assumption.

## Contents

- `artifact-manifest.json` is the content-addressed index for the complete
  paper artifact. It names symbols rather than mutable line numbers.
- `source-commit.txt` records the repository commit from which the submission
  artifact was assembled. Verification uses the manifest's per-path hashes
  and aggregate content digest, so it remains self-contained after a squash
  merge or in a source archive that does not carry the original commit object.
- `proof-manifest.toml` lists the six bounded theorem declarations used by the
  paper, their modules, model scopes, claim classes, and Lean axiom reports.
- `theorem-inventory.json` supplies the same theorem inventory for automated
  review.
- `lean-source.tar.gz` is a deterministic archive of the current Lean project.
  It contains no build cache, symbolic links, extended attributes, or
  machine-local files.

## Fast Verification

From the repository root:

```sh
bash scripts/check-programmable-sovereignty-artifact.sh
```

This command regenerates the artifact in check mode, verifies every file,
symbol, theorem, script, result, and hash, extracts the Lean archive into a
private temporary directory, and runs `lake build` there. If the recorded
source commit is available locally, the checker also compares the current
snapshot with that commit. The content-addressed checks do not require the
commit object to remain reachable.

## Full Reproduction

From the repository root:

```sh
bash scripts/check-programmable-sovereignty-artifact.sh --full
```

The full command additionally rebuilds the proof root, differential tests,
runtime and federation tests, live buyer closure, bilateral and replay
experiments, and the submission PDF. Fresh measurement outputs are written to
a private temporary directory so reproduction does not silently replace the
retained paper results.

The evaluated benchmark is machine-local. A new run should be expected to
produce different latency samples while preserving schemas, case counts,
non-dispatch assertions, and proof-package structure.

## Formal Boundary

The Lean archive models a strict predicate syntax over `ReceiptView` and
explicit finite domains. It proves structural treaty intersection, ladder
reduction, finite-domain no-widening, and pointwise agreement with the legacy
closure representation. It does not model cryptography, canonical JSON,
clocks, storage, organizational key control, or the production Rust runtime.
The independent Rust differential suite is alignment evidence, not extraction
or an implementation-refinement proof.
