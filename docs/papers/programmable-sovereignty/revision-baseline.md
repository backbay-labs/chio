# Programmable Sovereignty Revision Baseline

Baseline captured before the formal, evaluation, and prose revision.

## Source snapshot

- Commit: `51e46336b1f1d52908fc7b14cf34d9476935958f`
- Rust: `rustc 1.93.0 (254b59607 2026-01-19)`
- Cargo: `cargo 1.93.0 (083ac5135 2025-12-15)`
- Lean: `4.28.0`
- Lake: `5.0.0-src+7e01a1b`
- TeX: `pdfTeX 3.141592653-2.6-1.40.25`, TeX Live 2023/Debian
- Paper target in the checked-in source: USENIX Security 2027 Cycle 1

## Manuscript baseline

- Title: `Programmable Sovereignty: Lean-Attestable Constitutions Over
  Capability-Bounded Federated Receipts`
- USENIX PDF: 16 total pages
- References begin: page 14
- Body: 13 pages
- LaTeX submission gate: clean citations, references, bibliography, and body
  page count
- Existing PDF and supplementary snapshot date: May 18, 2026

## Formal baseline

The checked-in paper names four theorems from
`formal/lean4/Chio/Chio/Treaty/Intersection.lean`:

1. `treaty_admission_iff_predicate_intersection`
2. `treaty_admission_stable_under_ladder_floor`
3. `amendment_admissible_iff_backward_refinement`
4. `amendment_without_refinement_rejected`

`./scripts/check-formal-proofs.sh` builds the 23-job Lean root, finds no
`sorry`, and validates the theorem inventory and assumption manifest.

The successful build does not resolve these model gaps:

- `Constitution` stores opaque predicates of type `ReceiptId -> Bool`.
- `BackwardRefines` is universal implication over all receipt strings and has
  no decision procedure in the closure model.
- `PredicateLang.lean` calls this a category error and is not yet connected to
  the polity model.
- Lean `Polity` contains scope and constitution, not the paper's citizenship
  component `C`.
- The theorem domain is a receipt identifier, while the prose trace discusses
  evidence, decisions, and failure codes.
- No proof or differential gate connects the four theorems to the Rust treaty
  evaluator.

## Evaluation baseline

Checked-in generated results:

| Metric | Result | Evidence status |
| --- | --- | --- |
| Kernel dispatch allow | p50 86.567 us, Criterion CI 86.143 us to 86.846 us | Component measurement |
| Treaty intersection, `N = 1` | p50 135.29 us, p99 196.88 us | Component measurement |
| Treaty intersection, `N = 10` | p50 499.17 us, p99 655.08 us | Component measurement |
| Treaty intersection, `N = 100` | p50 4539.50 us, p99 4794.12 us | Component measurement |
| BBS selective disclosure | 624 bytes, p50 156378.58 us, p99 158658.71 us | Optional privacy-path measurement |
| Generic replay corpus | 50 replay goldens in 1 s | Does not cover bilateral admission |
| Receipt signing | Unreported | Existing scaffold not admissible |
| Receipt verification | Unreported | No dedicated paper harness |
| Anchor inclusion | Unreported | Outside narrowed contribution |
| Full bilateral allow and deny | Unreported | No dedicated paper harness |

The repository does contain a stronger unmeasured correctness surface:

- `scripts/check-chio-treaty-buyer-hero-loop.sh`
- `scripts/check-chio-live-treaty-buyer-closure.sh`
- `examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json`
- `crates/kernel/chio-runtime-harness/src/buyer_closure.rs`

The revision will promote this existing live path into the paper evaluation
instead of treating the generic replay corpus as bilateral evidence.

## Artifact-pointer drift

The paper promises durable `file:line` evidence, but its source snapshot has
already drifted from the current implementation:

- `admission_hook.rs:88` is now `with_fixed_now_unix_ms`; the runtime
  `evaluate` method begins at line 102.
- `treaty.rs:261` is now the closing line of
  `is_supported_treaty_scope_schema`; `compute_ladder_intersection` begins at
  line 262.
- `examples/chio-3vendor/src/main.rs` is a six-line command entry point; the
  fixture command implementation lives primarily in `src/commands.rs`, while
  the runtime buyer closure lives in `chio-runtime-harness`.

The revised artifact will use symbol names and a commit-pinned manifest.

## Baseline gate record

The following gates are required before Phase 1 begins:

```bash
./scripts/check-formal-proofs.sh
cargo test -p chio-runtime-core --test runtime_admission
cargo test -p chio-runtime-core --test runtime_buyer_review
cargo test -p chio-runtime-harness
cargo test -p chio-federation --lib
bash scripts/check-chio-live-treaty-buyer-closure.sh
make -C docs/papers/programmable-sovereignty submit-check
```

Record completion here after each command returns successfully:

- [x] Formal proof build, placeholder scan, and inventory sanity
- [x] Runtime admission tests, 34 passed
- [x] Runtime buyer-review tests, 21 passed
- [x] Runtime harness tests, 22 passed
- [x] Federation library tests, 101 passed
- [x] Live treaty-buyer closure, including generated package verification and
  adversarial rejection cases
- [x] USENIX LaTeX submission gate, 13 body pages

The SQLite serving-owner checks require newly created lock directories to be
owned by the effective user and not group- or world-writable. The first harness
run inherited a `0002` umask and correctly rejected its group-writable lock
root. The recorded successful runs used `umask 077` and a private `TMPDIR`
under `target/programmable-sovereignty-tmp`. No product check was disabled.
