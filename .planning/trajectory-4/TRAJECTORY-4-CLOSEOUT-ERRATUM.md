# Trajectory 4 Closeout Erratum

**Status**: trj4 is reopened. The prior closeout claim recorded in `TRAJECTORY-4-FINAL.md` and the audit-doc set is retracted in full.

**Reopen date**: 2026-05-05.

**Authoritative plan**: `/Users/connor/.claude/plans/typed-coalescing-hejlsberg.md` (wave-based closeout, Wave 0 through Wave 16).

## Why this erratum exists

A 10-agent post-merge audit of the integrated trj4 PR set (PR #579 plus follow-up PR #583) found a consistent pattern: structural framing landed (types, schemas, registry entries, doc generators) but runtime wiring did not (kernel/verifier hot paths, separate-file negative conformance tests, real proof artifacts behind theorem-inventory rows). Approximately 30 P0/P1 issues were filed against artifacts that the prior closeout summary lists under "Closed" or "Validation". The brainstorm catalog has roughly 126 ideas across 9 lenses, of which approximately 95% are not shipped in the strict "production hot path is wired and a real test exercises the failure path" sense.

Affirmative closure language across the trj4 docs (this folder), `releases.toml`, and `docs/` is therefore retracted and replaced with reopen language. New work proceeds under the wave plan.

## What is in scope of the retraction

- `releases.toml` `[trajectory_4]`: `trj4_release_status = "reopened"`; the previously recorded `trj4_release_tag` line has been retired in favor of this erratum reference.
- `.planning/trajectory-4/TRAJECTORY-4-FINAL.md`: superseded; "Closed" milestone entries are reopened.
- `.planning/trajectory-4/README.md`: the audit-doc table reads "Reopened" for every row that previously read "closed".
- `.planning/trajectory-4/audits/T*.md` rows that previously claimed closure on the integrated trj4 branch are downgraded to "reopened" by this erratum. Per-audit rewrites land in subsequent waves as their close bars are actually met.
- `docs/security/threat-coverage.md`: the heading is corrected to reflect the live `scripts/check-threat-coverage.sh` PASS state of 20 covered / 0 pending / 0 uncovered. A note records that 9 of the 20 covered rows currently have weak or meta-only coverage; Wave 4 of the wave plan hardens these rows.

## What is NOT changed by this erratum

- The actual artifacts that did land (mobile attestation verifier paths, threat-model JSON expansion, conformance test stubs, cargo-vet exemption burn-down) remain on `main` and are not reverted. The retraction is over the closure CLAIM, not the code.
- `releases.toml` retains `trj4_release_sha`, the workflow-run URLs, and the integrated PR URL for provenance.

## Pointers

- Wave plan: `/Users/connor/.claude/plans/typed-coalescing-hejlsberg.md`
- Threat coverage gate: `bash scripts/check-threat-coverage.sh`
- Close-bar tracker (Wave 0 deliverable, lands separately): `.planning/trajectory-4/closeout/CLOSE-BAR-TRACKER.md`
- Per-wave summaries (lands as each wave finishes): `.planning/trajectory-4/closeout/wave-NN-summary.md`

## How to read trj4 docs after this erratum

1. Treat any "closed", "delivered", "shipped", or "integrated" claim about trj4 outcomes as retracted unless it is restated in a wave-summary doc that post-dates 2026-05-05.
2. The wave plan is the source of truth for what trj4 means going forward.
3. `releases.toml` `trj4_release_status` is the machine-readable signal; CI gates and downstream automation should read it before treating any historical trj4 release tag as authoritative.
