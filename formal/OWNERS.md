# Formal Verification Ownership

This file names the humans on the hook for Chio's formal-verification surface
(Apalache TLA+ models, Lean4 proofs, Aeneas extraction, Kani harnesses, Rust
formal-verification glue, and the nightly liveness lane). It lives next to the
formal artifacts under `formal/` so ownership stays close to the code being
proved.

## Ownership

| Role          | Handle                         | Notes                                    |
| ------------- | ------------------------------ | ---------------------------------------- |
| Primary owner | @backbay-labs/chio-maintainers | Chio security team (formal verification) |
| Backup owner  | @backbay-labs/chio-maintainers | Same team; backup for primary absence    |

Update `CODEOWNERS` when formal-verification paths should route to different
GitHub handles.

## Responsibilities

The formal owners (primary and backup) are jointly on the hook for:

- **Apalache configuration:** keep `formal/tla/` model-checker configs
  (`.cfg` files, invariants, and the pinned Apalache version under
  `tools/install-apalache.sh`) green and reproducible. Bump the pin
  deliberately, never silently.
- **Invariant maintenance:** when the capability algebra, scope lattice,
  receipt chain, or revocation propagation rules change in
  `crates/chio-core-types/` or `crates/chio-kernel-core/`, update the
  corresponding TLA+ specs, Lean4 lemmas, and Kani harnesses so the
  formal artifacts stay in sync with executable code.
- **Counterexample triage:** when Apalache or Kani produces a
  counterexample (locally or in CI), reproduce it, classify it as
  spec-bug vs implementation-bug vs harness-bug, file the appropriate
  ticket, and drive it to closure. Counterexamples must not be silenced
  by widening the invariant without a written justification.
- **Nightly liveness lane:** own the nightly job that runs the long-form
  liveness / fairness checks (the lane that is too slow for per-PR CI).
  Keep its runtime budget honest, investigate timeouts, and surface
  regressions in the next stand-up rather than letting the lane go red
  unattended.

## Escalation

If the primary owner is unavailable, the backup owner has full authority
to merge formal-only changes (TLA+, Lean, Aeneas, Kani harness updates)
that are required to keep CI green. Escalations that touch the
capability algebra surface area, the `chio-core-types` API, or the
attestation verifier must wait for the primary owner or be explicitly
co-signed by the kernel-core owner listed in `CODEOWNERS`.

## Related files

- `CODEOWNERS` - routing for the `formal/**` glob (maintained manually).
- `formal/proof-manifest.toml` - inventory of proofs and their status.
- `formal/theorem-inventory.json` - machine-readable theorem index.
