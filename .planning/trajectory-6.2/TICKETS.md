# Chiodos 6.2 Tickets

## C6.2-001: Integrator

Owner: Integrator.

Acceptance:

- Create `codex/chiodos-6-2-verifier-owned-workflow-trust` from
  `main@2c653b26abbb4677608628f2a020e92c4b25128b`.
- Pin the baseline SHA in the lane README.
- Keep planning metadata out of production code and public artifacts.

## C6.2-002: Trust Roots

Owner: Chiodos verifier owner.

Acceptance:

- Add verifier trust bundle parsing and duplicate rejection.
- Trust bundle owns BBS issuers, peer pins, ladder refs, vendor keys,
  action-class policy, workflow-intersection hashes, and pinned revocation
  epoch.
- Empty or internally inconsistent bundles fail closed.

## C6.2-003: Workflow Intersection

Owner: Workflow owner.

Acceptance:

- Add `chio.chiodos-workflow-intersection.v1` to the proof package.
- Bind workflow id, workflow grant id, pairwise intersection refs, step class
  bindings, required vendor signers, and aggregate workflow receipt hash.
- Missing, mismatched, or untrusted workflow intersections fail closed.

## C6.2-004: Verifier Refactor

Owner: Chiodos verifier owner.

Acceptance:

- `verify_package` derives verifier state from trusted verifier material, not
  package-provided pins or policy.
- Unknown peers, peer key mismatch, ladder mismatch, missing action class, stale
  ladder ref, stale lease, and missing destructive governance fail closed.

## C6.2-005: CLI

Owner: CLI owner.

Acceptance:

- Replace `--trusted-issuers` with `--trust-bundle`.
- Positive packages exit successfully and write accepted report JSON.
- Rejected packages exit nonzero and write or expose a stable failure code.

## C6.2-006: Fixtures

Owner: Fixture owner.

Acceptance:

- Regenerate the three-vendor package, verifier trust bundle, and verifier
  report.
- Add committed negative fixtures for trust-root and workflow-intersection
  failure paths.

## C6.2-007: Specs And Schemas

Owner: Spec owner.

Acceptance:

- Freeze schemas for package, trust bundle, workflow intersection, trusted
  issuer registry, selective-disclosure proof, and verifier report.
- Refresh stale Chiodos fixture docs to reflect closed and deferred gaps.

## C6.2-008: Assurance

Owner: Assurance owner.

Acceptance:

- Extend `scripts/check-chiodos-proof-package.sh` for trust-bundle and negative
  fixture coverage.
- Run targeted Cargo tests, Chiodos gate, bounded gates, threat mutants, format
  check, and targeted clippy.
- Open PR, address review threads, and merge to `main`.
