# Chiodos 6.1 Tickets

## C6.1-001: Integrator

Acceptance:

- Create `codex/chiodos-6-1-strict-verifier` from current `main`.
- Pin the baseline SHA in the lane README.
- Keep planning metadata out of production code and public artifacts.

## C6.1-002: Federation

Acceptance:

- Emit and verify the strict Chiodos bilateral predicate profile.
- Include required `tool_args_hash`.
- Keep signature-slice compatibility separate from strict Chiodos conformance.
- Preserve fail-closed error mapping for malformed DSSE and statements.

## C6.1-003: Chiodos Library

Acceptance:

- Move proof-package types and verification into a production crate.
- Leave the three-vendor example as a fixture generator and consumer.
- Keep unsupported range, VC Data Integrity, and zkVM claims rejected.

## C6.1-004: CLI

Acceptance:

- Add `chio chiodos verify --package <path> --trusted-issuers <path> --report <path>`.
- Exit successfully only for accepted packages.
- Write verifier report JSON.

## C6.1-005: Fixtures

Acceptance:

- Committed fixtures verify through the production crate and CLI.
- Fixture checks separate deterministic package structure from BBS proof
  randomness.

## C6.1-006: Assurance

Acceptance:

- Extend `scripts/check-chiodos-proof-package.sh`.
- Add negative checks for legacy stub schemas, unsupported claims, and
  signature-slice substitution in strict mode.
- Update docs to remove stale partial-verifier claims only where closed.

## C6.1-007: Integration

Acceptance:

- Run the targeted Cargo tests, Chiodos gate, bounded gates, threat mutants,
  format check, and targeted clippy.
- Open PRs, address review threads, and merge to `main`.
