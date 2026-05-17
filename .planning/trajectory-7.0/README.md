# Chiodos 7.0 Live Cross-Vendor Runtime Spine

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chiodos-7-0-live-runtime-spine`

## Scope

Chiodos 7.0 moves the Chiodos surface from offline proof and operator evidence into a bounded local runtime spine. Chiodos admission must be able to deny or admit an actual `ChioKernel` tool call before dispatch, attach admission evidence to signed receipts, and support live loopback proof-package generation from runtime outputs.

The lane is local and bounded. It does not add dynamic trust, peer discovery, settlement execution, live downstream notification dispatch, hidden predicates, VC Data Integrity BBS, zkVM, FROST, new transports, or pheromone-driven lease or governance issuance.

## Contracts

- `chio.chiodos.runtime-admission-profile.v1`
- `chio.chiodos.runtime-admission-bundle.v1`
- `chio.chiodos.verifier-trust-bundle.v4`
- `chio.chiodos.runtime-trusted-verifiers.v1`
- `chio.chiodos.runtime-admission-report.v1`
- `chio.chiodos.runtime-workflow-run-report.v1`
- signed strict runtime trust input over verifier-owned Chiodos trust material

## Final Gates

- `cargo test -p chio-chiodos-runtime`
- `cargo test -p chio-kernel chiodos_runtime`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-chiodos-authority`
- `cargo test -p chio-pheromone-runtime`
- `cargo test -p chio-cli --bin chio chiodos_runtime`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-runtime-spine.sh`
- `bash scripts/check-chiodos-runtime-spine.sh --schema-only`
- `bash scripts/check-chiodos-runtime-spine.sh --negative-only`
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`
