# Chio 7.0 Live Cross-Vendor Runtime Spine

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chio-7-0-live-runtime-spine`

## Scope

Chio 7.0 moves the Chio surface from offline proof and operator evidence into a bounded local runtime spine. Chio admission must be able to deny or admit an actual `ChioKernel` tool call before dispatch, attach admission evidence to signed receipts, and support live loopback proof-package generation from runtime outputs.

The lane is local and bounded. It does not add dynamic trust, peer discovery, settlement execution, live downstream notification dispatch, hidden predicates, VC Data Integrity BBS, zkVM, FROST, new transports, or pheromone-driven lease or governance issuance.

## Contracts

- `chio.runtime.admission-profile.v1`
- `chio.runtime.admission-bundle.v1`
- `chio.federation.verifier-trust-bundle.v1`
- `chio.runtime.trusted-verifiers.v1`
- `chio.runtime.admission-report.v1`
- `chio.runtime.workflow-run-report.v1`
- signed strict runtime trust input over verifier-owned Chio trust material

## Final Gates

- `cargo test -p chio-runtime-core`
- `cargo test -p chio-kernel chio_runtime`
- `cargo test -p chio-attest-buyer-core`
- `cargo test -p chio-federation-authority`
- `cargo test -p chio-pheromone-runtime`
- `cargo test -p chio-cli --bin chio_runtime`
- `cargo test -p chio-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chio-runtime-spine.sh`
- `bash scripts/check-chio-runtime-spine.sh --schema-only`
- `bash scripts/check-chio-runtime-spine.sh --negative-only`
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`
