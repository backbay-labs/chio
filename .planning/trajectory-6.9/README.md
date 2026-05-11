# Chiodos 6.9 Relay Operations

## Baseline

- Branch: `codex/chiodos-6-9-relay-operations`
- Baseline SHA: `a4b885e135e29bae814399ca85da5fcdc7b0ec23`
- Active lane: production relay operations for the existing signed HTTP/JSON pheromone relay.

## Scope

This lane hardens local relay operation without changing the trust model. Peer directories remain verifier-owned. Request signatures remain mandatory. Pheromones remain advisory evidence.

In scope:

- Signed peer-directory bundles with issuer trust and rollback protection.
- Local-dev and production profile linting.
- Real signed scheduler delivery from `relay tick`.
- Durable relay health, readiness, status, retry, dead-letter, and catch-up pressure reporting.
- Operator docs and gate coverage for schema, positive, and negative scenarios.

Out of scope:

- Dynamic trust or peer crawling.
- Pheromone-driven authority decisions.
- Hidden predicates, VC DI BBS, zkVM, FROST, settlement, or new transport protocols.

## Final Gate Checklist

- `cargo test -p chio-pheromone-relay`
- `cargo test -p chio-pheromone-runtime`
- `cargo test -p chio-federation pheromone`
- `cargo test -p chio-cli --bin chio chiodos_pheromone`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-metrics-spec`
- `bash scripts/check-chiodos-pheromone-relay-ops.sh`
- `bash scripts/check-chiodos-pheromone-relay-ops.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-ops.sh --negative-only`
- Existing relay, runtime, transit, authority issuance, proof-package, bounded ship bar, bounded diagnostic, and threat mutant gates.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
