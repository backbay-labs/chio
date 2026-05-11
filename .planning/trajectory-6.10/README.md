# Chiodos 6.10: Static Relay Directory Lifecycle

Baseline SHA: `1cc8a37c226bd223e1d5a47af116f65f6b85d620`

Branch: `codex/chiodos-6-10-static-relay-directory`

## Scope

This lane hardens verifier-owned peer-directory lifecycle for the live pheromone relay. The product surface is static and operator-owned: active and candidate directory state, restart-safe promotion and rejection, previous-version continuity, removed-peer quarantine, supervisor examples, and executable drills.

## Non-Goals

- Dynamic peer discovery or crawling.
- Dynamic trust.
- Pheromone-driven authority, lease, governance, settlement, or workflow execution.
- Hidden predicates, VC DI BBS, zkVM, FROST, new transports, or multi-region HA.

## Product Rules

- Planning labels and ticket ids stay under `.planning`.
- Production code, CLI text, schemas, fixtures, scripts, and docs use product names.
- Production relay commands must prefer verified active directory state over raw peer-directory input.
- Raw peer directories remain local-dev and test-compatible only.

## Exit Gates

- `bash scripts/check-chiodos-pheromone-directory-lifecycle.sh`
- `bash scripts/check-chiodos-pheromone-directory-lifecycle.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-directory-lifecycle.sh --negative-only`
- Existing relay ops, relay, runtime, transit, authority, proof-package, bounded, diagnostic, and threat-mutant gates as feasible on the merge train.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates.
