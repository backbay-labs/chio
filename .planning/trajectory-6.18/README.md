# Chiodos 6.18 Signed Archive Package And Safe Extraction

Baseline SHA: `e933bb574d56868990f7d41bfbf6293853b62c7c`

Branch: `codex/chiodos-6-18-archive-package-extraction`

## Scope

Chiodos 6.18 promotes the archive packaging shadow lane into an active local evidence lane. It adds signed archive packages over selected relay alert assurance export bundle directories, strict package verification, safe extraction through a verified extraction plan, local physical archive readback drills, and retention handoff readiness evidence.

The lane stays local and artifact-first. Chio does not delete, move, upload, or mutate retained evidence; send notifications; store downstream credentials; accept dynamic sink URLs; mutate policy from alert state; discover trust dynamically; add new transports; settle payments; or add hidden predicates, VC Data Integrity BBS, zkVM, or FROST.

## Contracts

- `chio.pheromone.relay-alert-assurance-archive-package-manifest.v1`
- `chio.pheromone.relay-alert-assurance-archive-package-report.v1`
- `chio.pheromone.relay-alert-assurance-trusted-archive-packagers.v1`
- `chio.pheromone.relay-alert-assurance-archive-extraction-report.v1`
- `chio.pheromone.relay-alert-assurance-physical-archive-evidence.v1`
- `chio.pheromone.relay-alert-assurance-physical-archive-drill-report.v1`
- `chio.pheromone.relay-alert-assurance-retention-handoff-profile.v1`
- `chio.pheromone.relay-alert-assurance-retention-handoff-evidence.v1`
- `chio.pheromone.relay-alert-assurance-retention-handoff-report.v1`

## PR Train

1. Bundle identity prerequisite.
2. Archive package contracts and pure verification.
3. Archive package CLI create and verify.
4. Safe extraction plan and extraction command.
5. Physical readback drill and retention handoff readiness.
6. Dashboard, docs, gates, PR review closeout, and main rerun.

## Final Gates

- `cargo test -p chio-pheromone-relay alert_assurance_archive_package --test relay`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive-package.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive-package.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive-package.sh --negative-only`
- Existing export, archive, assurance, delivery, handoff, alert routing, bounded, diagnostic, and threat-mutant gates
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`
