# Chiodos 6.19 Archive Restore Drills And Extraction Hardening

Baseline SHA: `27b00d458c025d0ee3c0de8ff935dd989689d95a`

Branch: `codex/chiodos-6-19-archive-restore-hardening`

Stacking note: this branch is stacked on the open Chiodos 6.18 archive-package PR #676 because that PR is still draft/open. Rebase this branch onto `main` after 6.18 merges and refresh this baseline SHA before final merge.

## Scope

Chiodos 6.19 hardens local archive operations after 6.18. It adds reusable safe tar/gzip IO in `chio-cli`, refactors archive package create, verify, and extract onto that helper, hardens `.arcguard` and conformance archive extraction, adds archive package generations, and introduces local restore/readback drill reports.

The lane remains local and artifact-first. Chio does not delete, move, upload, or mutate retained evidence; send notifications; store downstream credentials; accept dynamic sink URLs; mutate policy from alert state; discover trust dynamically; add new transports; settle payments; or add hidden predicates, VC Data Integrity BBS, zkVM, or FROST.

## Contracts

- `chio.pheromone.relay-alert-assurance-archive-restore-profile.v1`
- `chio.pheromone.relay-alert-assurance-archive-restore-drill-report.v1`
- `chio.pheromone.relay-alert-assurance-archive-restore-negative-fixture-corpus.v1`

## PR Train

1. Safe archive helper and focused failing tests.
2. Archive package refactor and generation continuity.
3. `.arcguard` and conformance extraction hardening.
4. Restore drill contracts, CLI, fixtures, schemas, and gate.
5. Dashboard, docs, CI triggers, PR review closeout, and main rerun.

## Final Gates

- `cargo test -p chio-cli guard_archive_hardening`
- `cargo test -p chio-cli conformance_archive_hardening`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance`
- `cargo test -p chio-pheromone-relay alert_assurance_archive_hardening --test relay`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive-hardening.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive-hardening.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive-hardening.sh --negative-only`
- Existing archive package, export, archive, assurance, delivery, handoff, alert routing, bounded, diagnostic, and threat-mutant gates
- `cargo fmt --all -- --check`
- Targeted clippy for `chio-cli`, `chio-pheromone-relay`, and `chio-spec-validate` with `-D warnings`
