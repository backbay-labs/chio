# Chiodos 6.20 External Retention Evidence Review

Baseline SHA: `817a90f27e3bafd09f228ae39a2896aaf925c559`

Branch: `codex/chiodos-6-20-external-retention-review`

Stacking note: this branch is stacked on Chiodos 6.19 PR #680, which is stacked on Chiodos 6.18 PR #676. Rebase this branch onto `main` after 6.18 and 6.19 merge, then refresh this baseline SHA before final merge.

## Scope

Chiodos 6.20 adds a local-only external retention evidence review lane over archive package, restore drill, physical readback, and retention handoff artifacts. It answers whether a selected package generation set has enough bounded, hash-bound, caller-supplied local evidence for operator-managed external retention review.

The lane remains artifact-first. Chio does not delete, move, upload, or mutate retained evidence; call external retention systems; store downstream credentials; accept dynamic URLs; claim external custody; mutate policy from alert state; discover trust dynamically; add transports; settle payments; or add hidden predicates, VC DI BBS, zkVM, or FROST.

## Contracts

- `chio.pheromone.relay-alert-assurance-external-retention-profile.v1`
- `chio.pheromone.relay-alert-assurance-external-retention-review-report.v1`
- `chio.pheromone.relay-alert-assurance-external-retention-negative-fixture-corpus.v1`

## PR Train

1. Planning docs and active shadow promotion.
2. External retention profile/report contracts and focused relay tests.
3. CLI evidence loader and `retention external-review` command.
4. Schemas, fixtures, negative corpus, gate script, and CI trigger.
5. Dashboard and docs refresh.
6. Final verification, stacked PR, review-thread cleanup, merge, and post-merge rerun.

## Final Gates

- `cargo test -p chio-pheromone-relay external_retention_review --test relay`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-metrics-spec`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-external-retention.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-external-retention.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-external-retention.sh --negative-only`
- Existing archive hardening, archive package, export, archive, assurance, delivery, handoff, alert routing, bounded, diagnostic, and threat-mutant gates
- `cargo fmt --all -- --check`
- Targeted clippy for `chio-pheromone-relay`, `chio-cli`, and `chio-spec-validate` with `-D warnings`
