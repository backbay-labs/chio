# M05 Sweep Followups

| Source | Severity | Carried-forward owner | Rationale |
|--------|----------|-----------------------|-----------|
| PR #364 comments `3169733514`, `3169733525`, `3170857993`, `3170863110` on `.planning/trajectory-2/EXECUTION-STATE.json` and `.planning/trajectory-2/tickets/manifest.yml` | P1/P2 | LEDGER-R chore | The sweep instructions explicitly prohibit editing `EXECUTION-STATE.json` and `tickets/manifest.yml`. Existing replies already identify the ledger reconciliation path; this sweep records the items here and resolves the review threads without touching the ledger-owned artifacts. |
| `.planning/audits/M05-async-kernel.md` cargo-mutants baseline | P2 | post-CI mutants baseline refresh | The audit has `TBD (CI run pending)` because GitHub Actions billing is exhausted. The local sweep keeps source gates green and carries the mutants measurement forward to the first CI-enabled run. |
| `.planning/audits/M05-adversarial-escape-threat-model.md` phase handoffs | P2 | M05 sweep PR | P1 loader, P2 pending-vector, and P5 threat coverage handoffs are now covered by the current adversarial suite gates, threat-model schema gate, and generated threat coverage docs. |
