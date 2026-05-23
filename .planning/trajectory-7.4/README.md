# Chio 7.4 - Production Local Runtime Orchestration

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

This branch is intentionally stacked on the Chio 7.0-7.3 runtime spine work
because 7.3 is not yet merged into `main` in this workspace.

Goal: turn the one-shot semantic runtime proof-regeneration path into
repeatable local orchestration with static local profiles, durable run state,
restart/resume evidence, operator status, and repeated-run proof drift reports.

Planning names and trajectory metadata stay under `.planning`.

Non-goals: dynamic trust, peer discovery, settlement execution, live
notification dispatch, hidden predicates, VC Data Integrity BBS, zkVM, FROST,
new transports, and pheromone-driven authority decisions.
