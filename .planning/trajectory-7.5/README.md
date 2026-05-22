# Chio 7.5 - Runtime Operations Supervision And Recovery

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

This branch is intentionally stacked on the Chio 7.0-7.4 runtime work
because 7.4 is not yet merged into `main` in this workspace.

Goal: harden local runtime orchestration for repeated operator use with run
leases, fencing, scheduler ticks, evidence health, provider health, recovery
drills, dry-run retention planning, and aggregate runtime ops status.

Planning names and trajectory metadata stay under `.planning`.

Non-goals: dynamic trust, peer discovery, settlement execution, live
notification dispatch, hidden predicates, VC Data Integrity BBS, zkVM, FROST,
new transports, distributed HA, and pheromone-driven authority decisions.
