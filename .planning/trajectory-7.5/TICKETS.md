# Chiodos 7.5 Tickets

- C7.5-001, Integrator: Create branch, planning docs, baseline SHA, final
  gates, no-planning-metadata rule, and 7.6 shadow note.
- C7.5-002, Ops Contracts: Add runtime ops types, schemas, registry entries,
  parser validation, golden fixtures, and stable failure codes.
- C7.5-003, Run Leases And Fencing: Add run lease acquisition, heartbeat,
  expiry, owner id, monotonic fencing token, conflict rejection, and stale
  token rejection.
- C7.5-004, Scheduler Tick: Add bounded local tick reports that claim pending
  runs, expire stale leases, honor max-runs, and reject stale profiles.
- C7.5-005, Derived Resume And Recovery Drills: Classify local recovery from
  durable state and block destructive replay or missing terminal evidence.
- C7.5-006, Evidence Sink Health And Immutability: Verify manifest roles,
  artifact paths, hashes, byte counts, and write/rename readiness.
- C7.5-007, Static Provider Health: Validate static local provider bindings
  without peer discovery or provider substitution.
- C7.5-008, Retention Planning: Add dry-run retention profiles and plans that
  never delete, move, compact, upload, or mutate runtime evidence.
- C7.5-009, Ops Status Aggregation: Emit aggregate runtime ops status from
  durable run state, leases, evidence health, and provider health.
- C7.5-010, Assurance: Add runtime ops gate modes, CI triggers, docs refresh,
  final verification, PR, review-thread cleanup, and post-merge gate rerun.
