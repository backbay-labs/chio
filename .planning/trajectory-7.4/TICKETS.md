# Ticket Map

- C7.4-001, Integrator: Create branch, planning docs, baseline SHA, ticket map,
  final gates, no-planning-metadata rule, and 7.5 shadow note.
- C7.4-002, Orchestration Contracts: Add profile, run contract, plan, run
  report, resume plan, status report, drift report, schema registry entries,
  parsers, validators, and fixtures.
- C7.4-003, Durable Runtime Store: Add SQLite-backed orchestration state for
  bundles, consumed destructive leases, trust floors, runs, steps, and evidence
  artifacts while preserving JSON fixture compatibility.
- C7.4-004, Kernel-Mediated Runner: Keep runtime admission before dispatch and
  bind local orchestration reports to verifier-accepted 7.3 proof evidence.
- C7.4-005, Resume And Evidence Sink: Add preflight/resume handling for store
  health, evidence directory safety, missing artifacts, hash mismatches, step
  gaps, terminal-state conflicts, and destructive replay refusal.
- C7.4-006, Operator Status: Emit status reports for backend, run counts,
  consumed leases, trust floors, latest failures, evidence health, ready, and
  degraded state.
- C7.4-007, Proof Drift: Compare repeated accepted runtime proof outputs and
  report deterministic semantic, artifact, and verifier drift.
- C7.4-008, CLI And Fixtures: Add orchestration CLI commands, parse tests,
  healthy fixtures, restart/resume fixtures, drift fixtures, and executable
  negatives.
- C7.4-009, Docs And Gates: Update docs, add runtime orchestration gate modes,
  and wire CI path triggers.
- C7.4-010, Closeout: Run gates, open PR, resolve review threads, merge, and
  rerun on `main`.
