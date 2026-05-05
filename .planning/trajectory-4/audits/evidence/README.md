# Trajectory-4 audit evidence

Per-ticket and per-slice evidence artifacts referenced by the audit docs in the parent directory.

## Layout

```
audits/evidence/
  TRJ4-001/                # one directory per ticket if it produces capture
    cascade-merge-log.txt
  TRJ4-011/
    nightly-mutants-2026-MM-DD.json
    nightly-mutants-2026-MM-DD.json
  TRJ4-T1.0.E/             # Evidence Gate tickets get their own directory
    proof-report-diff.txt
    schema-diff.txt
  threats/                 # cargo-mutants per-row sweeps for T0.D close bar
    agent_velocity_abuse.json
    behavioral_sequence_attack.json
    ...
```

## Naming

- Ticket-scoped artifacts go under `TRJ4-XXX/`.
- Cross-ticket / per-slice artifacts go under the slice name (e.g. `T1.1/lean-proof-output.txt`).
- Per-threat-row sweeps go under `threats/<threat_id>.json`.

## What lives here vs in the repo proper

- **In the repo**: signed conformance test source (`crates/chio-conformance/tests/...`), Lean theorem source (`formal/lean/...`), schema files (`spec/schemas/...`), claim/proof/theorem registries (`spec/registries/...`).
- **Under audits/evidence/**: derived artifacts and run logs. Things that change with each CI run, that are too noisy to commit on every change, but that the audit doc cites for "we ran this and it produced this."

## Retention

Artifacts here are retained for the trj4 cycle. After trj4 close, the audit docs are merged into a `TRAJECTORY-FINAL.md` (or equivalent) and the evidence directory is archived under `.planning/trajectory-4/archive/`.

## Not yet populated

This directory is bootstrapped by `TRJ4-000` and starts empty. Each ticket populates its own subdirectory as it lands.
