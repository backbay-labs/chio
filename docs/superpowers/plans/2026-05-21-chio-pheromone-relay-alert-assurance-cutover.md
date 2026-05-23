# Chio Pheromone Relay Alert Assurance Cutover

## Goal

Make the active Chio pheromone relay alert-assurance fixture tree stop carrying stale Chio relay identifiers while preserving the historical Chio fixture tree and legacy runbook artifacts.

## Scope

- Active fixture tree: `examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance`.
- Active gate: `scripts/check-chio-pheromone-relay-alert-assurance.sh`.
- Stale markers to reject in active Chio alert assurance artifacts:
  - `chio-relay`
  - `chio-pheromone-relay`
  - `CHIO_PHEROMONE_RELAY_RUNBOOK.md`

## Plan

1. Add a schema-only metadata gate that fails on stale Chio relay identifiers in the active Chio assurance tree.
2. Run the gate and confirm it fails on existing active Chio fixtures.
3. Convert active Chio relay assurance fixtures to `chio-relay`, `chio-pheromone-relay`, and `CHIO_PHEROMONE_RELAY_RUNBOOK.md`.
4. Run focused schema and assurance checks, then run formatting and drift scans.

## Non-goals

- Do not rewrite `examples/chio-3vendor`.
- Do not rewrite historical signed proof packages or old compatibility docs.
- Do not rename legacy `CHIO_*` docs that are retained for compatibility.
