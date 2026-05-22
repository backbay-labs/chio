# Chio Pheromone Spec and Registry Drift Cutover

## Goal

Close active Chio pheromone naming drift without rewriting historical signed
Chio artifacts.

## Scope

- Keep `spec/CHIO_PHEROMONE.md` as the active Chio pheromone contract.
- Preserve `CHIO_*` references only when they cite historical research or
  legacy draft specs.
- Remove legacy runtime schema IDs from active Chio schema definitions.
- Make focused Chio gates fail if active Chio schema metadata reintroduces
  Chio provenance or live schema enums.

## Tasks

1. Update active spec wording that still describes live Chio behavior as
   Chio behavior.
2. Keep historical research and signed-artifact citations explicit.
3. Remove `Chio-native schema IDs` accepted values from active Chio schema files.
4. Update schema manifest hashes for changed active schema files.
5. Add focused drift checks to the Chio pheromone runtime and transit gates.
6. Run schema-only gates plus text drift scans.

## Verification

- `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- `bash scripts/check-chio-pheromone-transit.sh --schema-only`
- `rg` scans for active Chio schema metadata and spec wording drift
