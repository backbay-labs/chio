# Chio relay script command cutover

## Objective

Make Chio-named pheromone relay gate scripts exercise public Chio relay commands
instead of the legacy `chio chiodos pheromone relay ...` compatibility surface.
The old Chiodos-named scripts may remain wrappers, but the Chio gates must prove
the Chio command surface.

## Plan

1. Capture a failing grep check showing Chio relay scripts still invoke legacy
   `chiodos pheromone relay` commands.
2. Mechanically replace those invocations with `chio pheromone relay ...` in
   `scripts/check-chio-pheromone-relay*.sh`.
3. Run the grep check, schema-only relay script gates, focused CLI parse tests,
   whitespace, and dash scan.

## Verification

- [x] `rg -n -- "--(?:bin chio )?-- chiodos pheromone relay|-- chiodos pheromone relay| chiodos pheromone relay" scripts/check-chio-pheromone-relay*.sh` finds legacy invocations before implementation.
- [x] `rg -n -- "--(?:bin chio )?-- chiodos pheromone relay|-- chiodos pheromone relay| chiodos pheromone relay" scripts/check-chio-pheromone-relay*.sh` returns no matches.
- [x] `bash scripts/check-chio-pheromone-relay.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-ops.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-alert-routing.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-alert-assurance.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-alert-delivery.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-alert-handoff.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-alert-assurance-export.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-relay-alert-assurance-archive.sh --schema-only`
- [x] `cargo test -p chio-cli --bin chio chio_pheromone`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
