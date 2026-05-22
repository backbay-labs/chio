# Chio pheromone runtime script command cutover

## Objective

Make the Chio-named pheromone runtime gate exercise public Chio receive and
query commands instead of the legacy `chio pheromone ...`
compatibility surface. Chio-named scripts may remain compatibility wrappers,
but Chio gates must prove the Chio command surface.

## Plan

1. Capture a failing grep check showing the Chio runtime script still invokes
   legacy `chio pheromone receive/query` commands.
2. Replace those invocations with `chio pheromone receive/query` in
   `scripts/check-chio-pheromone-runtime.sh`.
3. Run the grep check, runtime gate, focused CLI parse tests, shell syntax,
   formatting, whitespace, and dash scan.

## Verification

- [x] `rg -n -- "--(?:bin chio )?-- chio pheromone (receive|query)|-- chio pheromone (receive|query)| chio pheromone (receive|query)" scripts/check-chio-pheromone-runtime.sh` finds legacy invocations before implementation.
- [x] `rg -n -- "--(?:bin chio )?-- chio pheromone (receive|query)|-- chio pheromone (receive|query)| chio pheromone (receive|query)" scripts/check-chio-pheromone-runtime.sh` returns no matches.
- [x] `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-runtime.sh --negative-only`
- [x] `cargo test -p chio-cli --bin chio_pheromone`
- [x] `bash -n scripts/check-chio-pheromone-runtime.sh`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
