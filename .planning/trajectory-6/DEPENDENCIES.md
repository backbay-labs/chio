# Trajectory 6 Shadow Dependencies

Trajectory 6 may become active only after Trajectory 5.2 exits.

## Required Before Active T6

- `bash scripts/check-bounded-ship-bar.sh` passes in default mode.
- T5.2 release-truth docs agree on the post-#630 baseline SHA.
- `v0.1.0-bounded-chiodome` is either parked outside release scope or reopened
  by a future release lane with strict gates.
- Selective disclosure is either a non-release boundary or backed by real proof
  fixtures.

## Inputs From Existing Specs

- `docs/research/CHIODOS_3VENDOR_FIXTURE.md`
- `spec/CHIODOS_LADDER.md`
- `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`
- `spec/CHIODOS_SELECTIVE_DISCLOSURE.md`
- `spec/CHIODOS_PHEROMONE.md`

These inputs remain draft sources until an active T6 implementation plan
promotes specific interfaces.
