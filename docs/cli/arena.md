# `chio arena` CLI surface

The chio-arena CLI exposes three subcommands on the `chio` binary, all
guarded by the deterministic-replay contract: scenarios run deterministically,
every receipt bundle is bit-exact replayable, and any failures auto-promote
into the replay corpus and the adversarial suite via the existing CHIO_BLESS
gate.

## `chio arena run scenarios/<name>.toml`

Loads a scenario TOML, drives the kernel multiplexer under the deterministic
scheduler, and writes a receipt bundle byte-compatible with the `tests/replay/goldens/` layout under `target/arena/<scenario-id>/`.

Flags:

- `--output-root <DIR>`: override the bundle output root (default
  `target/arena/`).
- `--json`: emit a `chio.arena.run/v1` summary to stdout.

## `chio arena replay <scenario-id>`

Resolves `target/arena/<scenario-id>/` and delegates to the `chio replay`
engine. The arena does not reimplement signature verification or root
recomputation; the engine ingests the bundle directly.

Flags:

- `--output-root <DIR>`: override the bundle root.
- `--bundle-dir <DIR>`: bypass scenario-id resolution and replay a specific
  directory.
- `--json`: emit a `chio.arena.replay/v1` summary.

## `chio arena evolve scenarios/<seed>.toml --generations N`

Runs the co-evolution loop under the bounded-budget gate (default 200
generations or 30 minutes wall, whichever fires first). Emits the
leaderboard at `target/arena/leaderboard.{md,json}` with stable schema
`chio.arena.leaderboard/v1`.

Flags:

- `--generations <N>`: number of generations.
- `--wall-seconds <S>`: wall-clock budget in seconds.
- `--output-root <DIR>`: override the leaderboard output root.
- `--json`: emit a `chio.arena.evolve/v1` summary.

## Auto-promotion

A failing arena scenario can graduate to two corpora via the CHIO_BLESS gate:

1. Replay fixtures under `tests/replay/fixtures/arena/<class>/`.
   `BLESS_REASON=arena:<scenario-id>` is the only accepted reason; the
   per-PR cap (default 5) carries forward unchanged.
2. The adversarial suite under `crates/chio-adversarial-suite/cases/<class>/`.
   Until the suite scaffold lands, the writer falls back to
   `target/arena/promote-pending/`.

Neither path is wired to CI: the CHIO_BLESS gate refuses when `CI=true`, by
design.
