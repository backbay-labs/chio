# Trajectory 5.1 Formal Evidence

Date: 2026-05-09

Integrated main: `2afeb07a1febacd1323f6903fc96d7f764254420`

## Apalache

`python3 scripts/check-apalache-formal-slice.py` exited 0:

```text
check-apalache-formal-slice: OK
```

The local Apalache toolchain was present at
`/Users/connor/.local/bin/apalache-mc`. The bounded smoke command used
the same loop as `.github/workflows/apalache-safety.yml`:

```bash
apalache-mc check --length=6 --config=formal/apalache/MCMonotoneLogApalache.cfg formal/apalache/MonotoneLogApalache.tla
apalache-mc check --length=6 --config=formal/apalache/MCRevocationCutCompleteness.cfg formal/apalache/RevocationCutCompleteness.tla
apalache-mc check --length=6 --config=formal/apalache/MCReceiptBeforeAllow.cfg formal/apalache/ReceiptBeforeAllow.tla
apalache-mc check --length=6 --config=formal/apalache/MCKernelTransitionCancelSafe.cfg formal/apalache/KernelTransitionCancelSafe.tla
```

All four checks exited 0 with `EXITCODE: OK` and `NoError` up to
computation length 6.

## Lean

`lake` was not available on this local `PATH`, so Trajectory 5.1 does
not claim a local Lean `lake build` proof run. The proof inventory and
planning files remain mapped, but release-facing proof closure still
requires a prepared Lean toolchain or hosted workflow evidence.

## 5.1 Disposition

Apalache bounded safety is locally green. Lean proof execution is
explicitly not claimed by this evidence file.
