# Trajectory 5.1 Formal Evidence

Date: 2026-05-09

Trajectory 5.1 baseline: `db94ab9107e08aba90193b88aac20017b459f810`

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

The local Lean toolchain is installed through `elan`:

```text
elan 4.2.1 (3d5138e15 2026-03-18)
Lake version 5.0.0-src+3b0f286 (Lean version 4.28.0-rc1)
```

`lake build` was run from `formal/lean4/Chio` and exited 0:

```text
Build completed successfully (20 jobs).
```

## 5.1 Disposition

Apalache bounded safety and the Lean proof build are locally green for this
Trajectory 5.1 baseline.
