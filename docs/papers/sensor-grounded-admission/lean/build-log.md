# SensorGroundedAdmission.lean: build log

This file records the build environment and the exact commands used to
verify `SensorGroundedAdmission.lean`. The Lean source lives beside
this note. The file is not (yet) imported by the deployed substrate's
root module; it is built against the deployed `Chio.Treaty.PredicateLang`
and `Chio.Treaty.Intersection` modules.

## Environment

```
Lake version 5.0.0-src+3b0f286 (Lean version 4.28.0-rc1)
```

Lake binary at `~/.elan/bin/lake`, managed by elan.

## Baseline build (no changes)

Before any work, the deployed substrate's Lean project at
`formal/lean4/Chio/` built cleanly:

```
$ cd formal/lean4/Chio
$ lake build
Build completed successfully (23 jobs).
```

## Verification procedure

To verify `SensorGroundedAdmission.lean` against the deployed
substrate, copy the file into the Chio Treaty directory, register it
in the root module, and rebuild:

```bash
cp docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean \
   formal/lean4/Chio/Chio/Treaty/SensorGroundedAdmission.lean

# Append `import Chio.Treaty.SensorGroundedAdmission` to
# formal/lean4/Chio/Chio.lean (the root module).

cd formal/lean4/Chio
lake clean
lake build
```

After verification, the temporary copy and the root-module import line
are reverted so the deployed substrate's git state stays clean. The
paper-local copy is the canonical home until promotion is explicitly
decided.

## Build output (final run, clean from `lake clean`)

```
✔ [2/24] Built Chio.Proofs.SiblingSumBudget (701ms)
✔ [3/24] Built Chio.Proofs.HandshakeNegotiation (789ms)
✔ [4/24] Built Chio.Core.Receipt (909ms)
✔ [5/24] Built Chio.Proofs.AttenuationWitness (918ms)
✔ [6/24] Built Chio.Treaty.Intersection (890ms)
✔ [7/24] Built Chio.Proofs.Receipt (440ms)
✔ [8/24] Built Chio.Treaty.PredicateLang (869ms)
✔ [9/24] Built Chio.Treaty.BilateralAccept (515ms)
✔ [10/24] Built Chio.Treaty.SensorGroundedAdmission (883ms)
✔ [11/24] Built Chio.Core.Capability (4.0s)
✔ [12/24] Built Chio.Core.Revocation (390ms)
✔ [13/24] Built Chio.Core.Scope (472ms)
✔ [14/24] Built Chio.Spec.Properties (468ms)
✔ [15/24] Built Chio.Proofs.Revocation (564ms)
✔ [16/24] Built Chio.Proofs.Evaluation (550ms)
✔ [17/24] Built Chio.Core.Protocol (1.1s)
✔ [18/24] Built Chio.Proofs.Monotonicity (490ms)
✔ [19/24] Built Chio.Proofs.Protocol (759ms)
✔ [20/24] Built Chio.Proofs.AeneasEquivalence (693ms)
✔ [21/24] Built Chio.Capability.Delegation (573ms)
✔ [22/24] Built Chio.Proofs.FormalClosure (949ms)
✔ [23/24] Built Chio (268ms)
Build completed successfully (24 jobs).
```

`Chio.Treaty.SensorGroundedAdmission` builds at job 10 of 24; no
warnings or errors during the entire run.

## Axiom audit

After build, `#print axioms` against each of the four theorems
produced:

```
'Chio.Treaty.SensorAttestation.admission_predicate_separates_healthy_and_degraded_witnesses' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'Chio.Treaty.SensorAttestation.partition_contingency_mode_iff_degraded_subset' depends on axioms: [propext]
'Chio.Treaty.SensorAttestation.healthy_attestation_required_for_destructive_admission' depends on axioms: [propext]
'Chio.Treaty.SensorAttestation.degraded_sensor_admission_requires_re_admission_witness' depends on axioms: [propext]
```

No `sorry` axiom appears. The three axioms (`propext`,
`Classical.choice`, `Quot.sound`) are Lean's standard kernel axioms,
the same ones that underwrite the rest of the Chio Lean project.

## Project state after verification

The deployed substrate's Lean directories are unchanged from their
state before this verification run:

```
$ ls formal/lean4/Chio/Chio/Treaty/
BilateralAccept.lean
Intersection.lean
PredicateLang.lean

$ cd formal/lean4/Chio && lake build
Build completed successfully (23 jobs).
```

The `SensorGroundedAdmission.lean` file is held at
`papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean`
until promotion is explicitly decided.
