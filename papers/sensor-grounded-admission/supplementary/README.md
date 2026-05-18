# Supplementary Materials

Paper: "Sensor-Grounded Admission: Polity Receipts with Attested
Substrate State"
Venue: USENIX Security 2027 (Cycle 1)

This package makes the Lean 4 substrate behind the paper's formal
claims auditable by artifact reviewers. It contains a self-contained
tarball of the Lean sources, a TOML manifest and JSON inventory that
name each theorem and its axiom dependencies, and these instructions.

## Files

- `lean-source.tar.gz` Lean 4 project that compiles the four
  sensor-grounded theorems. Includes `lean-toolchain`, `lakefile.lean`,
  `lake-manifest.json`, the `Chio.lean` root module, the full `Chio/`
  subtree (Core, Capability, Proofs, Spec, Treaty) on which the
  sensor-grounded module depends, and a build README.
- `proof-manifest.toml` Submission-time snapshot of the four theorems,
  their Lean modules and fully qualified declarations, the paper
  section in which each is stated, and the axiom set reported by
  `#print axioms`.
- `theorem-inventory.json` Same content, JSON-shaped for tool
  consumption.

## Sensor-grounded theorems

All four are proved in `Chio/Treaty/SensorGroundedAdmission.lean`,
under the `Chio.Treaty.SensorAttestation` namespace:

1. `admission_predicate_separates_healthy_and_degraded_witnesses`
   (Section 4, headline existence theorem)
2. `partition_contingency_mode_iff_degraded_subset` (Section 4,
   partition-contingency biconditional)
3. `healthy_attestation_required_for_destructive_admission`
   (Section 4, destructive-admission projection)
4. `degraded_sensor_admission_requires_re_attestation` (Section 4,
   amendment re-attestation)

## Verifying the build

With `elan` installed, the tarball builds with two commands:

```
tar xzf lean-source.tar.gz
cd chio-lean && lake build
```

A cold cache takes roughly 3-5 minutes. The build succeeds without
warnings, without `sorry`, and without any project-local `axiom`.
The sensor-grounded module builds at job 10 of 24 in the dependency
graph.

## Verifying the axioms

The axiom set reported by Lean's `#print axioms` for each theorem is
recorded in `proof-manifest.toml` (and `theorem-inventory.json`). To
reproduce, append the four `#print axioms <name>` lines documented in
the tarball README to `Chio/Treaty/SensorGroundedAdmission.lean` and
run `lake env lean Chio/Treaty/SensorGroundedAdmission.lean`.

Only standard Lean kernel axioms appear:
- `admission_predicate_separates_healthy_and_degraded_witnesses`
  depends on `propext`, `Classical.choice`, `Quot.sound`.
- `partition_contingency_mode_iff_degraded_subset` depends on
  `propext`.
- `healthy_attestation_required_for_destructive_admission` depends
  on `propext`.
- `degraded_sensor_admission_requires_re_attestation` depends on
  `propext`, `Quot.sound`.

No project-specific axioms are introduced.
