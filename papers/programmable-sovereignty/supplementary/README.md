# Supplementary Materials

Paper: "Programmable Sovereignty: Lean-Attestable Constitutions Over
Capability-Bounded Federated Receipts"
Venue: USENIX Security 2027 (Cycle 1)

This package makes the Lean 4 substrate behind the paper's formal claims
auditable by artifact reviewers. It contains a self-contained tarball of
the Lean sources, a TOML manifest and JSON inventory that name each
parent-paper theorem and its axiom dependencies, and these instructions.

## Files

- `lean-source.tar.gz` Lean 4 project that compiles the four parent-paper
  theorems. Includes `lean-toolchain`, `lakefile.lean`, `lake-manifest.json`,
  the `Chio.lean` root module, the full `Chio/` subtree (Core, Capability,
  Proofs, Spec, Treaty), and a build README.
- `proof-manifest.toml` Submission-time snapshot of the four theorems,
  their Lean modules and fully qualified declarations, the paper section
  in which each is stated, and the axiom set reported by `#print axioms`.
- `theorem-inventory.json` Same content, JSON-shaped for tool consumption.

## Parent-paper theorems

All four are proved in `Chio/Treaty/Intersection.lean`:

1. `treaty_admission_iff_predicate_intersection` (Section 4, treaty
   intersection)
2. `treaty_admission_stable_under_ladder_floor` (Section 4, ladder-floor
   stability)
3. `amendment_admissible_iff_backward_refinement` (Section 4, amendment
   refinement)
4. `amendment_without_refinement_rejected` (Section 4, amendment
   refinement)

## Verifying the build

With `elan` installed, the tarball builds with two commands:

```
tar xzf lean-source.tar.gz
cd chio-lean && lake build
```

A cold cache takes roughly 3-5 minutes. The build succeeds without
warnings, without `sorry`, and without any project-local `axiom`.

## Verifying the axioms

The axiom set reported by Lean's `#print axioms` for each theorem is
recorded in `proof-manifest.toml` (and `theorem-inventory.json`). To
reproduce, append the four `#print axioms <name>` lines documented in
the tarball README to `Chio/Treaty/Intersection.lean` and run
`lake env lean Chio/Treaty/Intersection.lean`.

Only standard Lean kernel axioms appear:
- `treaty_admission_iff_predicate_intersection` depends on `propext`.
- `treaty_admission_stable_under_ladder_floor` depends on `propext`.
- `amendment_admissible_iff_backward_refinement` depends on no axioms.
- `amendment_without_refinement_rejected` depends on no axioms.

No project-specific axioms are introduced.
