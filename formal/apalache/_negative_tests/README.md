# Apalache Negative Tests

This directory holds deliberately broken variants and explicit rejected-claim
witnesses. A `spec-mutation` demonstrates that a production property is not
tautological. A `claim-witness` uses unmutated semantics to demonstrate why a
stronger candidate is not in the positive safety set.

The `apalache-negative` CI job enforces this directory through
`scripts/check-apalache-negative.sh`. CI-green means every registered broken
model still yields its expected counterexample. A parse failure, timeout,
unexpected exit code, missing Error outcome, or invalid ITF trace fails the
job rather than masquerading as a caught defect.

## Convention

For every property `P` in `formal/apalache/Foo.tla`, if the property has a
non-tautology obligation, add one Broken module and config that select exactly
one guard or state-update mutation so `P` becomes falsifiable. Register the
pair in `REGISTRY.toml` with the exact invariant name, production fix commit,
runtime regression test, length bound, and timeout. The config must select the
same named invariant as `falsifies`, and Apalache must report it violated
within the registered bound.

The mechanical action-mutation lane lives in `scripts/spec-mutants.py`. Its
schema-v2 allowlist in `formal/apalache/spec-mutants-allowlist.toml` registers
exact type-valid guard-weakening and post-state-corruption probes. When a
hand-written broken variant represents a mutation the campaign must retain,
add a `[[seed]]` entry as well as the negative registry entry. The mutator then
fails closed unless the production action contains the configured expression,
the broken action contains the replacement, and the inventory includes the
seed. Every deterministic sample and full campaign includes all registered
seeds.

A rejected candidate uses `classification = "claim-witness"`, an unmutated
config, and a mapped property that is deliberately absent from the aggregate
positive invariant. Its counterexample prevents later documentation from
silently reviving the rejected claim.

## Running locally

```bash
./scripts/check-apalache-negative.sh
```

Artifacts are written under `$CARGO_TARGET_DIR/apalache-negative` by default
(or workspace `target` when `CARGO_TARGET_DIR` is unset). Set
`CHIO_APALACHE_NEGATIVE_OUTPUT_DIR` to a strict descendant of the repository
`target` directory, `CARGO_TARGET_DIR`, or the system temporary directory to
retain them elsewhere. Roots, in-repository paths outside the configured
targets, and symlink escapes are rejected before cleanup. Each entry keeps its
command output and ITF trace in a separate directory.

Promote a retained `.itf.json` trace into `formal/tla/counterexamples/` with
`cargo xtask formal itf-to-regression` only after registering its production
replay family. The converter refuses to emit a test without that mapping.

If any run reports `NoError`, the corresponding production property is
unsound or has silently regressed to a tautology.

## Signal inversion

Apalache 0.50.1 reports an invariant violation with exit 12 and the marker
`The outcome is: Error`. The wrapper requires both signals plus a parseable
`violation*.itf.json` ITF object whose states match its parameter and variable
declarations. The log must name exactly the registry invariant and contain one
exact outcome. The wrapper then inverts that violation into a green job result.
Exit 0 with `NoError` is a negative-test failure. Every other outcome is a
distinct tool failure.
