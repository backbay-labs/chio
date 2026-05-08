# Apalache Negative Tests

This directory holds **deliberately broken** variants of the M06 Apalache
specs. The point is to demonstrate that the corresponding production
property is not tautologically satisfied: a real bug must produce a real
counterexample.

Negative-spec runs are local diagnostic only; CI does not enforce them.
The production specs in `.github/workflows/apalache-safety.yml` are the
load-bearing gate. These broken variants are sanity checks invoked when
a property is rewritten or revisited, and the captured logs under
`.planning/trajectory-5/lane-a-floor/evidence/` document the expected
counterexample for each property at the time the negative test was last
run.

## Convention

For every property `P` in `formal/apalache/Foo.tla`, if the property has
a non-tautology obligation, add `formal/apalache/_negative_tests/FooBroken.tla`
that mutates exactly one guard or one state update so `P` becomes
falsifiable. Apalache must report SafetyInv violated within a few states.

## Running locally

```bash
# ReceiptBeforeAllow non-tautology check (must produce a counterexample):
apalache-mc check \
  --length=4 \
  --config=formal/apalache/_negative_tests/MCReceiptBeforeAllowBroken.cfg \
  formal/apalache/_negative_tests/ReceiptBeforeAllowBroken.tla

# RevocationCutCompleteness non-tautology check (must produce a counterexample):
apalache-mc check \
  --length=4 \
  --config=formal/apalache/_negative_tests/MCRevocationCutCompletenessBroken.cfg \
  formal/apalache/_negative_tests/RevocationCutCompletenessBroken.tla
```

If either run reports `NoError`, the production property is unsound or has
silently regressed to a tautology.

## Why these are not in CI

Running negative tests in CI would gate a green build on a counterexample,
which inverts the green/red signal. The production gate (counterexample
absent on the unbroken specs) lives in `apalache-safety.yml` and is the
authoritative signal. The local procedure documented above is run by hand
when properties are touched.
