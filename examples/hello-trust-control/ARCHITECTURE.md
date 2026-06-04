# hello-trust-control Architecture Notes

## Module Boundaries

This example owns the smallest direct trust-plane lifecycle without an
application server in the middle. `run-trust.sh` starts only `chio trust serve`
with local SQLite authority, revocation, receipt, and budget stores.
`policy.yaml` owns the separate local `chio check` policy used to mint a tool
receipt for offline evidence export. `smoke.sh` owns the integrated flow:
service startup, capability issuance, token materialization, revocation
status, revocation, receipt minting, evidence export, evidence verification,
and summary artifact emission.

There is no crate manifest or language package manager boundary. The example
depends on the workspace `chio` binary and the shared hello HTTP shell helpers
only for port selection, readiness, binary discovery, and demo capability
issuance.

## Pain Points

The smoke script currently validates each step with small inline Python
fragments, but it does not validate the artifact graph as one lifecycle. That
means drift can slip through when a later artifact refers to a different
capability id, a materialized token stops matching the issued capability, the
receipt list does not contain the receipt reported by `chio check`, or the
summary claims evidence verification that the verifier output does not prove.

The receipt listing command has also drifted from the current CLI contract.
Local receipt reads now require an explicit tenant boundary or `--admin-all`;
the example intends to export a local administrative evidence package, so the
smoke must use `--admin-all` deliberately instead of relying on the old
implicit cross-tenant read behavior.

## Security And API Constraints

- Keep the upstream trust-control lifecycle explicit: service token, local
  stores, capability issuance, status, revocation, and evidence export must be
  visible in the script.
- Do not weaken the receipt tenant boundary. This example may use
  `--admin-all` because it is an operator-owned local smoke flow, but that
  choice must be explicit in the script.
- Do not introduce a fake app invocation. `chio check` currently issues its
  own policy-scoped capability; the trust-control capability lifecycle and the
  offline receipt lifecycle are adjacent surfaces, not the same token-use
  path.
- Preserve the generated JSON artifact names because they are the teaching
  surface and are referenced by the README.

## Affected Dependents

`examples/run-hello-smokes.sh` calls this smoke script by name, so it will pick
up the repaired flow. `examples/README.md` and
`examples/EXAMPLE_SURFACE_MATRIX.md` describe the same high-level example and
do not need semantic changes unless file names change. No crate API changes are
planned.

## Planned Material Improvement

Add a package-owned artifact verifier that checks the full trust-control smoke
output as a coherent lifecycle: issued capability shape, compact token
materialization, status-before/status-after transition, revoke response,
receipt list inclusion, evidence verifier output, and summary consistency.
Update the smoke to use the current receipt read boundary (`--admin-all`) and
to run the verifier as the final acceptance gate. Add focused unit tests for
the verifier so the example has a local test surface in addition to the live
smoke.
