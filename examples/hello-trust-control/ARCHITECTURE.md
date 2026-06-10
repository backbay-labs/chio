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

`examples/run-hello-smokes.sh` calls this smoke script by name.
`examples/README.md` and `examples/EXAMPLE_SURFACE_MATRIX.md` describe the same
high-level example and do not need semantic changes unless file names change.
No crate API changes are required.
