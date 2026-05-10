# Chiodos 6.3 Tickets

## C6.3-001 Integrator

Create the branch from the pinned baseline SHA, add lane planning docs, and preserve the no-planning-metadata rule outside `.planning/trajectory-6.3`.

Acceptance:

- Branch starts from `main@290246bfca03d58e140cf5e3d38b956c770342e6`.
- Planning docs record baseline, scope, tickets, and final gates.

## C6.3-002 API Hygiene

Rename production JSON parser APIs away from fixture naming.

Acceptance:

- `proof_package_from_json` parses proof packages.
- `verifier_report_from_json` parses verifier reports.
- No production caller uses `package_from_fixture_json` or `report_from_fixture_json`.

## C6.3-003 Authority Trust

Add verifier trust bundle v2 authority roots and enforce signer-key matching for leases and governance receipts.

Acceptance:

- Trust bundle v2 requires `leaseAuthorities` and `governanceAuthorities`.
- Lease issuer resolves to a trusted lease authority.
- Lease signer key matches the trusted authority key.
- Governance authorizing kernel resolves to a trusted governance authority.
- Governance signer key matches the trusted authority key.

## C6.3-004 Lease Scope Binding

Add `chio.chiodos-lease-scope-binding.v1` package artifacts and recompute lease scope digests from canonical preimages.

Acceptance:

- Scope digest preimage includes the fields listed in the execution plan.
- Verifier rejects wrong scope binding material before accepting a lease.
- Fixture includes one scope binding per capability lease.

## C6.3-005 Step Semantics

Enforce workflow step binding across step records, tool receipts, bilateral DSSE envelopes, lease refs, governance refs, and consistency anchors.

Acceptance:

- Step receipt id, tool name, output hash, DSSE hash, parent hash, destructive flag, governance receipt id, and consistency anchor are checked.
- Current fixture uses `chiodos:consistency:<workflow_id>:<step_index>`.

## C6.3-006 Schemas

Add and register schemas for lease, governance receipt, lease scope binding, trust bundle v2, and tightened proof package artifacts.

Acceptance:

- Schema registry names all Chiodos 6.3 schemas.
- Chiodos gate requires those schema files.
- Schema manifest is refreshed.

## C6.3-007 Fixtures And Negatives

Regenerate committed fixtures and add negative cases for authority, scope, step, DSSE, and consistency mismatches.

Acceptance:

- Positive package verifies through the production library and CLI.
- Negative corpus rejects every committed mutation with a stable failure code.

## C6.3-008 Assurance

Wire the Chiodos gate into CI, run final verification, open PR, resolve all review threads, and merge.

Acceptance:

- `.github/workflows/chiodos-proof-package.yml` runs the Chiodos gate on PRs and pushes to main.
- Final gate checklist in `README.md` is run before merge.
- PR review threads are queried and resolved before merge.
