# Chiodos 6.4 Tickets

## C6.4-001 Integrator

Create the branch from the pinned baseline SHA, add lane planning docs, record owner tickets and final gates, and keep planning metadata under `.planning/trajectory-6.4`.

Acceptance:

- Branch starts from `main@384733b8bf5575c6106a3e32c4d6e5de4b2ddfad`.
- Planning docs record baseline, scope, tickets, final gates, and the no-planning-metadata rule.
- Runtime authority issuance is tracked only as shadow planning.

## C6.4-002 Trust Freshness

Add trust bundle v3 and signed revocation checkpoint parsing.

Acceptance:

- Strict verification accepts only `chio.chiodos.verifier-trust-bundle.v3`.
- Revocation checkpoint schema, signature, freshness window, duplicate entries, and epoch height are checked.
- Historical trust bundle v2 remains parseable but not accepted for strict verification.

## C6.4-003 Offline Revocation

Replace allow-all revocation behavior in `chio-chiodos`.

Acceptance:

- Revoked peers, vendors, BBS issuers, lease authorities, and governance authorities fail closed.
- Bilateral verification receives an offline revocation oracle derived from the signed checkpoint.

## C6.4-004 Authority Lifecycle

Enforce key ids, authority validity windows, authority status, future-issued artifact rejection, and governance receipt containment inside lease validity.

Acceptance:

- Inactive, expired, not-yet-valid, and revoked authority roots fail closed.
- Future-issued leases or governance receipts fail closed.
- Governance receipts for destructive steps are issued and expire within the matching lease window.

## C6.4-005 Verifier Context

Add required verifier context input and bind BBS proof nonce semantics to it.

Acceptance:

- CLI requires `--context`.
- Verifier rejects wrong audience, wrong challenge, expired context, future context, and wrong BBS proof nonce.
- Reports include the verifier context hash.

## C6.4-006 Disclosure Contract

Freeze reveal-set projection policy and enforce verifier-owned disclosed fields and indices.

Acceptance:

- Receipt, workflow, and step reveal-set ordering are documented by machine-readable policy.
- Unknown projection versions, duplicate disclosed indices, ciphersuite mismatch, unsupported range, VC DI, zkVM, and unknown proof extensions fail closed.
- Required disclosed fields and indices must be present.

## C6.4-007 Semantic Negatives

Add signed semantic negative generation for targeted mutations.

Acceptance:

- Negative packages re-sign dependent artifacts where needed so failures reach parent hash, tool receipt id, output hash, DSSE hash, scope digest, and consistency anchor checks.
- Negative reports use stable failure codes.

## C6.4-008 Schema And CLI Assurance

Extend schema validation and gate modes.

Acceptance:

- Package, trust bundle, context, report, selective proof, and negative corpus validate through `chio-spec-validate`.
- `scripts/check-chiodos-proof-package.sh --schema-only` validates JSON artifacts.
- `scripts/check-chiodos-proof-package.sh --negative-only` runs the negative corpus.

## C6.4-009 Docs And Closeout

Refresh Chiodos docs, open the PR, address all review threads, merge, and rerun the Chiodos gate on `main`.

Acceptance:

- 6.3 is marked merged.
- G6 remains reveal-set-only with hidden predicates deferred.
- G7, G11, and runtime authority issuance remain deferred.
- PR review threads are queried and resolved before merge.

