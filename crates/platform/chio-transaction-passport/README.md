# chio-transaction-passport

Verifies signed Chio transaction passports and the evidence bundles they anchor: the
passport itself, its evidence graph, verifier policy, and claim set, plus (for
runtime-security callers) the execution-lease and swarm artifacts a governed tool call
produces. Every check is a pure function of caller-supplied bytes and caller-pinned
trust keys; the only ambient input is the wall clock, consulted to check passport
expiry.

It is the shared platform-level verifier for transaction proof bundles:
`chio-control-plane`, `chio-proof-room`, `chio-risk-comptroller`,
`chio-trust-market-context`, `chio-enterprise-export`, and `chio-agent-web-interop`
verify passports through it instead of re-implementing the digest and signature
bindings.

## Responsibilities

- Validate a `TransactionPassport`'s shape, validity window, and self-certifying
  signature against caller-pinned trust keys.
- Validate evidence-graph structure: node/edge shape, content-addressed node ids
  (`id == sha256`), acyclicity, and the rule that advisory evidence cannot satisfy an
  authority edge.
- Bind the passport to its evidence graph, verifier policy, and claim set by digest and
  path, and enforce verifier-policy gates (accepted issuers, required evidence roles,
  accepted transparency states, omission-policy match).
- In standalone mode, independently re-verify the capability -> guard-decision ->
  receipt -> trust-root signature chain and every cross-artifact digest binding,
  without trusting the claim set's self-reported status.
- Verify runtime-security evidence: execution leases, sandbox attestations,
  tool-server acknowledgements, revocation-freshness and trusted-time proofs, terminal
  receipts, policy-activation receipts, and the swarm task graphs, route-plan receipts,
  budget pools, and join receipts a lease references.
- Sign a transaction passport (`sign_transaction_passport`) on behalf of an issuer
  whose keypair matches the passport's self-certifying identity.

## Public API

Passport shape and signature:

- `TransactionPassport`, `TransactionOmissionPolicyEntry` - the passport document and
  its per-claim omission entries.
- `verify_minimal_passport_schema`, `verify_minimal_passport_schema_at` - schema,
  validity-window, digest-shape and path-safety checks on a passport alone.
- `sign_transaction_passport` - sign a passport with a `Keypair` whose public key
  matches its self-certifying issuer.
- `verify_transaction_passport_signature` - verify a passport's signature against
  caller-pinned trust keys.
- `verify_transaction_passport_signature_with_evidence_graph` - verify against a
  signed evidence graph digest and accept a redacted "scoped" graph that is a subset
  of it.

Root-graph verification (claim set is trusted, except `claim.risk.*`):

- `verify_passport_root_and_claim_set_artifacts`,
  `verify_passport_root_and_claim_set_artifacts_with_external_claims`,
  `verify_passport_root_and_claim_set_artifacts_unchecked_signature_with_external_claims`
  - bind passport, evidence graph, verifier policy and claim set, and enforce policy
  gates.
- `verify_minimal_passport_artifacts` - the schema, digest and policy-gate subset of
  the above, without passport signature or claim-set checks.
- `TransactionVerifierReport` - the resulting report, built with
  `verified`/`failed`/`with_transparency_state`/`with_claim_results`.

Standalone verification (the crate re-derives every binding itself):

- `verify_standalone_minimal_passport_artifacts`,
  `verify_standalone_minimal_passport_artifacts_unchecked_signature` - full
  self-contained verification of the capability -> guard-decision -> receipt ->
  trust-root chain, restricted to the six `claim.transaction.*` structural claims.
- `validate_transaction_evidence_graph` - structural validation of evidence-graph
  bytes alone.
- `transaction_evidence_graph_transparency_state` - derive
  `transparency_preview` / `not_present` from evidence-graph bytes. The
  `trust_anchored` tier requires cryptographic verification of an inclusion
  proof against a checkpoint signed by a pinned key, so it is only reachable
  through the artifact-carrying verification surfaces.
- `validate_verifier_policy_artifact` - standalone verifier-policy shape validation.

Runtime security:

- `verify_runtime_security_claims`, `verify_runtime_security_claims_with_trust` -
  verify a `RuntimeSecurityBundle` and produce a `RuntimeSecurityReport`.
- `RuntimeSecurityBundle`, `RuntimeSecurityTrust` - the input bundle (passport,
  graphs, artifacts) and the pinned trust keys.

Schema ids (`TRANSACTION_PASSPORT_SCHEMA_ID`, `TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID`,
`TRANSACTION_VERIFIER_POLICY_SCHEMA_ID`, `TRANSACTION_VERIFIER_REPORT_SCHEMA_ID`,
`TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID`, `RUNTIME_EXECUTION_LEASE_SCHEMA_ID`,
`RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID`, `RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID`,
`RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID`) and the crate-wide `TransactionPassportError`.

## Testing

`cargo test -p chio-transaction-passport`. The test suite cross-checks fixtures
against the JSON Schemas in `spec/schemas/chio-transaction/v1/` via `jsonschema`.

## See also

- `chio-core-types` - supplies Ed25519 signing/verification and the signed-artifact
  schema registry evidence-graph nodes are checked against.
- `chio-control-plane`, `chio-proof-room`, `chio-risk-comptroller`,
  `chio-trust-market-context`, `chio-enterprise-export`, `chio-agent-web-interop` -
  platform and product crates that verify transaction passports through this crate.
