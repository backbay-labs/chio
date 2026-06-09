# Transaction Passport And Evidence Graph

Status: architecture outline
Primary source: `../agent-drafts/01-transaction-passport-evidence-graph.md`
Confidence: high that this is the central missing launch feature.

## Problem

Chio has many proof primitives: receipts, capability validation, policy hashes, guard decisions, evidence exports, lineage structures, commerce examples, settlement evidence, disclosure work, and risk concepts. The launch problem is that a public reviewer has no single signed artifact that says:

"This transaction happened under this authority, through this delegation path, with this lineage, these disclosures, this commerce state, this settlement context, and this risk posture."

The Transaction Passport is that artifact.

## Core Artifact

`chio.transaction-passport.v1` is a signed root over a typed evidence graph.

Minimum fields:

- `schema`
- `passport_id`
- `subject`
- `issuer`
- `issued_at`
- `expires_at`
- `transaction_kind`
- `root_evidence_graph_digest`
- `claim_set_digest`
- `verifier_policy_digest`
- `trust_roots`
- `artifact_refs`
- `omission_policy`
- `signature`

The passport must not inline every artifact. It should commit to an evidence graph root and reference typed sub-artifacts by digest, URI, and media type.

## Evidence Graph

`chio.transaction.evidence-graph.v1` is a DAG of typed nodes and edges.

Node classes:

- `intent`
- `capability`
- `policy`
- `guard_decision`
- `runtime_receipt`
- `delegation_witness`
- `swarm_task`
- `swarm_join`
- `lineage_statement`
- `disclosure_proof`
- `commerce_order`
- `payment_or_settlement`
- `risk_report`
- `external_projection`
- `verifier_report`

Edge classes:

- `authorizes`
- `attenuates`
- `executes`
- `derives`
- `binds`
- `settles`
- `discloses`
- `reconciles`
- `projects_to`

Every edge must name the predicate it proves. A graph edge that merely says two files are related is not enough.

## Claim Set

`chio.transaction.claim-set.v1` is the machine-readable claim inventory.

Example claim classes:

- `authority.valid_at_action_time`
- `policy.hash_matched`
- `guard.allowed_request`
- `guard.allowed_response`
- `delegation.parent_child_scope_valid`
- `swarm.join_parent_set_valid`
- `lineage.root_to_outcome_connected`
- `disclosure.profile_satisfied`
- `commerce.order_state_replayed`
- `settlement.finality_verified`
- `risk.reserve_reconciled`
- `external_projection.digest_bound`

Each claim has:

- `claim_id`
- `status`: `verified`, `failed`, `omitted`, `unsupported`
- `required_evidence`
- `evidence_refs`
- `failure_reason`
- `verifier_module`

## Omission Policy

The passport must support honest omission. Some evidence may be absent because there is no join path, because an external protocol does not carry that proof, or because a privacy profile forbids disclosure.

Required omission statuses:

- `omitted_no_join_path`
- `omitted_privacy_policy`
- `omitted_external_protocol_lacks_slot`
- `omitted_not_applicable`
- `omitted_unsupported_current_version`

Omissions must be signed into the passport. Silent omission is a proof failure.

## Verification Workflow

1. Parse passport envelope.
2. Verify signature and trust root.
3. Resolve evidence graph.
4. Verify all graph node digests.
5. Verify graph acyclicity and required edge predicates.
6. Load verifier policy.
7. Run claim-specific verifiers.
8. Produce `chio.transaction.verifier-report.v1`.
9. Fail closed if required evidence is missing, mismatched, expired, unsupported, or over-disclosed.

## Product Surface

The passport should be visible in three places:

- CLI: `chio proof verify transaction-passport.json`
- Proof Room: transaction overview, graph view, claim table, failure explorer
- External envelope: digest-bound projection into partner protocols

## Negative Cases

Launch fixtures should include:

- receipt signature mismatch;
- policy hash mismatch;
- graph edge references unknown node;
- commerce order id mismatch;
- settlement proof binds a different order;
- disclosure proof leaks forbidden field;
- risk report leaves reserve unreconciled;
- external projection references a stale receipt digest.

## Open Design Decisions

1. Whether durable Transaction Passport code stays in existing attest, control-plane, lineage, and CLI surfaces or eventually earns a new crate. Do not create `chio-transaction` first unless owner review proves existing crates cannot carry the abstraction.
2. Whether verifier policies are pure schema/policy files or compiled Rust modules with named policy ids.
3. Whether passport bundles use a zip/tar container or directory layout for public proof room upload.
4. Whether external proof envelopes reference the passport or can independently carry a subset of claims.
