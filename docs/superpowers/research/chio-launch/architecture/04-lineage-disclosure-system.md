# Lineage, Selective Disclosure, And Privacy

Status: architecture outline
Primary source: `../agent-drafts/04-lineage-disclosure-privacy.md`
Confidence: high for gap diagnosis, moderate for cryptographic implementation details.

## Position

Selective disclosure is not "redact JSON and hope." It is a verifier-enforced contract over signed evidence. The launch claim needs three things:

1. a disclosure proof;
2. a signed lineage subgraph;
3. a leakage ledger that accounts for what was exposed.

## Current Risk

The current BBS projection work is promising but not enough for a launch privacy claim:

- projection v1 appears too thin for transaction-level proof;
- spec and implementation may diverge on workflow/step projections;
- kernel runtime receipts do not consistently carry BBS signatures;
- evidence export emits audit material, not privacy packages;
- verifier policy cannot yet reject excess disclosure;
- hidden predicates are not verifier-grade;
- signed redacted lineage subgraph export is missing.

## Disclosure Capsule

`chio.disclosure.capsule.v1` contains:

- `capsule_id`
- `transaction_passport_ref`
- `privacy_profile_ref`
- `issuer`
- `holder`
- `verifier`
- `disclosed_messages`
- `hidden_predicate_results`
- `bbs_proof_refs`
- `redacted_artifact_refs`
- `signed_lineage_subgraph_ref`
- `leakage_ledger_ref`
- `signature`

## BBS Projection V2

`chio.bbs-projection.manifest.v2` should define typed message classes:

- core identity;
- authority;
- policy;
- guard decision;
- request/response digest;
- economic authorization;
- commerce state;
- settlement state;
- risk state;
- lineage refs;
- timing bucket;
- disclosure policy refs.

Rules:

- v2 is a new manifest, not an expansion of v1 by accident.
- Every message slot has stable index, type, sensitivity class, and disclosure eligibility.
- Exact timing should default to bucket or hidden predicate, not direct disclosure.
- Wholesale JSON hashes are commitment-only unless manifest declares typed children.

## Kernel BBS Runtime Modes

Modes:

- `off`: current receipt behavior.
- `opportunistic`: add BBS projection where keys and projection manifest exist.
- `required`: deny or fail report if BBS projection cannot be produced.
- `privacy_profile_required`: produce only projections allowed by verifier profile.

Runtime should bind:

- projection manifest digest;
- ciphersuite;
- issuer key id;
- receipt digest;
- BBS signature or proof material;
- disclosure eligibility.

## Verifier Privacy Profiles

`chio.disclosure.verifier-privacy-profile.v1` declares:

- required disclosed fields;
- forbidden disclosed fields;
- hidden predicates;
- maximum leakage budget;
- allowed sensitivity classes;
- lineage depth requirements;
- evidence class floors;
- redaction map;
- transaction binding;
- excess disclosure behavior.

Default launch rule: excess disclosure fails under privacy profiles.

## Signed Lineage Subgraph

`chio.lineage.signed-subgraph.v1` is a redacted, signed DAG.

Nodes:

- intent;
- capability;
- policy;
- guard decision;
- receipt;
- task;
- join;
- order event;
- settlement event;
- risk event;
- external projection.

Edges:

- authorizes;
- executes;
- derives;
- discloses;
- redacts;
- settles;
- reconciles;
- projects.

Verifier rules:

- root binds Transaction Passport;
- all node digests verify;
- redactions have reasons;
- lineage depth satisfies policy;
- no duplicate contradictory node identities;
- graph signature verifies.

## Leakage Ledger

`chio.disclosure.leakage-ledger.v1` accounts for:

- disclosed field;
- derived fact;
- sensitivity class;
- reason;
- policy allowance;
- verifier need;
- redaction alternative;
- residual inference note;
- transaction binding.

The ledger is mandatory even when empty.

## Negative Cases

- valid BBS proof but forbidden field disclosed;
- hidden predicate not declared in manifest;
- lineage graph omits required parent;
- leakage ledger missing disclosed field;
- redacted artifact digest mismatch;
- projection manifest id mismatch;
- privacy profile does not bind transaction id.
