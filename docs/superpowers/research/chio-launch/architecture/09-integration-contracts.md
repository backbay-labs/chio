# Integration Contracts

Status: second-pass architecture refinement
Confidence: high for contract boundaries, moderate for exact module placement.

## Purpose

The first research pass correctly identified the Transaction Passport as the missing public proof root. This second-pass contract document tightens the join rules between sub-artifacts so the launch build does not create another set of strong but isolated proofs.

## Contract 1 - Registry Before Verifier

No new signed artifact should be accepted by a verifier until it exists in:

1. `spec/schemas/<domain>/...`;
2. `spec/schemas/registry.json`;
3. `spec/schemas/MANIFEST.sha256`;
4. `scripts/check-chio-schema-registry.sh` if the schema lives under a newly checked root;
5. the Rust signed-artifact schema registry exposed through `KNOWN_SIGNED_ARTIFACT_SCHEMAS` or its generated successor;
6. `spec/registries/claim-registry.v1.json` and `spec/registries/proof-manifest.v1.json` if the artifact carries a public claim;
7. a positive fixture;
8. a negative unknown-schema fixture.

This is not paperwork. The protocol already treats unknown signed-artifact schema IDs as fail-closed.

## Contract 2 - Passport Root Owns The Launch Verdict

Domain verifiers can emit their own reports, but the launch verdict comes from `chio.transaction.verifier-report.v1`.

Allowed:

- commerce verifier reports order replay;
- settlement verifier reports chain/payment finality;
- risk verifier reports reserve reconciliation;
- disclosure verifier reports privacy-profile compliance.

Required:

- the Transaction Passport verifier consumes those domain reports by digest;
- the final launch verdict lists every required claim as verified, failed, omitted, or unsupported;
- unsupported claims cannot appear in homepage proof copy.

## Contract 3 - Evidence Graph Edges Are Typed Predicates

The evidence graph cannot be a generic file manifest. Every edge must explain a proof relation.

Required edge predicates:

- `authorizes`
- `attenuates`
- `executes`
- `derives`
- `binds`
- `settles`
- `discloses`
- `redacts`
- `reconciles`
- `projects-to`

Verifier rule: an unknown predicate fails unless the verifier policy explicitly marks it advisory.

## Contract 4 - Commerce Order Is The Subject For Money

Every payment, settlement, risk, facility, coverage, payout, reserve, or slash artifact must bind the same commerce order id or explicitly state why no order exists.

Verifier rejects:

- settlement proof with a different order id;
- risk report with no order binding when coverage is claimed;
- payment proof that binds only a merchant and amount but not an order;
- reserve release or slash that binds a claim but not the covered order or exposure.

## Contract 5 - External Protocols Are Projection Subjects

MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE objects are external subjects or evidence formats. They do not replace Chio authority.

Verifier report must classify each external claim as:

- `native-external-proof`;
- `chio-sidecar-proof`;
- `digest-bound-reference`;
- `advisory-observation`;
- `unsupported`.

## Contract 6 - Privacy Profiles Are Semantic Gates

A BBS or SD-JWT proof that cryptographically verifies is still invalid if it violates the Chio verifier privacy profile.

Verifier rejects:

- forbidden disclosed field;
- undeclared hidden predicate;
- exact value disclosed when only a range predicate was allowed;
- missing leakage ledger entry;
- lineage subgraph that omits a required parent.

## Contract 7 - Swarm Continuation Is Required For Child Work

Nested execution cannot rely on caller metadata as authority.

Every child execution must bind:

- graph digest;
- parent receipt or join receipt;
- continuation token;
- per-hop witness;
- route-plan receipt if crossing a protocol boundary;
- revocation epoch;
- budget lease if metered.

## Contract 8 - Risk Ledgers Do Not Share Spendable Balances

Claim payout, reserve release, reserve slash, and market slash are distinct ledger flows. A reconciliation report must prove that one reserve unit was consumed by at most one flow.

Verifier rejects:

- payout and release of the same reserve amount;
- reserve slash and market slash consuming the same backing;
- payout settlement proof not bound to claim id;
- claim decision not bound to coverage decision and order id.

## Contract 9 - Proof Room Is A Verifier Consumer

The Proof Room renders verifier reports. It does not define proof semantics.

Required:

- CLI verifier and Proof Room produce the same verdict for the same bundle;
- invalid fixtures remain visible;
- redacted values remain redacted;
- every failed claim links back to evidence graph node and edge ids.

## Contract 10 - Copy Is Downstream Of Verifier Coverage

Homepage and docs copy should be generated or checked against verifier coverage.

Copy lint should reject:

- bare `ACP`;
- "every action" without receipt coverage;
- "multi-swarm coordination" without swarm fixture coverage;
- "selective disclosure" without privacy-profile negative fixtures;
- "settlement context" without commerce order binding;
- "insurance" without risk comptroller report;
- "autonomous pricing" without actuarial and capital adequacy artifacts.

## Contract 11 - Online Enforcement Precedes Proof

The Transaction Passport can report runtime authority only for actions that passed online kernel and tool-server gates.

Required for side-effecting runtime claims:

- kernel allow receipt;
- execution lease;
- fresh nonce;
- revocation freshness proof;
- active policy digest;
- sandbox attestation;
- tool-server acknowledgement;
- terminal receipt or signed incident receipt.

After-the-fact evidence cannot upgrade an unleased tool call into authorized execution.

## Contract 12 - Advisory Evidence Never Authorizes

Advisory observations, traces, external payment success, supply-chain attestations, webhook signatures, OAuth tokens, identity assertions, browser screenshots, and projection metadata cannot satisfy native Chio authority claims.

Verifier rejects:

- advisory observation on an `authorizes` edge;
- payment or settlement proof used as tool authorization;
- identity lifecycle proof used as delegated action authority;
- UI, hosted, plugin, or SIEM state used as verifier verdict.

## Contract 13 - Preflight Is Planning Evidence

Preflight, rehearsal, replay, benchmark, and synthetic fixtures are valuable only when labeled as planning or evaluation evidence.

Verifier rejects:

- preflight report used as live receipt;
- rehearsal token used in live dispatch;
- recorded replay overwritten by live rerun output;
- benchmark score without corpus version, provider profile, and negative fixtures.
