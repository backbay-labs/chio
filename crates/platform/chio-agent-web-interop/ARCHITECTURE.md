# chio-agent-web-interop architecture

## Overview

The crate is a pure, offline verifier at the boundary between Chio-native
authority and evidence from protocols Chio does not control. It performs no
I/O: every input arrives as bytes inside an `AgentWebInteropBundle`, and every
output is a `Result` of `AgentWebInteropReport` or the shared
`TransactionPassportError`. Its central invariant is
that external proof never becomes Chio authority by itself: every supported
protocol must disclaim its own signature or status as authoritative, and the
only artifact that can grant authority is a signed `ChioReceipt`, independently
re-verified for every envelope.

This crate covers offline proof verification, not live protocol traffic. A
protocol's own adapter crate, where one exists, is where Chio actually speaks
that protocol.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `AgentWebInteropBundle`, `AgentWebVerifierTrust`, replay store types, and report types; read-only and replay-consuming verification orchestration; receipt re-verification, commerce order-context binding, and claim-mapping enforcement. |
| `src/evidence.rs` | Evidence graph model (`AgentWebEvidenceGraph`/`Node`/`Edge`/`Role`) and parsing: schema check, node/edge shape, duplicate-id and dangling-reference rejection, safe relative-path validation, digest-checked artifact byte lookup. |
| `src/policy.rs` | Verifier policy model (`AgentWebVerifierPolicy`) and parsing: schema check, non-empty required claims. |
| `src/protocols.rs` | Static registry of the 30 supported source protocols: external-subject schema id, required "unsupported" external-authority claim(s), supported source versions, per-protocol error message. |
| `src/claims.rs` | Claim id constants: the four `claim.agent_web.*` claims this crate can verify, and one `claim.external.*_is_chio_authority` constant per source protocol. |
| `src/artifacts.rs` | `AgentWebProofEnvelope` and `ExternalProjectionManifest` models and validation (content-addressed envelope id, ed25519 signature, manifest shape), the external-subject dispatch table, inline `validate_subject` for 9 protocols (Kubernetes admission, OCI, VC, SD-JWT VC, BBS, Sigstore, in-toto, DSSE, SLSA provenance), shared JSON-field helpers. |
| `src/artifacts/*.rs` (21 files) | One `validate_subject` per remaining source protocol: `a2a`, `acp_client`, `acp_commerce`, `ag_ui`, `ap2`, `asyncapi`, `browser_automation`, `calendar`, `cloudevents`, `email`, `graphql_http`, `mcp`, `oauth2`, `openapi`, `openid_connect`, `rpa`, `scim`, `slack`, `spiffe`, `standard_webhooks`, `x402`. |

## Verification flow

1. Verify the passport's signature against the signed evidence graph
   (`root_evidence_graph_bytes` when the bundle carries a signed superset,
   else `evidence_graph_bytes` itself) using `trust`'s pinned passport signer
   keys, and that `evidence_graph_bytes` is a node/edge subset of it when the
   two differ; verify the passport's pinned digests match the supplied
   evidence graph and verifier policy bytes (`chio-transaction-passport`).
2. Parse and structurally validate the evidence graph and verifier policy.
3. Index every `external-projection-manifest` node by `projection_id`,
   validating each manifest's shape and its protocol's mandatory
   unsupported-claim declaration.
4. For each `agent-web-proof-envelope` node: validate the envelope itself,
   bind it to its projection manifest and to an `external-subject` node via
   required graph edges, validate the external subject's schema tag, and
   dispatch to the protocol-specific `validate_subject`.
5. For commerce payment protocols (acp-commerce, ap2, x402), resolve a bound
   `CommerceOrderContext` node and cross-check order id, amount, and
   currency or asset.
6. Re-verify every `ChioReceipt` the envelope references: graph edge
   binding, signature, action hash, kernel-key trust, `MediatedDecision` /
   `Mediated` kind and level, `Allow` decision, and digest binding to both
   the external subject and the verifier policy.
7. Fold each envelope's claim mapping into the verified-claims list and its
   unsupported claims and limitations into the report; require at least one
   projection, reject any policy that requires a `claim.external.*` claim,
   and require every policy-required `claim.agent_web.*` claim to have
   verified.
8. In a consuming verification mode, atomically reserve every validated
   Standard Webhooks replay entry only after the complete report passes, and
   only after reproducing the expected read-only report when one is supplied.

## Standard Webhooks replay modes

Agent Web verification separates read-only and consuming operations.
`verify_agent_web_interop_with_trust` validates the timestamp window, HMAC,
graph, envelope, receipt, and claims without reading or writing replay state,
so offline verification is idempotent.
`verify_agent_web_interop_with_trust_and_consume_replays` performs the same
validation and then atomically reserves every Standard Webhooks identifier.
`verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches`
also requires the consuming pass to reproduce an expected read-only report
before it reserves identifiers. Failed validation or a report mismatch
reserves nothing.

The CLI uses read-only verification for `chio proof verify`. `chio proof
collect` consumes replay entries only after proof-family, root-claim, parity,
and required-claim checks pass and the consuming report matches the initial
read-only report. When consuming Standard Webhooks replay protection is
configured, `CHIO_AGENT_WEB_REPLAY_STORE_PATH` must name an available durable
SQLite database. A missing or unavailable store fails closed.

Replay keys are `(replay_scope, webhook_id)`. After the delivery HMAC
succeeds, the verifier derives the opaque scope with a domain-separated HMAC
over the verifier secret identity and signed endpoint digest. Stores receive
the lowercase-hex scope but never the raw verifier secret. Independent
authenticated senders or endpoints can therefore reuse a webhook identifier
without sharing replay state. During SQLite migration, legacy rows without a
scope receive a reserved unscoped marker and conservatively block that
identifier in every scope until the row expires.

The in-memory and SQLite stores require positive global and per-scope live
entry capacities. Exhaustion denies fail closed and never evicts a live
marker. Expired markers are reclaimed only after complete batch validation
and capacity checks succeed. SQLite serializes count and insert with an
immediate transaction, and reopening a database with limits below retained
live rows fails instead of deleting them. Default constructors use bounded
constants; `new_with_capacity` and `open_with_capacity` let hosts set explicit
limits.

A shared store remains a global availability boundary. Hosts should size
per-scope limits for expected sender rates, size the global limit for available
memory or disk, and use separate stores when tenants need independent
availability guarantees. Every process that opens one SQLite replay database
must use the same capacity policy.

## Invariants and failure modes

- Fail-closed parsing throughout: every artifact struct uses
  `#[serde(deny_unknown_fields)]`, and empty required strings, unknown enum
  variants, and dangling graph node/edge references are rejected before any
  semantic check runs.
- External authority never substitutes for Chio authority: a protocol's
  `claim.external.*_is_chio_authority` claim must appear in its projection
  manifest's `unsupported_claims`, and a verifier policy that requires any
  `claim.external.*` claim is rejected regardless of what the bundle
  contains.
- The four `claim.agent_web.*` claims are mandatory on every envelope and
  can never be mapped with evidence class `native-external-proof`; that
  evidence class is reserved for claims a manifest does not also list as
  unsupported.
- Artifact bytes are digest-checked against their evidence graph node's
  `sha256` before any parsing (`raw_artifact_bytes`), and node paths are
  rejected if absolute, containing `..`, backslashes, or a Windows drive
  prefix.
- Standard Webhooks is the only protocol with an independent cryptographic
  check inside this crate (HMAC-SHA256 over
  `id.timestamp.body_digest.endpoint_digest`). Read-only callers may supply a
  replay window and seen-id set; consuming callers use an atomic scoped replay
  store. Every other protocol's authenticity rests on the bound `ChioReceipt`.
- This crate defines no error type of its own; every failure is a
  `chio_transaction_passport::TransactionPassportError` variant
  (`AgentWebClaimFailed`, `InvalidAgentWebArtifact`, `MissingAgentWebArtifact`,
  `InvalidEvidenceGraphArtifact`, `UnsupportedEvidenceGraphSchema`,
  `InvalidVerifierPolicyArtifact`, `UnsupportedVerifierPolicySchema`).

## Dependencies

Internal: `chio-transaction-passport` supplies `TransactionPassport`,
passport signature and minimal-artifact verification, the evidence-graph and
verifier-policy schema id constants, and the `TransactionPassportError` type
this crate reuses for all its own errors. `chio-commerce-order` supplies
`CommerceOrderContext` for cross-checking acp-commerce, ap2, and x402
payments. `chio-core-types` supplies `PublicKey`/`Signature`, canonical JSON
hashing (`canonical_json_bytes`, `sha256_hex`), and the
`ChioReceipt`/`Decision`/`ReceiptKind`/`TrustLevel` types re-verified for
every bound receipt. No dependency is aliased. External: `serde`/`serde_json`
for artifact parsing, `sha2`/`hmac` for digesting and Standard Webhooks HMAC
verification, `base64` for decoding Standard Webhooks signatures.
