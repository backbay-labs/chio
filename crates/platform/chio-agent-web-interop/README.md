# chio-agent-web-interop

`chio-agent-web-interop` verifies Agent Web proof bundles: evidence that an
action taken through an external, non-Chio protocol was projected into the
Chio evidence model without inheriting authority it never earned. It is an
offline verifier, not a protocol client - it parses artifacts a caller already
assembled and never opens a network connection itself.

Chio authority in a verified bundle always traces back to a signed
`ChioReceipt` bound into the evidence graph. An external protocol's own
signature, status field, or "success" response only shows the projection
matches what happened externally; it is never proof that Chio authorized it.

## Responsibilities

- Verify a transaction passport's signature against its evidence graph, and
  that the graph and verifier policy match the passport's pinned digests
  (via `chio-transaction-passport`).
- Parse and structurally validate the evidence graph and verifier policy:
  node/edge shape, digest format, safe relative paths, no dangling
  references, no duplicate node ids.
- Validate each `AgentWebProofEnvelope` (content-addressed id, ed25519
  signature against trusted sidecar keys) and its bound
  `ExternalProjectionManifest` (supported protocol/version, digest and
  signature algorithm rules).
- Cover 30 external source protocols: agent/tool (MCP, A2A, ACP-Client,
  ACP-Commerce, AG-UI, browser automation, RPA), payments (AP2, x402),
  identity and access (OAuth2, OpenID Connect, SCIM, SPIFFE, Kubernetes
  admission), supply-chain attestation (Sigstore, SLSA, in-toto, DSSE, OCI),
  verifiable credentials (VC, SD-JWT VC, BBS), and general web/SaaS
  (Standard Webhooks, CloudEvents, GraphQL over HTTP, OpenAPI, AsyncAPI,
  Gmail, Google Calendar, Slack).
- Dispatch each envelope's external-subject bytes to that protocol's
  structural validator once the envelope and its projection manifest are
  confirmed well-formed and mutually bound.
- Re-verify every `ChioReceipt` an envelope references (signature, action
  hash, kernel-key trust, decision, digest binding) and, for commerce
  payment protocols, cross-check a bound `CommerceOrderContext`.
- Enforce that a verifier policy can require only `claim.agent_web.*`
  claims; reject any policy that requires a `claim.external.*` claim.
- Emit an `AgentWebInteropReport` of verified claims, per-envelope
  projections, unsupported claims, and limitations.

## Public API

- `AgentWebInteropBundle` - the input: `passport`, `evidence_graph_bytes`
  (+ optional `root_evidence_graph_bytes` when the passport signs a
  superset graph), `verifier_policy_bytes`, and `artifacts` (bundle-relative
  path to raw bytes).
- `AgentWebVerifierTrust` - pinned trust, built with
  `with_trusted_passport_signer_keys`, `with_trusted_receipt_kernel_keys`,
  `with_trusted_envelope_sidecar_keys`, `with_standard_webhooks_secret` /
  `with_standard_webhooks_secret_for`, `with_standard_webhooks_replay_window`,
  `with_seen_standard_webhooks_id`.
- `verify_agent_web_interop_with_trust(bundle, trust) ->
  Result<AgentWebInteropReport, TransactionPassportError>` - the entry point.
- `verify_agent_web_interop(bundle)` - shorthand for
  `verify_agent_web_interop_with_trust` with empty trust; only succeeds if
  the bundle needs no pinned key, so real bundles use the trust-carrying form.
- `AgentWebInteropReport`, `AgentWebProjectionResult`, `AgentWebClaimEvidence`
  - the output report and its per-envelope and per-claim detail.

## Testing

`cargo test -p chio-agent-web-interop`

## See also

- `chio-transaction-passport` - passport signature and schema verification
  this crate builds on.
- `chio-commerce-order` - commerce order context cross-checked for
  acp-commerce, ap2, and x402 payments.
- `chio-core-types` - receipt, key, and canonical-hashing primitives
  re-verified here.
- `chio-proof-room`, `chio-control-plane` - consumers of this verifier for
  Agent Web proof bundles.
