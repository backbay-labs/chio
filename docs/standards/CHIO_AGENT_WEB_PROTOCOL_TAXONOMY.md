# Chio Agent Web Protocol Taxonomy

Status: launch taxonomy
Owner: launch-standards-review
Updated: 2026-07-03

This taxonomy defines how Chio talks about external Agent Web surfaces in public launch material. External standards can supply evidence, identifiers, signatures, manifests, or transport semantics. They do not become Chio authority unless a Chio verifier binds them to a Transaction Passport, Chio receipt, policy, and trusted key set.

## Authority Classes

| Class | Meaning | Launch wording |
| --- | --- | --- |
| Chio authority | A Chio verifier recomputes digests, verifies signatures against pinned keys, binds receipts or policies, and emits a Chio claim. | "verified by Chio" |
| Native external proof | The external protocol has its own signature, attestation, or conformance proof, and Chio verifies it as evidence. | "bound as external proof" |
| Chio sidecar proof | Chio carries a sidecar envelope or report beside an external object. | "projected through a Chio proof envelope" |
| Digest-bound reference | Chio binds an external object by canonical digest or schema digest but does not re-implement the external runtime. | "bound by digest" |
| Advisory observation | Chio records the external fact for context only. It cannot authorize or settle by itself. | "advisory evidence" |
| Unsupported claim | The verifier has no shipped positive fixture or enforcement path. | "not launch-supported" |

## Surface Map

| Surface | Current launch role | Authority rule |
| --- | --- | --- |
| MCP | Tool and resource protocol evidence. | Chio may bind mediated MCP calls and object digests. MCP alone is not Chio authorization. |
| A2A | Agent task and message evidence. | Chio may bind A2A task evidence for version v1.0.0. A2A alone is not Chio authority. |
| ACP-Client | IDE or client permission/session evidence. | Use the full name `ACP-Client`; never use the unqualified acronym. |
| ACP-Commerce | Commerce and merchant protocol evidence. | Use the full name `ACP-Commerce`. It is subordinate commerce evidence unless Chio verifies and binds it. |
| AG-UI | Agent/user event stream evidence. | Chio requires a start, content, end event sequence and digest-bound receipts. UI events alone are not authority. |
| OpenAPI | HTTP API description and operation evidence. | Launch support is limited to the versions and fixtures the verifier parses. Do not imply newer-version coverage without fixtures. |
| AP2 | Payment mandate and authorization evidence. | AP2 evidence is commerce evidence and must be bound to the order context. |
| x402 | Payment-required or payment-verification evidence. | x402 evidence is payment evidence and must be bound to the order context. |
| VC, BBS, SD-JWT | Credential and selective-disclosure evidence. | Privacy or credential claims require the Chio disclosure verifier and profile gates. |
| Standard Webhooks | Signed webhook delivery evidence. | Webhook signatures prove delivery authenticity only. They do not prove Chio authorization. |
| CloudEvents | Event identity and envelope evidence. | CloudEvents fields can be digest-bound, not treated as authorization. |
| GraphQL and GraphQL over HTTP | Query, variables, schema, and response evidence. | Draft HTTP material stays draft-labeled. |
| AsyncAPI | Event-driven API description evidence. | Chio may bind publish or consume evidence only when Chio owns the mediation path. |
| OAuth and OIDC | Identity and token admission evidence. | OAuth tokens and OIDC ID tokens are not Chio capabilities. |
| SCIM | Identity lifecycle evidence. | SCIM can inform revocation, not authorize tool execution. |
| SPIFFE and SPIRE | Workload identity evidence. | SPIFFE identifies workloads. It does not delegate agent authority. |
| Kubernetes admission | Cluster admission evidence. | Chio claims prevent-boundary admission only for Chio-owned admission webhooks. |
| OCI | Image, artifact, descriptor, subject, and referrer evidence. | Digest-pinned OCI references can be trusted. Mutable tags are not trusted artifact refs. |
| Sigstore, SLSA, in-toto, DSSE | Supply-chain and signed statement evidence. | These support release or artifact provenance. They do not prove runtime authorization by themselves. |

## Copy Rules

- Name the exact external surface. Use `ACP-Client` or `ACP-Commerce`; never use the unqualified acronym.
- Say "projection", "sidecar proof", or "digest-bound evidence" when Chio is not the external protocol's own authority.
- Say "verified by Chio" only when a shipped verifier recomputes the evidence and a positive fixture covers the claim.
- Do not describe Chio as a global replacement protocol, all-surface native authority, or authority verified by every external protocol.
- Do not claim current support for protocol versions or standards without a source-log row and fixture coverage.
