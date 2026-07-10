# chio-agent-web-interop Design

## D9 Crate Home Decision

`chio-agent-web-interop` stays in `crates/platform` as a cross-protocol proof verifier for external Agent Web envelopes. It covers projections for Standard Webhooks, CloudEvents, GraphQL, MCP, A2A, ACP-Client, ACP-Commerce, AP2, x402, OpenAPI, AsyncAPI, browser/RPA, SaaS connectors, OAuth/OIDC, SCIM, SPIFFE/SPIRE, Kubernetes admission, OCI refs, VC/BBS/SD-JWT, Sigstore, SLSA, in-toto, and DSSE.

The default homes considered were the protocol adapter crates. Adapter crates translate live protocol traffic; this crate verifies offline evidence that external artifacts are projections under Chio authority, not authority by themselves.

## Boundary

This crate parses and verifies Agent Web evidence and emits Agent Web verifier reports. It does not run protocol clients, open network connections, or grant external authority.

## Invariants

External proof never becomes Chio authority. Receipts, sidecars, signatures, projection manifests, and subject digests must be graph-bound and verified against pinned keys or local secrets.
