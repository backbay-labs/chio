# Chio protocol strategy research, May 2026

## Context

Six parallel research agents investigated whether Chio should expand its protocol coverage along directions the prior memo had rejected or deprioritized: pub/sub mediation, decentralized agent networks, OAuth/OIDC posture, policy-engine collaboration, workflow orchestrator coverage, and below-L7 surfaces. This overview synthesizes their findings into a phased build queue and surfaces the audit results that are worth knowing on their own.

Branch: `research/protocol-strategy-2026` off `main` at `14b4de625`. Companion docs in this directory.

## TL;DR

Audit revealed more existing coverage than the prior memo assumed. Five surprises (below) change the build plan: the priority is now to **close vocabulary and audit gaps in what already exists**, then add high-ROI new bridges (n8n, Zapier+Make, AGNTCY ACP, Cedar policy engine), then strategic expansions (NANDA/AGNTCY directory consumption, pre-signed URL gating, GitHub Actions workflow_dispatch). Database wire protocols, SOCKS5, DNS, TLS interception, Agora, AGNTCY SLIM as a wire bridge: defer or hard skip.

## What we already have (audit surprises)

1. **Python `chio-streaming` SDK** (~5000 LOC) already covers consumer-side mediation for Kafka, NATS, Pulsar, EventBridge, GCP Pub/Sub, Redis Streams, and Flink. The Rust kernel does *not* sit as a generic broker subscriber (zero NATS/Kafka/AMQP refs in any crate) and `HttpEgressContract` at [`chio-egress-contract/src/lib.rs:14`](crates/chio-egress-contract/src/lib.rs:14) is HTTP-only. The two sides don't speak the same policy vocabulary. ([01](docs/research/protocol-strategy/01-pubsub-coverage-audit.md))

2. **Real OAuth 2.1 authorization server** inside the hosted MCP edge at [`chio-mcp-remote/src/remote_mcp/oauth.rs:22`](crates/chio-mcp-remote/src/remote_mcp/oauth.rs:22): PKCE-S256, RFC 8693 token exchange, RFC 9396 RAR under a bounded `chio-governed-rar-v1` profile, RFC 8414 AS metadata, RFC 9728 protected-resource metadata, JWKS, sender-constrained tokens via `cnf` (chio-native DPoP, mTLS, attestation). No DCR/refresh/SCIM/MFA. ([03](docs/research/protocol-strategy/03-oauth-oidc-issuer.md))

3. **`chio-temporal` and `chio-airflow` SDKs** already provide activity-level mediation for Temporal and Airflow. The realistic agent threat surface for these orchestrators is already covered in-platform. ([05](docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md))

4. **`chio-envoy-ext-authz`** transparently covers QUIC and gRPC. No separate bridge needed for those. ([06](docs/research/protocol-strategy/06-below-l7-mediation.md))

5. **`ExternalGuard` + `AsyncGuardAdapter` machinery** at [`chio-guards/src/external/mod.rs:119`](crates/chio-guards/src/external/mod.rs:119) already has circuit breaker, token bucket, TTL cache, retry, and fail-closed defaults. Any new policy-engine integration can blanket-adapt onto this existing plumbing instead of building parallel infrastructure. ([04](docs/research/protocol-strategy/04-policy-engine-collaborators.md))

## Recommended build queue

### Wave A — Close gaps in what we already have

- **Add `EventPublish` / `EventConsume` variants** to `ToolAction` ([`chio-guards/src/action.rs:16`](crates/chio-guards/src/action.rs:16)) and add manifest constraints for topics/subjects/ARNs in `chio-manifest`. This makes Rust kernel policy speak the same vocabulary as the Python `chio-streaming` SDK. Without this, the SDK enforces but the kernel can't replay or audit. ([01](docs/research/protocol-strategy/01-pubsub-coverage-audit.md))
- **Consolidate OAuth consumer/verifier posture**: extend `CallerIdentity` ([`chio-http-core/src/identity.rs:44`](crates/chio-http-core/src/identity.rs:44)) with OAuth shape, add RFC 9449 JWT DPoP at the HTTP boundary, add actor-chain validation per the IETF agent-OBO draft, emit RFC 9470 step-up challenges from policy guards. ([03](docs/research/protocol-strategy/03-oauth-oidc-issuer.md))
- **Rename and scope-clamp the existing AS** to "Chio Governed Authorization Bridge" — mint tokens for the Chio MCP edge only when no upstream AS understands governed RAR. Do not compete with WorkOS/Stytch/Scalekit/Aembit as an enterprise IdP. ([03](docs/research/protocol-strategy/03-oauth-oidc-issuer.md))

### Wave B — High-ROI new bridges

- **n8n orchestrator-egress mediation** (priority 1). 686% abuse spike per the Cisco Talos n8mare report; weakest incumbent security story; signed-receipt model is a genuine upgrade. ([05](docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md))
- **Zapier + Make.com paired adapter** (priority 2). Identical webhook wire shape, one adapter, highest agent-webhook volume. ([05](docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md))
- **Cedar `PolicyEngineProvider`** — new trait in `chio-external-guards` (`engine() -> &'static str`, `policy_digest() -> [u8; 32]`, `evaluate() -> EngineDecision`), blanket-adapted as `ExternalGuard`. Engine ID + policy digest feed into `ChioReceiptBody.policy_hash` and `GuardEvidence` ([`chio-core-types/src/receipt.rs:159`](crates/chio-core-types/src/receipt.rs:159)) for replay. Cedar first because Rust-native, formally analyzable, no sidecar, matches the fail-closed stance from CLAUDE.md. ([04](docs/research/protocol-strategy/04-policy-engine-collaborators.md))

### Wave C — Strategic expansions

- **AGNTCY ACP bridge** (`chio-bridge-acp`). OpenAPI-specified, request/response shaped, real downstream consumers (Webex Agent Central Service), lands cleanly under existing `ToolServerConnection`. ([02](docs/research/protocol-strategy/02-decentralized-agent-networks.md))
- **`DirectoryProvider` seam** for read-only consumption of NANDA and AGNTCY directories — no peer participation, no auto-imported capabilities, no widening of local trust. This is the pattern that lets Chio benefit from decentralized agent indexes without becoming one. ([02](docs/research/protocol-strategy/02-decentralized-agent-networks.md))
- **GitHub Actions `workflow_dispatch` egress mediation** (priority 3 in the orchestrator wave). Despite GitHub's 2026 Agentic Workflow Firewall, the agent-attribution gap is real. ([05](docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md))
- **`PresignedUrlGuard`** in `chio-data-guards/` (sibling of `SqlQueryGuard`). Covers S3, GCS, and Azure SAS pre-signed URLs — the one below-L7 surface that pencils out, because pre-signed URLs are arguably L7 "tool calls" packaged as URLs. ([06](docs/research/protocol-strategy/06-below-l7-mediation.md))

### Wave D — Coverage gaps to close in the streaming SDK

- **AMQP / RabbitMQ, AWS SNS+SQS, and WebSub** have zero coverage in either `chio-streaming` or any Rust crate. Add them once Wave A vocabulary lands. ([01](docs/research/protocol-strategy/01-pubsub-coverage-audit.md))

### Defer or hard skip

- **Database wire protocols** (Postgres/MySQL/Mongo) and **SOCKS5**: defer to a future `chio-wire-mediation` sibling crate, explicitly *not* an extension of `chio-egress-contract`. ([06](docs/research/protocol-strategy/06-below-l7-mediation.md))
- **DNS** (DoH/DoT) and **TLS interception**: hard skip. L3/L4 territory; well-served by incumbents (Cisco Umbrella, NextDNS, Cloudflare Gateway, Palo Alto/Zscaler/Netskope). ([06](docs/research/protocol-strategy/06-below-l7-mediation.md))
- **Agora protocol**: research-track, defer behind operator-pinned Protocol Documents. ([02](docs/research/protocol-strategy/02-decentralized-agent-networks.md))
- **AGNTCY SLIM** as a wire bridge: treat as a pluggable transport for future phases, not a `ToolServerConnection`. ([02](docs/research/protocol-strategy/02-decentralized-agent-networks.md))
- **Temporal, Airflow, Step Functions, Argo dedicated bridges**: existing in-platform SDKs cover the realistic activity-level threat. Revisit only on customer demand. ([05](docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md))

## Cross-cutting design themes

Three patterns surfaced across the docs that are worth promoting to architecture-level conventions:

- **DirectoryProvider seam (from 02)**: a read-only trait for federated discovery that does not widen local trust. Reusable beyond NANDA/AGNTCY.
- **PolicyEngineProvider as ExternalGuard adapter (from 04)**: pattern for any out-of-process policy delegation; reuses the existing async-adapter plumbing.
- **Double-gating egress (from 05)**: `ToolServerConnection` manifest + policy first, then `HttpEgressContract` at the wire. This is now the canonical pattern for "agent triggers external action."
- **Receipts embed engine-id + policy-digest (from 04)**: extending `ChioReceiptBody.policy_hash` to cover decisions delegated to Cedar/OPA/OpenFGA makes receipts portably auditable across the policy-engine boundary.

## Naming-collision warning

Three protocols are named "ACP":

1. **Zed's Agent Client Protocol / Anthropic Compute Protocol** — covered today by [`chio-acp-edge`](crates/chio-acp-edge/).
2. **IBM Agent Communication Protocol** — converging with A2A; no Chio bridge today.
3. **AGNTCY Agent Connect Protocol** — the new bridge proposed in Wave C.

The Wave C bridge should not be named `chio-acp-*`. Suggest `chio-agntcy-acp-*` or `chio-bridge-agntcy`.

## Open questions for product owner

1. Is the existing OAuth AS in `chio-mcp-remote` actively used or stale? Affects whether rename + scope-clamp is sufficient or it should be deleted.
2. Are `chio-temporal` and `chio-airflow` production-deployed or speculative? Affects whether to deprioritize dedicated orchestrator bridges with confidence.
3. Should `DirectoryProvider` be a new crate or live in `chio-federation`?
4. Cedar adoption: greenfield-only first guard, or migrate an existing guard as proof?
5. Wave A vocabulary changes (`EventPublish`/`EventConsume`) likely require a schema bump in `chio-manifest`. Is that worth bundling with other v3 schema work?

## Files

- [01-pubsub-coverage-audit.md](docs/research/protocol-strategy/01-pubsub-coverage-audit.md)
- [02-decentralized-agent-networks.md](docs/research/protocol-strategy/02-decentralized-agent-networks.md)
- [03-oauth-oidc-issuer.md](docs/research/protocol-strategy/03-oauth-oidc-issuer.md)
- [04-policy-engine-collaborators.md](docs/research/protocol-strategy/04-policy-engine-collaborators.md)
- [05-workflow-orchestrator-mediation.md](docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md)
- [06-below-l7-mediation.md](docs/research/protocol-strategy/06-below-l7-mediation.md)
