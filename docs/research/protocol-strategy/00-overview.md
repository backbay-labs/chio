# Chio protocol strategy research, May 2026

## Context

Six parallel research agents investigated whether Chio should expand its protocol coverage along directions the prior memo had rejected or deprioritized: pub/sub mediation, decentralized agent networks, OAuth/OIDC posture, policy-engine collaboration, workflow orchestrator coverage, and below-L7 surfaces. This overview synthesizes their findings into a phased build queue and surfaces the audit results that are worth knowing on their own.

Branch: `research/protocol-strategy-2026` off `main` at `14b4de625`. Companion docs in this directory.

> **Plan-of-record note (PR 652 review):** This round-1 overview is retained as historical context. Use [00-overview-v2.md](00-overview-v2.md) as the current synthesis and [18-decision-packet.md](18-decision-packet.md) as the architecture decision packet before implementation tickets.

> **Erratum**: AGNTCY ACP is dead. The `agntcy/acp-spec` repo was archived 2026-04-11 and absorbed into A2A. The AGNTCY ACP bridge bullet in Phase C below is struck; only consume-only Directory + Identity integration via the `DirectoryProvider` seam survives. See [17-agntcy-revisited.md](17-agntcy-revisited.md). Also: the n8n priority-1 framing originally cited the Talos 686% spike (which is Chain D, not blocked by Chio); the actually-blocked attack chain is Chain C (prompt-injection agent-to-webhook). See [11-n8n-threat-mapping.md](11-n8n-threat-mapping.md).

## TL;DR

Audit revealed more existing coverage than the prior memo assumed. Five surprises (below) change the build plan: the priority is now to **close vocabulary and audit gaps in what already exists**, then add high-ROI new bridges (n8n Chain C only, Zapier+Make, Cedar policy engine), then strategic expansions (NANDA / AGNTCY directory consumption, pre-signed URL gating, GitHub Actions workflow_dispatch). Database wire protocols, SOCKS5, DNS, TLS interception, Agora, AGNTCY SLIM as a wire bridge: defer or hard skip.

## What we already have (audit surprises)

1. **Python `chio-streaming` SDK** (~5000 LOC) already covers consumer-side mediation for Kafka, NATS, Pulsar, EventBridge, GCP Pub/Sub, Redis Streams, and Flink. The Rust kernel does *not* sit as a generic broker subscriber (zero NATS/Kafka/AMQP refs in any crate) and `HttpEgressContract` at [`chio-egress-contract/src/lib.rs:14`](../../../crates/chio-egress-contract/src/lib.rs#L14) is HTTP-only. The two sides don't speak the same policy vocabulary. ([01](01-pubsub-coverage-audit.md))

2. **Real OAuth 2.1 authorization server** inside the hosted MCP edge at [`chio-mcp-remote/src/remote_mcp/oauth.rs:22`](../../../crates/chio-mcp-remote/src/remote_mcp/oauth.rs#L22): PKCE-S256, RFC 8693 token exchange, RFC 9396 RAR under a bounded `chio-governed-rar-v1` profile, RFC 8414 AS metadata, RFC 9728 protected-resource metadata, JWKS, sender-constrained tokens via `cnf` (chio-native DPoP, mTLS, attestation). No DCR/refresh/SCIM/MFA. ([03](03-oauth-oidc-issuer.md))

3. **`chio-temporal` and `chio-airflow` SDKs** already provide activity-level mediation for Temporal and Airflow. The realistic agent threat surface for these orchestrators is already covered in-platform. ([05](05-workflow-orchestrator-mediation.md))

4. **`chio-envoy-ext-authz`** transparently covers QUIC and gRPC. No separate bridge needed for those. ([06](06-below-l7-mediation.md))

5. **`ExternalGuard` + `AsyncGuardAdapter` machinery** at [`chio-guards/src/external/mod.rs:119`](../../../crates/chio-guards/src/external/mod.rs#L119) already has circuit breaker, token bucket, TTL cache, retry, and fail-closed defaults. Any new policy-engine integration can blanket-adapt onto this existing plumbing instead of building parallel infrastructure. ([04](04-policy-engine-collaborators.md))

## Recommended build queue

### Phase A: close gaps in what we already have

- **Add `EventPublish` / `EventConsume` variants** to `ToolAction` ([`chio-guards/src/action.rs:16`](../../../crates/chio-guards/src/action.rs#L16)) and add manifest constraints for topics/subjects/ARNs in `chio-manifest`. This makes Rust kernel policy speak the same vocabulary as the Python `chio-streaming` SDK. Without this, the SDK enforces but the kernel can't replay or audit. ([01](01-pubsub-coverage-audit.md))
- **Consolidate OAuth consumer/verifier posture**: extend `CallerIdentity` ([`chio-http-core/src/identity.rs:44`](../../../crates/chio-http-core/src/identity.rs#L44)) with OAuth shape, add RFC 9449 JWT DPoP at the HTTP boundary, add actor-chain validation per the IETF agent-OBO draft, emit RFC 9470 step-up challenges from policy guards. ([03](03-oauth-oidc-issuer.md))
- **Rename and scope-clamp the existing AS** to "Chio Governed Authorization Bridge": mint tokens for the Chio MCP edge only when no upstream AS understands governed RAR. Do not compete with WorkOS / Stytch / Scalekit / Aembit as an enterprise IdP. ([03](03-oauth-oidc-issuer.md))

### Phase B: high-ROI new bridges

- **n8n orchestrator-egress mediation (Chain C only)**. The 686% Talos abuse spike is Chain D (ingress webhook abuse, NOT blocked by Chio: below our layer). The actually-blocked chain is Chain C (prompt-injection agent-to-webhook exfiltration), where workflow-ID allowlist + typed input constraints + `HttpEgressContract` authority pinning + loopback/link-local/ULA denial give end-to-end coverage; receipts add chain-of-custody. ([05](05-workflow-orchestrator-mediation.md), [11](11-n8n-threat-mapping.md))
- **Zapier + Make.com paired adapter** (priority 2). Identical webhook wire shape, one adapter, highest agent-webhook volume. ([05](05-workflow-orchestrator-mediation.md))
- **Cedar `PolicyEngineProvider`**: new trait in `chio-external-guards` (`engine() -> &'static str`, `policy_digest() -> String` hex, `evaluate() -> EngineDecision`), blanket-adapted as `ExternalGuard`. Engine ID + policy digest feed into `ChioReceiptBody.policy_hash` and `GuardEvidence` ([`chio-core-types/src/receipt.rs:159`](../../../crates/chio-core-types/src/receipt.rs#L159)) for replay. Cedar first because Rust-native, formally analyzable, no sidecar, matches the fail-closed stance from CLAUDE.md. ([04](04-policy-engine-collaborators.md))

### Phase C: strategic expansions

- **`DirectoryProvider` seam** for read-only consumption of NANDA and AGNTCY directories (no peer participation, no auto-imported capabilities, no widening of local trust). This is the pattern that lets Chio benefit from decentralized agent indexes without becoming one. Lives in `chio-directory`. Mirrors Webex (the only documented production AGNTCY consumer) which uses Identity + Directory and never touched ACP. ([02](02-decentralized-agent-networks.md), [17](17-agntcy-revisited.md))
- **GitHub Actions `workflow_dispatch` egress mediation** (priority 3 in the orchestrator wave). GitHub's current Agent Workflow Firewall / `gh-aw` coverage and naming need official refresh before ticketing; Chio's likely gap is outside-in agent attribution. ([05](05-workflow-orchestrator-mediation.md))
- **`PresignedUrlGuard`** in `chio-data-guards/` (sibling of `SqlQueryGuard`). Covers S3, GCS, and Azure SAS pre-signed URLs: the one below-L7 surface that pencils out, because pre-signed URLs are arguably L7 "tool calls" packaged as URLs. ([06](06-below-l7-mediation.md))

> ~~AGNTCY ACP bridge~~ (`chio-bridge-acp`): **STRUCK**. ACP archived 2026-04-11; absorbed into A2A. See [17-agntcy-revisited.md](17-agntcy-revisited.md).

### Phase D: coverage gaps to close in the streaming SDK

- **AMQP / RabbitMQ, AWS SNS+SQS, and WebSub** have zero coverage in either `chio-streaming` or any Rust crate. Add them once Phase A vocabulary lands. ([01](01-pubsub-coverage-audit.md))

### Defer or hard skip

- **Database wire protocols** (Postgres / MySQL / Mongo) and **SOCKS5**: defer to a future `chio-wire-mediation` sibling crate, explicitly *not* an extension of `chio-egress-contract`. ([06](06-below-l7-mediation.md))
- **DNS** (DoH / DoT) and **TLS interception**: hard skip. L3/L4 territory; well-served by incumbents (Cisco Umbrella, NextDNS, Cloudflare Gateway, Palo Alto / Zscaler / Netskope). ([06](06-below-l7-mediation.md))
- **Agora protocol**: research-track, defer behind operator-pinned Protocol Documents. ([02](02-decentralized-agent-networks.md))
- **AGNTCY SLIM** as a wire bridge: treat as a pluggable transport for future phases, not a `ToolServerConnection`. ([02](02-decentralized-agent-networks.md))
- **Temporal, Airflow, Step Functions, Argo dedicated bridges**: existing in-platform SDKs cover the realistic activity-level threat. Revisit only on customer demand. ([05](05-workflow-orchestrator-mediation.md))

## Cross-cutting design themes

Three patterns surfaced across the docs that are worth promoting to architecture-level conventions:

- **DirectoryProvider seam (from 02)**: a read-only trait for federated discovery that does not widen local trust. Reusable beyond NANDA / AGNTCY.
- **PolicyEngineProvider as ExternalGuard adapter (from 04)**: pattern for any out-of-process policy delegation; reuses the existing async-adapter plumbing.
- **Double-gating egress (from 05)**: `ToolServerConnection` manifest + policy first, then `HttpEgressContract` at the wire. This is now the canonical pattern for "agent triggers external action."
- **Receipts embed engine-id + policy-digest (from 04)**: extending `ChioReceiptBody.policy_hash` (canonical form: hex `String`) to cover decisions delegated to Cedar / OPA / OpenFGA makes receipts portably auditable across the policy-engine boundary.

## Naming-collision warning

Three protocols are named "ACP":

1. **Zed's Agent Client Protocol / Anthropic Compute Protocol**: covered today by [`chio-acp-edge`](../../../crates/chio-acp-edge/).
2. **IBM Agent Communication Protocol**: converging with A2A; no Chio bridge today.
3. **AGNTCY Agent Connect Protocol**: archived 2026-04-11; absorbed into A2A. No Chio bridge planned.

The `chio-acp-*` namespace is owned by Zed's ACP. Do not propose other crates with that prefix.

## Open questions for product owner

1. Is the existing OAuth AS in `chio-mcp-remote` actively used or stale? (Answered in [07](07-oauth-as-usage-audit.md): live but opt-in scaffolding. Outcome: feature flag + rename + scope-clamp.)
2. Are `chio-temporal` and `chio-airflow` production-deployed or speculative? Affects whether to deprioritize dedicated orchestrator bridges with confidence. (Both exist with real LOC counts and clean activity-level interceptor patterns; production deployment unknown without telemetry.)
3. Should `DirectoryProvider` be a new crate or live in `chio-federation`? (Answered: new `chio-directory` leaf crate; see [08](08-agntcy-acp-bridge-spec.md) and [17](17-agntcy-revisited.md).)
4. Cedar adoption: greenfield-only first guard, or migrate an existing guard as proof? (Answered: Option A' = greenfield + two flagship ports `McpToolGuard` and `EgressAllowlistGuard`; see [10](10-cedar-first-guard.md).)
5. Vocabulary changes (`EventPublish` / `EventConsume`) are now folded into current `chio.manifest.v1` planning because Chio is unreleased. (Keep fail-closed validation, remove pre-release compatibility negotiation, and use [09](09-event-action-schema.md) plus [18](18-decision-packet.md) only as historical inputs.)

## Files

- [01-pubsub-coverage-audit.md](01-pubsub-coverage-audit.md)
- [02-decentralized-agent-networks.md](02-decentralized-agent-networks.md)
- [03-oauth-oidc-issuer.md](03-oauth-oidc-issuer.md)
- [04-policy-engine-collaborators.md](04-policy-engine-collaborators.md)
- [05-workflow-orchestrator-mediation.md](05-workflow-orchestrator-mediation.md)
- [06-below-l7-mediation.md](06-below-l7-mediation.md)
- See also: [00-overview-v2.md](00-overview-v2.md) (extended synthesis), [reviews/](reviews/) (audit reviews), [17-agntcy-revisited.md](17-agntcy-revisited.md) (AGNTCY follow-up), [18-decision-packet.md](18-decision-packet.md) (PR 652 decision packet)
