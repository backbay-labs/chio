# 03. OAuth 2.1 / OIDC Issuer Posture for Chio

> **Historical research note:** This document is background for PR 652, not the
> implementation plan of record. Use [00-overview-v2.md](00-overview-v2.md)
> and [18-decision-packet.md](18-decision-packet.md) for current planning.
> OAuth AS implementation tickets remain blocked until a dedicated ADR or
> equivalent decision note is accepted.

## TL;DR

Chio should adopt a hybrid **issuer-of-last-resort plus PDP-with-step-up** posture. The codebase already ships a non-trivial OAuth 2.1 authorization server inside the hosted MCP edge (`crates/chio-mcp-remote/src/remote_mcp/oauth.rs`) with PKCE, RFC 8693 token exchange, RFC 9396 rich authorization details, RFC 8414 metadata, RFC 9728 protected-resource metadata, and a Chio-specific sender-constraint extension. Walking that back would discard real, tested code. But Chio should *not* market itself as a general-purpose enterprise IdP that competes with WorkOS, Stytch, or Scalekit. The right framing is: Chio is a policy decision point (PDP) for agent tool calls that, where no upstream AS can express the governance contract Chio needs (governed RAR, transaction-context, attestation-bound sender constraint), mints a narrow access token bound to a single protected resource (the Chio MCP edge). For everything else, Chio consumes and verifies upstream OAuth/OIDC tokens, surfaces them in `CallerIdentity`, and returns step-up challenges when policy requires fresher human approval. Issuer scope stays bounded to the `chio-governed-rar-v1` profile; broad user-facing authentication and lifecycle remain non-goals.

## Phase 1: What Chio Has Today

### A working OAuth 2.1 authorization server inside the hosted MCP edge

The most important finding is that the hosted MCP edge already runs a `LocalAuthorizationServer` that goes well beyond a stub. The endpoints registered by the router include the standard well-known documents plus an authorize/token/jwks triple:

- `crates/chio-mcp-remote/src/remote_mcp/http_service.rs:216-239` wires `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-authorization-server/{*rest}`, `/oauth/authorize`, `/oauth/token`, and `/oauth/jwks.json`.
- Path constants live in `crates/chio-mcp-remote/src/remote_mcp/session_core.rs:86-101`.

What this AS supports:

- **PKCE S256 only** (`crates/chio-mcp-remote/src/remote_mcp/oauth.rs:283-296, 589-595`). Plain PKCE and non-PKCE flows are refused.
- **Authorization code grant with resource-parameter binding** (RFC 8707): the `resource` field is required and must equal the advertised protected resource (`oauth.rs:561-574`).
- **RFC 8693 token exchange** with `urn:ietf:params:oauth:grant-type:token-exchange` and `urn:ietf:params:oauth:token-type:access_token` subject token type (`oauth.rs:216-225, 328-409`).
- **RFC 9396 rich authorization requests** under a Chio-specific profile (`chio-governed-rar-v1`). Only three `type` values are accepted: `chio_governed_tool`, `chio_governed_commerce`, `chio_governed_metered_billing` (`crates/chio-kernel/src/operator_report.rs:62-66`).
- **Chio transaction context**, a non-standard top-level parameter and JWT claim carrying intent hash, approval evidence, runtime-assurance digest, delegated call-chain, and an optional identity continuity assertion (`oauth.rs:36-83, 444-461`).
- **Sender-constrained tokens via `cnf`** with three proof families: chio-native DPoP key (`chio_dpop_v1`), mTLS thumbprint (`chio_mtls_thumbprint_v1`), and attestation digest (`chio_attestation_binding_v1`). Constants: `crates/chio-kernel/src/operator_report.rs:71-75`. Binding logic: `oauth.rs:43-48, 305-314`. Spec: `spec/PROTOCOL.md:1405-1434`.
- **JWKS publication** with EdDSA / OKP / Ed25519 keys (`oauth.rs:527-538`).
- **AS metadata document** publishing the canonical Chio profile id and schema alongside standard fields (`http_service.rs:1413-1422`, `spec/PROTOCOL.md:1436-1448`).
- **Bounded DCR**: the metadata document references an optional upstream `registration_endpoint` (`http_service.rs:1497-1505`), but Chio does not itself implement RFC 7591 dynamic client registration. Static `client_id` strings are accepted at the authorize endpoint without enforcement (`oauth.rs:553-559`).

### A separate runtime DPoP layer (chio-native, not RFC 9449)

The kernel ships its own DPoP variant for tool invocation in `crates/chio-kernel/src/dpop.rs:1-100`. Schema is `chio.dpop_proof.v1`. Body fields are `capability_id`, `tool_server`, `tool_name`, `action_hash`, `nonce`, `issued_at`, `agent_key`. This is *not* RFC 9449 JWT DPoP. The gap is explicit: the spec promises RFC-shaped DPoP at the HTTP boundary but ships a Chio-native proof everywhere. The intended end state is that the edge verifies HTTP DPoP and synthesizes internal caller context, keeping `chio.dpop_proof.v1` as the internal invocation proof. See `spec/PROTOCOL.md` for the DPoP boundary contract.

### Identity surface that consumes, not issues, broadly

`CallerIdentity` in `crates/chio-http-core/src/identity.rs:44-65` knows Bearer, ApiKey, Cookie, MtlsCertificate, Anonymous. Note what it does *not* know: OAuth issuer, scopes, federated claims, sender-constraint. Those live one layer up in the hosted edge as `SessionAuthMethod::OAuthBearer` with fields `issuer`, `subject`, `audience`, `scopes`, `federated_claims`, `enterprise_identity`, `token_fingerprint` (`crates/chio-mcp-remote/src/remote_mcp/oauth.rs:851-872`). This split is meaningful: the universal core CallerIdentity is a token-hash-and-subject pair, while the hosted edge keeps a richer OAuth-shaped projection that only some surfaces use.

The hosted edge has three OAuth verifier modes (`oauth.rs:783-819`):

- `StaticBearer` (token equality)
- `JwtBearer` (verifier-side JWT validation)
- `IntrospectionBearer` (RFC 7662 introspection against an upstream AS)

There is no client-credentials, device-code, CIBA, FAPI, or refresh-token implementation, and no SCIM lifecycle. `spec/PROTOCOL.md:100` is explicit: "automatic SCIM provisioning lifecycle" is a non-goal.

### Adjacent identity stack

- `did:chio` self-certifying Ed25519 plus `did:web`/`did:key`/`did:jwk` interop (well-trodden in `crates/chio-did/`).
- Agent Passport: native JSON-signed bundle, W3C VC v1 compatible (`crates/chio-credentials/`).
- A narrow OID4VP verifier-side bridge under `crates/chio-credentials/src/oid4vp.rs`, paired with a non-goal in `spec/PROTOCOL.md:107-109` against generic OID4VP/SIOP/DIDComm.
- Hybrid PQ signatures (Ed25519 + ML-DSA-65) at `spec/PROTOCOL.md:172-177`.
- Federation via `federated_origin_kernel_id` in delegation receipts.
- A `step_up` outcome already exists in the underwriting decision vocabulary (`spec/PROTOCOL.md:1789`) but it is a credit/budget decision, not an OAuth step-up auth challenge.

### Honest summary

Chio today is **both** a token consumer (introspection, JWT bearer, mTLS, static) **and** a token issuer (narrow, bounded to `chio-governed-rar-v1`). The issuer surface is real but is undersold and underspecified outside the hosted MCP edge. There is no plan-of-record in `docs/` for whether the issuer is a permanent product surface, a transitional bridge, or a fallback for cases where no upstream AS understands governed RAR.

## Phase 2: External Landscape (2025-2026)

### WorkOS AuthKit and multi-hop delegation

WorkOS published "OAuth multi-hop delegation for AI agents" framing in 2025 (workos.com/blog/oauth-multi-hop-delegation-ai-agents). The model: each hop is a distinct OAuth exchange. The orchestrator holds a user-bound token, exchanges it (RFC 8693) for an agent-bound token at the next hop, attaches an actor claim and authorization details, and the downstream resource verifies the actor chain. WorkOS positions itself as the AS that mints these tokens with enterprise SSO (SAML/OIDC/SCIM) on the inbound side and per-agent client identities on the outbound side. Strong on lifecycle, IdP federation, and admin UX.

### Stytch agent-specific auth

Stytch in 2025 launched "Connected Apps" and agent auth primitives positioned around delegated tokens, fine-grained per-tool consent screens, and SDK-level helpers for letting an agent act with user-scoped credentials. The product story is consumer-shaped (user signs in, agent inherits scopes) rather than enterprise-RBAC-shaped. Strong on the user-consent UX, lighter on enterprise SCIM and audit.

### Scalekit agent identity / OBO

Scalekit (2025) is explicitly an "agent identity platform" and ships OAuth on-behalf-of (OBO) flows along with agent registries. They publish per-agent identifiers, per-agent credentials, and OBO token exchange where the upstream user identity is preserved as `act` chain. Audience targets are enterprise B2B integrators.

### Aembit non-human IAM

Aembit (aembit.io/blog/iam-agentic-ai/) positions for non-human identity, workload-to-workload auth, and policy-driven credential brokering. They sit between agent runtimes and downstream APIs, vending short-lived credentials per call with policy attached. Less "AS" and more "credential exchange + access broker."

### Strata identity orchestration

Strata is identity orchestration: route auth events across multiple IdPs without re-platforming. Not an AS itself; a policy-driven router across Okta, Ping, Azure AD, etc. Relevant because Chio's bridge contract has structural overlap (decide-and-route).

### IETF draft on OAuth on-behalf-of for AI agents

`draft-oauth-ai-agents-on-behalf-of-user-00` (ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-00.html) formalizes the OBO actor chain for AI agents over RFC 8693 token exchange, with new `actor_token` semantics that carry agent identity, capability constraints, and user-on-behalf-of claims. Currently `-00`, expected to iterate through 2026. Anyone shipping agent OAuth today is shipping against this draft or a precursor.

### OAuth 2.1 plus RAR (RFC 9396)

OAuth 2.1 (draft) consolidates 6749/6750/7636 and bans implicit and password grants. RFC 9396 (RAR) gives agents a typed `authorization_details` array instead of unstructured space-delimited scopes. The industry is settling on RAR as the right way to express fine-grained per-tool, per-action authorization. Chio's `chio_governed_tool`/`chio_governed_commerce`/`chio_governed_metered_billing` are already RFC 9396-shaped (`oauth.rs:33-35, 512-514`).

### FAPI 2.0

FAPI 2.0 (final, 2025) is the high-assurance profile: mandatory PKCE, sender-constrained tokens (DPoP or mTLS), PAR, audience-restricted access tokens, no shared secrets. Banking and regulated verticals. Chio's hosted edge already meets most of FAPI 2.0's substance (PKCE-required, resource-bound, sender-constrained, JWT access tokens) but does not implement RFC 9126 PAR or claim FAPI conformance.

### MCP authorization spec

MCP's 2025-11-25 authorization spec (modelcontextprotocol.io/specification/2025-11-25/basic/authorization) requires HTTP-transport MCP servers to behave as OAuth-protected resources: serve `/.well-known/oauth-protected-resource`, respond `401 WWW-Authenticate: Bearer resource_metadata=...`, expect clients to discover the AS via the resource metadata, and accept access tokens with `aud` matching the resource. Chio already implements this end of the contract (`oauth.rs:757-768, 982-995`; `http_service.rs:1386, 1413-1422`). Chio also offers a self-hosted AS for callers that have no upstream AS, but the spec encourages MCP servers to *delegate* AS duty to an external provider where possible.

### A2A authorization

A2A 1.0 (Agent2Agent, agent-to-agent task protocol) requires that agent endpoints declare supported authentication schemes in their agent card and use HTTP-level auth headers (Bearer, mTLS, etc.). It does not mandate OAuth specifically but recommends sender-constrained tokens where multi-agent delegation is involved. Less prescriptive than MCP today.

## Phase 3: Recommendation

### Posture: "PDP that triggers step-up, AS of last resort"

Chio's stated identity is "universal security kernel for AI agent tool calls" (`AGENTS.md`). That is fundamentally a PDP role, not an IdP role. The market is converging on a layered model where:

- Enterprise IdPs (WorkOS, Stytch, Okta, Entra) authenticate humans and mint user-on-behalf-of base tokens.
- Agent identity platforms (Scalekit, Aembit) mint per-agent client identities and exchange tokens with actor claims.
- Policy decision points (Chio) evaluate the call against governed RAR and either admit, deny, or signal step-up.
- Resource servers verify the inbound chain.

Chio should plant its flag on the third row. The recommended posture has three concrete commitments:

1. **Default: consumer + verifier.** All hosted-edge surfaces, all sidecar profiles, and all MCP bridges should accept upstream OAuth/OIDC tokens (JWT or introspected) as the primary admission mechanism. Today's `JwtBearer` and `IntrospectionBearer` paths (`oauth.rs:798-817`) are the right foundation. Extend `CallerIdentity` (`crates/chio-http-core/src/identity.rs:8-37`) to carry OAuth-shaped fields natively rather than projecting them on the hosted edge alone.
2. **Surface: PDP with step-up challenge.** When a tool call exceeds the authority of the inbound token (RAR insufficient, intent hash not yet approved, runtime-assurance digest stale, identity assertion missing), return an OAuth-shaped challenge response that names the missing `authorization_details`, the protected resource, and a recommended AS to redirect to. This is the natural extension of the existing underwriting `step_up` outcome (`spec/PROTOCOL.md:1789`). The signal is informational; the actual fresh authorization happens at the customer's chosen AS.
3. **Bounded issuer-of-last-resort.** Keep the existing `LocalAuthorizationServer` (`oauth.rs:22-539`), but reframe and rename it as the **Chio Governed Authorization Bridge**. Its only purpose is to mint tokens scoped to the Chio MCP edge as the protected resource when no upstream AS understands the `chio-governed-rar-v1` profile. It is not an enterprise IdP. It does not implement DCR, refresh tokens, social login, password flows, MFA, SCIM, or session UI beyond the approval page. Tokens it mints have short TTLs and are bound to a single resource.

### Why not pure issuer

The non-goal at `spec/PROTOCOL.md:100` ("automatic SCIM provisioning lifecycle") is the giveaway. Full IdP posture requires SCIM, password reset, MFA enrollment, recovery, social login, admin consoles. WorkOS/Stytch/Scalekit have spent years and engineering on these. Chio building parity is a multi-year detour from the kernel proposition.

### Why not pure consumer

Three reasons. First, the code is already there and has tests (`crates/chio-cli/tests/mcp_auth_server.rs`, hosted-mcp auth_flows tests). Second, the `chio-governed-rar-v1` profile is genuinely novel: no upstream AS currently understands `chio_transaction_context.runtimeAssuranceEvidenceSha256` or attestation-bound `cnf` claims. Until upstream ASs catch up (or Chio publishes the profile and seeds adoption), an issuer-of-last-resort lets customers run governed RAR without forcing them to wait on their existing IdP vendor. Third, MCP's authz spec encourages bring-your-own-AS but accepts self-hosted; Chio can ship the easy path today and migrate to delegated AS over time.

### Sketch: what to build

For the **consumer + step-up** path:

- Promote OAuth fields into `CallerIdentity` in `chio-http-core` (add `oauth: Option<OAuthCaller>` with issuer, scopes, authorization_details, cnf, actor chain).
- Add an OAuth-shaped challenge response builder in `chio-policy` that emits an
  RFC 9470 step-up challenge using `error="insufficient_user_authentication"`
  with authentication-strength parameters such as `acr_values` and `max_age`.
  If Chio also needs RAR context, carry `authorization_details` as a Chio/MCP
  extension, not as an RFC 9470 challenge parameter.
- Implement RFC 9449 JWT DPoP at the HTTP edge (edge verifies HTTP DPoP and synthesizes internal caller context). Keep `chio.dpop_proof.v1` as the internal invocation proof. See `spec/PROTOCOL.md` for the DPoP boundary contract.
- Add a durable replay store for both proof families.
- Track and validate actor-chain claims per `draft-oauth-ai-agents-on-behalf-of-user`. Surface the chain in receipts.

For the **bounded issuer**:

- Rename `LocalAuthorizationServer` to `ChioGovernedAuthorizationBridge` to signal scope.
- Document explicitly in `spec/PROTOCOL.md` that this surface is not an enterprise IdP and lists the things it intentionally does not do.
- Optionally add RFC 9126 PAR to align with FAPI 2.0 substance without claiming the badge.
- Optionally add a minimal `client_credentials` grant gated to deterministic-derivation enterprise subjects, for service-to-service Chio-to-Chio token exchange.
- Do not add: DCR, refresh tokens, social login, password grants, MFA enrollment, SCIM, account recovery, session cookies for human users.

### Where this lands Chio against the market

Chio becomes the policy and receipts layer that customers wire WorkOS or Scalekit *into*, not the thing they pick instead. The `chio-governed-rar-v1` profile becomes a shared vocabulary anyone (WorkOS, Stytch, Okta, internal ASs) can issue against. Chio's edge accepts those tokens, runs policy, signs a receipt, and returns step-up challenges when fresh consent is required. The issuer surface stays as a migration aid and a reference implementation, not a product.

## Open Questions

1. Does the product owner intend `chio-governed-rar-v1` to be public-spec material that other ASs are encouraged to adopt, or is it Chio-private with no incentive for WorkOS/Scalekit to implement?
2. Is the step-up challenge response a Chio-proprietary extension to MCP, a contribution to the MCP authz spec, or an RFC 9470 conformance commitment?
3. Should the bounded issuer get a feature-flag deprecation path (off by default in v3, removable in v4) once upstream ASs adopt governed RAR, or is it a permanent product surface?
4. How does the step-up posture interact with A2A 1.0 agent-to-agent flows where there is no human in the loop and no AS reachable mid-task?
5. Should `CallerIdentity` carry the full actor chain (per `draft-oauth-ai-agents-on-behalf-of-user`) or a hash-only attribution token that the receipt verifier can dereference later? The PROTOCOL non-goal against "synthetic cross-issuer passport scoring" (`spec/PROTOCOL.md:101`) argues for hash-only.
6. Is there appetite to claim FAPI 2.0 conformance in 2026, given the hosted edge already meets most of the substantive requirements?
