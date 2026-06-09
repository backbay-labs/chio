# External Standards Proof Envelope

Date: 2026-06-09

Agent: H

Scope: research and planning only. This draft does not propose code edits. It
maps Chio's current repository assets to external standards and defines the
proof-envelope work needed before Chio can make an honest "Agent Web" interop
claim.

Confidence:

- High for local repository asset inventory because it is based on current
  worktree inspection.
- High for primary-source standards facts that cite current official documents.
- Moderate for external protocol stability because several agent-commerce and
  agent-interaction specifications are active, beta, draft, or versioned by
  dated snapshots.

## Executive Position

The launch story should not claim that Chio is a new universal wire protocol.
That would be weak and probably false. The stronger claim is narrower:

> Chio can be the proof and authorization envelope that travels across MCP,
> A2A, Agent Client Protocol, AG-UI, OpenAPI, x402, AP2, Agentic Commerce
> Protocol, VC, SD-JWT VC, BBS, Sigstore, SLSA, and in-toto surfaces without
> replacing those standards.

That claim is credible only if the proof envelope is explicitly detached from
runtime authority. The signed Chio receipt remains the authority. External
protocol projections are verifiable views, evidence references, or compatibility
bindings. They must not mutate receipt truth, widen capability scope, or turn
visibility into trust activation.

The right product name is not "Chio Agent Web Protocol." The right name is:

`Agent Web Proof Envelope`

The term "proof envelope" is deliberately subordinate. It says Chio carries
proof across the agent web. It does not say Chio owns every peer protocol.

## Current Repository Assets

### Protocol and receipt core

- `spec/PROTOCOL.md:15` defines Chio as a capability-scoped mediation and
  evidence system for agent tool use.
- `spec/PROTOCOL.md:18` to `spec/PROTOCOL.md:24` states that native
  agent-to-kernel protocol, signed receipts, trust-control services, and
  MCP-compatible edges are part of the shipped repository only where the kernel
  owns dispatch and receipt authority.
- `spec/PROTOCOL.md:45` to `spec/PROTOCOL.md:46` already names portable trust
  artifacts for `did:chio`, Chio schema issuance, challenge/response
  presentation, evidence export, and certification.
- `spec/PROTOCOL.md:61` to `spec/PROTOCOL.md:71` scopes wrapped MCP and A2A
  consumption to kernel-backed receipt authority.
- `spec/PROTOCOL.md:105` to `spec/PROTOCOL.md:113` explicitly excludes hosted
  tool mediation and OAuth authorization-server product status until separate
  decisions and tests exist.
- `spec/PROTOCOL.md:680` to `spec/PROTOCOL.md:708` defines `ChioReceipt`,
  including `receipt_kind`, `boundary_class`, `tool_origin`, `actor_chain`,
  optional BBS material, kernel key, algorithm hint, and signature.
- `spec/PROTOCOL.md:712` to `spec/PROTOCOL.md:733` defines content-addressed
  receipt identity and the signed wrapper that binds receipt id, body, and
  optional BBS signature.

### MCP and OAuth assets

- `crates/chio-mcp-adapter/README.md:3` to
  `crates/chio-mcp-adapter/README.md:7` says the adapter wraps existing MCP
  servers so Chio can govern tools, resources, and prompts.
- `crates/chio-mcp-edge/README.md:3` to
  `crates/chio-mcp-edge/README.md:7` says the edge exposes Chio-governed tools
  over MCP transports.
- `crates/chio-mcp-remote/README.md:7` to
  `crates/chio-mcp-remote/README.md:22` describes hosted MCP over HTTP/SSE,
  OAuth 2.0 and DPoP token flows, enterprise federation, rate limiting, admin
  routes, and receipt-bearing kernel dispatch.
- `crates/chio-mcp-remote/README.md:73` to
  `crates/chio-mcp-remote/README.md:76` requires fail-closed rejection before
  MCP session creation when valid bearer or DPoP proof is absent.
- `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:1` to
  `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:6` states the Chio OAuth
  profile is a normative reference only and that hosted OAuth AS product work is
  blocked.
- `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:13` to
  `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:21` maps signed governed
  receipt metadata into a narrow OAuth-family profile rather than minting a
  second mutable authorization document.
- `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:126` to
  `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:138` defines bounded
  sender constraints for DPoP public key, mTLS thumbprint, and attestation hash.
- `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:187` to
  `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md:239` defines
  sender-constrained semantics and fail-closed missing, stale, replayed, or
  mismatched proofs.
- `crates/chio-mcp-remote/src/remote_mcp/oauth.rs:1` to
  `crates/chio-mcp-remote/src/remote_mcp/oauth.rs:20` has request-time access
  token inputs for authorization details, transaction context, and sender
  constraints.
- `crates/chio-mcp-remote/src/remote_mcp/oauth.rs:204` to
  `crates/chio-mcp-remote/src/remote_mcp/oauth.rs:219` supports authorization
  code and token-exchange grants and rejects unsupported grant types.

### A2A assets

- `spec/PROTOCOL.md:2835` to `spec/PROTOCOL.md:2855` documents the shipped A2A
  adapter contract: Agent Card discovery, JSON-RPC and HTTP+JSON bindings,
  send and streaming message, task get, task subscribe, cancel, push-notification
  config, fail-closed auth negotiation, durable task correlation, and partner
  admission policy.
- `spec/PROTOCOL.md:2856` to `spec/PROTOCOL.md:2869` says Chio's
  `metadata.chio.targetSkillId` convention is adapter-local and is not a core
  A2A field.
- `crates/chio-a2a-adapter/README.md:3` to
  `crates/chio-a2a-adapter/README.md:11` describes the A2A-to-Chio adapter as a
  mediation shim for external A2A agents, not a full A2A server.
- `crates/chio-a2a-edge/README.md:7` to
  `crates/chio-a2a-edge/README.md:19` describes the outward A2A server surface,
  Agent Card publication, kernel-routed `message/send`, deferred
  receipt-bearing lifecycle, BridgeFidelity, and non-authoritative passthrough
  helpers.
- `crates/chio-a2a-adapter/src/protocol.rs:1` to
  `crates/chio-a2a-adapter/src/protocol.rs:21` models Agent Cards, security
  schemes, interfaces, capabilities, skills, and documentation URLs.
- `crates/chio-a2a-adapter/src/protocol.rs:61` to
  `crates/chio-a2a-adapter/src/protocol.rs:99` models send, get, subscribe,
  cancel, and metadata-bearing task requests.
- `crates/chio-a2a-adapter/src/auth.rs:129` to
  `crates/chio-a2a-adapter/src/auth.rs:147` requires an outbound
  `HttpEgressContract` for A2A dispatch.

### Agent Client Protocol assets

- `crates/chio-acp-edge/README.md:8` to
  `crates/chio-acp-edge/README.md:22` says the outward ACP server maps Chio tools
  to ACP capabilities, intercepts permission requests, exposes lifecycle
  semantics, routes through the kernel by default, evaluates BridgeFidelity, and
  emits signed Chio receipts on kernel-backed paths.
- `crates/chio-acp-proxy/README.md:9` to
  `crates/chio-acp-proxy/README.md:20` says the proxy spawns an ACP agent,
  forwards JSON-RPC, intercepts permission, file, terminal, and session update
  messages, and can promote observed audit entries downstream.
- `crates/chio-acp-proxy/README.md:47` to
  `crates/chio-acp-proxy/README.md:52` states path traversal and missing
  capability tokens fail closed before the message reaches the agent subprocess.
- `crates/chio-acp-edge/src/types.rs:3` to
  `crates/chio-acp-edge/src/types.rs:19` models ACP capability advertisements
  with id, name, description, category, permission requirement, and bridge
  fidelity.
- `crates/chio-acp-edge/src/types.rs:144` to
  `crates/chio-acp-edge/src/types.rs:160` defines the kernel execution context:
  capability token, agent id, optional DPoP proof, execution nonce, governed
  intent, approval token, and model metadata.

### AG-UI assets

- `crates/chio-ag-ui-proxy/README.md:8` to
  `crates/chio-ag-ui-proxy/README.md:21` says the AG-UI proxy validates
  capability tokens for UI-facing actions and emits signed receipts with event
  type, target UI component, and action classification.
- `crates/chio-ag-ui-proxy/src/event.rs:8` to
  `crates/chio-ag-ui-proxy/src/event.rs:29` models event id, timestamp, agent id,
  session id, event type, target component, classification, and opaque JSON
  payload.
- `crates/chio-ag-ui-proxy/src/event.rs:63` to
  `crates/chio-ag-ui-proxy/src/event.rs:85` defines display, mutate, navigate,
  create, destroy, submit, and alert classifications.
- `crates/chio-ag-ui-proxy/src/event.rs:87` to
  `crates/chio-ag-ui-proxy/src/event.rs:132` validates identity fields and
  classifies mutating versus display-only events.

### OpenAPI assets

- `spec/PROTOCOL.md:135` to `spec/PROTOCOL.md:153` defines HTTP and OpenAPI
  surfaces: HTTP substrate, OpenAPI-to-manifest derivation, reverse proxy, cert
  commands, and deterministic mapping from `HttpReceipt` to `ChioReceipt`.
- `spec/OPENAPI-INTEGRATION.md:20` to `spec/OPENAPI-INTEGRATION.md:32` says
  `chio-openapi` parses OpenAPI 3.0.x and 3.1.x and rejects unsupported
  versions.
- `spec/OPENAPI-INTEGRATION.md:125` to `spec/OPENAPI-INTEGRATION.md:145` maps
  each operation to one `ToolDefinition`.
- `spec/OPENAPI-INTEGRATION.md:173` to `spec/OPENAPI-INTEGRATION.md:240` defines
  the current `x-chio-*` vocabulary: sensitivity, side effects, approval
  required, budget limit, and publish.
- `crates/chio-openapi/README.md:3` to `crates/chio-openapi/README.md:10`
  describes OpenAPI 3.x parsing into Chio `ToolManifest`.
- `crates/chio-openapi-mcp-bridge/README.md:3` to
  `crates/chio-openapi-mcp-bridge/README.md:11` says the bridge presents
  Chio-governed HTTP APIs as MCP tools and routes invocations through the kernel
  before upstream HTTP dispatch.
- `crates/chio-openapi-mcp-bridge/src/dispatch.rs:165` to
  `crates/chio-openapi-mcp-bridge/src/dispatch.rs:203` requires an
  `HttpEgressContract`, enforces response-size checks, and rejects redirect
  responses.

### Cross-protocol assets

- `crates/chio-cross-protocol/README.md:8` to
  `crates/chio-cross-protocol/README.md:34` centralizes shared protocol-family
  enums, target protocol registry, lifecycle contract, BridgeFidelity,
  semantic hints, cross-protocol capability-envelope constants, and the
  orchestrator.
- `docs/standards/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json:7` to
  `docs/standards/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json:13`
  qualifies a signed, fail-closed, intent-aware governance control plane across
  HTTP, MCP, A2A, and ACP while explicitly excluding ecosystem-wide market
  dominance.
- `docs/standards/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json:20` to
  `docs/standards/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json:72`
  names gate conditions for explicit route selection, shared executor registry,
  multi-hop route execution, policy-aware route selection, and signed route
  evidence.
- `scripts/qualify-cross-protocol-runtime.sh:63` to
  `scripts/qualify-cross-protocol-runtime.sh:80` runs the local cross-protocol
  runtime qualification command set.
- `scripts/qualify-cross-protocol-runtime.sh:82` to
  `scripts/qualify-cross-protocol-runtime.sh:131` writes the qualification
  report ceiling and executed command list.

### Payment interop and web3 assets

- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:5` to
  `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:10` states that payment
  interop sits on top of governed dispatch and settlement truth and never
  replaces receipts, approval context, or the official web3 dispatch contract.
- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:14` to
  `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:23` ships bounded projection
  to x402, EIP-3009 digest preparation, Circle nanopayment candidate evaluation,
  and ERC-4337/paymaster compatibility.
- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:43` to
  `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:64` defines fail-closed
  payment posture and non-goals.
- `docs/standards/CHIO_WEB3_PROFILE.md:61` to
  `docs/standards/CHIO_WEB3_PROFILE.md:83` lists official web3 artifacts and
  their local parse boundaries.
- `docs/standards/CHIO_WEB3_PROFILE.md:85` to
  `docs/standards/CHIO_WEB3_PROFILE.md:111` keeps web3 subordinate to
  `did:chio`, signed receipts, local policy activation, durable receipt storage,
  and canonical settlement artifacts.
- `docs/standards/CHIO_WEB3_TRUST_PROFILE.json:1` to
  `docs/standards/CHIO_WEB3_TRUST_PROFILE.json:78` provides a concrete
  `chio.web3-trust-profile.v1` with key-binding certificate, chain scope,
  dispute windows, finality rules, regulated roles, custody boundary note, and
  local policy activation requirement.
- `scripts/qualify-web3-examples.sh:16` to
  `scripts/qualify-web3-examples.sh:59` validates the internet-of-agents web3
  example artifact set, including x402 payment satisfaction and settlement
  packet artifacts.
- `scripts/qualify-web3-examples.sh:61` to
  `scripts/qualify-web3-examples.sh:82` requires x402 payment status to be
  satisfied in the review result.

### Portable trust, VC, SD-JWT, and BBS assets

- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:5` to
  `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:13` defines the standards
  submission draft for portable trust as shipped.
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:17` to
  `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:49` lists `did:chio`,
  passports, verifier policy, challenge/response, OID4VCI, projected
  `application/dc+sd-jwt`, `jwt_vc_json`, OID4VP verifier, public identity,
  evidence export, federation, certification, and runtime attestation evidence.
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:50` to
  `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:58` excludes global trust
  registry, permissionless wallet distribution, generic OID4VP, DIDComm, and
  public-wallet ecosystem compatibility.
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:77` to
  `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:101` defines `did:chio`,
  native passport truth, OID4VCI profile ids, projected portable credential
  formats, JWKS publication, and SD-JWT VC claim disclosure limits.
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:264` to
  `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:330` defines fail-closed
  compatibility rules for unknown schemas, unsupported generic VC profiles,
  portable credential requests, holder binding, generic wallet widening, and
  runtime-attestation import.
- `crates/chio-credentials/README.md:3` to
  `crates/chio-credentials/README.md:10` says native passports remain
  canonically JSON-signed with Ed25519 and that standards-native projection is
  derived from the native passport rather than replacing it.
- `crates/chio-credentials/src/portable_sd_jwt.rs:7` to
  `crates/chio-credentials/src/portable_sd_jwt.rs:17` pins the SD-JWT VC
  configuration id, format, type URL, type metadata path, JWKS path, `typ`, hash
  algorithm, and key id.
- `crates/chio-credentials/src/portable_sd_jwt.rs:113` to
  `crates/chio-credentials/src/portable_sd_jwt.rs:131` defines SD-JWT VC type
  metadata, claim catalog, identity binding, type metadata URL, JWKS URL, always
  disclosed claims, selectively disclosable claims, and status reference kind.
- `crates/chio-credentials/src/portable_jwt_vc.rs:1` to
  `crates/chio-credentials/src/portable_jwt_vc.rs:24` defines the `jwt_vc_json`
  projection and explicitly records `supports_selective_disclosure`.
- `spec/CHIO_SELECTIVE_DISCLOSURE.md:7` to
  `spec/CHIO_SELECTIVE_DISCLOSURE.md:15` says Chio implements a v1 BBS proof
  slice over receipts and workflow receipts while deferring hidden range
  predicates, VC Data Integrity interop, and zkVM proofs.
- `spec/CHIO_SELECTIVE_DISCLOSURE.md:91` to
  `spec/CHIO_SELECTIVE_DISCLOSURE.md:119` pins Chio's BBS surface to
  `bbs-2023`, IRTF CFRG BBS signatures, BLS12-381 suites, and Ed25519 as the
  authoritative receipt signature.
- `spec/CHIO_SELECTIVE_DISCLOSURE.md:142` to
  `spec/CHIO_SELECTIVE_DISCLOSURE.md:188` defines Chio's receipt BBS projection
  table and canonical ordering.
- `spec/CHIO_SELECTIVE_DISCLOSURE.md:190` to
  `spec/CHIO_SELECTIVE_DISCLOSURE.md:221` defines `bbs_projection_version`,
  `bbs_signature`, and binding into the authoritative Ed25519 signature.

### Sigstore, SLSA, in-toto, and bilateral invocation assets

- `spec/PROTOCOL.md:1025` to `spec/PROTOCOL.md:1041` says the Rekor client is a
  real Sigstore Rekor REST client, but Merkle inclusion proof checking remains
  proposed evidence and is not yet implemented.
- `crates/chio-attest-verify/src/sigstore.rs:1` to
  `crates/chio-attest-verify/src/sigstore.rs:23` documents the Sigstore verifier
  surfaces and explicitly says Rekor Merkle inclusion and SET verification are
  incomplete on bundle paths.
- `crates/chio-attest-verify/src/sigstore.rs:47` to
  `crates/chio-attest-verify/src/sigstore.rs:80` embeds Sigstore trusted-root
  material and builds a verifier from it.
- `crates/chio-attest-verify/src/sigstore.rs:122` to
  `crates/chio-attest-verify/src/sigstore.rs:183` verifies detached blob
  signatures against Fulcio identity policy but marks Rekor inclusion false.
- `crates/chio-attest-verify/src/sigstore.rs:186` to
  `crates/chio-attest-verify/src/sigstore.rs:247` verifies Sigstore bundles,
  reapplies identity matching, extracts Rekor metadata, and reports whether
  bundle inclusion was verified.
- `crates/chio-guard-registry/src/pull.rs:10` to
  `crates/chio-guard-registry/src/pull.rs:17` tracks whether a Sigstore bundle
  was caller-provided or discovered as an OCI referrer.
- `crates/chio-guard-registry/src/pull.rs:72` to
  `crates/chio-guard-registry/src/pull.rs:100` pulls or accepts a Sigstore
  bundle, verifies it before cache admission when configured, and records bundle
  source plus verification state.
- `crates/chio-guard-registry/tests/oci_referrer_sigstore.rs:22` to
  `crates/chio-guard-registry/tests/oci_referrer_sigstore.rs:119` tests
  successful OCI referrer bundle discovery, missing referrers, missing referrer
  API, wrong subject, and descriptor mismatch.
- `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:8` to
  `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:19` defines the Chio-owned
  bilateral co-signed invocation predicate and names DSSE, in-toto, and RFC
  8785 as the framing.
- `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:41` to
  `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:61` states the structural gap:
  existing in-toto predicates are artifact-centric and do not encode two
  organizations independently committing to the same canonical invocation under
  separate policies.
- `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:74` to
  `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:96` reserves a proposed in-toto URI
  and the current Chio fallback predicate `chio.bilateral-cosign-invocation.v1`.
- `crates/chio-federation/src/bilateral.rs:1` to
  `crates/chio-federation/src/bilateral.rs:32` defines bilateral cross-kernel
  runtime co-signing and states that new canonical verification uses the
  bilateral DSSE verifier while older dual-signed receipts remain compatibility
  artifacts.
- `crates/chio-federation/src/bilateral.rs:139` to
  `crates/chio-federation/src/bilateral.rs:198` requires pinned peer ids, both
  signatures, valid base receipt signature, and Org B kernel key consistency.
- `crates/chio-federation/src/bilateral_dsse.rs:1` to
  `crates/chio-federation/src/bilateral_dsse.rs:32` defines the DSSE wire format
  and distinguishes the legacy signature-slice profile from the strict Chio
  bilateral invocation predicate.
- `crates/chio-federation/src/bilateral_dsse.rs:49` to
  `crates/chio-federation/src/bilateral_dsse.rs:83` pins DSSE payload type,
  predicate types, in-toto Statement type, PAE prefix, and receipt subject name
  prefix.
- `crates/chio-federation/src/bilateral_dsse.rs:131` to
  `crates/chio-federation/src/bilateral_dsse.rs:205` models Statement subject,
  kernel identities, bilateral predicate fields, tool args hash, capability
  lease ref, policy summary, governance receipt ref, consistency anchor, and
  treaty binding.

## External Primary Facts

### MCP

Primary source: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>

- The current MCP authorization spec is dated 2025-11-25 and says MCP servers
  can support HTTP authorization with OAuth 2.1 plus additional MCP-specific
  requirements.
- MCP servers implementing authorization must implement OAuth 2.0 Protected
  Resource Metadata.
- Protected resource metadata must include an `authorization_servers` field with
  one or more authorization-server issuer URLs.
- MCP clients are encouraged to derive the resource metadata URL by inserting
  `/.well-known/oauth-protected-resource` before the path component of the MCP
  server URL.
- MCP servers that accept OAuth bearer tokens must validate tokens according to
  OAuth protected-resource requirements.
- The 2025-11-25 revision says client ID metadata documents are recommended,
  while dynamic client registration is optional. This matters because older MCP
  auth guidance and older local assumptions can drift.

Primary source: <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>

- The 2025-06-18 MCP authorization revision is still useful as change context
  because it explicitly notes Resource Indicators from RFC 8707. Chio's hosted
  profile should treat `resource` binding as mandatory for its own security
  posture even if MCP clients vary by revision.

### A2A

Primary source: <https://a2a-protocol.org/dev/specification/>

- A2A defines communication between agents, not tool invocation inside one
  process.
- A2A servers must make an Agent Card available to clients. The card describes
  skills, service endpoint URL, and authentication requirements.
- A2A uses JSON-RPC 2.0 over HTTP(S) as the primary transport.
- The spec defines task lifecycle concepts, messages, artifacts, streaming, and
  push notifications.
- A2A security scheme objects are modeled after OpenAPI security schemes.
- A2A does not make Chio-style signed receipts native. Chio proof material must
  be a namespaced extension, side artifact, task artifact, or metadata field,
  not a claim about core A2A semantics.

### Agent Client Protocol

Primary source: <https://agentclientprotocol.com/protocol/overview>

- Agent Client Protocol is a JSON-RPC protocol for communication between code
  editors and agent servers.
- The protocol currently documents v1.
- Clients and agents initialize sessions with a protocol version and filesystem
  capabilities.
- The protocol defines request-permission, file, terminal, and session-update
  flows that align with Chio's ACP proxy interception surface.
- Custom `_meta` fields exist in the protocol family, but Chio must treat
  proof-envelope carriage through `_meta` as a Chio extension rather than a
  portable ACP truth claim unless the external protocol accepts it.

### AG-UI

Primary sources:

- <https://docs.ag-ui.com/concepts/events>
- <https://docs.ag-ui.com/concepts/messages>
- <https://docs.ag-ui.com/concepts/tools>
- <https://docs.ag-ui.com/concepts/state>

External facts:

- AG-UI is an event-driven protocol for agent-to-frontend applications.
- Event streams include lifecycle, text/message, tool-call, state-management,
  and special events.
- AG-UI has an explicit start-content-end event pattern for streamed operations.
- AG-UI tools describe frontend-executable functions the agent can call.
- AG-UI state is updated through events, including patch-style state deltas.
- Chio's AG-UI proof projection should bind event id, run/session id, event
  type, target component, classification, and state/tool-call hashes. It should
  not claim AG-UI has native Chio receipt semantics.

### OpenAPI

Primary source: <https://spec.openapis.org/oas/v3.1.1.html>

- OpenAPI 3.1.1 is the official specification for describing HTTP APIs.
- Paths and operations are the natural mapping point from HTTP routes to Chio
  tool definitions.
- Security schemes are descriptive API metadata. They do not replace Chio
  capability checks, guard evaluation, or signed receipt truth.
- Chio's `x-chio-*` vocabulary is an OpenAPI vendor-extension layer. External
  OpenAPI validators should ignore unknown `x-*` fields, but Chio-specific
  proof-envelope semantics still require Chio-side validation.

### x402

Primary sources:

- <https://www.x402.org/>
- <https://docs.x402.org/core-concepts/facilitator>
- <https://github.com/x402-foundation/x402>

External facts:

- x402 is an open protocol around HTTP 402 Payment Required.
- The common flow is: client request, server returns payment requirements,
  client prepares and signs payment, server verifies through a facilitator, and
  the server then serves the paid resource.
- Facilitators verify and settle payments so resource servers do not have to
  directly implement every chain or settlement detail.
- x402 is payment-state interop, not tool-authorization proof. A Chio projection
  must bind payment requirements to the governed settlement dispatch and receipt
  digest without leaking full policy or guard evidence to the facilitator.

### AP2

Primary sources:

- <https://github.com/google-agentic-commerce/AP2>
- <https://raw.githubusercontent.com/google-agentic-commerce/AP2/main/README.md>
- <https://github.com/google-agentic-commerce/AP2/blob/main/python/src/ap2/types.py>

External facts:

- AP2 is Google's Agent Payments Protocol repository.
- AP2 centers authorization around mandates rather than merely a payment token.
- The repository models intent mandates, cart mandates, and payment mandates.
- The Python reference types show mandate claims that include hashes, expiry,
  merchant, amount, currency, and supported payment methods.
- Chio can bind `receipt_id`, `receipt_digest`, governed intent hash, approval
  token id, and settlement dispatch hash into AP2 mandate references, but should
  not claim AP2 native support until an AP2-conformant fixture validates the
  exact extension point.

### Agentic Commerce Protocol

Primary sources:

- <https://agenticcommerce.dev/>
- <https://github.com/agentic-commerce-protocol/agentic-commerce-protocol>
- <https://raw.githubusercontent.com/agentic-commerce-protocol/agentic-commerce-protocol/main/spec/2026-04-17/openapi/openapi.agentic_checkout.yaml>

External facts:

- Agentic Commerce Protocol is an open standard for agent-assisted commerce
  checkout.
- The public repository contains a dated OpenAPI snapshot for the checkout
  surface.
- The protocol is commerce-checkout interop, not a generic tool authorization
  envelope.
- Chio's projection should bind checkout/order/payment artifacts to governed
  intent and receipt digests. It should not overload "ACP" because this acronym
  collides with Agent Client Protocol and historical AGNTCY ACP.

### VC 2.0

Primary source: <https://www.w3.org/TR/vc-data-model-2.0/>

- Verifiable Credentials Data Model 2.0 is a W3C Recommendation dated
  2025-05-15.
- VC 2.0 defines an ecosystem data model for interoperable claims and
  verifiable presentations.
- The data model is not itself Chio's native receipt format.
- A Chio VC projection must either use a conforming VC representation or say
  clearly that it is a Chio portable credential derived from native Chio
  passports.

### BBS Data Integrity

Primary source: <https://www.w3.org/TR/vc-di-bbs/>

- Data Integrity BBS Cryptosuites v1.0 is a W3C Candidate Recommendation Draft,
  current as of 2026-04-28.
- The cryptosuite defines BBS-based selective disclosure in the W3C Data
  Integrity and VC ecosystem.
- Chio's BBS receipt projection is not the same thing as W3C Data Integrity BBS.
  Chio signs canonical JSON receipt projections and keeps Ed25519 as the
  authoritative receipt signature. W3C BBS works through Data Integrity proof
  processing and RDF/JSON-LD style mechanisms.
- A launch claim must say "BBS-backed Chio receipt selective disclosure" unless
  and until Chio implements a conforming VC Data Integrity BBS projection.

### SD-JWT VC

Primary sources:

- <https://www.rfc-editor.org/rfc/rfc9901.html>
- <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc>

External facts:

- RFC 9901 defines Selective Disclosure for JWTs.
- SD-JWT VC remains tracked through the IETF OAuth working group draft at the
  cited datatracker page. The current Chio draft should treat it as a moving
  standards dependency unless a final RFC has been published after this draft
  was written.
- The media type `application/dc+sd-jwt` appears in the SD-JWT VC draft family.
- Chio's `application/dc+sd-jwt` passport profile aligns with the SD-JWT VC
  direction but is only a Chio passport projection. It is not generic SD-JWT VC
  interoperability for arbitrary credential types.

### Sigstore

Primary sources:

- <https://docs.sigstore.dev/>
- <https://docs.sigstore.dev/logging/overview/>
- <https://docs.sigstore.dev/cosign/verifying/>
- <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>

External facts:

- Sigstore combines signing, certificate identity, and transparency-log
  evidence.
- Fulcio issues short-lived signing certificates backed by identity providers.
- Rekor is Sigstore's transparency log.
- Verifying a Sigstore artifact is stronger when it validates the artifact
  signature, certificate identity, trust root, and transparency-log inclusion.
- Chio currently has real Sigstore verification paths, but Rekor Merkle
  inclusion and SET verification gaps must be closed before Chio can claim full
  transparency-log verification.

### SLSA, in-toto, and DSSE

Primary sources:

- <https://slsa.dev/spec/v1.1/provenance>
- <https://in-toto.io/Statement/v1>
- <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>

External facts:

- SLSA provenance v1.1 is a build-provenance predicate. It is not a runtime
  tool-invocation predicate.
- in-toto Statement v1 binds one or more subjects to a predicate type and
  predicate body.
- DSSE signs opaque payload bytes using pre-authentication encoding. It supports
  detached, envelope-level signatures over payloads such as in-toto Statements.
- Chio's bilateral invocation predicate is correctly positioned as a custom
  runtime predicate proposal, not as SLSA provenance.

## Exact Gaps

1. **No single Agent Web Proof Envelope schema exists.**
   Chio has receipts, bilateral DSSE, BBS receipt projections, portable
   credentials, OAuth profile projection, web3 payment interop artifacts, and
   cross-protocol route evidence. It does not yet have one detached,
   standards-facing envelope that says "this external protocol object is bound
   to this Chio receipt and these verification rules."

2. **Acronym collision is severe.**
   `ACP` currently means at least Agent Client Protocol, Agentic Commerce
   Protocol, and historical AGNTCY Agent Connect Protocol. The repo already
   contains `docs/research/protocol-strategy/08-agntcy-acp-bridge-spec.md`,
   which warns that AGNTCY ACP is superseded and should not be implemented as
   `chio-acp-*`. Launch copy must never say bare "ACP."

3. **MCP OAuth product posture is internally split.**
   The repo has hosted MCP OAuth and DPoP code, but the standards-facing OAuth
   profile says hosted OAuth AS product work remains blocked. The launch claim
   must say "bounded hosted MCP auth profile" or "normative projection," not
   "Chio is an OAuth authorization server product."

4. **MCP auth changed after older drafts.**
   The current 2025-11-25 MCP auth spec recommends client ID metadata documents
   and makes dynamic client registration optional. Chio implementation and docs
   must track current MCP auth, not freeze around older dynamic-registration
   assumptions.

5. **A2A version naming needs a hard re-check before public claim.**
   `spec/PROTOCOL.md` says `A2A v1.0.0`. The public A2A site currently exposes
   a development specification. Do not publish a versioned A2A conformance claim
   until the exact current stable A2A version and Agent Card schema snapshot are
   pinned in a fixture.

6. **BBS is not W3C Data Integrity interop yet.**
   Chio's BBS path is a receipt projection. W3C BBS Data Integrity is a VC/Data
   Integrity cryptosuite. The repo itself says VC Data Integrity interop is
   deferred.

7. **SD-JWT VC is still bounded to Chio passport projection.**
   `application/dc+sd-jwt` support is a derived Chio passport credential. It is
   not arbitrary SD-JWT VC support, not generic wallet support, and not generic
   OID4VP compatibility.

8. **Sigstore transparency verification is incomplete.**
   Chio verifies keyless and detached Sigstore shapes but documents that Rekor
   Merkle inclusion and SET verification are not complete. The proof envelope
   must carry `rekor_inclusion_verified=false` honestly until that is fixed.

9. **OpenAPI proof-envelope extensions are not currently parsed.**
   Chio parses existing `x-chio-*` extensions, but there is no
   `x-chio-proof-envelope`, `x-chio-receipt-binding`, or
   `x-chio-evidence-profile` parser contract.

10. **Payment interop has privacy and authority traps.**
    x402 facilitators, AP2 mandates, and checkout protocols do not need full
    Chio guard evidence. The envelope must bind hashes and references, not leak
    policy internals or treat payment success as authorization success.

11. **External protocol-specific carriage is unproven.**
    A proof envelope can be carried as metadata, side artifact, URL, header,
    resource, task artifact, custom event, or checkout extension depending on
    the protocol. The repo does not yet have fixture-backed validation for each
    carrier.

12. **SLSA is the wrong runtime claim.**
    Chio should use in-toto Statement plus a Chio runtime predicate for
    invocations. SLSA provenance can cover build and release artifacts, not the
    runtime tool call itself.

## Agent Web Proof Envelope

### Definition

`Agent Web Proof Envelope` is a detached, signed or digest-bound projection
envelope that binds an external protocol object to one or more Chio receipts.
It does not replace `ChioReceipt`, `ChioReceipt` signatures, capability tokens,
guard outcomes, policy hashes, or local trust activation.

Proposed schema id:

`chio.agent-web-proof-envelope.v1`

Minimum fields:

| Field | Meaning |
| --- | --- |
| `schema` | Fixed string `chio.agent-web-proof-envelope.v1`. |
| `envelope_id` | Content-addressed id over canonical JSON without signatures. |
| `created_at_unix_ms` | Envelope creation timestamp. |
| `issuer` | `did:chio` or HTTPS issuer that signs or publishes the envelope. |
| `source_receipts` | One or more receipt references: receipt id, body SHA-256, kernel key, signature algorithm, receipt kind, boundary class. |
| `external_subject` | Protocol object being projected: MCP tool call, A2A task, ACP permission request, AG-UI event, OpenAPI operation, x402 payment requirement, AP2 mandate, checkout session, VC, in-toto subject. |
| `capability_binding` | Capability id or lease ref, issuer, subject, scope digest, expiry, and matched grant index when available. |
| `policy_binding` | Policy hash, guard summary hash, decision, denial reason, or advisory boundary. |
| `actor_chain` | Signed actor attribution chain copied or hashed from receipt truth. |
| `route_binding` | Protocol family, edge id, target protocol, BridgeFidelity, route-selection evidence digest. |
| `payment_binding` | Optional governed settlement dispatch id, payment requirement hash, mandate hash, checkout/order hash, and payment status reference. |
| `selective_disclosure` | Optional BBS projection id, disclosed fields, proof package hash, nonce binding, and verifier context hash. |
| `supply_chain_binding` | Optional in-toto Statement digest, DSSE envelope digest, Sigstore bundle digest, SLSA provenance reference. |
| `verification_profile` | Named verification rules and fail-closed conditions for the recipient. |
| `non_authority_notice` | Fixed statement that the envelope is evidence and cannot widen Chio runtime authority. |
| `signatures` | Optional DSSE signatures or Chio-native detached signatures over canonical envelope bytes. |

### Invariants

1. A verifier must verify the source Chio receipt before trusting any projection.
2. The external subject digest must match the protocol object actually observed.
3. Proof-envelope success must never override a Chio denial receipt.
4. Missing source receipt, stale capability, unknown schema, unknown projection,
   unsupported protocol family, mismatched hash, or untrusted issuer fails closed.
5. Payment success can satisfy payment precondition only. It cannot imply tool
   authorization.
6. Registry, directory, marketplace, listing, or Agent Card visibility cannot
   imply local trust activation.
7. Selective disclosure proofs must be nonce-bound to verifier context.
8. Protocol-native metadata fields are carriers only. The source of truth is
   still the Chio receipt plus the envelope signature.

## Projections Into Each Protocol

### MCP projection

Projection target:

- Chio-owned MCP-compatible surfaces in `chio-mcp-edge`, `chio-mcp-adapter`, and
  `chio-mcp-remote`.

Subject binding:

- Hash `method`, tool/resource/prompt id, input arguments, `MCP-Session-Id` when
  present, authenticated resource, caller subject, and Chio receipt id.

Carrier:

- Prefer a Chio-namespaced MCP resource URI such as
  `chio://receipts/{receipt_id}/proof-envelope`.
- For tool outputs, allow `structuredContent.chioProofEnvelopeRef` or a
  Chio-owned metadata field only when the Chio edge controls the MCP response.
- Do not claim MCP-native proof semantics.

Minimum verification:

- Validate MCP bearer token and resource binding.
- Validate DPoP if the grant requires it.
- Validate Chio receipt and envelope hash.
- Confirm `receipt_kind=mediated_decision` before claiming preventive
  authorization.

Gap:

- Need current MCP 2025-11-25 auth fixture covering protected resource metadata,
  authorization-server metadata, resource binding, bearer validation, DPoP, and
  proof-envelope resource retrieval.

### A2A projection

Projection target:

- `chio-a2a-adapter` for consuming external A2A agents.
- `chio-a2a-edge` for exposing Chio tools as A2A skills.

Subject binding:

- Hash Agent Card URL, skill id, interface URL, `message_id`, `context_id`,
  `task_id`, message parts, metadata Chio skill selector, task lifecycle state,
  and Chio receipt id.

Carrier:

- `message.metadata.chioProofEnvelopeRef`.
- Task artifact containing `application/vnd.chio.proof-envelope+json`.
- Agent Card extension advertising the proof-envelope profile only after an A2A
  conformance fixture proves the extension is tolerated.

Minimum verification:

- Verify Agent Card source, declared security scheme, partner-admission policy,
  outbound egress contract, message hash, task correlation, receipt, and
  envelope.

Gap:

- Need A2A fixture for Agent Card extension, message metadata, task artifact
  carriage, streaming lifecycle, cancel lifecycle, and push notification config
  without weakening A2A semantics.

### Agent Client Protocol projection

Projection target:

- `chio-acp-edge` outward Agent Client Protocol surface.
- `chio-acp-proxy` editor-to-agent subprocess proxy.

Subject binding:

- Hash JSON-RPC method, id, params, capability id, permission request, file path,
  terminal command, agent id, model metadata, and Chio receipt id.

Carrier:

- `session/request_permission` response metadata when the edge controls the
  response.
- `session/update` observed tool-call event metadata for audit-only flows.
- Sidecar proof-envelope file or URL for large evidence.

Minimum verification:

- Validate capability token, path scope, terminal guard decision, DPoP if
  required, execution nonce if present, and receipt signature.

Gap:

- Need a protocol-level fixture distinguishing signed receipt paths from
  unsigned audit entries. Launch copy must not imply every ACP proxy observation
  is automatically a signed receipt.

### AG-UI projection

Projection target:

- `chio-ag-ui-proxy`.

Subject binding:

- Hash `event_id`, timestamp, agent id, session id, event type, target component,
  classification, and payload digest.

Carrier:

- Custom AG-UI event with type `chio.proof_envelope_ref`.
- Side-channel receipt URL or digest in event payload only after the target UI
  agrees to display or store it.

Minimum verification:

- Validate event boundary, event ordering, mutating classification, capability
  token, receipt signature, and payload digest.

Gap:

- Need streaming order fixtures for start-content-end sequences and state patch
  deltas so the envelope binds to the event sequence, not only one event.

### OpenAPI projection

Projection target:

- `chio-openapi`, `chio-openapi-mcp-bridge`, `chio api protect`, and HTTP
  substrate receipts.

Subject binding:

- Hash OpenAPI document id, server URL, method, path template, operation id,
  parameters, request body digest, response digest, and Chio receipt id.

Carrier:

- New Chio vendor extension:
  `x-chio-proof-envelope-profile: chio.agent-web-proof-envelope.v1`.
- Optional response header:
  `Chio-Proof-Envelope: sha256=<digest>; url=<receipt-or-envelope-url>`.
- Optional response body field only for APIs that already expose Chio metadata.

Minimum verification:

- Validate OpenAPI 3.0.x or 3.1.x parse, route binding, path parameter
  declaration, egress contract, no redirect follow, response-size bound,
  receipt, and envelope.

Gap:

- Need parser and fixture support for `x-chio-proof-envelope-profile` and
  `x-chio-receipt-binding`, or the launch claim must say proof envelopes are
  sidecar artifacts only.

### x402 projection

Projection target:

- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md` and x402 requirement
  artifacts.

Subject binding:

- Hash x402 payment requirement object, resource URL, facilitator URL, accepted
  token list, chain/network id, amount, payment status, governed settlement
  dispatch id, and Chio receipt id.

Carrier:

- Chio field inside a local x402 requirement artifact when the spec and
  facilitator tolerate extension fields.
- Otherwise adjacent proof URL or digest, never embedded guard details.

Minimum verification:

- Validate Chio settlement dispatch first.
- Verify x402 payment requirement hash and payment satisfaction status.
- Verify payment amount, token, chain, resource, and facilitator match local
  policy.
- Verify payment success does not override receipt denial.

Gap:

- Need a facilitator-compatible fixture showing exactly where Chio hashes can
  live without leaking policy evidence or breaking x402 clients.

### AP2 projection

Projection target:

- AP2 mandates.

Subject binding:

- Bind Chio governed intent hash to an AP2 intent mandate.
- Bind Chio cart/order hash and receipt digest to an AP2 cart mandate.
- Bind Chio settlement dispatch hash and approval token id to an AP2 payment
  mandate.

Carrier:

- AP2 mandate extension, transaction data, or separate evidence URL after
  confirming the reference implementation accepts the field.

Minimum verification:

- Verify AP2 mandate signatures or presentations according to AP2.
- Verify mandate hashes match the Chio governed intent and receipt.
- Verify expiry, amount, currency, merchant, payment method, and Chio settlement
  policy.

Gap:

- Need AP2-conformant sample vectors. Do not rely on a free-form Chio JSON blob
  inside AP2 until the reference implementation accepts it.

### Agentic Commerce Protocol projection

Projection target:

- Agentic Commerce Protocol checkout OpenAPI snapshot.

Subject binding:

- Hash checkout session, merchant id, order id, payment token reference,
  shipping/tax terms if present, governed intent hash, approval token id,
  settlement dispatch id, and Chio receipt id.

Carrier:

- Order metadata or extension field if protocol-compliant.
- Out-of-band proof-envelope URL when the checkout API does not define a safe
  extension field.

Minimum verification:

- Verify checkout object hash, payment reference, amount, merchant, order state,
  and Chio receipt.
- Keep checkout success separate from authorization success.

Gap:

- Need a dated Agentic Commerce Protocol snapshot fixture. The protocol uses
  dated OpenAPI snapshots, so Chio must pin the date and schema digest.

### VC 2.0 projection

Projection target:

- Chio portable trust profile and external verifier-facing credentials.

Subject binding:

- Bind Chio subject DID, passport id, issuer DIDs, credential count, Merkle roots,
  lifecycle state, and optional runtime attestation digest.

Carrier:

- Native Chio passport.
- `jwt_vc_json` Chio passport projection.
- `application/dc+sd-jwt` Chio passport projection.
- Do not claim generic VC 2.0 support unless a conforming VC transformation is
  built and tested.

Minimum verification:

- Verify native passport first.
- Verify projected credential signature.
- Verify holder binding.
- Verify lifecycle state and freshness.
- Reject unsupported credential types and generic wallet widening.

Gap:

- Need a public transformation note from native Chio passport to any VC 2.0
  conforming representation, plus a verifier fixture against an external VC
  implementation.

### BBS projection

Projection target:

- Chio receipt selective disclosure.

Subject binding:

- Bind BBS projection version, BBS public key, BBS signature, source receipt id,
  disclosed fields, verifier nonce, and Chio receipt signature.

Carrier:

- Chio selective-disclosure proof package.
- Optional proof-envelope reference in external protocol metadata.
- Not W3C Data Integrity BBS unless a separate Data Integrity projection exists.

Minimum verification:

- Verify Chio receipt Ed25519 signature.
- Verify BBS signature over the canonical Chio projection.
- Verify reveal set, projection version, nonce, and verifier context.

Gap:

- Hidden predicates and W3C VC Data Integrity interop are deferred.

### Sigstore projection

Projection target:

- Guard registry, attest verification, build/release artifacts, and optional
  proof-envelope anchoring.

Subject binding:

- Hash artifact bytes, Sigstore bundle, Fulcio identity, OIDC issuer, Rekor log
  index, inclusion proof status, source receipt id, and envelope digest.

Carrier:

- Sigstore bundle or OCI referrer for guard artifacts.
- DSSE envelope with in-toto Statement for proof packages.

Minimum verification:

- Verify artifact digest.
- Verify signing certificate and identity policy.
- Verify signature.
- Verify Rekor inclusion and SET when claiming transparency-log verification.

Gap:

- Rekor Merkle and SET verification must be implemented or the envelope must
  carry `rekor_inclusion_verified=false`.

### SLSA and in-toto projection

Projection target:

- Build/release provenance for Chio artifacts.
- Runtime invocation predicate via Chio-owned in-toto predicate proposal.

Subject binding:

- For build artifacts, use SLSA provenance.
- For runtime invocation, use in-toto Statement with
  `predicateType=chio.bilateral-cosign-invocation.v1` or the proposed in-toto
  canonical URI after WG adoption.

Carrier:

- DSSE envelope over an in-toto Statement.

Minimum verification:

- Verify DSSE PAE signature.
- Verify Statement subject digest.
- Verify predicate type.
- Verify both kernels' policy summaries, capability lease refs, peer pins, and
  source receipt.

Gap:

- Standards adoption of the bilateral runtime predicate is not complete. Chio
  must keep its namespaced predicate until accepted.

## Conformance Matrix

| Surface | External source | Current Chio asset | Envelope projection | Minimum honest claim | Blocking gates |
| --- | --- | --- | --- | --- | --- |
| MCP auth and tools | MCP 2025-11-25 auth spec | `chio-mcp-remote`, `chio-mcp-edge`, OAuth profile | Resource or metadata ref to `chio.agent-web-proof-envelope.v1` | Chio-governed MCP-compatible proof envelope where Chio owns dispatch | Current MCP auth fixture, resource metadata, DPoP, receipt verification |
| A2A | A2A dev spec | `chio-a2a-adapter`, `chio-a2a-edge` | Agent Card extension, task artifact, or message metadata | Chio can attach proof refs to A2A skills and tasks | Pin A2A version, Agent Card schema, task lifecycle vectors |
| Agent Client Protocol | Agent Client Protocol v1 | `chio-acp-edge`, `chio-acp-proxy` | Permission metadata, session update, sidecar ref | Chio can receipt or audit ACP permission, file, terminal, and tool-call flows | Separate signed receipt path from unsigned audit path |
| AG-UI | AG-UI event docs | `chio-ag-ui-proxy` | Custom proof-envelope event or payload ref | Chio can receipt mutating UI events and bind streams to receipts | Sequence fixture for streaming, tool calls, and state patches |
| OpenAPI | OpenAPI 3.1.1 | `chio-openapi`, `chio-openapi-mcp-bridge` | `x-chio-proof-envelope-profile` and response header | Chio can bind HTTP operation execution to proof envelopes | Extension parser, sidecar/header fixture, response digest tests |
| x402 | x402 docs and repo | Payment interop profile, examples | Payment requirement hash plus receipt/dispatch ref | Chio can prove a payment requirement is tied to governed dispatch | Facilitator-compatible extension or sidecar fixture |
| AP2 | Google AP2 repo | Payment interop profile only | Mandate hash and Chio receipt/intent/dispatch refs | Chio can map proof refs to AP2 mandates after fixtures | AP2 sample vectors and extension acceptance |
| Agentic Commerce Protocol | ACP commerce repo and OpenAPI snapshot | Payment interop profile only | Checkout/order/payment hash plus receipt refs | Chio can bind checkout states to governed receipts | Dated snapshot fixture, extension or sidecar rule |
| VC 2.0 | W3C VC 2.0 Recommendation | Portable trust profile, passport projections | Chio passport-derived VC or SD-JWT VC | Chio supports bounded passport projection, not generic VC | External verifier fixture and transformation doc |
| BBS Data Integrity | W3C BBS CRD | Chio selective disclosure | Chio BBS proof ref, not W3C DI proof | Chio supports BBS-backed receipt disclosure | W3C DI projection and hidden predicate work deferred |
| SD-JWT VC | RFC 9901 plus SD-JWT VC draft | `portable_sd_jwt.rs` | `application/dc+sd-jwt` passport credential | Chio supports a bounded passport SD-JWT VC profile | Track draft finalization, external verifier fixture |
| Sigstore | Sigstore docs | `chio-attest-verify`, guard registry referrers | Sigstore bundle digest and identity proof | Chio can verify signatures and identities, with honest Rekor flag | Merkle inclusion and SET verification for full claim |
| SLSA | SLSA provenance v1.1 | Release/build docs and attest verifier | Build provenance for artifacts | Chio can use SLSA for build provenance only | Keep runtime invocation out of SLSA claim |
| in-toto and DSSE | in-toto Statement v1, DSSE protocol | Bilateral DSSE predicate | DSSE Statement with Chio runtime predicate | Chio can express bilateral runtime invocation as custom predicate | WG adoption or namespaced fallback and verifier vectors |

## Taxonomy Naming Risks

### Do not use bare `ACP`

Use:

- `ACP-Client` for Agent Client Protocol.
- `ACP-Commerce` for Agentic Commerce Protocol.
- `AGNTCY-ACP` only for historical Agent Connect Protocol references.

Never use:

- `Chio ACP bridge` without qualifier.
- `ACP-compatible` without naming which ACP.
- `Agent Commerce Protocol` when the source says `Agentic Commerce Protocol`.

### Do not call Chio a replacement for MCP or A2A

Use:

- `MCP-compatible proof envelope`.
- `A2A skill proof projection`.
- `kernel-owned dispatch path`.

Avoid:

- `Chio replaces MCP`.
- `Chio is the A2A security layer`.
- `universal agent protocol`.

### Do not call Chio BBS "W3C BBS Data Integrity" yet

Use:

- `BBS-backed Chio receipt selective disclosure`.

Avoid:

- `W3C Data Integrity BBS compatible`.
- `VC BBS proof`.

### Do not call SD-JWT VC support generic

Use:

- `Chio passport SD-JWT VC projection`.

Avoid:

- `EUDI wallet compatible`.
- `generic SD-JWT VC verifier`.
- `generic OID4VP wallet support`.

### Do not call payment success authorization

Use:

- `payment precondition satisfied`.
- `governed settlement dispatch bound to receipt`.

Avoid:

- `x402 authorized the tool`.
- `AP2 authorized the capability`.
- `checkout success equals Chio allow`.

### Do not use SLSA for runtime invocation

Use:

- `SLSA provenance for build artifacts`.
- `in-toto Chio bilateral invocation predicate for runtime calls`.

Avoid:

- `SLSA runtime invocation proof`.

## Tests and Gates

### Existing gates to keep

- `scripts/qualify-cross-protocol-runtime.sh`
- `scripts/qualify-universal-control-plane.sh`
- `scripts/qualify-web3-examples.sh`
- `scripts/qualify-web3-runtime.sh`
- `scripts/qualify-web3-e2e.sh`
- `scripts/qualify-web3-ops-controls.sh`
- `cargo test -p chio-cross-protocol`
- `cargo test -p chio-mcp-edge`
- `cargo test -p chio-mcp-remote`
- `cargo test -p chio-a2a-adapter`
- `cargo test -p chio-a2a-edge`
- `cargo test -p chio-acp-edge`
- `cargo test -p chio-acp-proxy`
- `cargo test -p chio-ag-ui-proxy`
- `cargo test -p chio-openapi`
- `cargo test -p chio-openapi-mcp-bridge`
- `cargo test -p chio-credentials`
- `cargo test -p chio-selective-disclosure`
- `cargo test -p chio-attest-verify`
- `cargo test -p chio-guard-registry`

### New proof-envelope gates

1. `check-agent-web-proof-envelope-schema`
   - Validate `chio.agent-web-proof-envelope.v1` JSON Schema.
   - Reject unknown `schema`.
   - Reject missing receipt ref.
   - Reject missing external subject hash.
   - Reject unknown protocol family.
   - Reject payment-only envelope with no governed receipt.

2. `check-agent-web-proof-envelope-canonical-id`
   - Canonicalize using RFC 8785.
   - Compute envelope id.
   - Recompute after signature insertion.
   - Assert signatures do not alter id preimage.

3. `check-mcp-proof-envelope-fixtures`
   - MCP protected resource metadata fixture.
   - Authorization server metadata fixture.
   - DPoP required and missing-DPoP negative tests.
   - Proof-envelope resource read.
   - Tool result metadata reference.

4. `check-a2a-proof-envelope-fixtures`
   - Agent Card extension fixture.
   - `message/send` metadata fixture.
   - streaming task artifact fixture.
   - cancel and get lifecycle fixture.
   - unsupported metadata negative fixture.

5. `check-acp-client-proof-envelope-fixtures`
   - `session/request_permission` allow and deny.
   - `fs/read_text_file` and `fs/write_text_file` path scope.
   - `terminal/create` command guard.
   - unsigned session update audit path.
   - signed receipt path.

6. `check-ag-ui-proof-envelope-fixtures`
   - text streaming start-content-end sequence.
   - tool-call sequence.
   - state patch sequence.
   - mutating UI event denial.
   - payload hash mismatch.

7. `check-openapi-proof-envelope-fixtures`
   - OpenAPI 3.0 and 3.1 parse.
   - `x-chio-proof-envelope-profile` parse.
   - response header proof ref.
   - redirect rejection.
   - response digest mismatch.

8. `check-payment-proof-envelope-fixtures`
   - x402 requirement hash binding.
   - x402 payment satisfaction binding.
   - AP2 mandate hash binding.
   - Agentic Commerce Protocol checkout snapshot binding.
   - payment success with Chio denial negative test.

9. `check-vc-proof-envelope-fixtures`
   - Native passport verification.
   - `application/dc+sd-jwt` verification.
   - `jwt_vc_json` verification.
   - unsupported VC type rejection.
   - stale lifecycle rejection.

10. `check-bbs-proof-envelope-fixtures`
    - Ed25519 receipt verification first.
    - BBS reveal set verification.
    - nonce binding.
    - unknown projection rejection.
    - hidden predicate rejection until implemented.

11. `check-sigstore-proof-envelope-fixtures`
    - detached signature verification.
    - keyless bundle verification.
    - OCI referrer bundle discovery.
    - wrong subject rejection.
    - Rekor inclusion flag accuracy.
    - full Rekor Merkle and SET verification once implemented.

12. `check-intoto-bilateral-proof-envelope-fixtures`
    - DSSE PAE verification.
    - in-toto Statement subject digest.
    - strict Chio predicate acceptance.
    - legacy signature-slice rejection as strict conformance.
    - one-signature-only rejection.
    - mismatched peer pins rejection.

### Launch blocking gate

Do not claim `Agent Web Proof Envelope` externally until:

- every row in the conformance matrix has at least one positive fixture;
- every row has at least one negative fixture;
- protocol version, schema digest, or dated snapshot is pinned;
- external-carrier wording is checked against primary source docs;
- Sigstore transparency wording is honest about Rekor inclusion state;
- taxonomy copy has no bare `ACP`;
- marketing copy says `proof envelope`, not replacement protocol.

## Phased Plan

### Phase 0: Freeze names and claim ceiling

Deliverables:

- Adopt `Agent Web Proof Envelope`.
- Ban bare `ACP`.
- Define launch claim ceiling:
  `Chio projects signed receipt proof into external protocols where Chio owns or
  can verify the dispatch and evidence boundary.`
- Define non-claim:
  `Chio is not replacing MCP, A2A, OpenAPI, x402, AP2, Agentic Commerce
  Protocol, VC, Sigstore, SLSA, or in-toto.`

Exit gate:

- One glossary document.
- One copy lint that fails on bare `ACP`, `universal agent protocol`, and
  `SLSA runtime invocation`.

### Phase 1: Specify the envelope

Deliverables:

- `chio.agent-web-proof-envelope.v1` JSON Schema.
- Canonicalization and id rules.
- Verification profile registry.
- Per-protocol projection profiles.
- Threat model covering authority confusion, payment confusion, metadata
  stripping, replay, registry visibility inflation, and proof leakage.

Exit gate:

- Schema validation.
- Canonical id vectors.
- Unknown schema and mismatched digest negative tests.

### Phase 2: Bind existing Chio assets

Deliverables:

- Receipt ref profile.
- Bilateral DSSE ref profile.
- BBS proof ref profile.
- OAuth governed transaction profile ref.
- Web3 settlement dispatch/payment ref profile.
- Sigstore ref profile with honest Rekor status.

Exit gate:

- Existing local fixtures pass.
- Existing cross-protocol and web3 qualification scripts pass.
- No code path treats proof envelope as capability token or OAuth token.

### Phase 3: Protocol carrier fixtures

Deliverables:

- MCP resource and metadata fixtures.
- A2A Agent Card, message metadata, and task artifact fixtures.
- Agent Client Protocol permission, file, terminal, and session-update fixtures.
- AG-UI event stream fixtures.
- OpenAPI extension/header fixtures.
- x402/AP2/Agentic Commerce Protocol payment/checkout fixtures.
- VC/SD-JWT VC/BBS verification fixtures.
- Sigstore/in-toto/DSSE package fixtures.

Exit gate:

- Positive and negative fixtures for every protocol row.
- Dated external schema snapshots checked into standards fixture inventory.
- Primary-source links in each fixture README.

### Phase 4: Standards outreach package

Deliverables:

- in-toto WG issue or proposal for bilateral co-signed runtime invocation.
- MCP issue or discussion for receipt/proof metadata best practice if needed.
- A2A extension discussion or compatibility note if Agent Card extension is used.
- AG-UI custom event compatibility note.
- OpenAPI vendor extension note.
- Payment-interop notes for x402, AP2, and Agentic Commerce Protocol.
- W3C/IETF note that Chio passport SD-JWT VC is bounded and not generic wallet
  compatibility.

Exit gate:

- Public issue links or written maintainer feedback where feasible.
- If maintainers reject a carrier, Chio uses sidecar refs only and documents it.

### Phase 5: Launch qualification

Deliverables:

- `CHIO_AGENT_WEB_PROOF_ENVELOPE_QUALIFICATION_MATRIX.json`.
- `CHIO_AGENT_WEB_PROOF_ENVELOPE_RUNBOOK.md`.
- `CHIO_AGENT_WEB_PROOF_ENVELOPE_PARTNER_PROOF.md`.
- Artifact bundle with SHA256SUMS and logs.

Exit gate:

- All protocol rows green.
- All taxonomy lints green.
- All local gates green.
- Hosted CI green or explicitly documented as informational if user direction
  says not to wait.
- Final public copy reviewed against the exact claim ceiling.

## Top Recommendations

1. **Lead with proof envelope, not protocol replacement.**
   The strongest standards posture is interoperability by projection. The
   weakest posture is pretending Chio owns the wire standards.

2. **Make `Agent Web Proof Envelope` a detached signed artifact with source
   receipt refs.**
   Do not embed authority inside MCP/A2A/ACP/AG-UI/OpenAPI/payment metadata.
   Metadata is only a carrier.

3. **Fix taxonomy before implementation.**
   The bare acronym `ACP` will corrupt the launch story. Use `ACP-Client`,
   `ACP-Commerce`, and `AGNTCY-ACP`.

4. **Close or honestly flag Rekor inclusion.**
   Sigstore is a strong trust story only if Chio either verifies Rekor Merkle
   inclusion/SET or labels the status false in every envelope.

5. **Do not overclaim VC, BBS, or SD-JWT.**
   Current Chio support is bounded passport projection and Chio receipt
   selective disclosure. W3C VC Data Integrity BBS and generic SD-JWT VC wallet
   interop are later work.

## Source Links Used

- MCP authorization 2025-11-25:
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- MCP authorization 2025-06-18:
  <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- A2A specification:
  <https://a2a-protocol.org/dev/specification/>
- Agent Client Protocol:
  <https://agentclientprotocol.com/protocol/overview>
- AG-UI events:
  <https://docs.ag-ui.com/concepts/events>
- AG-UI messages:
  <https://docs.ag-ui.com/concepts/messages>
- AG-UI tools:
  <https://docs.ag-ui.com/concepts/tools>
- AG-UI state:
  <https://docs.ag-ui.com/concepts/state>
- OpenAPI 3.1.1:
  <https://spec.openapis.org/oas/v3.1.1.html>
- x402:
  <https://www.x402.org/>
- x402 facilitator docs:
  <https://docs.x402.org/core-concepts/facilitator>
- x402 repository:
  <https://github.com/x402-foundation/x402>
- Google AP2:
  <https://github.com/google-agentic-commerce/AP2>
- AP2 README:
  <https://raw.githubusercontent.com/google-agentic-commerce/AP2/main/README.md>
- AP2 Python types:
  <https://github.com/google-agentic-commerce/AP2/blob/main/python/src/ap2/types.py>
- Agentic Commerce Protocol:
  <https://agenticcommerce.dev/>
- Agentic Commerce Protocol repository:
  <https://github.com/agentic-commerce-protocol/agentic-commerce-protocol>
- Agentic Commerce Protocol checkout OpenAPI snapshot:
  <https://raw.githubusercontent.com/agentic-commerce-protocol/agentic-commerce-protocol/main/spec/2026-04-17/openapi/openapi.agentic_checkout.yaml>
- W3C Verifiable Credentials Data Model 2.0:
  <https://www.w3.org/TR/vc-data-model-2.0/>
- W3C Data Integrity BBS Cryptosuites v1.0:
  <https://www.w3.org/TR/vc-di-bbs/>
- RFC 9901 SD-JWT:
  <https://www.rfc-editor.org/rfc/rfc9901.html>
- SD-JWT VC IETF draft:
  <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc>
- Sigstore docs:
  <https://docs.sigstore.dev/>
- Sigstore Rekor overview:
  <https://docs.sigstore.dev/logging/overview/>
- Sigstore cosign verifying:
  <https://docs.sigstore.dev/cosign/verifying/>
- Fulcio OID info:
  <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>
- SLSA provenance v1.1:
  <https://slsa.dev/spec/v1.1/provenance>
- in-toto Statement v1:
  <https://in-toto.io/Statement/v1>
- DSSE protocol:
  <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>
