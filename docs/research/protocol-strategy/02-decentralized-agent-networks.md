# Decentralized Agent Networks: Chio Integration Strategy

Status: draft, May 2026. Supersedes the earlier "reject as out-of-scope" memo.

> **Erratum:** AGNTCY ACP was archived on 2026-04-11. The "build `chio-bridge-acp` first" framing in sections 2 and 5 below is obsolete; only the consume-only `DirectoryProvider` seam survives. See [17-agntcy-revisited.md](17-agntcy-revisited.md). Additionally per the bridge review: the `chio-bridge-*` prefix is not a workspace convention (existing pattern is `-edge` / `-adapter` / `-proxy`), so even had ACP survived, the crate would be `superseded AGNTCY ACP adapter name`, not `chio-bridge-acp`. The body of this doc is preserved as historical context.

## TL;DR

This historical memo has been superseded by docs 17 and 18. The surviving
direction is consume-only, operator-pinned directory data that never becomes
capability scope. AGNTCY ACP bridge work, SLIM, Agora, live directory import,
and below-L7 mediation remain deferred. The kernel keeps its closed-world view
and refuses to widen local trust from directory assertions.

## 1. NANDA

NANDA (Networked AI Agents in Decentralized Architecture, MIT Media Lab,
Prof. Ramesh Raskar) frames itself as "DNS for agents": a lean index that
resolves to dynamic, cryptographically verifiable AgentFacts records, with
multi-endpoint routing, capability assertions, and sub-second revocation
([projectnanda.org](https://projectnanda.org),
[arXiv:2507.14263](https://arxiv.org/abs/2507.14263)). The deployed surface
today is largely a documentation hub plus a directory listing roughly
1,000 agents ([projnanda/projnanda GitHub](https://github.com/projnanda/projnanda),
[The New Stack overview](https://thenewstack.io/how-mits-project-nanda-aims-to-decentralize-ai-agents/)).
The project itself calls the current stage "Phase 1: Foundations" and the
ecosystem analysis paper ([arXiv:2508.03095](https://arxiv.org/pdf/2508.03095))
treats NANDA as one architectural option among several rather than a fielded
system.

- Surface to mediate. None of NANDA's discovery surface is request/response
  in the Chio sense. The mediatable surface is downstream: once NANDA has
  resolved an AgentFacts record to a concrete endpoint speaking MCP, A2A,
  ACP, or HTTP, Chio's existing bridges handle the actual tool call. The
  "Chio surface" for NANDA is a `DirectoryProvider` (see cross-cutting
  section), not a `ToolServerConnection`.
- Identity bridging. AgentFacts are cryptographically signed records with
  endpoint and capability assertions ([arXiv:2507.14263](https://arxiv.org/abs/2507.14263)).
  Map them to `did:web` when the AgentFacts publisher controls a domain
  (the typical NANDA pattern, mirroring DNS-rooted issuance), and to
  `did:key` when only a raw key is present. Populate `CallerIdentity.subject`
  with the NANDA agent identifier and `tenant` with the NANDA namespace.
  The NANDA-asserted capability strings stay as advisory metadata. They
  never become Chio capability scopes, since those are signed by Chio
  authorities.
- Non-goal boundary. Chio does not run a NANDA index node, does not
  participate in peer gossip, does not auto-register a directory entry,
  does not honor NANDA capability assertions as local grants, and does not
  resolve unknown identifiers on the hot path. The directory is consulted
  out-of-band, an operator pins the subset they care about, and the kernel
  keeps its closed-world view. This aligns with the current protocol
  non-goals on permissionless identity discovery.
- Receipt semantics. The receipt covers the local kernel's verdict on a
  resolved peer call. The AgentFacts record hash and the NANDA index
  fingerprint go into receipt metadata as provenance, the same way a
  `did:web` resolution snapshot would. The receipt does not attest to
  anything about the NANDA index itself.
- Bridge sketch. New crate `chio-directory-nanda`. Pulls AgentFacts via
  the NANDA index HTTP API, validates the embedded signatures, caches the
  records, and exposes a `DirectoryProvider` impl. MVP scope: read-only
  consumer, no publishing, no gossip, no CRDT update participation. Key
  dependencies: `reqwest`, `serde_json`, `ed25519-dalek` (and `did-web`
  resolver from existing `chio-identity`).
- Risk. Index supply-chain compromise (mass swap of endpoint URLs in
  records) is mitigated because AgentFacts are individually signed and
  Chio resolves only operator-allowlisted identifiers. The bigger risk
  is policy drift if operators are tempted to auto-import NANDA capability
  hints as grants. The bridge MUST NOT expose a path from NANDA strings
  into the capability path.

## 2. AGNTCY (SLIM, OASF, ACP)

AGNTCY is the Cisco-Outshift-founded, Linux-Foundation-donated open-source
agent stack ([docs.agntcy.org](https://docs.agntcy.org/)). It splits into
three pieces relevant here.

ACP (Agent Connect Protocol) is OpenAPI-described REST: POST to invoke,
GET to poll status, with SSE streaming, fully specified at
[spec.acp.agntcy.org](https://spec.acp.agntcy.org/) and
[github.com/agntcy/acp-spec](https://github.com/agntcy/acp-spec). Note: the
acp-spec repository was archived on April 11, 2026, with the work
continuing under the broader docs umbrella, signaling consolidation rather
than abandonment. This is the protocol Chio should bridge.

SLIM (Secure Low-Latency Interactive Messaging) is a custom message bus
with mTLS, MLS group encryption, pub/sub plus request/reply plus streaming
patterns, and a SLIMRPC layer for protobuf RPC similar to gRPC over HTTP/2
([github.com/agntcy/slim](https://github.com/agntcy/slim),
[IETF draft-mpsb-agntcy-slim-01](https://datatracker.ietf.org/doc/draft-mpsb-agntcy-slim/),
[docs.agntcy.org/slim/slim-rpc](https://docs.agntcy.org/slim/slim-rpc/)).
It is a transport, not a tool protocol. SLIM is pre-1.0 (release candidates
at v1.4.0-rc.x).

OASF is a schema framework for agent records, OCI-based, supporting A2A and
MCP descriptors. It is a directory schema, not a wire protocol.

Production data point: Webex's Agent Central Service ships AGNTCY directory
and identity components for MCP server registration and verifiable
credentials ([Webex developer blog](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps)).
SLIM and ACP are not called out as in production there.

- Surface to mediate. ACP. Its `POST /runs`, status `GET`, and SSE event
  stream map directly to `ToolServerConnection::invoke` and
  `invoke_stream` (chio-kernel/src/runtime.rs:255). The ACP "agent" is
  the tool server, an ACP "run" is one tool call, and ACP run inputs and
  outputs are JSON, which lines up with `serde_json::Value` arguments
  and outputs. SLIM is mediated only when it carries ACP, A2A, or MCP
  bodies, and only at the application-frame level. The kernel never sees
  raw SLIM packets.
- Identity bridging. ACP authentication is whatever the OpenAPI security
  schemes declare (bearer, mTLS). The kernel maps these into
  `CallerIdentity.auth_method` exactly as the HTTP substrate bridge
  already does (chio-http-core/src/identity.rs:44). Where AGNTCY identity
  service issues verifiable credentials, the VC subject is mapped to
  `did:web` when domain-anchored or `did:jwk` when raw-key. The AGNTCY
  agent ID populates `CallerIdentity.agent_id`.
- Non-goal boundary. Chio does not implement OASF publishing, does not
  speak SLIM as a peer (only as a wrapped transport when an operator
  configures it), and does not honor AGNTCY identity credentials as
  delegation issuers without an operator-installed trust anchor. The
  AGNTCY directory is consumed through the same `DirectoryProvider`
  abstraction as NANDA.
- Receipt semantics. Standard Chio receipt covering one ACP run.
  Provenance fields record the ACP server URL, the AGNTCY-asserted
  identity (if present and verified), and the SLIM endpoint id if SLIM
  was the transport. Group membership and pub/sub fan-out, if any, stay
  inside SLIM and are not part of the signed receipt: the receipt covers
  the kernel's verdict on a specific bilateral call.
- Historical bridge sketch. This is superseded and must not be ticketed.
  The archived sketch used two crates. `chio-bridge-acp` implements
  `ToolServerConnection` over the published OpenAPI: generate a client
  from `spec.acp.agntcy.org`, drive runs, fold SSE into
  `ToolServerStreamResult`. MVP wraps a single ACP server URL with bearer
  or mTLS auth. `chio-transport-slim` is optional and shipped later: a
  thin layer that lets the ACP client speak over SLIM instead of HTTP/2.
  Key dependencies: generated OpenAPI client, `reqwest`, `tokio-stream`
  for SSE, and (later) the SLIM Rust client from the agntcy/slim repo.
- Risk. ACP has no built-in capability or signed-decision surface, so a
  raw ACP deployment lets agents accept tool calls without an
  intermediary like Chio. That is the whole reason to bridge it. The
  bridge MUST refuse to forward without a Chio capability, even when ACP
  itself is happy. SLIM's group/pub-sub patterns are a fan-out hazard:
  if the kernel ever finds itself terminating a SLIM channel directly,
  it must reject multi-recipient frames and pub/sub deliveries that
  cannot be reduced to one mediated tool call.

## 3. Agora

Agora ([agoraprotocol.org](https://agoraprotocol.org),
[arXiv:2410.11905](https://arxiv.org/abs/2410.11905)) is a research
meta-protocol: agents speak natural language to negotiate a "routine"
(a Protocol Document, "PD", a plain-text spec hashed with SHA1), then
switch to that routine for repeat interactions. The 2025 draft Proposed
Standard ([agoraprotocol.org/docs/protocol/specification](https://agoraprotocol.org/docs/protocol/specification))
is a "lightweight JSON-based framework for two-party exchanges (client
and server)" over HTTPS POST, with a `protocolHash` field selecting an
active PD and an optional `/wellknown` listing supported hashes. The
demo network of 100 agents is described in the paper and the
[paper-demo repository](https://github.com/agora-protocol/paper-demo);
production deployments are not claimed. Authentication is explicitly
out of scope in the spec.

- Surface to mediate. Once a routine is negotiated and pinned to a
  `protocolHash`, the wire is a normal HTTPS POST with a JSON body that
  conforms to the PD. That call is request/response shaped and fits
  `ToolServerConnection::invoke`. The negotiation phase itself
  (free-form natural-language exchange) is not mediatable by Chio in a
  meaningful way and should run outside the kernel boundary.
- Identity bridging. Agora has no native identity, by design. The bridge
  layers identity from below: if the HTTPS endpoint authenticates with
  bearer or mTLS, that maps to `CallerIdentity.auth_method` exactly as
  in the HTTP substrate. If the operator pins a `did:web` for the Agora
  peer, that becomes the `CallerIdentity.subject`. The PD hash goes into
  receipt metadata.
- Non-goal boundary. Chio does not negotiate PDs, does not host the
  routine LLM, and does not interpret natural-language frames. The
  bridge accepts only calls that present a `protocolHash` matching an
  operator-allowlisted PD. Free-form Agora traffic is rejected at the
  edge.
- Receipt semantics. The receipt covers one routine invocation. The
  bound PD hash and the peer endpoint identity go into the receipt as
  provenance, so an auditor can later resolve which routine and which
  peer was in scope. The receipt does not attest that the PD itself is
  safe; that judgment lives in the operator's allowlist.
- Historical bridge sketch. Single crate `chio-bridge-agora`, research-track, not
  shipped to v1. MVP: one `ToolServerConnection` per allowlisted PD,
  treating the PD's request schema as the tool input schema. The PD
  becomes effectively an OpenAPI-flavored manifest for one tool. Key
  dependencies: `reqwest`, a small PD parser, the existing canonical
  JSON utilities.
- Risk. The PD is just a text file. A malicious peer can rotate to a
  new PD hash that looks identical but encodes different semantics. The
  bridge MUST verify the PD's SHA1 (Agora's chosen identifier, which is
  itself a concern: SHA1 collision resistance is broken, so consider
  layering a SHA-256 of the PD inside Chio's allowlist), and treat any
  unrecognized hash as a hard deny. Without this discipline, "negotiated"
  routines become a polymorphic-tool attack surface.

## 4. Cross-Cutting: A `DirectoryProvider` Trait

Two of the three integrations (NANDA, AGNTCY) and parts of the third
(Agora well-known endpoints) are fundamentally "consume a directory of
peers, never widen trust." That argues for a single seam.

Proposed trait, sketched, in `chio-directory`:

```text
trait DirectoryProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn lookup(&self, id: &str) -> Result<DirectoryRecord, DirError>;
    async fn allowlisted(&self) -> Vec<DirectoryRecord>;
}

struct DirectoryRecord {
    canonical_id: String,        // did:web / did:key / did:chio
    endpoints: Vec<EndpointHint>,
    advisory_capabilities: Vec<String>, // never used as Chio scope
    signed_blob: Vec<u8>,        // upstream-signed record, for provenance
    upstream_signer: String,     // identifier of the directory
}
```

The operator configures one or more `DirectoryProvider`s. The kernel
consults them at bridge wire-up time, not on the hot path. Resolution
results feed `CallerIdentity` and bridge endpoint configuration, and the
signed blob plus directory name go into receipt provenance. Critically,
`advisory_capabilities` is structurally separate from
`CapabilityToken::scope`; a future refactor must not collapse them. This
keeps the v2 non-goal on "permissionless public identity discovery that
widens local trust" (PROTOCOL.md:106) load-bearing.

A second cross-cutting note: SLIM-style alternative transports should
plug in at the same layer as the existing HTTP/UDS transports under
`ToolServerConnection`, not at the bridge layer. Treat SLIM as the
moral equivalent of "mTLS over UDS" with a different framing. That
keeps the bridge implementations transport-agnostic.

## 5. Historical Phased Rollout (superseded)

The rollout below is archived research, not an implementation plan. The
accepted current plan defers AGNTCY ACP bridge work and keeps only static,
operator-pinned directory consumption in scope after the receipt/read-boundary
foundation is merged.

Phase 1 (superseded): ACP bridge.
- Superseded AGNTCY ACP bridge sketch using the archived acp-spec OpenAPI.
- `DirectoryProvider` trait introduced with an `acp-static` impl that
  reads an operator-curated list of ACP endpoints.
- No SLIM, no NANDA. HTTP only.
- Reasoning: ACP is OpenAPI over HTTP, has a concrete spec, and Webex
  already operates the surrounding directory/identity bits, so
  there's a real downstream consumer.

Phase 2 (superseded): NANDA consumption.
- `chio-directory-nanda` as a `DirectoryProvider`.
- Read-only AgentFacts ingestion with operator allowlists.
- Wire NANDA-resolved endpoints to existing MCP/A2A/ACP bridges.
- Reasoning: NANDA is positioning to become the cross-vendor directory,
  but the actual code is still in Phase 1 Foundations per the project
  itself ([projectnanda.org](https://projectnanda.org)); ship the
  consumer in time for the Apr 2026 NANDA Summit ecosystem, defer any
  Chio-side publishing indefinitely.

Phase 3 (v4 candidate): SLIM transport plug-in.
- `chio-transport-slim` once the SLIM IETF draft stabilizes past
  `draft-mpsb-agntcy-slim` and the upstream Rust client hits 1.0.
- Only the unary request/reply pattern is exposed to bridges; pub/sub
  and streaming-group patterns stay below the bridge.

Defer: Agora. Do not build `chio-bridge-agora` in the current protocol
foundation. Revisit only after Agora demonstrates production deployments,
adopts an identity story, and the receipt/read-boundary foundation is merged.

Hard non-goals across phases: no NANDA index participation, no SLIM
group/pub-sub termination at the kernel, no Agora PD negotiation inside
the kernel, no auto-import of any upstream "capability" string into
Chio's signed capability scope.

## Appendix: Citation Map

- NANDA project page: [projectnanda.org](https://projectnanda.org)
- NANDA index paper: [arXiv:2507.14263](https://arxiv.org/abs/2507.14263)
- NANDA repo (docs hub): [github.com/projnanda/projnanda](https://github.com/projnanda/projnanda)
- New Stack overview: [thenewstack.io](https://thenewstack.io/how-mits-project-nanda-aims-to-decentralize-ai-agents/)
- Registry survey paper: [arXiv:2508.03095](https://arxiv.org/pdf/2508.03095)
- AGNTCY docs: [docs.agntcy.org](https://docs.agntcy.org/)
- ACP spec: [spec.acp.agntcy.org](https://spec.acp.agntcy.org/),
  [github.com/agntcy/acp-spec](https://github.com/agntcy/acp-spec) (archived 2026-04-11)
- SLIM repo: [github.com/agntcy/slim](https://github.com/agntcy/slim)
- SLIM IETF draft: [datatracker.ietf.org/doc/draft-mpsb-agntcy-slim](https://datatracker.ietf.org/doc/draft-mpsb-agntcy-slim/)
- SLIMRPC docs: [docs.agntcy.org/slim/slim-rpc](https://docs.agntcy.org/slim/slim-rpc/)
- Webex AGNTCY integration: [developer.webex.com blog](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps)
- Agora homepage: [agoraprotocol.org](https://agoraprotocol.org)
- Agora paper: [arXiv:2410.11905](https://arxiv.org/abs/2410.11905)
- Agora spec: [agoraprotocol.org/docs/protocol/specification](https://agoraprotocol.org/docs/protocol/specification)
- Agora demo repo: [github.com/agora-protocol/paper-demo](https://github.com/agora-protocol/paper-demo)
