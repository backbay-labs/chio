# Competitive Landscape: Agent Protocols, Payment Rails, and Security

**Last updated:** 2026-03-21
**Scope:** Protocols, payment mechanisms, identity standards, and infrastructure
competing in the agent capability/security space.

---

## 1. Agent Communication Protocols

### Google A2A (Agent-to-Agent)

**What it does.** Task routing protocol between agents. Agents publish Agent
Cards (JSON metadata describing capabilities). Tasks flow through a
request/response lifecycle with streaming support. Donated to the Linux
Foundation in June 2025, gaining broad vendor adoption (150+ launch partners).
Reached v1.0 with JWS-signed Agent Cards (RFC 7515).

| Dimension | Assessment |
|-----------|------------|
| Identity | Agent Cards are JWS-signed (RFC 7515) as of v1.0, providing cryptographic identity for card publishers. Discovery is DNS/HTTP-based. |
| Capability delegation | None. Any agent that discovers another's Agent Card can send it tasks. No scoped authorization tokens. |
| Budget/spending | Not addressed. No invocation limits, cost ceilings, or economic primitives. |
| Receipts/proof | None. Task state transitions are observable but not cryptographically attested. No signed audit trail. |
| Revocation | None at protocol level. Revoking an agent's access requires removing its Agent Card from discovery or firewall-level blocking. |
| Cross-org trust | Relies on transport-layer TLS and application-level API keys. No delegation chains or federated trust model. |

**Bottom line.** A2A v1.0 added signed Agent Cards, giving it a cryptographic
identity layer for card publishers. However, it still has no scoped
authorization tokens, no capability delegation, and no mechanism to constrain
what a discovered agent can do beyond transport-layer controls.

### MCP (Model Context Protocol, Anthropic)

**What it does.** Standardizes how LLMs call tools. Defines tool schemas,
resources, prompts, and sampling. Transport over stdio or HTTP+SSE. Broad
adoption across AI tooling (Cursor, Windsurf, Claude Desktop). Adding
OpenTelemetry-based logging as of early 2026.

| Dimension | Assessment |
|-----------|------------|
| Identity | Partial. Server identity was originally implicit (whoever is on the other end of the stdio pipe or HTTP endpoint). OAuth 2.1 support added in 2026 spec revision provides authenticated identity for HTTP transports, but stdio transport remains unauthenticated. |
| Capability delegation | None. All tools a server exposes are available to the connected client. No scoped tokens, no per-tool authorization. |
| Budget/spending | Not addressed. No invocation caps, bandwidth limits, or cost tracking. |
| Receipts/proof | None. OTel logging provides observability but not cryptographic attestation. Logs are mutable infrastructure, not signed proof. |
| Revocation | Not applicable -- no capabilities to revoke. Disconnecting the transport is the only mechanism. |
| Cross-org trust | Not addressed. Each client-server pair is a point-to-point connection. No multi-hop delegation or federated trust. |

**Bottom line.** MCP is a tool-calling wire format, not a security protocol. It
explicitly defers authorization to the application layer. The OTel additions
provide telemetry, not proof. A compromised MCP server has full access to
whatever the host process can do.

### ANP (Agent Network Protocol, W3C Community Group)

**What it does.** DID-based agent identity and communication. Agents resolve
each other via DID Documents, establish authenticated channels, and exchange
messages. Strongest identity layer among agent protocols. Backed by the W3C
Agent Network Protocol Community Group.

| Dimension | Assessment |
|-----------|------------|
| Identity | Strong. DID-based with multiple verification methods. Agents have cryptographic identifiers resolvable to public keys. |
| Capability delegation | Minimal. DID Auth establishes identity, but there is no scoped capability token model. Authorization is left to application logic. |
| Budget/spending | None. No economic primitives, no invocation budgets, no cost attestation. |
| Receipts/proof | None. Authentication events can be logged but the protocol does not define signed receipts or an append-only audit trail. |
| Revocation | DID Document updates can rotate keys, but there is no capability-level revocation or cascade semantics. |
| Cross-org trust | DID federation provides cross-org identity resolution. Trust decisions are still application-specific. |

**Bottom line.** ANP has the best identity story outside of Chio, but stops at
"who are you?" and never reaches "what are you allowed to do?" or "prove what
you did."

### Microsoft Agent Framework (AutoGen / Semantic Kernel / Azure AI Agent Service)

**What it does.** Orchestration framework for multi-agent systems. AutoGen
provides a conversation-based programming model. Semantic Kernel integrates
with Azure services. Azure AI Agent Service is the managed runtime. Tightly
coupled to Azure identity (Entra ID) and Azure OpenAI.

| Dimension | Assessment |
|-----------|------------|
| Identity | Azure Entra ID (formerly AAD). Strong within Azure, not portable. |
| Capability delegation | None at protocol level. Azure RBAC governs resource access, not tool-level capability. |
| Budget/spending | Azure cost management at the infrastructure level. No protocol-level budget tokens. |
| Receipts/proof | Azure Monitor / Application Insights logging. Infrastructure-level observability, not cryptographic attestation. |
| Revocation | Azure RBAC policy changes. Not real-time, not capability-scoped. |
| Cross-org trust | Azure B2B / Entra External ID. Federated identity but no capability delegation across organizations. |

**Bottom line.** Enterprise-grade within Azure's walled garden. No portable
protocol semantics. Moving to another cloud or on-prem deployment means
rebuilding the security model from scratch.

### OpenAI Agents SDK

**What it does.** Lightweight Python SDK for building multi-agent workflows.
Agents, handoffs (passing control between agents), guardrails (input/output
validation), and tracing. Designed for rapid prototyping of agentic
applications.

| Dimension | Assessment |
|-----------|------------|
| Identity | None. Agents are Python objects with a name string. No cryptographic identity. |
| Capability delegation | Handoffs pass conversation context but not scoped authority. No capability tokens. |
| Budget/spending | None. |
| Receipts/proof | Tracing via the OpenAI dashboard. Application-level logs, not signed attestations. |
| Revocation | Not applicable. |
| Cross-org trust | Not addressed. Single-process SDK. |

**Bottom line.** A developer convenience library, not a protocol. No security
semantics whatsoever.

### CrewAI / LangGraph

**What they do.** Workflow orchestration frameworks for multi-agent systems.
CrewAI provides role-based agent definitions with sequential/parallel task
execution. LangGraph models agent workflows as state machines with
persistence and human-in-the-loop support.

| Dimension | Assessment |
|-----------|------------|
| Identity | None. Agents are configuration objects. |
| Capability delegation | None. Agents access whatever tools the developer wires in. |
| Budget/spending | None at protocol level. LangGraph Cloud has usage-based pricing but no protocol-level budgets. |
| Receipts/proof | LangSmith tracing (LangGraph). Application-level observability. |
| Revocation | Not applicable. |
| Cross-org trust | Not addressed. |

**Bottom line.** Workflow engines, not protocols. They define how agents
coordinate, not how agents are authorized or audited.

---

## 2. Agent Payment Protocols

### Stripe Agent Commerce

**What it does.** Stripe's agent commerce stack consists of two distinct
products. ACP-Commerce (Agentic Commerce Protocol/Suite) provides Agent Checkout -- a
hosted payment flow where an agent can present a checkout session to a user --
along with Shared Payment Tokens (a user authorizes a spending scope, and the
agent presents the token at checkout). MPP (Machine Payments Protocol,
announced Q1 2026) is a separate product enabling agents to pay other agents
directly without human-in-the-loop checkout.

| Dimension | Assessment |
|-----------|------------|
| Identity | Stripe Connect account identity. Agents are API consumers, not cryptographically identified principals. |
| Capability delegation | Shared Payment Tokens scope spending (amount, merchant category, time window). Closest to capability tokens in the payment space, but limited to financial transactions. |
| Budget/spending | Strong within Stripe's domain: spending limits, merchant restrictions, time bounds on Shared Payment Tokens. |
| Receipts/proof | Stripe Sigma / webhook events. Financial transaction records, not tool-call attestations. No signed proof of what the agent *did* with the payment. |
| Revocation | Token expiry and Stripe Dashboard revocation. No cascade semantics. |
| Cross-org trust | Stripe Connect handles multi-party settlements. Trust is Stripe-mediated, not protocol-native. |

**Gap.** Stripe can prove "agent paid $X to merchant Y" but cannot prove
"agent used tool Z with arguments W under policy P, and the result was R."
There is no connection between the payment authorization and the tool
invocation that triggered it.

### Google Agent Payments v2 (AP2)

**What it does.** Google's agent payment protocol (extensions to Google Pay
for agent contexts). Introduces Intent Mandates: user-approved spending
authorizations that agents present to merchants. Value Delivery Chains (VDC)
track multi-hop value flow from user intent to final settlement.

| Dimension | Assessment |
|-----------|------------|
| Identity | Google Account identity. Agents authenticated via Google Cloud credentials. |
| Capability delegation | Intent Mandates are the closest analogue to Chio capability tokens in the payment space. They carry user-approved scope (merchant categories, amounts, time bounds) and can be attenuated by intermediary agents. |
| Budget/spending | Strong: Intent Mandates carry explicit spending limits and category restrictions. |
| Receipts/proof | VDC chains provide a value-flow audit trail. Financial receipts, not tool-action receipts. No signed attestation of tool behavior. |
| Revocation | Mandate expiry and explicit user revocation via Google Pay. |
| Cross-org trust | Google-mediated. Mandates flow through Google's settlement infrastructure. |

**Gap.** AP2's Intent Mandates are structurally similar to Chio capability
tokens but operate exclusively in the payment domain. They cannot authorize
tool invocations, constrain tool arguments, or produce proof of tool behavior.

### Coinbase x402

**What it does.** HTTP 402-based micropayment protocol. When a server
returns HTTP 402 Payment Required, the client constructs a payment proof
(on-chain or via USDC) and retries the request with a payment header. Enables
pay-per-request API access for agents.

| Dimension | Assessment |
|-----------|------------|
| Identity | Wallet address (Ethereum/Base). Cryptographic identity via blockchain keys. |
| Capability delegation | None. Each request is an independent payment. No scoped authorization tokens. |
| Budget/spending | Per-request pricing. No aggregate budget controls or spending caps at the protocol level. |
| Receipts/proof | On-chain settlement provides payment proof (transaction hash). No proof of what was done with the paid-for resource. |
| Revocation | Not applicable -- each payment is atomic. |
| Cross-org trust | Blockchain-mediated. Trustless settlement but no federated capability model. |

**Gap.** x402 proves "agent paid for API call" but not "agent was authorized
to make this specific tool call with these arguments under this policy." The
on-chain receipt is a payment receipt, not an action receipt.

### Visa Intelligent Commerce / TAP & Mastercard Agent Pay

**What they do.** Network-level agent payment frameworks. Visa's Intelligent
Commerce platform provides agent identity verification, tokenized
credentials, and transaction controls at the network level. Mastercard's
Agent Pay enables agent-initiated purchases with biometric or
cryptographic verification. Both integrate with existing card networks.

| Dimension | Assessment |
|-----------|------------|
| Identity | Network-level agent identity. Visa uses AI-Ready Credentials; Mastercard uses Agent Pay verification tokens. |
| Capability delegation | Transaction controls (amount limits, merchant categories, geographic restrictions). Commerce-scoped, not tool-scoped. |
| Budget/spending | Strong within card network parameters. |
| Receipts/proof | Standard card network settlement records. |
| Revocation | Card-level controls (freeze, category blocks). |
| Cross-org trust | Card network serves as trust anchor. Global reach but commerce-only. |

**Gap.** Card networks can authorize "agent may spend $500 at electronics
merchants" but have no concept of "agent may invoke read_file on server A with
path constraints limited to /data/**."

---

## 3. Agent Security and Compliance

### AIUC (The Artificial Intelligence Underwriting Company)

**What it does.** Insurance-backed compliance framework for AI agents. Defines
the AIUC-1 standard for agent behavior certification. Participating companies
undergo quarterly audits of their agent systems. Agents that pass receive an
AIUC certification mark and access to pooled liability insurance.

| Dimension | Assessment |
|-----------|------------|
| Attestation model | Periodic snapshots. Quarterly audits evaluate agent behavior against AIUC-1 criteria. Between audits, agents are assumed compliant. |
| Continuous monitoring | Not protocol-native. AIUC recommends monitoring but does not define a real-time attestation format. |
| Cryptographic proof | None. Certification is a signed PDF from the auditor, not a machine-verifiable cryptographic attestation. |
| Scope | Organizational (company-level certification), not per-agent or per-invocation. |

**Gap.** The AIUC provides "this company's agents were compliant as of last
audit" but not "this specific tool invocation was authorized, policy-checked,
and attested at 2026-03-21T14:30:00Z." The gap between quarterly snapshots is
a compliance blind spot.

### Armilla AI

**What it does.** AI liability insurance backed by Lloyd's of London.
Armilla's Guardrail Warranty provides coverage for AI model failures.
Companies submit their models to Armilla's reliability testing pipeline; models
that pass receive insurance coverage with defined liability limits.

| Dimension | Assessment |
|-----------|------------|
| Attestation model | Pre-deployment testing gate. Models are evaluated once, not continuously monitored at the invocation level. |
| Scope | Model-level, not tool-invocation-level. |
| Cryptographic proof | None at the protocol level. |

**Gap.** Armilla proves "this model passed reliability tests before deployment"
but cannot prove "this model's tool invocation at time T was authorized and
produced result R under policy P."

---

## 4. Agent Identity Standards

### IETF AIMS (Agent Identity and Messaging Standard, draft)

**What it does.** IETF draft combining SPIFFE (workload identity), WIMSE
(Workload Identity in Multi-System Environments), and OAuth 2.0 token
exchange for agent workload identity. Agents receive SPIFFE IDs
(spiffe://domain/agent/name), authenticate via X.509 SVIDs, and use OAuth
token exchange to obtain scoped access tokens for downstream services.

| Dimension | Assessment |
|-----------|------------|
| Identity | Strong. SPIFFE-based workload identity with X.509 certificates. Platform-independent. |
| Capability delegation | OAuth 2.0 token exchange can produce scoped tokens, but scoping is coarse (OAuth scopes, not tool-level grants). |
| Receipts/proof | Not addressed. AIMS defines identity, not attestation. |
| Revocation | SPIFFE SVID rotation and OAuth token expiry. No capability-level cascade revocation. |

**Bottom line.** AIMS provides the identity substrate but not the authorization
or attestation layers. Chio's identity model is compatible with SPIFFE IDs
(the spec supports SPIFFE URIs as agent/server identifiers).

### UCAN (User-Controlled Authorization Networks)

**What it does.** Decentralized capability-based authorization using
JWTs. UCANs are delegable, attenuable tokens where each delegation step
narrows the permission scope. Originally designed for decentralized storage
(Fission/WNFS), now applied to broader authorization scenarios. Based on
the UCAN spec (ucanto).

| Dimension | Assessment |
|-----------|------------|
| Identity | DID-based. Issuers and audiences are identified by did:key or did:web. |
| Capability delegation | Strong. The core design: delegable tokens with monotonic attenuation. Closest to Chio's capability model among existing standards. |
| Receipts/proof | UCAN Invocation receipts exist in the spec (ucan/invocation) but adoption is limited. Receipts are not Merkle-committed. |
| Revocation | UCAN Revocation spec defines MUST-level cascade semantics (all derivatives must be marked invalid). Adoption is growing but not yet universal across implementations. |

**Differences from Chio:**
- UCAN tokens are JWTs; Chio uses Ed25519 over canonical JSON (deterministic signing, no JWT header ambiguity).
- UCAN has no kernel/TCB concept -- the verifier is the resource server, which may also be the tool. Chio separates enforcement from tool execution.
- UCAN receipts are optional; Chio receipts are mandatory for every decision (allow and deny).
- UCAN has no formal verification of safety properties.
- UCAN has no invocation budget constraints in the token.

### SPIFFE/SPIRE

**What it does.** SPIFFE (Secure Production Identity Framework for Everyone)
defines a standard for workload identity using URIs and X.509 certificates.
SPIRE is the production implementation. Originally designed for microservice
mesh identity, now being applied to agent workload identity (see IETF AIMS).

| Dimension | Assessment |
|-----------|------------|
| Identity | Strong. X.509 SVIDs with automatic rotation. Production-proven at scale. |
| Capability delegation | Not in scope. SPIFFE identifies workloads; it does not authorize specific actions. |
| Receipts/proof | Not in scope. |

**Bottom line.** SPIFFE is an identity primitive, not an authorization
protocol. Chio uses a SPIFFE-compatible identifier format for tool server IDs
(the codebase notes server IDs "may be a SPIFFE URI"), but there is no runtime
SPIFFE/SPIRE integration -- no SVID issuance, no workload attestation, no
mTLS via SPIRE.

---

## 5. Agent Economy Infrastructure

### Skyfire

**What it does.** Self-described as "Visa for the AI economy." Provides agent
wallets, payment routing, and settlement infrastructure. Agents register
with Skyfire, receive a wallet, and can pay for API calls or services from
other agents. Skyfire handles currency conversion, settlement, and
compliance (KYC/KYB for wallet holders).

| Dimension | Assessment |
|-----------|------------|
| Model | Centralized payment router with agent wallets. |
| Capability delegation | None. Skyfire authorizes payments, not tool invocations. |
| Receipts | Financial settlement receipts. No tool-action attestation. |

### Crossmint

**What it does.** Virtual cards and wallets for AI agents. Agents receive
virtual Visa/Mastercard numbers, enabling them to make purchases on any
merchant that accepts cards. Crossmint's Know-Your-Agent (KYA) framework
identifies the agent operator for compliance purposes.

| Dimension | Assessment |
|-----------|------------|
| Model | Card-issuing platform for agents. |
| Identity | KYA framework maps agents to their operating organizations. Identity is operator-level, not agent-level. |
| Capability delegation | Card spending controls (limits, merchant categories). Commerce-scoped. |
| Receipts | Card transaction records. |

### Nevermined

**What it does.** Multi-party agent billing and settlement. Agents register
service offerings with pricing. Consumers purchase credits, which are
decremented as services are consumed. Settlement distributes revenue across
multi-agent pipelines based on contribution tracking.

| Dimension | Assessment |
|-----------|------------|
| Model | Credits-based consumption metering with multi-party revenue split. |
| Capability delegation | Credits authorize consumption volume, not specific tool operations. |
| Receipts | Usage records for billing. Not cryptographically signed tool-action attestations. |

### Orb / Amberflo / Metronome

**What they do.** Usage-based billing platforms. They meter API calls, compute
tokens consumed, and generate invoices. Increasingly used to meter agent API
consumption.

| Dimension | Assessment |
|-----------|------------|
| Model | Metering and billing infrastructure. |
| Receipts | Usage records for invoicing. Not cryptographic attestations. |

**Common gap across agent economy infrastructure.** All of these platforms
track "how much was consumed/spent" but none track "what was done, under what
authority, with what result, verified by what policy." They are accounting
systems, not attestation systems.

---

## 6. Competitive Matrix

| Dimension | A2A | MCP | ANP | Stripe ACP-Commerce | AP2 | x402 | IETF AIMS | UCAN | Chio |
|-----------|-----|-----|-----|------------|-----|------|-----------|------|------|
| **Cryptographic identity** | Partial (signed Agent Cards) | Partial (OAuth 2.1) | Yes (DID) | -- | -- | Yes (wallet) | Yes (SPIFFE) | Yes (DID) | Yes (Ed25519; SPIFFE-compatible ID format) |
| **Scoped capability tokens** | -- | -- | -- | Partial (payment) | Yes (payment) | -- | Partial (OAuth) | Yes | Yes |
| **Delegation chains** | -- | -- | -- | -- | Partial (VDC) | -- | -- | Yes | Yes |
| **Cascade revocation** | -- | -- | -- | -- | -- | -- | -- | Yes (spec-level) | Yes |
| **Invocation budgets** | -- | -- | -- | Yes (spending) | Yes (spending) | Per-request | -- | -- | Yes |
| **Signed receipts (every decision)** | -- | -- | -- | -- | -- | Payment only | -- | Optional | Yes |
| **Signed audit evidence** | -- | -- | -- | -- | -- | On-chain | -- | -- | Yes (signed receipts, checkpoints, exportable inclusion proof material) |
| **Executable safety evidence** | -- | -- | -- | -- | -- | -- | -- | -- | Yes (differential tests, runtime qualification, informative Lean work) |
| **Fail-closed enforcement** | -- | -- | -- | -- | -- | -- | -- | -- | Yes |
| **Kernel as TCB (privilege separation)** | -- | -- | -- | -- | -- | -- | -- | -- | Yes |
| **Cross-org federated trust** | -- | -- | Partial (DID) | Stripe Connect | Google-mediated | Blockchain | SPIFFE federation | DID federation | Yes (delegation chains) |
| **Subject-bound tokens (DPoP)** | -- | -- | -- | -- | -- | Wallet-bound | mTLS | DID-bound | Partial (subject binding implemented; per-invocation DPoP specified, not yet in code) |

Chio is unusual in covering all twelve dimensions within one governed execution stack, but not every Chio dimension is at the strongest imaginable boundary today. The bounded release is strongest on fail-closed mediation, signed receipts, budgets, and kernel-enforced execution, while sender-constrained invocation proofs and transparency-log semantics remain explicitly bounded or optional.
The closest competitor on authorization semantics is UCAN, which lacks the
kernel TCB, mandatory receipts, invocation budgets, and formal proofs (UCAN
does specify cascade revocation at the spec level). The closest competitor on
payment semantics is Google AP2,
which lacks tool-level authorization and cryptographic action receipts.

---

## 7. Chio's Structural Advantages

These properties are architectural and cannot be retrofitted onto existing
protocols without redesigning their core abstractions.

### 7.1 Kernel as Trusted Computing Base

The Chio kernel sits between the untrusted agent and sandboxed tool servers.
The agent cannot address the kernel (no PID, no socket path, no signing key
visible). The kernel is the sole nexus for capability validation, guard
evaluation, receipt signing, and tool dispatch. This is a process-level
privilege separation that MCP, A2A, and every other agent protocol lacks --
they all allow direct agent-to-tool communication.

Retrofitting a kernel into MCP would require breaking the stdio/HTTP
client-server model that the entire ecosystem is built on.

### 7.2 Delegation Chains with Bounded Revocation Coverage

Chio capability tokens carry an ordered `delegation_chain` field listing
every ancestor capability ID from root to leaf. When any ancestor is
presented as part of that chain is revoked, the descendant presentation is
rejected. The current shipped runtime goes further than simple caller-presented
revocation coverage: the kernel validates delegation-link signatures, requires
persisted ancestor capability snapshots for every referenced parent, checks
delegator/delegatee continuity at every hop, enforces delegated scope ceilings
plus declared attenuations, and rejects the leaf if any recursive ancestor is
missing, revoked, or structurally inconsistent.

UCAN's Revocation spec defines MUST-level cascade semantics at the spec level.
Chio's shipped boundary is still distinct: it relies on locally trusted ancestor
snapshots rather than globally replicated lineage state. This is distinct
from OAuth refresh token rotation, where revoking a refresh token does not
automatically invalidate downstream tokens issued via token exchange.

### 7.3 Receipts as Protocol Primitive

Every kernel decision -- allow or deny -- produces a signed ChioReceipt
containing the capability ID, tool name, action, decision, content hash,
policy hash, per-guard evidence, and the kernel's Ed25519 signature. Receipts
are stored as signed audit artifacts with checkpoint and export support.

This is not ordinary logging. OTel traces (MCP's approach) are mutable,
filterable, and deletable. Chio receipts are signed decision artifacts backed
by checkpoint material and operator-local storage. A missing receipt remains a
useful signal of protocol drift or operational failure, but Chio's bounded
release does not claim public transparency-log or strong non-repudiation
semantics.
Receipts cover denials as well as approvals -- you can prove an agent was
blocked, not just that it succeeded.

### 7.4 Safety Evidence Boundary

Chio's core safety boundary is backed by executable differential tests, runtime
tests, conformance, and release qualification. The Lean work remains useful
and informative, but it is not the shipped release gate while portions remain
outside the root import surface or contain `sorry` placeholders.

- **P1 (Capability monotonicity):** The shipped runtime and differential tests
  defend subset behavior for the selected grant set.
- **P2 (Presented revocation coverage):** If a capability ID or presented
  delegation ancestor ID is in the revocation store, the kernel denies it.
- **P3 (Fail-closed guarantee):** Errors during evaluation produce denial
  decisions.
- **P4 (Receipt integrity):** Every kernel decision produces a signed receipt.
- **P5 (Presented delegation-chain structure):** Depth, connectivity, and
  timestamp monotonicity helpers define the bounded structural contract for a
  presented chain.

No other agent protocol ships this exact mix of differential tests, signed
receipt evidence, qualification lanes, and optional formal artifacts. Chio's
bounded release should be compared on that executable evidence boundary rather
than on proof branding alone.

### 7.5 Subject-Bound Tokens via DPoP

Chio capability tokens carry a subject field binding them to the presenting
agent's Ed25519 key; this binding is checked at validation time. The protocol
spec also defines per-invocation DPoP proofs (adapted from RFC 9449), and the
runtime can require PoP on selected grants. That makes replay materially
harder on those bounded paths, but the bounded release does not claim that all
capabilities are universally sender-constrained or useless if stolen.

OAuth DPoP exists but is not integrated into any agent protocol. UCAN binds
tokens to DIDs but does not require per-invocation proof-of-possession.

### 7.6 Fail-Closed with Exhaustive Guard Evidence

The kernel's evaluation pipeline is fail-closed: any error during capability
validation, guard evaluation, or tool dispatch results in a denial receipt.
There is no "default allow" mode. Guard evidence is collected per-guard and
included in the receipt, providing a complete audit trail of why a decision
was made.

This is verifiable at the policy level before deployment -- Chio policies are
validated at load time, and invalid policies are rejected. The kernel never
operates with an unverified policy.

---

## 8. Key Gaps Chio Fills

### 8.1 No protocol combines identity + capability delegation + economic primitives + receipts

The competitive landscape splits into three silos:

1. **Communication protocols** (A2A, MCP) define how agents talk but not what
   they are allowed to do or how to prove what they did.
2. **Payment protocols** (Stripe ACP-Commerce, AP2, x402) define how agents pay but
   not what they are authorized to do with what they paid for.
3. **Identity standards** (AIMS, UCAN, SPIFFE) define who agents are but not
   what scoped authority they hold or how to attest their actions.

Chio is the only protocol where a single token simultaneously expresses
identity (subject-bound Ed25519 key), authorization (scoped tool grants with
argument constraints), economic limits (invocation budgets), and produces
cryptographic proof (signed receipts in a Merkle log) for every decision.

### 8.2 The missing authorization layer between "user approves" and "payment executes"

Stripe's Shared Payment Tokens and Google's Intent Mandates authorize
spending. But between "user approved $50 for electronics" and "agent charged
$47.99 at merchant X," there is no attestation of what tool calls the agent
made, what arguments it used, what policies constrained it, or what results it
received. The authorization gap is:

```
User intent -> [???] -> Payment execution -> Settlement
               ^^^^^
               Chio fills this gap
```

Chio's capability token authorizes the tool invocations that lead to a
payment decision. The receipt chain proves the agent's reasoning path from
authorized capability to tool result to payment trigger. This makes the
agent's behavior auditable end-to-end, not just at the payment boundary.

### 8.3 Continuous cryptographic attestation vs. periodic audits

The AIUC's quarterly audits and Armilla's pre-deployment testing create point-in-time
compliance snapshots. Between snapshots, agent behavior is unattested. A model
update, configuration change, or novel input could cause policy violations that
go undetected until the next audit cycle.

Chio produces a signed receipt for every tool invocation in real time. The
receipt plane provides continuous signed action evidence with checkpoint and
export support. Compliance is therefore no longer only a periodic assertion --
it can be tied to specific invocations and reviewed against signed receipt
artifacts and the kernel's public key. The bounded release still does not
claim public transparency-log semantics.

The difference is structural: audits verify *systems*, receipts verify
*actions*. Chio makes every agent action independently verifiable without
trusting the agent, the operator, or the auditor.
