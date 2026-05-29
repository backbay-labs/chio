# Chio Protocol Stack: Strategic Vision

**Date:** 2026-04-13
**Status:** Active strategy document
**Scope:** Cross-protocol position, priority stack, novel security features, long-term roadmap

---

## 0. How To Read This Document

This document mixes three kinds of statements. They should not be read as if
they have the same epistemic weight:

- **Current state.** What is shipped in the repo today, or what the current
  CLI/runtime demonstrably supports.
- **Design proposal.** Architecture we intend to build, but which is not yet
  implemented.
- **Strategic assumption.** A directional thesis about the market, buyer, or
  eventual business model. These guide prioritization, but are not primary
  evidence by themselves.

Where a surface is only proposed, this document now labels it explicitly. In
particular: `chio mcp serve`, `chio mcp serve-http`, `chio api protect`, the
HTTP/framework substrate packages, ACP live-path cryptographic receipts, and
the receipt dashboard ship today. `chio start --config chio.yaml` and the
stronger market-position claims remain strategic or proposed rather than
current runtime fact. The shared `CrossProtocolOrchestrator` substrate is no
longer purely proposed; the stronger technical control-plane thesis is now
qualified on the supported authoritative surfaces, while the broader
partner/ecosystem thesis remains future.

---

## 1. The One-Sentence Vision

**Current defensible claim:** Chio is a cryptographically signed, fail-closed,
intent-aware governance control plane on the qualified authoritative HTTP, MCP,
A2A, and ACP surfaces. OpenAI remains deferred until caller-executed function
tool mediation is separately implemented and qualified.

**Strategic thesis:** Chio could become the comptroller of the agent economy --
but only if the broader cross-protocol, economic, federated-governance, and
external market-adoption layers are proven in production rather than assumed
by narrative.

---

## 2. The Protocol Landscape (April 2026)

Three protocols now dominate agent infrastructure. Each solves one problem
well. None solves the problem that matters most.

### MCP: Agent-to-Tool (Anthropic)

MCP is the leading open tool-calling wire format in the current agent tooling
ecosystem. It defines tool schemas, resources, prompts, sampling, and
completions over stdio or HTTP+SSE. In this document, MCP's importance is a
working strategic assumption based on ecosystem observation, not a citation-
backed market measurement.

MCP is a tool-calling wire format. It explicitly defers authorization to the
application layer. OpenTelemetry logging provides observability, not proof.
There are no capability tokens, no delegation chains, no signed receipts, and
no revocation semantics.

### A2A: Agent-to-Agent (Google / Linux Foundation)

A2A is the clearest open attempt to standardize agent-to-agent discovery and
task exchange. It introduces signed Agent Cards, task lifecycle streaming, and
DNS/HTTP discovery. Chio treats A2A as strategically important, but this
document does not use it as the system of record for ecosystem metrics.

A2A added cryptographic identity for card publishers but still has no scoped
authorization tokens, no capability delegation, and no mechanism to constrain
what a discovered agent can do beyond transport-layer controls.

### ACP: Editor-to-Agent (Zed Industries)

The LSP for AI. ACP defines how editors and IDEs communicate with coding
agents through a structured JSON-RPC protocol. Permission requests, filesystem
operations, terminal commands, and session lifecycle flow through a typed
message contract.

ACP has permission-request semantics but no cryptographic attestation of what
the agent actually did, no signed receipts, and no delegation model.

### The Convergence

Chio's working strategic assumption is that many enterprise agent deployments
will encounter all three interaction patterns: MCP for tool access, A2A for
multi-agent coordination, and ACP for developer-facing agent integration. The
three protocols are complementary, not competitive.

### The Gap Nobody Fills

No protocol provides cross-protocol cryptographic attestation. An agent that
reads a database via MCP, delegates a subtask via A2A, and modifies code via
ACP produces three separate, unlinked, unsigned event streams. There is no
unified proof of what happened. There is no cross-protocol receipt chain.
There is no single artifact an auditor, insurer, or regulator can verify.

Chio fills that gap.

---

## 3. Chio's Unique Position

Chio is not an alternative to MCP, A2A, or ACP. It is the authorization,
attestation, and audit layer that sits across all three.

### Chio Is Not Just an MCP Gateway

MCP gateway-style enforcement is an important adoption wedge, but it is not the
full Chio architecture and should not be treated as the end-state product
identity.

A pure gateway gives a clean enforcement chokepoint for wrapped MCP traffic.
That is useful. It is also structurally incomplete:

- It evaluates requests at the protocol boundary, often with weaker access to
  full workflow history, delegation ancestry, and cross-step intent than the
  kernel itself can preserve.
- It only governs the traffic that actually passes through it. Agent actions
  may migrate to A2A, ACP, native APIs, or framework-specific skill surfaces.
- If the market shifts from MCP-heavy integrations toward protocol-mixed or
  native-function architectures, an MCP-only control point secures a shrinking
  fraction of agent behavior.

Chio should therefore position wrapped MCP enforcement as the fastest current
on-ramp, not the complete runtime-security strategy.

Detailed research notes and open questions live in
`RUNTIME-SECURITY-GATEWAY-VS-CONTEXT-RESEARCH.md`. The complementary HTTP and
framework adoption track lives in `HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md`.

### Three Runtime Security Layers

Chio's runtime-security story is strongest when described as three layers, not
one:

1. **Deterministic governance.** Capability validation, static policy checks,
   guards, budgets, revocation, and fail-closed enforcement.
2. **Continuous observability.** Signed receipts, delegation lineage, session
   traces, cost attribution, and evidence bundles that explain what happened.
3. **Dynamic governance.** Optional future controls that use live context,
   drift signals, and intent/risk scoring to change what is allowed mid-session.

Today Chio ships layers 1 and 2 broadly and now qualifies a bounded but real
form of layer 3 on the claim-eligible authoritative surfaces. Broader
ecosystem-wide dynamic governance remains strategic expansion rather than a
market-qualified claim.

### Three Protocol Adapters, One Kernel

```
  MCP Server  <-->  chio-mcp-adapter  <--\
                                         \
  A2A Agent   <-->  chio-a2a-adapter  <---+--->  Chio Kernel  --->  Receipt Log
                                         /         |
  ACP Agent   <-->  chio-acp-proxy    <--/     Guard Pipeline
```

Every tool invocation, agent delegation, and code action flows through the
same trusted kernel. The kernel validates capability tokens, runs the guard
pipeline, and signs receipts -- regardless of which protocol originated the
request.

### Current Signed Receipt Posture Across Shipped Protocol Surfaces

The receipt log is protocol-agnostic. An MCP tool call, an A2A task
delegation, ACP live-path action, and Chio-governed HTTP/API call all use the
same signed evidence model: timestamped, capability-bound, and append-only.
Today that is shipped on the live paths that actually reach the kernel. What is
still future is the full protocol-to-protocol fabric and literal
kernel-convergence work that would make every bridge hop flow through one
reusable orchestration layer by construction, not merely the existence of a
shared orchestrator substrate.

### The Receipt Log as the Deepest Long-Term Moat

The receipt log is not just an audit trail. It is a billing ledger, a
compliance record, a behavioral dataset, and an underwriting input -- all from
one data structure. Every receipt that flows through Chio deepens a dataset that
would be hard to match: a competitor would need comparable authorization,
attestation, portability, and real deployment distribution before they could
assemble an equivalent evidence corpus.

The key nuance: observability is not equivalent to enforcement. Chio should not
collapse those concepts. The receipt log is valuable because it is rooted in
enforced, signed execution, not because it is "just more telemetry."

### Chio vs. Microsoft AGT

Microsoft's Agent Governance Toolkit is the clearest emerging runtime-
governance reference point as of April 2026. Public Microsoft material
emphasizes multi-language packaging, a stateless policy engine, DID-based
identity, and dynamic trust scoring. Chio should not dismiss AGT as a toy or as
an Azure-only niche. The better contrast is:

- AGT appears strongest on packaging, language reach, and enterprise
  distribution.
- Chio's differentiation thesis is portable signed receipts, cross-protocol
  delegation/evidence chains, and economic primitives in the decision path.
- AGT is not best framed as "single protocol"; Chio wins if it proves broader
  attested lineage and third-party-verifiable evidence, not if it relies on a
  weak competitor caricature.

Cross-protocol signed receipts are now shipped for the live MCP, A2A, ACP, and
HTTP/API substrate paths that execute through the kernel. The remaining gap is
not ACP receipt promotion itself; it is the more generic orchestration layer
described in `CROSS-PROTOCOL-BRIDGING.md`, plus broader deployment proof that
the multi-surface story holds under real operator workloads.

### Chio's Differentiation Thesis Today

| Area | Chio position | Status / caveat |
|------|--------------|-----------------|
| **Capability tokens** | Attenuated, time-bounded, subject-bound, revocable, with bounded Lean support for attenuation | Shipped in the core model |
| **Guard evidence** | Composable fail-closed guards with signed evidence capture | Shipped; advanced stateful guards remain planned |
| **Receipt signing** | Kernel-signed receipts on shipped MCP, A2A, ACP live-path, and HTTP/API substrate flows | Shipped on current live paths; OpenAI remains deferred; generic orchestration remains future |
| **Merkle commitment** | Append-only receipt log with checkpoint publication | Shipped in the receipt architecture |
| **Formal verification** | Bounded verified-core model, claim registry, and runtime qualification outside that boundary | Real but not full theorem-prover coverage |
| **Economic primitives** | Budgets, settlement hooks, and insurance-linked framing in the security path | Mixed: some pieces shipped, broader market story is a strategic bet |
| **Cross-protocol lineage** | One evidence model spanning MCP, A2A, ACP, HTTP/API substrates, and future native surfaces | Shipped evidence model on current live paths; generic orchestrator and larger-scale operator proof still needed |

The adjacent comparison set is broader than one product. Runtime governance
toolkits, policy engines, API-security platforms, and observability systems all
cover part of this landscape. Chio's claim is the fusion of deterministic
enforcement, signed portable evidence, delegation lineage, and economic
controls -- not that no adjacent system exists.

---

## 4. The Priority Stack

Three tiers, ordered by impact and dependency.

### Tier 1: Do Now

These items unblock adoption and close the most visible gaps in the current
shipping surface.

| Item | Rationale | Crate | Status |
|------|-----------|-------|--------|
| ACP kernel integration | Promote chio-acp-proxy from unsigned audit entries to full signed receipts via injected kernel service | `chio-acp-proxy` | [Shipped] |
| MCP proxy DX polish | The repo already ships `chio mcp serve` and `chio mcp serve-http`; Tier 1 work is simplifying naming, defaults, and docs further, potentially including an `chio proxy` alias | `chio-cli` | |
| Unified runtime config | Single `chio.yaml` that configures MCP, A2A, and ACP edges with shared policy | `chio-cli` | [Partial -- flat schema shipped, nested schema proposed. See spec/CONFIGURATION.md] |
| Symlink fix | Workspace symlink resolution for monorepo consumers | `chio-cli` | |

**Why Tier 1 first:** ACP live-path cryptographic enforcement is now landed, so
the remaining Tier 1 work is about adoption clarity: wrapped MCP DX polish and
truthful documentation for the proposed future entry points that still do not
ship.

**Runtime-security framing:** Tier 1 is about making deterministic governance
and signed observability easy to adopt. It is intentionally not framed as full
dynamic or intent-aware governance on day one.

### Tier 2: Build Next

These items extend the protocol surface and complete the compliance story.

| Item | Rationale | Crate | Status |
|------|-----------|-------|--------|
| A2A edge crate | Bidirectional bridging: expose Chio tools as A2A Agent Cards | `chio-a2a-edge` | [Shipped] |
| ACP edge crate | Bidirectional bridging: expose Chio tools as ACP capabilities | `chio-acp-edge` | [Shipped] |
| MCP adapter completion | Close coverage from 14 tests to 80+, covering streaming, error paths, and edge cases | `chio-mcp-adapter` | [Shipped] |
| Compliance certificates | Session-scoped, single-artifact proof bundles for auditors (SOC 2, HIPAA, EU AI Act) | `chio-core` | [Shipped] |

**Why Tier 2 second:** Edge symmetry means every protocol gets both inbound
adaptation (consume external tools) and outbound exposure (publish Chio tools).
This is what makes Chio a hub, not just a consumer. Compliance certificates
are the artifact that enterprise security and legal teams actually want to see.

### Tier 3: Strategic Bets

These items create new market categories or defensible network effects.

| Item | Rationale | Crate / Surface | Status |
|------|-----------|-----------------|--------|
| Capability attenuation SDK | Programmatic sub-agent delegation with provable subset guarantees | `chio-core` | |
| Receipt dashboard expansion | The dashboard ships today; the strategic work is adding cross-protocol traces, compliance views, and certificate inspection | `chio-cli/dashboard` | |
| OpenAI function calling adapter | Deferred caller-executed function-tool mediation surface | Future crate TBD | Blocked until v1 receipt authority and adapter qualification |
| WASM guard runtime | Custom guards authored in any language compiled to WASM, sandboxed execution | `chio-guards` | [Shipped] |
| Kubernetes admission controller | Enforce Chio capability policies at pod deployment time | `sdks/k8s` | [Shipped] |

**Why Tier 3 last:** These are force multipliers that assume Tier 1 and Tier 2
are complete. The WASM guard runtime and K8s controller extend Chio into
infrastructure-level enforcement. The OpenAI adapter remains deferred and must
not be treated as shipped or authoritative until the v1 receipt authority gates
and adapter qualification tests land. The dashboard work here is expansion of
an existing operator surface, not net-new UI creation.

### Tier 4: Next Horizon

These items represent the forward-looking expansion once the current tiers are
fully landed and battle-tested in production.

| Item | Rationale | Surface |
|------|-----------|---------|
| Multi-region consensus | Distributed receipt log replication across geographic regions with consistency guarantees for global deployments | `chio-consensus` |
| Public certification marketplace | Third-party auditors and tool authors publish Chio compliance certificates that consumers can verify independently | `chio-marketplace` |
| Synthetic scoring and simulation | Generate synthetic agent workloads to test guard configurations, budget policies, and capability delegation graphs before production deployment | `chio-sim` |
| Receipt-backed SLA enforcement | Automated SLA compliance checking using receipt chain evidence, with breach detection and escalation | `chio-sla` |
| Cross-org federated policy negotiation | Organizations exchange and negotiate capability delegation ceilings through a structured protocol, not ad-hoc configuration | `chio-federation` |

**Why Tier 4 is horizon work:** These items assume mature production adoption
across multiple organizations and protocol surfaces. Multi-region consensus
requires real geographic distribution. The certification marketplace requires
a critical mass of tool authors and auditors. Synthetic scoring requires a
stable guard and budget model to simulate against. These are valuable
directions, but premature to build before Tier 1-3 are proven at scale.

### Cross-Language Packaging Constraint

The kernel can remain Rust-first. The adoption surface cannot.

Chio's current shipping story is strongest where the Rust CLI can wrap a known
protocol edge directly. That is valuable, but it is not enough to win ordinary
API developers or mixed-language platform teams. The complementary adoption
track is defined in `HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md`:

- zero-code sidecar / reverse-proxy onboarding
- OpenAPI-driven manifest and policy generation
- Python first, TypeScript second, Go third for native packaging
- thin framework wrappers over shared substrate adapters

This is not optional DX polish. It is the packaging path that keeps Chio from
being a strong kernel with weak reach.

---

## 5. Chio's Differentiation Features

These features are where Chio appears differentiated today or where it is making
explicit strategic bets. Some are shipped. Some are in progress. Some are
research horizon.

### 5.1 Capability Delegation with Attenuation (Shipped)

When Agent A delegates a capability to Agent B, the delegated token is a
provable subset of the parent token. Delegation can narrow scope, reduce
invocation limits, shorten time windows, and tighten parameter constraints.
Delegation cannot amplify. This is not a convention. It is a structural
property with bounded Lean mechanization and executable differential tests for
the current verified-core model. It is not a claim that every production
delegation, budget, revocation-store, or transport path is theorem-prover
complete.

Sub-agent tokens carry their full ancestry. Any verifier can walk the
delegation chain and confirm that every hop only narrowed authority.

### 5.2 Usage-Bounded Tokens (Shipped)

Capability tokens carry invocation limits per grant. The kernel's BudgetStore
enforces limits atomically: try_increment either succeeds or denies. Budget
records travel with the capability through delegation, and attenuated tokens
inherit the tighter of the parent's remaining budget or the delegated budget.

Planned extensions:
- **Data volume limits:** cap bytes read/written per grant, not just invocation count
- **Time + usage composition:** "100 invocations OR 24 hours, whichever comes first"
- **Monetary budget enforcement:** per-grant spending ceilings in denominated currency, enforced through the chio-link oracle runtime

### 5.3 Capability Attestation Chaining (Shipped)

Receipts hash-chain within sessions. Each receipt references the hash of the
previous receipt in the session, creating an ordered, tamper-evident sequence.
A gap in the chain is detectable. A reordering is detectable. The chain is
the foundation for session compliance certificates.

### 5.4 Session Compliance Certificates (Shipped)

A session compliance certificate is a single artifact that proves:
- Every tool invocation in the session was authorized by a valid capability token
- Every guard in the pipeline evaluated and produced a signed decision
- No receipt in the chain was tampered with or reordered
- The session stayed within its budget, time, and scope constraints

One artifact. One verification. Auditor-ready. The certificate references the
receipt chain root hash and the capability token IDs, so a verifier can
reconstruct the full evidence independently.

### 5.5 Zero-Knowledge Capability Proofs (Research Horizon: 2027-2028)

Prove that an agent holds a capability token with sufficient scope to perform
an action, without revealing the token itself, the issuer, or the full scope.
This enables privacy-preserving capability verification for cross-organization
agent collaboration where neither party wants to disclose their internal
authorization structure.

The research direction is ZK-SNARKs over the capability token structure, with
the kernel as the trusted prover and external verifiers checking the proof
without seeing the witness.

### 5.6 Multi-Party Capability Approval (Planned)

N-of-M signing for high-stakes capabilities. A capability token for
"transfer funds > $10,000" requires signatures from 3 of 5 designated
approvers before the kernel accepts it. The approval set is encoded in the
token itself, and the kernel validates the threshold before any guard runs.

This maps directly to enterprise approval workflows: dual control for
financial operations, committee approval for infrastructure changes, and
multi-department sign-off for cross-functional agent deployments.

---

## 6. The Protocol-Agnostic Tool Store

The three-adapter architecture creates a natural opportunity: a tool store
where publishers register once and Chio automatically exposes the tool through
every protocol edge.

### Publish Once, Expose Everywhere

A tool author writes a tool, signs a manifest, and registers it with Chio.
The MCP edge exposes it as an MCP tool. The A2A edge publishes it in an
Agent Card. The ACP edge makes it available to coding agents. One tool
definition, three protocol surfaces, zero additional work for the author.

### Federated Capability Exchange

Organizations running Chio can federate capability tokens across organizational
boundaries. Delegation chains span federation boundaries. The receipt chain
captures the full cross-org lineage. Federation trust is explicit, bounded,
and auditable -- not implicit or ambient.

### Discovery API and Revenue Model

A unified discovery surface spans all three protocols: query by tool name,
capability scope, or protocol preference. The marketplace model follows
naturally: Chio-mediated billing where every invocation produces a receipt
carrying financial metadata. The receipt chain is the settlement evidence.
The billing ledger is not a separate system. It is the receipt log.

This is a strategic thesis, not a present-day claim that a multi-protocol tool
store or liability-linked billing surface is already implemented.

---

## 6.5 Claim Gate

Chio can honestly claim a stronger breakthrough today:

- Chio ships a cryptographically signed, fail-closed, intent-aware governance
  control plane with shared executor registry resolution, signed
  route-selection evidence, receipt-bearing multi-hop route execution, and a
  shared lifecycle contract across the qualified authoritative HTTP, MCP,
  A2A skills, and ACP capabilities. OpenAI tool execution remains deferred
  until the v1 receipt and read-boundary gates are merged.
- Chio ships a cryptographically signed, fail-closed governance kernel and a
  bounded protocol-aware cross-protocol execution fabric across HTTP APIs,
  MCP, A2A skills, and ACP capabilities
- the shipped orchestrator now supports explicit metadata-driven qualified
  non-native authoritative bridge execution through registered target
  executors rather than collapsing every authoritative path directly to
  `Native`
- on the supported authoritative paths, execution is kernel-mediated,
  receipt-bearing, and explicit about lifecycle and fidelity limits, including
  the authoritative deferred-task mediation Chio now exposes on A2A and ACP
  public surfaces
- the repo ships multi-language substrate packages that preserve that kernel
  contract across Python, TypeScript, Go, Rust, JVM, and .NET surfaces
- Chio now also ships explicit operator-facing economic control surfaces,
  partner-visible receipt and settlement contract packages, and bounded
  federated multi-operator proof bundles that justify calling the software
  **comptroller-capable** on qualified local evidence

Chio should not yet claim:

- a proved comptroller-of-the-agent-economy market position
- "comptroller of the agent economy" as a proved market position rather than a
  strategic thesis

Broader market-position claims require at least these additional proofs:

- independent external operators running Chio as a live economic control plane
- partners consuming Chio-issued receipts, checkpoints, reconciliation, or
  settlement artifacts as authoritative workflow inputs
- external evidence that meaningful economic workflows would fail or lose
  partner acceptance without Chio
- stronger ecosystem and economic validation for the market-position story

The authoritative machine-readable gates now split these levels explicitly:

- bounded runtime substrate:
  `docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`
- stronger technical control-plane thesis:
  `docs/standards/CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json`
- comptroller-capable market-position boundary:
  `docs/standards/CHIO_COMPTROLLER_MARKET_POSITION_MATRIX.json`

The reason this matters to runtime security is simple: if tools and skills can
be invoked through multiple protocols or through native APIs, security
architecture cannot stop at MCP chokepoints alone.

The same principle applies to HTTP/OpenAPI surfaces. Spec-driven import is a
useful governance wedge, but route publication should be curated rather than
treated as a naive 1:1 "every endpoint becomes a tool" rule.

---

## 7. Developer Experience Roadmap

Five phases, each building on the last. The goal is to take Chio from "powerful
but requires expertise" to "secure any agent in one command." The phases below
explicitly distinguish shipped surfaces from proposed next steps.

### Phase 1: Wrapped MCP Edge Commands (Shipped, DX polish next)

Current shipped surface:

```
chio mcp serve --policy <policy.yaml> --server-id <id> <command>...
```

and, for hosted HTTP:

```bash
chio mcp serve-http --policy <policy.yaml> --server-id <id> --listen <addr> <command>...
```

These commands already wrap an MCP server subprocess, interpose the Chio
kernel, and produce signed receipts for every tool call. The next DX step is
to simplify naming, defaults, and documentation further, potentially including
an `chio proxy` alias.

This is the **adoption wedge**, not the architectural boundary. Chio should win
initial deployment through wrapped MCP edges while building toward broader
protocol and native-surface coverage.

### Phase 2: `chio.yaml` Unified Runtime Config (Proposed)

One configuration file that defines all three protocol edges, shared policy,
capability authorities, and receipt storage:

```yaml
edges:
  mcp:
    servers:
      - name: database
        command: "npx @db/mcp-server"
  a2a:
    agents:
      - url: "https://agent.example.com"
  acp:
    agent:
      command: "claude-code"
      workspace: "/home/user/project"
policy:
  guards: [forbidden-path, shell-command, egress-allowlist]
receipts:
  store: sqlite
  path: "./chio-receipts.db"
```

Status note: this is a design proposal. The repo currently supports `chio_yaml`
as a policy format, but does not currently ship an `chio start --config chio.yaml`
runtime command.

### Phase 3: Guard SDK

Custom guards in Rust or any language that compiles to WASM. A guard is a
pure function: it receives the tool call context and returns allow or deny
with evidence. The SDK provides the trait, the WASM runtime provides the
sandbox, and the kernel provides the integration.

### Phase 3.5: Behavioral and Intent Signals (Research / Design)

Chio should explicitly research which live signals are useful for runtime risk
evaluation without introducing a false sense of precision:

- workflow drift from the initial session objective
- unusual tool sequencing or data-volume changes
- cross-tool exfiltration patterns
- mismatch between declared task intent and observed side effects
- escalation triggers for human approval

The important discipline is to treat these as inputs to optional governance
layers, not as magic "understanding" that replaces deterministic controls.

### Phase 4: Receipt Dashboard Expansion (Base Surface Shipped)

The receipt dashboard already exists as an operator-facing UI. The expansion
work is cross-protocol trace visualization, compliance certificate inspection,
and richer non-receipt summaries. The dashboard reads from the receipt store
and presents data that is already there -- it does not introduce new data
collection.

### Phase 5: Hosted Managed Service

Chio-as-a-service with per-receipt pricing. Organizations that do not want to
operate the kernel, receipt store, or control plane can use the hosted service.
The trust model is preserved: the managed kernel signs receipts with keys the
customer controls, so the hosted service cannot forge receipts. Key custody,
verifier onboarding, and trust-root distribution are specified separately in
`TRUST-MODEL-AND-KEY-MANAGEMENT.md`.

---

## 8. Enterprise Go-to-Market

Four concentric rings, each capturing a different buyer.

These rings are strategic assumptions about adoption order. They are not
presented here as externally validated market research.

### Ring 1: Open-Source Adoption (Developers)

Chio is open source and free. Developers adopt it because `chio mcp serve` /
`chio mcp serve-http` are the fastest current way to add authorization and audit
to an MCP server. A future `chio proxy` alias may compress that further. The
receipt log is local SQLite. No account, no sign-up, no cloud dependency.

### Ring 2: Enterprise SIEM Integration (Security Teams)

`chio-siem` exports receipt data to Splunk, Datadog, Elastic, and any SIEM
that accepts structured events. Security teams adopt Chio because it gives
them the agent audit trail they cannot get from any other source. The
integration is the wedge into enterprise procurement.

But SIEM export alone is not the runtime strategy. Post-hoc monitoring without
pre-execution enforcement is still reactive.

### Ring 3: Managed Receipt Analytics (Compliance Teams)

Compliance teams need artifacts, not dashboards. Session compliance
certificates, receipt chain exports, and EU AI Act Article 19 traceability
reports are the artifacts Chio produces natively. Managed analytics packages
these artifacts with retention policies, automated report generation, and
regulator-ready formatting.

### Ring 4: Liability Market Integration (Insurance Industry)

Chio receipts are actuarial data. The behavioral metrics computed from the
receipt log -- reliability, compliance rate, scope discipline, delegation
hygiene -- are the inputs an underwriter needs to price agent liability
coverage. Per-session pricing, capability-scoped coverage, and receipt-backed
claims adjudication could create a new category: parametric agent insurance.
This is a long-term strategic bet, not a claim that product-market fit is
already proven.

---

## 9. Integration Roadmap

Current shipped and planned integrations, ordered by expected adoption impact.

| Integration | Description | Status |
|-------------|-------------|--------|
| **OpenAI function calling adapter** | Wrap caller-executed OpenAI-style function calls through the Chio kernel | Deferred until separately implemented and qualified |
| **HTTP/OpenAPI sidecar** | Reverse-proxy adoption path for any documented API, with manifest generation from OpenAPI and `x-chio-*` policy hints | Shipped |
| **Python / TypeScript / Go substrate SDKs** | Multi-language middleware and wrapper packages around the Rust kernel | Shipped |
| **LangChain / LlamaIndex wrappers** | Python packages that inject Chio authorization into existing agent frameworks | Planned |
| **Kubernetes admission controller** | Enforce Chio capability policies at pod deployment, reject workloads without valid tokens from trusted Chio issuers | Shipped |
| **WASM guard runtime** | Execute custom guards compiled to WASM in a sandboxed runtime | Planned |
| **HSM integration** | Hardware Security Module support for kernel signing keys (PKCS#11, AWS CloudHSM, Azure HSM) | Planned |
| **TEE / confidential computing** | Run the Chio kernel inside a Trusted Execution Environment (Intel SGX, AMD SEV, ARM CCA) | Research |
| **SCIM provisioning** | Sync agent identities and capability grants from enterprise identity providers | Planned |
| **OpenTelemetry collector** | Export receipt data as OTel spans for existing observability infrastructure | Planned |

These integrations matter partly because agent execution is already moving
beyond MCP-specific surfaces. Chio's protocol-agnostic story gets stronger as it
secures a wider share of actual runtime behavior.

---

## 10. Cross-Adapter Test Coverage

Current state and targets for the four protocol surfaces.

| Adapter | Tests (Current) | Grade | Target | Target Grade |
|---------|-----------------|-------|--------|--------------|
| `chio-mcp-adapter` | 14 | C | 80+ | A |
| `chio-a2a-adapter` | 56 | A- | 60+ | Maintain |
| `chio-acp-proxy` | 129 | A | 130+ | Maintain |
| `chio-mcp-edge` | 42 | B+ | 60+ | A- |

Counts reflect `#[test]` functions in each crate's source tree. For line-level
coverage metrics, see CI reports.

The MCP adapter is the oldest crate and has the weakest coverage relative to
its surface area. The gap is concentrated in streaming, error propagation,
resource template resolution, nested flows, and OAuth token refresh. Closing
to 80+ tests is a Tier 2 priority. The A2A and ACP crates demonstrate that
thorough adapter coverage is achievable; the MCP adapter needs the same
treatment.

---

## 11. The Architecture Debate (Resolved)

Three architectural questions arose during the multi-protocol expansion. All
three are now resolved with clear rationale.

### ACP Proxy: Boundary Proxy, Not Tool Server

The ACP proxy sits at the boundary between the editor client and the ACP agent.
It is not a tool server. It does not implement tools. It intercepts JSON-RPC
messages, enforces capability-based access control, and generates audit entries.

The kernel is injected as a service, not embedded as a library. This means the
proxy can run alongside a Chio kernel that is already managing MCP and A2A
edges, producing receipts into the same log. The alternative -- making the ACP
proxy a standalone tool server -- would have created a second receipt log and a
second policy evaluation path, violating the single-kernel invariant.

Note: `chio-acp-proxy` and `chio-acp-edge` serve opposite directions.
The proxy is an inbound adapter (intercepts an existing ACP session for
security enforcement). The edge is an outbound adapter (exposes Chio
tools to ACP editors as if they were native ACP capabilities). The
"not a tool server" characterization applies to the proxy only.

### Unified Trait: Lightweight Metadata, Not Behavioral Abstraction

The three adapters (MCP, A2A, ACP) share a common trait surface for metadata:
tool names, descriptions, input schemas, and capability requirements. They do
not share a behavioral abstraction. Each protocol has distinct transport
semantics (stdio pipes, HTTP streaming, JSON-RPC bidirectional) that would be
distorted by a forced common interface.

The shared surface is intentionally thin: enough to support cross-protocol
discovery and the tool store, not so thick that protocol-specific behavior
leaks through an inappropriate abstraction.

### Edge Symmetry: Bidirectional Bridging for All Three Protocols

Every protocol gets two crate surfaces:

| Protocol | Inbound (consume external) | Outbound (expose Chio tools) |
|----------|---------------------------|----------------------------|
| MCP | `chio-mcp-adapter` | `chio-mcp-edge` |
| A2A | `chio-a2a-adapter` | `chio-a2a-edge` (Tier 2) |
| ACP | `chio-acp-proxy` | `chio-acp-edge` (Tier 2) |

Inbound adapters wrap external protocol servers as Chio tool servers. Outbound
edges expose Chio-native tools through the external protocol's wire format.
Bidirectional bridging is what makes Chio a protocol hub rather than a
protocol consumer. An Chio-native tool registered once is discoverable and
invocable from MCP clients, A2A agents, and ACP editors simultaneously.

---

## The Strategic Thesis

Chio's near-term protocol bet centers on MCP, A2A, and ACP, but the broader
strategic view is that agent execution will remain protocol-mixed: MCP, A2A,
ACP, native APIs, and framework-level tool surfaces will coexist.
None of these surfaces natively solve authorization, attestation, or non-
repudiation, because those are not their jobs.

Chio is the system that aims to sit across those surfaces and answer the
questions that matter after the agent acts: was it authorized, what did it
cost, can you prove it, and who is liable if it went wrong?

The receipt log is the asset. Every signed receipt makes the dataset larger,
the compliance story stronger, and the operational evidence richer. The
protocol adapters are the distribution mechanism. The kernel is the trust
anchor. Liability-market applications are a long-term strategic extension if
the security and compliance layers prove valuable first.

Chio does not compete with agent protocols. It makes them safe to use for
things that matter.
