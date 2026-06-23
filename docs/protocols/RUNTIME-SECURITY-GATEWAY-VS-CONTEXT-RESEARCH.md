# Runtime Security Research: Gateway vs Context

**Status:** Working research / brainstorming document
**Date:** 2026-04-13
**Scope:** MCP gateway limits, direct-access monitoring limits, protocol bypass, Chio implications

---

## 1. Why This Document Exists

Chio currently has a strong story around deterministic governance and signed
observability, especially on wrapped MCP surfaces. Recent external research and
market commentary sharpen an important architectural risk:

> An organization can secure MCP traffic and still fail to secure a meaningful
> share of real agent runtime behavior.

This document is for researching and pressure-testing that exact issue.

It is intentionally not a polished product spec. It is a workspace for:

- framing the problem precisely
- collecting external signals
- generating architecture options
- identifying what Chio should claim now versus later

---

## 2. External Framing Inputs

### 2.1 Software Analyst / SACR Article

Source:

- `Runtime Security for AI Agents: An Identity Governance Perspective`
- Published March 18, 2026
- URL: `https://softwareanalyst.substack.com/p/runtime-security-for-ai-agents-an`

Useful takeaways:

- runtime security is described as three layers:
  - deterministic governance
  - non-deterministic behavioral analysis / observability
  - non-deterministic governance
- the article argues gateway-style MCP enforcement and direct-access monitoring
  solve different parts of the problem
- it explicitly states neither approach is sufficient alone
- it highlights that execution is already diversifying across homegrown agents,
  SaaS builders, and local workforce tools
- it treats MCP as an important proving ground, but not the permanent boundary
  of runtime security

### 2.2 LinkedIn Summary Post

Source:

- LinkedIn post summarizing the same research
- URL:
  `https://www.linkedin.com/posts/software-analyst_cybersecurity-ciso-aiagents-activity-7449538725535137792-AYzK`

Useful takeaways:

- centralized MCP gateways create a clear choke point but often evaluate calls
  with weak session-level context
- direct-access monitoring sees richer context but is reactive
- skills/native API architectures may reduce the long-term share of traffic
  routed through MCP gateways

### 2.3 Evidence Caution

These sources are useful framing inputs, not neutral final authority. They are
valuable because they articulate the architectural tradeoff clearly, not because
they settle market truth by themselves.

### 2.4 Verified Competitive Anchors (April 2026)

This document should distinguish clearly between official facts, inference, and
internal thesis.

- **Microsoft AGT:** official Microsoft materials describe an open-source
  runtime-security toolkit with Python, TypeScript, Rust, Go, and .NET
  packaging; a stateless policy engine; DID-based identity; Ed25519 support;
  and dynamic trust scoring.
  Source:
  `https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/`
- **OPA:** official OPA materials describe a general policy engine with
  structured input evaluation and decision logs.
  Sources:
  `https://www.openpolicyagent.org/docs` and
  `https://www.openpolicyagent.org/docs/management-decision-logs`
- **Cerbos:** official Cerbos materials describe a policy decision point
  exposed through API/SDK integrations across multiple languages.
  Source: `https://docs.cerbos.dev/cerbos/latest/api/index.html`
- **Spec-first API security:** API-security platforms such as 42Crunch show
  that OpenAPI-first governance is an operationally viable pattern, even if
  they are not agent-runtime attestation systems.
  Sources:
  `https://42crunch.com/api-security-platform/` and
  `https://docs.42crunch.com/latest/content/concepts/about_platform.htm`

Research discipline:

- do not repeat public metrics we cannot verify from primary sources
- do not present TAM/ARR scenario modeling as protocol research
- do not treat competitor caricatures as strategy

---

## 3. Problem Statement

Two incomplete security patterns are emerging:

### Pattern A: Gateway-Centric Enforcement

Strengths:

- deterministic chokepoint
- credential brokering and request/response inspection
- easy mental model for buyers and operators
- relatively clear deployment path for wrapped MCP traffic

Weaknesses:

- limited workflow context if decisions are made on isolated calls
- weaker visibility into delegation ancestry, prior steps, and session drift
- easy to overestimate coverage if agents can route around the gateway
- structurally tied to the protocol boundary it sits on

### Pattern B: Direct-Access / Native Monitoring

Strengths:

- richer behavioral context
- visibility into why an agent is acting, not just what endpoint it hit
- better suited to drift detection and dynamic escalation inputs

Weaknesses:

- often reactive rather than pre-execution
- can collapse into observability theater if it cannot block
- harder to explain as a deterministic control surface

### Core Tension

If a system can block but lacks enough context, it risks brittle enforcement or
a false sense of safety.

If a system can observe context but cannot gate execution, it risks becoming a
forensics product rather than a runtime security layer.

---

## 4. Chio Working Position

Chio should not choose between these patterns naively. The stronger Chio thesis
is:

1. deterministic governance is the minimum credible base layer
2. signed observability is required to make governance auditable and useful
3. dynamic governance should be treated as an optional higher layer, not as a
   prerequisite for the system to be valuable

In Chio terms:

- **Layer 1:** capabilities, guards, budgets, revocation, allow/deny
- **Layer 2:** receipts, lineage, traces, compliance bundles, operator reports
- **Layer 3:** future dynamic controls based on intent/risk/drift signals

This means Chio should aim to combine enforcement and context without claiming
that every risk can be solved through intent inference.

---

## 5. Key Architecture Questions

### 5.1 Is `chio mcp serve` the Product or the Wedge?

Working answer:

- it should be the wedge
- it should not define the platform boundary

Why:

- MCP is useful for adoption
- MCP-only security is structurally incomplete
- Chio becomes more defensible as more runtime surfaces feed the same kernel and
  receipt graph

### 5.2 Where Should Context Live?

Options:

- at the protocol gateway
- in the kernel session model
- in a separate behavioral analytics layer

Working direction:

- the kernel session model should be the canonical context substrate
- gateways and edges should feed it
- analytics can consume it, but should not become the primary source of truth

### 5.3 What Can Be Dynamic Without Becoming Hand-Wavy?

Likely candidates:

- volume anomalies
- workflow drift from declared session objective
- unusual tool-sequence changes
- unexpected domain/egress changes
- data movement across tool boundaries
- approval escalation triggers for high-risk operations

Bad candidate framing:

- vague "AI understands intent"
- opaque score-driven blocking with no auditability
- probabilistic controls presented as deterministic guarantees

### 5.4 How Much Protocol Breadth Is Enough?

Questions:

- is MCP + A2A + ACP-Client enough to cover the most important near-term runtime
  surfaces?
- how urgent is an OpenAI/native-function surface relative to ACP-Client edge work?
- should Chio define "native execution surfaces" as a first-class category
  separate from protocol adapters?

### 5.5 Is the Language Gap Real?

Working answer:

- yes
- the kernel can stay Rust-first, but adoption cannot
- day-one reach requires a sidecar plus language-native packaging
- Python first, TypeScript second, Go third is the most credible initial order

Implication:

- the HTTP/framework track in `HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md` is not
  optional DX garnish; it is the escape hatch from a Rust-only adoption story

### 5.6 Can OpenAPI Be a Universal Control Surface?

Working answer:

- OpenAPI is the strongest baseline control surface for ordinary HTTP APIs
- it is not ground truth for all runtime behavior
- it needs curation, overrides, and side-effect classification
- it does not replace protocol adapters for ACP-Client/editor surfaces, desktop tools,
  or native-function execution

Implication:

- Chio should frame OpenAPI as the best current wedge for HTTP/API governance,
  not as proof that every API route can or should become an agent tool

### 5.7 Which Guard Classes Should Fail Closed?

Working answer:

- request/response guards and session-aware deterministic guards can fail
  closed by default
- anomaly and sequence analysis should start as signed advisory signals or
  escalation inputs, not as magic hard-blocking AI
- product language should separate these classes instead of calling all of them
  "guards" as if they are operationally identical

---

## 6. Hypotheses To Test

### H1

Most buyers initially understand and purchase deterministic governance more
easily than dynamic runtime governance.

Implication:

- Chio should lead with enforceable controls and signed evidence, not intent AI

### H2

Buyers will still ask for richer context once they begin operating agents at
scale, especially after first incidents or audit requests.

Implication:

- signed observability is not optional decoration; it is the bridge from static
  controls to operational trust

### H3

MCP gateway products will become easier to sell than protocol-agnostic runtime
systems in the short term, but weaker as a long-term moat if execution moves to
native APIs and mixed protocol stacks.

Implication:

- Chio should use MCP to land, then expand aggressively into non-MCP surfaces

### H4

Many organizations will accept "deterministic governance + strong signed
observability" before they accept fully dynamic policy mutation at runtime.

Implication:

- Chio can be valuable before shipping intent-aware dynamic governance

---

## 7. Evaluation Criteria For Architectures and Vendors

When evaluating Chio or competitors, ask:

### Coverage

- What percentage of real agent runtime traffic is actually mediated?
- Which surfaces are out of scope: MCP, A2A, ACP-Client, native APIs, workstation
  tools, SaaS builders?
- Can agents bypass the control plane by using a different protocol or direct
  API path?

### Deterministic Enforcement

- Can the system block before execution?
- Are decisions capability- or policy-bound?
- Are allow/deny outcomes explicit and reproducible?

### Context Quality

- Does the system preserve session history?
- Can it connect actions across steps, tools, protocols, and delegated agents?
- Does it know the declared objective, approvals, and tool lineage?

### Evidence Quality

- Are logs mutable or signed?
- Is there an append-only or checkpointed ordering model?
- Can a third party verify evidence without trusting a vendor dashboard?

### Dynamic Governance

- Are dynamic controls optional or mandatory?
- What signals feed them?
- How are false positives and false negatives handled?
- Can the operator explain why a decision changed mid-session?

### Adoption

- Is deployment easy enough to wedge into current agent paths?
- Does the easiest deployment path create a false sense of total coverage?
- Is packaging broad enough to meet developers where they already build?

### Competitive Categories Worth Tracking

| Category | Representative systems | What they prove | What Chio still needs to prove |
|----------|------------------------|-----------------|-------------------------------|
| **Runtime governance** | Microsoft AGT | multi-language packaging and policy-engine DX matter | portable signed evidence and broader cross-surface lineage can justify a differentiated platform |
| **Policy decision points** | OPA, Cerbos | deterministic policy evaluation is well understood and operationally valuable | agent-native delegation, signed receipts, and economic controls matter enough to warrant a new layer |
| **API contract security** | 42Crunch and similar OpenAPI-first platforms | spec-driven governance is a viable wedge for HTTP APIs | session context, delegated authority, and post-action attestation can extend the model beyond plain API security |
| **Observability / forensics** | OTel, LangSmith, vendor dashboards | operators want traces, context, and investigation surfaces | enforcement plus signed portability is more valuable than observability alone |

---

## 8. Chio Architecture Directions To Explore

### Direction A: Stronger Session Context in the Kernel

Questions:

- should Chio sessions carry a declared objective hash or workflow intent field?
- should every protocol edge feed a normalized session-context object?
- should approvals and prompt bundle hashes be first-class kernel metadata?

### Direction B: Context-Aware Guards

Idea:

- guards remain deterministic functions, but can read richer session context

Examples:

- "delete is only allowed if the session objective includes cleanup"
- "high-volume export after low-volume read drift requires escalation"
- "tool sequence deviates from approved workflow template"

### Direction C: Signed Risk Signals

Idea:

- Chio could emit signed behavioral/risk observations without immediately turning
  them into block decisions

Why:

- preserves auditability
- avoids pretending dynamic governance is perfectly reliable
- allows operators to begin with alerting/escalation before hard blocking

### Direction D: Native-Surface Coverage

Idea:

- define adapters/edges not only for named protocols, but for major native
  execution surfaces such as function-calling APIs or framework-internal tool
  calls

Why:

- reduces the risk that Chio becomes "excellent at securing a shrinking slice"

### Direction E: Guard Taxonomy and Rollout

Idea:

- separate edge-local deterministic guards, session-aware deterministic guards,
  and signed advisory analytics into explicit product classes

Why:

- the implementation and buyer expectations are different
- only some classes should be fail-closed by default
- this prevents a false equivalence between SSRF blocking and probabilistic
  behavioral inference

---

## 9. Open Research Questions

- What is the minimum session context needed to make deterministic enforcement
  meaningfully safer than isolated request inspection?
- Which dynamic signals are reliable enough to operationalize first?
- How should Chio represent "declared intent" without relying on unverifiable
  natural-language summaries?
- Should Chio dynamic governance produce hard denies, soft escalations, or
  signed advisory signals first?
- Which surfaces are most urgent after MCP: A2A, ACP-Client, or native function
  calling?
- How should Chio measure real coverage versus perceived coverage in a customer
  deployment?

---

## 10. Research Backlog

### Short-Term

- map Chio's current shipped coverage by runtime surface
- document which session context fields already exist in the kernel
- compare MCP wrapped enforcement to hosted direct-access trust-control paths
- define an honest "coverage statement" template for docs and sales
- build a verified-vs-thesis competitor matrix that can be reused across docs

### Medium-Term

- design a normalized session-objective / approval / workflow-context model
- prototype context-aware guard inputs without introducing probabilistic logic
- design signed advisory risk observations
- compare ACP-Client and native-function adapters as the next non-MCP priority

### Longer-Term

- prototype dynamic escalation instead of binary allow/deny
- study how to bind behavioral signals into compliance artifacts without
  overstating certainty
- evaluate whether Chio needs a dedicated behavioral analytics subsystem or can
  keep this as a kernel + evidence-layer extension

---

## 11. Current Working Conclusion

The most credible Chio position today is:

- deterministic governance first
- signed observability second
- dynamic governance third
- protocol-agnostic coverage as the long-term requirement
- moat claims as differentiation theses, not universal absolutes
- TAM/ARR modeling in separate strategy material unless externally sourced

Chio should land via wrapped MCP enforcement, but it should not describe itself
as merely an MCP gateway. The deeper product is a kernel-centered runtime
governance and evidence system that becomes more valuable as agent execution
spreads across protocols and native surfaces. The HTTP/framework adoption track
is part of that same coverage story, not a separate product identity.
