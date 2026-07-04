# Chio: Vision and Strategic Narrative

This document is strategic narrative, not the authoritative claim gate. The
current authoritative technical claim is the universal control-plane thesis
on the qualified authoritative surfaces, and the repo also qualifies a
stronger local economic boundary: Chio is comptroller-capable software on the
documented operator, partner, and bounded federated proof surfaces. The
broader market-position story remains strategic rather than proved. See
[docs/release/QUALIFICATION.md](../release/QUALIFICATION.md).

Chio is pre-release. The current Chio-owned protocol, schema, SDK, and runtime
surfaces are v1-only. Roadmap labels in this narrative are internal
milestones, not protocol or wire compatibility versions.

---

## 1. The Problem

The agent economy is no longer speculative. McKinsey projects $3-5 trillion in annual value from AI agents by 2030. Enterprises are deploying agents that move money, modify infrastructure, sign contracts, and operate across organizational boundaries. The tooling layer these agents depend on was never designed for any of this.

MCP -- the Model Context Protocol -- is a dumb pipe. It defines how an agent calls a tool. It says nothing about who the agent is, what it is allowed to do, whether the action was authorized, or what proof exists that anything happened. There is no identity. There is no delegation. There is no receipt. There is no revocation. MCP is a function-call wire format masquerading as infrastructure.

This is not an incremental gap. It is a structural absence.

**The consequences are already visible:**

- **A significant portion of organizations have zero audit trail** for agent actions (industry surveys estimate roughly one-third). When an agent modifies a production database, creates a financial transaction, or accesses patient records, there is no cryptographic proof it was authorized to do so and no signed record of what it did.

- **Hundreds of millions in unbudgeted agent spend** have leaked across the Fortune 500 as autonomous workloads scale without governance (Flexera's 2025 State of the Cloud report documents widespread cloud cost overruns, with agent workloads a growing contributor). Agents operate without spending caps, without delegation chains that track cost responsibility, and without budget enforcement at the protocol level.

- **Six competing payment protocols** -- ACP-Commerce, AP2, x402, MPP, TAP, Agent Pay -- are racing to wire money between agents. None of them solve the prerequisite problem: proving that the agent was authorized to spend, that the action it paid for actually occurred, and that the receipt is cryptographically bound to the authorization chain that permitted it.

Payment without authorization is just a pipe to a wallet. Authorization without proof is just a policy document nobody can verify after the fact. The agent economy needs both, and it needs them fused at the protocol layer.

No existing protocol combines identity, capability delegation, economic
primitives, and non-repudiable receipts into a single coherent system on the
qualified authoritative surfaces Chio now governs.

Chio now does.

---

## 2. Chio's Position

> **MCP tells agents how to call tools. Chio proves what they were allowed to do, what it cost, and what happened.**

Chio is not a security layer bolted onto MCP. It is not a wrapper, a proxy, or
an audit sidecar. Chio is what you need when agents do real things, when the
action has consequences, when someone needs to know it was authorized, what it
cost, and when a machine-verifiable proof must exist after the fact.

**The core primitive is non-repudiation.** Each mediated action that flows through Chio
produces a signed, timestamped, capability-bound receipt. That receipt is not a
log line. It is a cryptographic attestation: a specific capability token was
exercised to invoke this tool, with these parameters, and the kernel rendered
this decision. The receipt references the capability by ID, and the full
authorization chain is reconstructable by looking up the capability token.

This is what separates Chio from everything else in the landscape:

| Dimension | What it means | Why it matters |
|-----------|---------------|----------------|
| **Identity** | Every agent, tool server, and authority has a cryptographic identity bound to Ed25519 keys | You cannot authorize what you cannot identify. You cannot revoke access from an anonymous caller. |
| **Capability delegation** | Time-bounded, attenuated, revocable tokens that flow through delegation chains with monotonic attenuation | An agent that can read your database should not be able to write to it. An agent authorized for 10 invocations should not be able to delegate 100. Delegation must only narrow, never amplify. |
| **Economic primitives** | Per-grant budgets, constraint-based parameter narrowing, spending limits that travel with the capability token | The authorization layer IS the spending authorization. The delegation chain IS the cost-responsibility chain. |
| **Receipts** | Signed, append-only attestations for every allow, deny, cancel, and incomplete outcome | The receipt log has the structure of an audit trail, a billing ledger, and a compliance record. One data structure, three functions. |

Chio occupies the authorization and attestation layer. It sits above any payment
rail, below any agent framework, and beside any identity provider. It is the
layer that answers: was this agent allowed to do this, what did it cost, and
can you prove it?

---

## 3. What Chio Already Has

This is not a pitch deck for vaporware. Chio is a shipped and tested protocol
implementation with real runtime governance surfaces, signed receipts, and a
substantial implementation-linked formal-methods track. The formal claim is
precise: Chio's security-critical protocol semantics are mechanically checked
subject to published audited assumptions, while platform and external-service
behavior stays inside the explicit trusted boundary. Here is what exists
today:

### Kernel as Trusted Computing Base

The agent never reaches the tool server on Chio's governed authoritative paths.
Every governed tool invocation flows through the Chio kernel, a trusted
mediator that validates capability tokens, runs the guard pipeline, and signs
receipts. The agent does not know the kernel's address, PID, or keys. This is
not defense in depth. It is architectural privilege separation.

### Seven Composable, Fail-Closed Guards

The guard pipeline runs in sequence. If any guard denies, the pipeline denies. Every denial produces signed evidence. The seven shipped guards:

| Guard | Function |
|-------|----------|
| `forbidden-path` | Blocks access to sensitive filesystem paths |
| `shell-command` | Blocks dangerous shell commands |
| `egress-allowlist` | Controls network egress by domain |
| `path-allowlist` | Allowlist-based path access with session-root enforcement |
| `mcp-tool` | Restricts MCP tool invocations by name and pattern |
| `secret-leak` | Detects secrets in file writes |
| `patch-integrity` | Validates patch safety before application |

Guards are composable. Operators configure them through HushSpec policy files.
The pipeline is fail-closed by design. Core capability properties have formal
support in the Lean track, the pure Rust decision core is the implementation
linkage target, and side-effecting runtime closure is defended through executed
qualification lanes plus audited assumptions.

### Cascade Revocation Through Delegation Chains

Revoking a capability token revokes every token delegated from it on the
supported runtime path. This is not a best-effort propagation. It is a
structural property of the delegation chain: the kernel checks ancestor links
on invocation and fails closed when revocation state invalidates the chain.
This is a runtime-qualified property, not a current theorem-prover claim over
the full Rust revocation-store path.

### Subject-Bound Tokens

Capability tokens are bound to the agent's cryptographic identity. A token
stolen without the subject key is worthless to a different principal. Subject
binding eliminates bearer-token replay across principals; per-invocation DPoP
is the follow-on hardening that adds freshness and nonce replay resistance.

### Receipt DAG

Receipts are not flat. Nested operations -- an agent calling a tool that calls another tool -- produce parent-child receipt chains. The receipt DAG preserves the full lineage of every operation, including who authorized each step, what capability was exercised, and what the kernel decided. This is the foundation for cost attribution, compliance reporting, and dispute resolution.

### Per-Grant Budgets with Constraint Narrowing

Every grant in a capability token can carry invocation limits and parameter
constraints. Delegation can tighten these constraints but never loosen them. An
agent authorized to read files in `/data/reports` cannot delegate access to
`/data/`. An agent with a 10-invocation budget cannot delegate a 20-invocation
budget. Monotonic attenuation is supported by bounded Lean mechanization over
the current verified-core model plus executable differential tests. Budget
mutation now has a bounded model for the precheck/commit decision, while
settlement-side state transitions remain assumption-bound outside the pure
protocol core.

### Formal Evidence Boundary

Chio has an implementation-linked formal evidence boundary. The
machine-readable boundary is `formal/proof-manifest.toml`, audited external
contracts live in `formal/assumptions.toml`, theorem coverage lives in
`formal/theorem-inventory.json`, and public claim rules live in
`docs/reference/CLAIM_REGISTRY.md`.

The current formal evidence supports:

- **P1 capability attenuation**: Lean mechanization over the verified-core
  model plus executable differential tests.
- **P2 revocation denial**: Lean proofs that revoked tokens and
  revoked presented ancestors cannot pass the pure revocation/evaluation
  model.
- **P3 fail-closed evaluation**: Lean proofs that the pure evaluator and
  adjacent admission models deny invalid signatures, invalid time windows,
  revoked capabilities, revoked ancestors, out-of-scope requests, invalid DPoP,
  invalid session anchors, exhausted budgets, and missing approvals.
- **P4 receipt and checkpoint properties**: symbolic Lean proofs and runtime
  receipt-signing tests. This is not a proof of the concrete Ed25519 or
  SHA-256 implementations.
- **P5 presented delegation-chain structure**: bounded model theorems for
  presented chains, not a proof of every runtime graph or store behavior.
- **P6 local parent-link soundness**: observed parent edges require a parent
  request in the same authenticated session.
- **P7 receipt-lineage soundness**: verified lineage requires verifying both
  receipts, trusted kernel signature, and signed linkage.
- **P8 session continuity soundness**: verified continuity requires a valid
  session anchor and continuation artifact.
- **P9 delegation/provenance consistency**: verified call chains require
  consistent subjects and parent capability references.
- **P10 report truthfulness**: reports and exports cannot upgrade asserted or
  observed evidence into verified evidence.

The current release does not claim first-principles proofs of crypto
libraries, OS clocks, TLS, SQLite, subprocess isolation, hosted registries,
external chains, clustering, or settlement. Those surfaces are defended through
audited assumptions, Rust tests, conformance tests, smoke tests, release
qualification, and the strict Rust verification lanes declared for
Creusot/Kani.

### HA Distributed Control Plane

The trust control plane -- capability authority, revocation store, budget store, receipt store -- runs in a leader/follower HA configuration with durable sequence-based replication. Budget writes advance on monotonic sequence numbers. Failover preserves invariants. This is tested through a repeat-run qualification lane that proves deterministic behavior under leader transitions.

### Qualified MCP Adapter Coverage

Chio wraps existing MCP servers on the adapter paths qualified by the current
repo. The adapter covers core tool invocation and selected MCP surfaces where
Chio can preserve its control boundary: capability evaluation before dispatch,
guard evidence, and signed receipts. MCP features that execute outside Chio's
decision path, depend on remote provider semantics, or lack current
qualification remain future or detect-only work rather than full compatibility
claims. Existing deployments can still migrate incrementally by wrapping MCP
servers first, then adding deeper policy and receipt coverage as surfaces are
qualified.

---

## 4. The Agent Economy Thesis

The strategic insight is this: Chio does not need a second identity to serve
the agent economy. What it already is maps directly to economic
infrastructure.

**Capability tokens ARE programmable spending authorizations.**

A capability token says: this agent can invoke these tools, with these parameters, subject to these constraints, until this time, with this invocation budget. That is not an access control token. That is a spending authorization -- scoped, time-bounded, delegatable, and revocable. Once monetary budgets ship (Q2 2026 roadmap), the difference between "you can call the `transfer_funds` tool with `max_invocations: 50`" and "you are authorized to spend up to $500" is a label, not a redesign.

**Delegation chains ARE cost-responsibility chains.**

When Agent A delegates a capability to Agent B, the delegation chain records who authorized whom, with what constraints, at what time. This is exactly the data structure needed for cost attribution. When Agent B consumes 200 invocations under a capability delegated by Agent A (or, with monetary budgets, spends $200), the receipt chain traces the authority back to the original grant. Chargebacks, cost allocation, and budget reconciliation fall out of the existing data model.

**The receipt log has the structure of a billing ledger.**

Every mediated decision receipt records: the capability that authorized the action, the tool that was invoked, the parameters that were passed, the authorization decision, the timestamp, and the kernel's cryptographic signature. Trace and advisory receipts record observation semantics and outcomes instead of authorization decisions. When monetary budgets are added (see Roadmap), mediated receipts can become billing events with no transformation required. The receipt log is a pre-audited, cryptographically signed, append-only ledger that happens to also be a compliance record and an operational audit trail. Merkle commitment plus signed checkpoint publication over the receipt log is the planned enhancement that adds tamper-evident ordering guarantees and portable verification.

**The guard pipeline IS a compliance engine.**

Rate limits, spending caps, parameter constraints, egress restrictions, path allowlists, secret detection -- these are not just security controls. They are compliance controls. SOC 2, HIPAA, PCI-DSS, and SOX all require demonstrable access controls with audit evidence. The guard pipeline produces exactly this: a signed record of every control that was evaluated, every decision that was made, and every piece of evidence that informed the decision.

**Chio's position:** the authorization and attestation layer that sits above any
payment rail. Agents will pay for things through many payment protocols. Chio
does not compete with those protocols. It answers the questions they cannot:
was the agent authorized to pay, can you prove it, who delegated the
authority, what constraints applied, and what signed evidence exists?

---

## 5. The Agent Reputation Vision

Chio already emits the core behavioral data needed for agent reputation. Once
the runtime persists a local capability-lineage index and a per-grant
attribution path, the system can compute useful trust scores without
introducing external telemetry. The receipts are the primary data source.

### Behavioral Metrics from Existing Receipts

- **Reliability:** ratio of successful completions to total invocations, computed from receipt outcomes
- **Compliance:** ratio of clean passes through the guard pipeline to total evaluations, computed from guard evidence
- **Scope discipline:** frequency of out-of-scope or over-budget attempts, computed from deny receipts
- **Delegation hygiene:** depth and breadth of delegation chains, constraint tightness, computed from capability token metadata
- **Operational pattern:** tool usage distribution, invocation frequency, time-of-day patterns, computed from receipt timestamps and tool identifiers

### Agent Passports

Agent reputation materializes as a W3C Verifiable Credential: an Agent
Passport. The passport is a portable, cryptographically signed attestation of
an agent's behavioral track record, issued by a Chio-participating authority
and verifiable by any relying party.

The current shipped surface already supports offline verification,
relying-party policy evaluation, filtered disclosure, challenge-bound holder
presentations, portable verifier-policy distribution, replay-safe challenge
state, and multi-issuer passport composition. The unfinished pieces are
status, distribution, revocation, and broader wallet/ecosystem semantics.

The passport carries:
- Cumulative reliability and compliance scores
- Tool categories the agent has operated in successfully
- Maximum delegation depth the agent has been trusted with
- Budget ceiling the agent has operated under without violation
- Time-in-service and volume metrics

### A Credit-Bureau-Like Trust Layer

If enough operators adopt the model, every receipt that flows through Chio
contributes to a behavioral dataset that no other protocol produces. Over
time, that dataset could support a credit-bureau-like trust layer for AI
agents: a portable way to answer "should I trust this agent with this
capability?"

Graduated authority follows naturally. An agent with 10,000 clean receipts, zero guard violations, and a track record of operating within budget constraints earns higher trust. It gets longer TTLs, deeper delegation authority, and higher budget ceilings. An agent with a history of out-of-scope attempts, budget overruns, and guard denials gets shorter leashes.

This is not a reputation system bolted onto Chio after the fact. It is a
computation over the data Chio already produces as a side effect of doing its
primary job, provided the local join substrate is made explicit in the
implementation plan.

---

## 6. Competitive Landscape

| Capability | **Chio** | **A2A** | **MCP** | **ANP** | **x402** | **AP2** | **IETF Drafts** |
|------------|----------|---------|---------|---------|----------|---------|-----------------|
| **Cryptographic identity** | Ed25519 per-principal | Signed Agent Cards | None | DID-based crypto identity | None | None | Proposed |
| **Capability delegation** | Attenuated, time-bounded, chain-tracked | None | None | None | None | None | None |
| **Budget/spending controls** | Per-grant, constraint-narrowing | None | None | None | Payment only | Payment only | None |
| **Signed receipts** | Every outcome, signed and append-only | None | None | None | Payment receipt | Payment receipt | None |
| **Cascade revocation** | Delegation-chain-aware, runtime-qualified | None | None | None | None | None | None |
| **Cross-org trust** | Delegated capability chains with subject binding | OAuth-based | None | Directory-based | None | None | Proposed |
| **Formal verification** | Implementation-linked P1-P10 core with audited assumptions | None | None | None | None | None | None |
| **Fail-closed guarantee** | Runtime-tested and fail-closed by design | Implementation-dependent | No enforcement layer | Implementation-dependent | N/A | N/A | Proposed |
| **Guard pipeline** | 7 composable guards with evidence capture | N/A | N/A | N/A | N/A | N/A | N/A |
| **MCP compatibility** | Qualified wrap-and-run adapter paths | N/A | Native | N/A | N/A | N/A | N/A |

The competitive picture is clear. Payment protocols solve payment. Discovery
protocols solve discovery. Communication protocols solve communication. None of
them solve authorization, attestation, and non-repudiation. Chio is the layer
that treats every agent action as a provable event with cryptographic
identity, scoped authority, and signed evidence.

---

## 7. Strategic Roadmap

The roadmap is now organized around the Chio milestone ladder rather than the
older pre-rename quarterly sketch:

- **v2.5 Chio Rename and Identity Realignment:** finish the rename as a
  compatibility program, not a cosmetic rebrand
- **v2.6 Governed Transactions and Payment Rails:** turn the economic-security
  thesis into governed transaction intent, truthful settlement linkage, x402
  and ACP-Commerce/SPT bridges, and operator-visible reconciliation
- **v2.7 Portable Trust, Certification, and Federation Maturity:** finish
  passport lifecycle, certification discovery, enterprise identity propagation,
  and conservative cross-org trust distribution
- **v2.8 Risk, Attestation, and Launch Closure:** add insurer-facing behavioral
  feeds, attested runtime assurance tiers, proof/spec closure, and a real GA
  decision

The sequence matters. Chio first becomes one coherent product, then makes
economic governance real, then makes trust portable, then makes that evidence
strong enough for underwriting, standards, and public claims.

---

## 8. The Flywheel

Chio's strategic position creates a self-reinforcing adoption cycle. Each stage
feeds the next.

```
                    Protocol Adoption
                   /                  \
                  /                    \
    More adoption &                     Receipt Data
    higher stakes                       accumulates
         |                                   |
         |                                   |
    Insurance &                          Certification
    economic integration                 becomes possible
         |                                   |
         |                                   |
    Underwriting                        Underwriting
    data exists                         data grows
                  \                    /
                   \                  /
                    Reputation Network
```

**Stage 1: Protocol adoption.** Teams adopt Chio because they need
authorization and audit for agent operations. Every wrapped MCP server, every
native tool, and every delegated capability generates receipts.

**Stage 2: Receipt data accumulates.** The receipt log grows. Behavioral patterns emerge. Reliability scores, compliance rates, scope discipline metrics -- all computable from data that already exists.

**Stage 3: Certification becomes possible.** With enough receipt data, Chio
Certify can issue meaningful attestations: this tool server is well-behaved,
this agent has a clean track record, and this delegation pattern is safe.
Certification is not a checkbox. It is a statistical claim backed by
cryptographic evidence.

**Stage 4: Underwriting data grows.** Certification data is actuarial data. An insurer can now answer: what is the probability that this agent, operating under these constraints, with this behavioral history, will cause a loss exceeding $X? The receipt log is the dataset that makes this computation possible.

**Stage 5: Insurance and economic integration.** Agent operations become insurable. Insurable operations attract higher-value use cases. Higher-value use cases demand stronger authorization and more granular receipts. The cycle accelerates.

**Stage 6: More adoption at higher stakes.** Organizations that previously
kept agents away from consequential actions such as financial transactions,
healthcare decisions, legal operations, and infrastructure changes begin
deploying agents with Chio because the authorization, attestation, and
insurance infrastructure makes it safe to do so.

The flywheel is self-reinforcing because each stage produces the input the next stage requires. Receipt data enables certification. Certification enables underwriting. Underwriting enables insurance. Insurance enables higher-stakes adoption. Higher-stakes adoption produces more receipt data.

The data moat deepens with every receipt. No competitor can replicate this
dataset without first building the authorization and attestation layer that
produces it. By the time they do, Chio's behavioral dataset will be the
largest, most granular, and most cryptographically rigorous record of agent
operations in existence.

---

## The Bet

Chio is a bet on a specific future: one where AI agents are economic actors with
real authority, real budgets, and real consequences. In that future, the
protocols that win are not the ones that help agents call functions. They are
the ones that prove what happened when agents did things that mattered.

Chio is that layer: the authorization layer, the attestation layer, the proof
layer, and the evidence layer that makes agent operations auditable,
insurable, and trustworthy.

The infrastructure is built. The proofs compile. The receipts are signed. What remains is execution.
