# Review Findings and Next Steps

> **Internal engineering backlog:** Findings below are review inputs and
> prioritization notes for the team. They are **not** a statement of unfixed
> production bugs for customers or partners. Tracked release risks:
> [RISK_REGISTER.md](../release/RISK_REGISTER.md).

> **Date**: April 2026
> **Source**: Six parallel review agents covering blind spots, DX/adoption,
> economic model, production reality, standards/compliance, and future ideas.
> All findings grounded in actual codebase state.

---

## Executive Summary

The documentation effort produced 25+ design docs covering integrations,
guard absorption, and architectural extensions. This review found:

- **3 structural security gaps** that no amount of guards will fix
- **4 critical DX blockers** preventing any external adoption
- **A surprisingly deep economic layer** (7 crates) that is undocumented
- **The strongest compliance story is EU AI Act**; FedRAMP and PCI DSS are the biggest blockers
- **Coding agents are the clearest onboarding path** -- should be P0
- **Human-in-the-loop is needed by 6/10 production patterns** but rated P2

---

## 1. Structural Security Gaps (Red Team)

These require architecture work, not new guards:

### 1.1 TOCTOU in the Wrapper Pattern (CRITICAL)

Between `evaluate()` returning Allow and the tool actually executing,
there is an unbounded window. Capability could be revoked, budget
exhausted, or time-expired. The agent can delay execution, replay the
verdict, or substitute a different tool call.

**Fix options:**
- Short-lived execution nonce bound to the verdict (must be presented
  within N seconds to the tool server, which validates with kernel)
- Kernel-dispatched execution (kernel calls tool server directly, agent
  never touches the verdict) -- this is the native Chio transport but
  no framework integration uses it

### 1.2 Agent Memory Is Ungoverned (HIGH)

Chio governs tool calls but not what agents write to their own memory
stores (vector DBs for RAG, conversation history, scratchpad files).
Poisoned context = indirect prompt injection across sessions.

**Fix options:**
- Memory-write constraints: new `Constraint` variants scoping what an
  agent can store (key patterns, content size, retention TTL)
- Memory-read governance: receipts for memory reads, not just tool calls
- Cross-session context integrity: hash chain of memory writes linked
  to receipts

### 1.3 Sidecar Bypass in Wrapper Pattern (HIGH)

In the wrapper integration pattern (all 9+ framework integrations),
nothing prevents the agent from calling tools directly without going
through the sidecar. This is "governance by convention."

**Fix options:**
- Honest documentation: trust-level taxonomy distinguishing "mediated"
  (kernel dispatches) from "advisory" (agent calls sidecar)
- Tool server authentication: tool servers reject calls without a
  valid receipt-intent token from the kernel
- Network-level enforcement: tool server only accepts connections
  from the kernel sidecar (firewall, mTLS, Envoy ext_authz)

### 1.4 Other Red Team Findings

| Finding | Severity | Fix |
|---------|----------|-----|
| No WASM guard module signing | High | Add Ed25519 signing to guard manifests |
| No emergency kill switch (global revocation) | High | Agent-level and global circuit breaker on kernel |
| Multi-tenant isolation incomplete | High | Tenant-scoped budgets, receipts, guard configs |
| Model metadata is self-reported, unverifiable | Medium | Attestation from inference provider, not agent |
| No hardware-backed agent identity (TPM/enclave) | Medium | Extend DPoP with hardware attestation |
| Cross-session behavioral detection absent | Medium | Anomaly detection over receipt streams |

---

## 2. Developer Experience Blockers (DX Review)

### 2.1 Nothing Published to Package Registries (CRITICAL)

No PyPI packages, no npm packages. A developer cannot `pip install`
anything. Zero organic discovery. Every SDK is path-referenced. This is
the single largest adoption blocker.

**Fix:** Publish `chio-sdk-python`, `chio-fastapi`, `chio-langchain` to
PyPI. Publish `@chio-protocol/node-http` to npm. Automated CI publishing.

### 2.2 No Testing Without the Kernel (HIGH)

No `MockChioClient`, no `allow_all()` test fixture, no dry-run mode.
Every SDK call requires a running Rust binary.

**Fix:** Ship `chio_sdk.testing` module with `MockChioClient` that returns
configurable verdicts without network calls.

### 2.3 No 5-Minute Quickstart for Python/TS Devs (HIGH)

Requires compiling Rust or authenticating to private GHCR. A Python
developer cannot try Chio without a Rust toolchain.

**Fix:** Pre-built binaries (homebrew, cargo-binstall, GitHub Releases).
Public Docker image. `npx chio-sidecar` or `uvx chio-sidecar` one-liner.

### 2.4 Zero Framework Integrations Ship as Code (HIGH)

9+ framework design docs but only `chio-langchain` exists as a package.
Nothing for CrewAI, AutoGen, LlamaIndex, or Vercel AI SDK.

**Fix:** Ship at least one framework integration as a working package
with tests. CrewAI is highest priority (largest mindshare, worst default
trust model).

### 2.5 Other DX Findings

- Error messages lack "what to do next" guidance
- Receipt dashboard exists but is buried (`chio trust serve`)
- Migration from MCP is possible but not documented as a guide
- The "zero code change" sidecar story is genuinely strong but not the
  first thing developers see
- Competitive DX gap: "just use API keys" is zero new infrastructure;
  Chio is 100x more setup for the first tool call

---

## 3. Economic Layer (Undocumented Asset)

Chio has 7 economic crates that the documentation effort completely missed:

| Crate | What it does |
|-------|-------------|
| `chio-metering` | Per-receipt cost attribution, budget enforcement, billing export |
| `chio-credit` | Credit risk management, exposure ledger, credit facilities, bonds |
| `chio-underwriting` | 4-tier agent risk classification, 13 reason codes, evidence-based |
| `chio-market` | Liability marketplace, 5 coverage classes, quote/bind/claims workflow |
| `chio-settle` | On-chain settlement (EVM + Solana), escrow, cross-chain (CCIP) |
| `chio-listing` | Tool server / credential issuer / provider registry |
| `chio-open-market` | Decentralized marketplace economics, bonds, penalties, governance |

### Economic Gaps

1. **Agent-to-agent payment routing** -- metering covers agent-to-tool-server
   but not peer-to-peer agent payments
2. **Dynamic pricing / discovery** -- no price comparison, auction, or
   negotiation protocol for tool access
3. **Hierarchical budget governance** -- no per-team / per-project budget
   trees for enterprise fleet management
4. **Economic threat model** -- no formal analysis of budget exhaustion
   attacks, price manipulation, or Sybil attacks
5. **Federated fiscal composition** -- the primitives exist for namespace-scoped
   economic zones but the composition guide is missing

---

## 4. Production Pattern Coverage

| Pattern | Coverage | Key Gap |
|---------|----------|---------|
| **Coding agents** (Cursor, Claude Code) | Best covered | Ship `chio-code-agent` as P0 onboarding |
| **Customer support agents** | Partial | Content-plane governance, HITL escalation |
| **Data analysis agents** | Not covered | Data layer constraints (blocking gap) |
| **Multi-agent swarms** | Well covered architecturally | Swarm-level aggregate budgets |
| **Sales/CRM agents** | Mostly gapped | ExternalApiCall, RecipientAllowlist |
| **Infrastructure agents** | Recognized, not built | Plan/apply two-phase capability |
| **Security operations agents** | Partial | Escalation protocol for remediation |
| **Research agents** | Mostly covered | Citation tracking |
| **Voice/phone agents** | Not mentioned anywhere | Sub-10ms eval latency not a design goal |
| **Autonomous trading agents** | Partial | Position limits, market-hours constraints |

**Most common patterns today:** Coding agents and customer support.
Chio should optimize the onboarding path for coding agents first.

**Human-in-the-loop is needed by 6/10 patterns** (customer support,
CRM, infrastructure, SecOps, trading, data analysis) but is currently
rated P2. Should be P0.

---

## 5. Standards and Compliance

| Framework | Status | Blocker? |
|-----------|--------|----------|
| **EU AI Act** | Covered (clause-by-clause mapping exists) | No |
| **Colorado SB 24-205** | Covered (test-backed mapping) | No |
| **SOC 2 Type II** | Partially covered (session compliance cert) | Mapping doc needed |
| **NIST AI RMF** | Partially covered (primitives exist, no mapping doc) | P1 doc task |
| **ISO 42001** | Partially covered (technical controls exist) | P1 doc task |
| **OWASP LLM Top 10** | Partially covered (3 of 10 are model-layer, out of scope) | Content safety gap |
| **HIPAA** | Partially covered (PII guards, column constraints) | BAA framework needed |
| **MITRE ATLAS** | Partially covered (tool-layer attacks covered) | Model-layer blind spots expected |
| **PCI DSS** | Not covered | Mapping doc + financial constraints needed |
| **FedRAMP** | Not covered | FIPS 140-2 crypto, HSM integration required |
| **California SB 1047** | Not covered | Mapping doc needed |

**Top compliance blockers for enterprise adoption:**
1. FedRAMP (FIPS crypto requirement -- Ed25519 needs FIPS validation path)
2. PCI DSS (no mapping, financial constraints unbuilt)
3. NIST AI RMF / ISO 42001 (mapping docs are small effort, high impact)

---

## 6. Future Ideas (Competitive Moats)

### Near-Term (build now, leverages existing primitives)

| Idea | Feasibility | Defensibility |
|------|-------------|---------------|
| **Receipt as proof-of-safe-behavior** | High -- receipts already signed and Merkle-committed | Strong -- no competitor has per-invocation attestations |
| **Agent behavioral profiling** | High -- receipt store has reporting queries | Strong -- receipt data is proprietary to Chio |
| **Regulatory API** | High -- `SignedExportEnvelope` exists | Medium -- packaging exercise |
| **Agent versioning / rollback** | Trivial -- field addition to WorkloadIdentity | Low standalone, table stakes |

### Medium-Term (6-12 months, strongest moats)

| Idea | Feasibility | Defensibility |
|------|-------------|---------------|
| **Agent insurance protocol** | High -- `chio-underwriting` is remarkably mature | Very strong -- typed risk taxonomies for agent behavior |
| **Cross-kernel federation** | Medium -- choreography receipts show the pattern | Strong -- bilateral receipt chains are unique |
| **Capability marketplace** | Medium -- `chio-market` + `chio-listing` exist | Medium -- requires network effects |
| **Agent passport** | Medium -- needs `chio-kernel-core` WASM first | Strong if Chio becomes the standard |
| **Natural language policies** | Medium -- LLM compiles English to HushSpec | Medium -- anyone can build this |
| **Agent constitution** | Medium -- HushSpec is the compiled form | Medium |

### Long-Term (research)

| Idea | Feasibility | Defensibility |
|------|-------------|---------------|
| **Federated receipt verification (ZK)** | Low -- needs circuit design, proving infra | Very strong |
| **Compute attestation (TEE)** | Low -- depends on hardware vendor SDKs | Strong for regulated verticals |

---

## 7. Recommended Priority Adjustments

Based on all six reviews, the coverage map priorities should shift:

| Item | Current Priority | Recommended | Why |
|------|-----------------|-------------|-----|
| Human-in-the-loop protocol | P2 | **P0** | Needed by 6/10 production patterns |
| PyPI/npm publishing | Not listed | **P0** | Single largest adoption blocker |
| `chio-code-agent` adapter | P1 (desktop scoping) | **P0** | Best-covered pattern, fastest onboarding |
| MockChioClient / test fixtures | Not listed | **P0** | Blocks all framework integration work |
| Pre-built binary distribution | Not listed | **P1** | Blocks quickstart without Rust toolchain |
| TOCTOU fix (execution nonces) | Not listed | **P1** | Structural security gap |
| WASM guard module signing | Not listed | **P1** | Running unsigned code in policy path |
| Emergency kill switch | Not listed | **P1** | No global circuit breaker |
| Voice/phone agent latency | Not listed | **P2** | Emerging pattern, needs WASM kernel first |
| Agent memory governance | Not listed | **P2** | Cross-session poisoning attack |
| Economic layer developer guide | Not listed | **P1** | Overview doc exists; developer how-to and budget hierarchy gap remain |
| FIPS crypto path | Not listed | **P1** | Blocks government/regulated adoption |
