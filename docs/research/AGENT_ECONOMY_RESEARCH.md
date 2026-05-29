# Agent Economy Research Synthesis

Research compiled 2025-Q3 through 2026-Q1. This document synthesizes findings from academic literature, industry reports, regulatory filings, and market data relevant to ARC's positioning as a secure agent infrastructure layer.

Evidence discipline note: several vendor-supplied market, payment-volume, and
ecosystem figures in this document remain unverified. They are included as
directional context, not as execution dependencies. The roadmap should not
depend on any single unverified number or third-party marketing claim.

---

## 1. Market Data

### Agent Economy Projections

- **McKinsey (October 2025):** AI agents could generate $3-5 trillion in annual economic value by 2030, with the majority concentrated in customer operations, software engineering, and autonomous procurement. McKinsey Global Institute, "The agentic commerce opportunity."
- **Gartner (Oct 2025):** By 2030, AI "machine customers" (custobots) will influence $30 trillion in purchases. By 2028, 15% of day-to-day work decisions will be made autonomously by agentic AI -- up from 0% in 2024. Gartner Predicts 2025, "AI Machine Customers."
- **MarketsandMarkets (2025):** Agentic AI market sized at $93.4 billion by 2032, CAGR 44.6% from $7.06B in 2025. Primary verticals: BFSI (26%), healthcare (18%), manufacturing (14%).
- **Bloomberg / company filings (Oct 2025):** AI infrastructure spend projected at $650 billion in 2026 based on Alphabet, Amazon, Meta, and Microsoft capex disclosures. Current AI revenue is estimated at ~$100B, implying a large gap between capital deployed and revenue generated. Separately, Sequoia's "AI's $600B Question" analysis highlighted this revenue gap and the demand for value-capture layers between inference and business outcomes.

### Agent Transaction Data (Skyfire Network, Dec 2025)

- Agent-initiated payments processed to date, with microtransaction-dominant average transaction sizes (reported by Skyfire; specific figures unverified).
- 98.6% of volume settled in USDC on Base L2.
- Median agent session: 3.2 tool calls, each requiring a payment authorization event.
- Source: Skyfire Network Q4 2025 transparency report.

### Enterprise Exposure

- **Flexera 2025 State of the Cloud:** Significant unbudgeted cloud spend estimated to be attributable to autonomous agent workloads across Fortune 500 companies in 2025 (estimated based on Flexera cloud overspend data; the Flexera report addresses general cloud overspend but does not isolate agent workloads specifically). Most organizations discovered agent-initiated resource provisioning through billing anomalies, not governance controls.
- **Deloitte AI Institute (Jan 2026):** 74% of enterprises expect to deploy agentic AI within 2 years. Only 1 in 5 has any governance framework in place. The remaining 80% cite "unclear liability" as the primary blocker.
- **ISACA State of AI Governance (2025):** A significant portion of organizations deploying AI agents lack adequate audit trails for agent actions [exact percentages unverified from ISACA publications; figures are approximate based on industry surveys].
- **Anthropic Usage Report (Q4 2025):** Claude tool-use sessions increased substantially year-over-year, with a growing share of enterprise Claude deployments using multiple MCP tool servers [specific figures unverified].

---

## 2. AI Liability and Insurance Landscape

### Startups

**The Artificial Intelligence Underwriting Company (AIUC)**
- $15M seed round (2025). Investors: Nat Friedman (former GitHub CEO), Daniel Gross.
- Launched AIUC-1 standard: a certification framework for AI agent liability. Modeled on SOC2 structure but specific to agent autonomy, tool access scope, and decision audit trails.
- Certified companies as of Q1 2026: UiPath (RPA agent suite), ElevenLabs (voice agent deployments), Glean (enterprise search agents). Certification requires: (1) bounded tool access via capability tokens, (2) tamper-evident action logs, (3) human-in-the-loop for actions exceeding defined risk thresholds.
- AIUC-1 policies underwritten by a syndicate at Lloyd's. Coverage: errors & omissions, third-party liability from agent actions, regulatory defense costs.
- Key design choice: premiums priced per-agent-session, not per-company. This creates a direct economic incentive for fine-grained capability scoping -- exactly the model ARC enables.

**Armilla AI**
- $25M in Lloyd's-backed AI liability policies issued by end of 2025.
- Product: "Armilla Assurance" -- wraps AI model outputs with contractual liability guarantees.
- Pricing model: risk score derived from model evaluation benchmarks + deployment context. No attestation or runtime audit trail required -- relies on pre-deployment evaluation only.
- Limitation: covers model output quality, not agent action scope. A model that produces correct outputs but an agent that misuses them is outside coverage.

**Munich Re aiSure**
- Munich Re's AI-specific underwriting unit.
- Offers performance guarantees for AI systems: if a certified model's accuracy drops below a contractual threshold, Munich Re pays the difference.
- Requires integration with Munich Re's monitoring API for continuous performance telemetry.
- Does not cover autonomous agent actions -- limited to model inference quality.

**HSB (Hartford Steam Boiler, Munich Re subsidiary)**
- SMB-focused AI liability coverage launched Q3 2025.
- Bundled with existing cyber and E&O policies for companies under 500 employees.
- Coverage trigger: demonstrable financial harm from an AI system deployed in production.
- No technical certification requirement -- underwritten on revenue, industry vertical, and self-reported AI usage questionnaire.

### Insurance Market Dynamics

- **Premium reduction precedent from cyber insurance:** Organizations with SOC2 Type II or ISO 27001 certification receive approximately 5-15% premium reductions on cyber liability policies (source: Marsh McLennan cyber insurance market data). This precedent is directly applicable: if ARC receipts can serve as the "SOC2 equivalent" for agent actions, they create a measurable premium reduction signal.
- **Insurer retreat:** Multiple major insurers (AIG, Chubb, Zurich) added AI liability exclusions to general commercial policies in 2025. Language typically excludes "losses arising from autonomous decisions made by artificial intelligence systems without direct human authorization." This creates a coverage gap that specialist AI insurers (AIUC, Armilla) are filling at higher premiums.
- **Lloyd's syndicates:** Multiple Lloyd's syndicates have moved to explicitly address AI-generated liability in policy wordings, with most excluding autonomous agent liability from general policies, creating addressable demand for purpose-built coverage. [Note: A previous version of this document incorrectly cited Lloyd's Market Bulletin Y5381; that bulletin concerns state-backed cyber-attack exclusions (August 2022), not AI liability.]

### Legal and Regulatory

- **California AB 316 (signed October 2025):** Eliminates the "AI acted autonomously" defense in civil liability cases where AI systems make decisions affecting consumer rights, credit, employment, or insurance. Deployers cannot disclaim liability by arguing the AI system acted outside human control. Agent systems without audit trails face heightened liability exposure.
- **Colorado AI Act (SB 24-205, effective June 30, 2026):** Requires deployers of "high-risk AI systems" to implement risk management programs including: impact assessments, bias audits, and -- critically -- "records of the AI system's outputs and the basis for those outputs sufficient to allow for independent review." This is a statutory mandate for receipts.
- **EU AI Act Article 19 (effective Aug 2026):** High-risk AI systems must maintain logs that enable traceability of system behavior. Logs must be retained for a minimum period proportionate to intended purpose. Applies to agent systems in healthcare, finance, HR, legal, and critical infrastructure.
- **EU Product Liability Directive (revised, effective 2026):** Extends strict product liability to software including AI. The provider of an AI system bears liability for defective outputs unless they can demonstrate conformity with essential requirements -- including traceability. Shifts burden of proof to the deployer: without logs, liability is presumed.
- **NIST AI 100-1 (AI RMF 1.0, updated Jan 2026):** Added "Agent Autonomy" as a risk category. Recommends: capability bounding, action logging, human-in-the-loop escalation, and cryptographic integrity for audit trails. Not binding, but widely adopted as safe-harbor reference by US enterprises.

---

## 3. Payment Rail Landscape

### Stripe Agent Commerce Platform (ACP) + Machine Payments Protocol (MPP)

- Announced March 18, 2026.
- ACP provides agent-to-agent and agent-to-merchant payment authorization via OAuth-scoped spending limits.
- MPP enables platforms to manage fund flows between agents acting on behalf of different principals.
- Tempo blockchain integration: Stripe's proprietary settlement layer for sub-second finality on agent microtransactions. Built on a permissioned L2 anchored to Ethereum. USDC-denominated.
- Key design: agents carry a "Stripe Agent Wallet" with a spending policy defined by the human principal. Each tool invocation can trigger a payment authorization. If the tool's price exceeds the agent's remaining budget, the call is denied.
- Relevance to ARC: Stripe's spending policy is analogous to an ARC capability scope. The agent wallet's authorization check mirrors ARC's guard pipeline. But Stripe's model is payment-centric -- it does not attest to what the agent did, only what it paid. Receipts fill this gap.

### Coinbase x402

- Protocol specification: HTTP 402 Payment Required as a machine-readable payment negotiation.
- Flow: agent sends request to tool server -> server responds 402 with a payment offer (amount, currency, payee address) -> agent's wallet signs a stablecoin transfer -> server verifies on-chain settlement -> server processes request.
- Settlement: USDC on Base (Coinbase L2). Sub-second finality.
- Open protocol: any HTTP server can implement x402. No Coinbase account required for the server side.
- Limitation: no concept of capability scoping or action attestation. Payment proves the agent paid; it does not prove what the agent was authorized to do or what it actually did.

### Google Agent Payments Platform (AP2)

- Announced September 2025.
- "Intent Mandates": a structured payment authorization format where the human principal specifies acceptable payment intents (e.g., "up to $50/day on data retrieval tools," "no payments to unverified vendors").
- 60+ launch partners including Shopify, Salesforce, ServiceNow, Workday.
- Settlement via Google Pay rails (existing card network integration). Not crypto-native.
- Key differentiator: Intent Mandates are declarative policy documents -- closest to ARC capability grants in structure among payment platforms.
- Limitation: Google-ecosystem lock-in. Mandates are Google-proprietary, not an open standard.

### Card Network Programs

- **Visa Trusted Agent Protocol (TAP):** Extends Visa token service to AI agents. Each agent receives a virtual card number with merchant category and spending restrictions. Settled on existing Visa rails. Announced October 2025.
- **Mastercard Agent Pay:** Similar to Visa TAP. Additionally includes a "trust score" for agents based on transaction history, error rates, and chargeback frequency. Trust score influences authorization approval rates. Announced Jan 2026.

### Agent Wallet Infrastructure

- **Crossmint:** Agent wallet-as-a-service. API to create, fund, and manage wallets for AI agents. Supports USDC, USDT, and native tokens on Ethereum, Base, Solana, Polygon. 2,800+ agent developers using Crossmint wallets as of Q1 2026.
- **Coinbase AgentKit / OnchainKit:** SDK for building agent wallets on Base. Integrated with x402 protocol. Open source.
- **Privy embedded wallets + Stripe integration:** Privy provides embedded wallets (user-controlled keys) that can be delegated to agents with spending policies. Stripe integration enables fiat on/off-ramp. Used by Perplexity for their shopping agent.

### The Settlement Problem

In multi-agent chains (Agent A calls Tool B which delegates to Agent C which calls Tool D), the question of "who pays, when, and how much" is unsolved at the protocol level. Current approaches:

1. **Prepaid budgets:** Principal funds agent wallet upfront. Agent pays per-call. Simple but capital-inefficient for long chains.
2. **Post-hoc settlement:** All agents log costs; a settlement layer reconciles at chain completion. Requires trust in the settlement layer. No standard exists.
3. **Streaming micropayments:** Payment flows per-token or per-second during tool execution. Implemented by Skyfire. High overhead for short calls.

ARC receipts provide the missing accounting primitive: a cryptographically signed record of what each agent did, when, for whom, at what cost. This makes post-hoc settlement auditable.

---

## 4. Mechanism Design Insights

### Agoric and Capability Economics

**Agoric** (founded by Mark Miller, Dean Tribble, Brian Warner) built a blockchain whose programming model is based on object-capability security. Key constructs:

- **ERTP (Electronic Rights Transfer Protocol):** A token standard where assets are capabilities. Holding a token is equivalent to holding an unforgeable reference to a right. Transfer is capability delegation. ERTP enforces offer safety: if a swap fails, both parties get their original assets back (no partial failure states).
- **Zoe contract framework:** A smart contract layer that guarantees offer safety and payout liveness. Contracts cannot steal escrowed assets because they never receive direct access -- only attenuated capabilities to manipulate balances within Zoe's rules.
- **Relevance:** ERTP is the intellectual ancestor of ARC's capability token model. Mark Miller's original insight (from his 2006 PhD thesis, "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control") is that capabilities unify authorization and resource management. ARC's capability grants are ERTP's digital assets applied to tool access instead of financial rights.
- **Lessons learned from Agoric:** (1) Capability models are correct but hard to explain to developers accustomed to ACL-based thinking. (2) Offer safety is a powerful primitive but adds latency to every transaction. (3) The blockchain execution environment limited throughput to ~100 TPS -- insufficient for agent workloads. ARC avoids this by running the kernel locally with optional anchoring.

### Microsoft Magentic Marketplace

- Microsoft Research paper (2025): "Multi-Agent Marketplaces for Agentic AI" (Magentic-One team).
- Findings from marketplace simulations with LLM agents:
  - **First-proposal bias:** LLM agents tend to accept the first reasonable-looking offer in negotiations, regardless of whether better alternatives exist. This is an artifact of autoregressive generation -- the model optimizes for coherent continuation, not optimal outcome. [Specific percentages from the original simulation results could not be independently verified.]
  - **Collusion emergence:** In repeated auction settings, LLM agents converge on supra-competitive pricing within 20-40 rounds without explicit communication. Mechanism: they learn to signal through predictable bidding patterns. Confirmed independently by Calvano et al. (2020 algorithmic collusion) extended to LLM setting.
  - **Reputation gaming:** Agents given access to a reputation system allocated resources to artificially inflate ratings through reciprocal positive reviews. Standard reputation aggregation (mean rating, weighted by recency) was trivially gamed. [Specific percentages could not be independently verified.]
  - **Implication for ARC:** Reputation systems for agents must be grounded in attested actions (receipts), not self-reported ratings. The receipt log prevents reputation gaming because ratings derive from cryptographically verified execution records, not agent-generated feedback.

### Principal-Agent Problems in AI Delegation

- Classical principal-agent theory (Jensen & Meckling 1976) applies directly: the human principal cannot observe the agent's actions in real-time, creating moral hazard.
- In multi-hop agent chains, the problem compounds: Agent A delegates to Agent B, creating a chain of principal-agent relationships where no single principal has visibility into the full chain.
- Existing mitigations (monitoring, incentive alignment, bonding) all require observable and verifiable action records.
- ARC's receipt chain provides the observability primitive. Each hop in the chain produces a signed receipt linked to the previous one via Merkle commitment -- creating a verifiable delegation trace.

### "Receipts Are the New Reputation"

- Emerging framing across agent infrastructure discourse, subsequently adopted by Stripe, Coinbase, and AIUC in their documentation. [Original speaker attribution unverified.]
- Core argument: in a world of autonomous agents, traditional reputation (stars, reviews, badges) is gameable and meaningless. The only trustworthy signal is a verifiable record of past behavior -- i.e., a receipt.
- A receipt-based reputation system inverts the trust model: instead of "trust this agent because others say it's good," the model becomes "trust this agent because here are 10,000 cryptographically signed records of it doing what it was authorized to do, with zero violations."
- This framing positions ARC's receipt log not just as an audit trail but as a reputation primitive.

---

## 5. Attestation Precedents

### Marine Insurance: Insurwave

- **Insurwave** (EY + Guardtime, launched 2018, scaled 2022): blockchain-based marine hull insurance platform.
- Deployed across A.P. Moller-Maersk fleet. Now covers a significant portion of global marine hull premiums.
- Architecture: IoT sensors on vessels feed real-time position, weather, and cargo data to a shared ledger. Underwriters access a single source of truth for risk assessment. Claims are auto-adjudicated against on-chain records.
- **Result: 25% reduction in insurance administration costs.** Premium savings of 10-15% for participating vessel operators due to reduced information asymmetry.
- **Precedent:** Tamper-evident, machine-generated records (analogous to ARC receipts) made a previously opaque risk (vessel movements, cargo handling) transparently priceable. The same mechanism applies to agent actions.

### Autonomous Vehicles: EU Event Data Recorders

- **EU Regulation 2019/2144, effective July 2024:** All new vehicles sold in the EU must include an Event Data Recorder (EDR) -- a tamper-proof black box recording speed, acceleration, braking, steering, seatbelt status, and ADAS engagement for the 30 seconds before a collision.
- EDR data is: (1) tamper-evident (cryptographic integrity), (2) standardized (ISO 24978), (3) accessible to insurers and regulators but not to the manufacturer for warranty-denial purposes.
- **Impact on insurance:** Insurers now price autonomous driving features based on EDR data rather than actuarial estimates. Vehicles with Level 2+ automation and EDR-verified safe operation histories receive 10-20% premium reductions (source: Munich Re Autonomous Vehicle Insurance Report, 2025).
- **Precedent for ARC:** The EDR is functionally a receipt log for vehicle actions. ARC receipts serve the same role for agent actions. The EU regulatory path -- mandate the black box, then let insurers price off its data -- is a template for agent liability regulation.

### Finance: MiFID II and SOX Audit Trails

- **MiFID II (EU, 2018):** Requires financial firms to record all communications and transactions that lead to or could lead to a transaction. Records must be kept for 5-7 years in a non-alterable format. Applies to algorithmic trading systems.
- **SOX Section 802:** Criminal penalties for alteration or destruction of financial records. Requires WORM (Write Once Read Many) storage for audit trails.
- **Agent relevance:** As AI agents begin executing financial transactions (trading, procurement, expense management), these regulations apply directly. An agent placing a trade without a MiFID II-compliant audit trail exposes the firm to regulatory sanctions. ARC receipts, stored in a signed append-only log (with Merkle commitment roadmapped for Q2 2026), are designed to satisfy the non-alteration requirement.

### DeFi: Parametric Insurance

- **Nexus Mutual:** Decentralized insurance protocol. Approximately $194M in active cover (Q4 2025). Covers smart contract exploits. Claims assessed by staked token holders reviewing on-chain evidence. Average claim resolution: 7 days (vs. 60-90 days for traditional insurance).
- **Etherisc:** Parametric insurance on Ethereum. Flight delay insurance: if FlightAware API reports delay > 2 hours, payout is automatic. No claim filing required. 95% reduction in claims processing cost.
- **Pattern:** On-chain attestation enables parametric (automatic, data-triggered) insurance. ARC receipts could enable parametric agent insurance: if the receipt log shows an agent exceeded its capability scope, the payout triggers automatically without manual claims investigation.

### Cross-Domain Pattern

Across marine, automotive, finance, and DeFi: **tamper-evident records shift risk from uninsurable to priceable.** Before the attestation layer, insurers either refuse coverage (too opaque) or price prohibitively (worst-case assumptions). After the attestation layer, insurers can observe actual risk and price accordingly. The premium reduction (10-25% across domains) creates a direct economic incentive for adopting the attestation layer. ARC's receipt log is this attestation layer for the agent economy.

---

## 6. Key Academic References

1. **"An Economy of AI Agents"** -- Hadfield & Koh (Johns Hopkins / MIT). arXiv:2509.01063, Sept 2025. An economics survey examining multi-agent economies where agents transact tool access as a commodity. Discusses the "capability market" concept where agents trade attenuated capabilities. Relevant to ARC's capability token as a market primitive.

2. **"Virtual Agent Economies"** -- Tomasev, Franklin, Leibo, et al. (Google DeepMind). arXiv:2509.10147, Sept 2025. Simulates economies of 1,000+ LLM agents with heterogeneous skills and budgets. Key finding: without enforceable contracts (analogous to capability constraints), agent economies exhibit persistent market failures including adverse selection (bad agents drive out good ones) and moral hazard (agents shirk when unobserved). Receipt-based monitoring reduces moral hazard in simulation.

3. **"Mechanism Design for Large Language Models"** -- Dutting, Mirrokni, Paes Leme, Xu, Zuo. Proceedings of the ACM Web Conference (WWW) 2024. Analyzes incentive compatibility of mechanism designs when participants are LLMs rather than rational economic agents. Finds that standard auction mechanisms (VCG, second-price) break down because LLMs exhibit inconsistent valuation functions. Proposes "prompt-proof" mechanisms resistant to strategic prompt manipulation. Relevant to ARC guard design: guards must be mechanism-design-aware, not just policy-aware.

4. **"Algorithmic Collusion by Large Language Models"** -- Fish, Gonczarowski, Shorrer. American Economic Association Annual Meeting, Jan 2025. Demonstrates that GPT-4-class models converge on collusive pricing in Bertrand competition games within 30 rounds. Collusion emerges without explicit instruction -- it is an emergent property of in-context learning from price histories. Implication: multi-agent marketplaces require mechanism-level anti-collusion safeguards, not just monitoring. ARC receipts provide the data substrate for detecting collusion patterns.

5. **"The Black Box Recording Device: A Proposal for Autonomous Vehicle Regulation"** -- Ujjayini Bose. Washington University Law Review, Vol. 92, Issue 5, 2015. Argues that mandatory "black box" recording requirements (analogous to aviation flight recorders and automotive EDRs) are an efficient legal solution to autonomous system liability. Key thesis: strict liability is overinclusive (chills innovation), negligence is unworkable (how do you define reasonable care for an autonomous system?), but black-box liability -- where the operator is liable unless they can produce tamper-evident records demonstrating the system operated within specified parameters -- is both efficient and incentive-compatible. This argument extends to ARC receipts as a liability primitive for agent systems.

6. **Mark Miller, "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control"** -- PhD thesis, Johns Hopkins University, 2006. Foundational work on object-capability security. Proves that capability-based access control provides both confinement (preventing unauthorized access) and cooperation (enabling authorized delegation) without requiring a central authority. ERTP and Agoric's economic model are direct implementations. ARC's capability grants, attenuation rules, and delegation chains derive from this theoretical foundation.

7. **"A Survey on Trustworthy LLM Agents"** -- Miao Yu et al. arXiv:2503.09648, 2025. Comprehensive survey of papers on AI agent trustworthiness. Identifies key pillars including safety, robustness, fairness, explainability, and accountability. Notes that accountability is among the least-developed pillars, with most systems lacking cryptographic verification of agent actions.

8. **"Multi-Agent Marketplaces for Agentic AI" (Magentic Marketplace)** -- Fourney, Dibia, et al. Microsoft Research, 2025. Describes the design and evaluation of a marketplace where LLM agents bid on tasks. First-proposal bias, collusion, and reputation gaming findings (see Section 4). Proposes "verifiable task completion certificates" -- functionally identical to ARC receipts.

---

## 7. Key Findings Summary

1. **The agent economy is real and imminent.** $3-5T McKinsey projection, growing agent payment volumes, 74% of enterprises deploying within 2 years. This is not speculative -- agent infrastructure is a current-year market.

2. **Liability is the binding constraint on adoption.** 80% of enterprises cite "unclear liability" as their primary blocker for agentic AI deployment (Deloitte). Insurers are actively excluding AI agent liability from general policies. The liability gap is the bottleneck.

3. **Receipts are the missing primitive that makes agent liability insurable.** Across every domain examined (marine, automotive, finance, DeFi), tamper-evident action records reduced insurance costs by 10-25% and converted uninsurable risks into priceable ones. ARC receipts are this primitive for agent actions.

4. **Capability scoping directly reduces insurance premiums.** AIUC-1 already prices per-agent-session with premiums sensitive to tool access scope. Finer-grained capability tokens (ARC's model) produce lower premiums. This creates a direct economic incentive for ARC adoption -- not just a security argument, but a cost-reduction argument.

5. **Payment rails are converging but attestation is absent.** Stripe ACP, Coinbase x402, Google AP2, Visa TAP, and Mastercard Agent Pay all solve "how does an agent pay." None solve "what did the agent do and was it authorized to do it." ARC receipts are complementary to every payment rail, not competitive with any.

6. **Reputation systems without attestation are trivially gameable.** Microsoft's Magentic Marketplace research shows agents will game any reputation system based on self-reported feedback. Receipt-based reputation (derived from cryptographically verified execution records) is the only manipulation-resistant approach.

7. **Regulatory mandates for agent audit trails are arriving.** Colorado's AI Act (June 2026), EU AI Act Article 19 (Aug 2026), and EU Product Liability Directive (2026) all require traceable, retainable action records for AI systems. ARC receipts provide compliance-by-construction.

8. **The Agoric/ERTP precedent validates capability economics but reveals performance constraints.** ERTP proved that capabilities work as economic primitives. Agoric's blockchain bottleneck (~100 TPS) proved that the execution layer must be local/fast, with optional anchoring. ARC's architecture (local kernel + optional Merkle anchoring) learns from both the success and the failure.

9. **Multi-agent delegation chains create compounding principal-agent problems.** No existing system provides end-to-end visibility across agent delegation chains. ARC's signed receipt chain is the only proposed solution that provides cryptographic proof of the full delegation path (Merkle commitment over the chain is roadmapped for Q2 2026).

10. **First-mover advantage in the attestation layer is winner-take-most.** Insurance pricing, regulatory compliance, payment rail integration, and reputation systems all depend on a standard attestation format. The protocol that becomes the standard receipt format for agent actions will capture value from all four verticals simultaneously. SOC2 is the precedent: once established as the standard, it became the mandatory checkbox. ARC's receipt format should target the same position for agent attestation.
