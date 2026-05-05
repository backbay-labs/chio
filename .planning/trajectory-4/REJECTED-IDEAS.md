# Trajectory-4 Rejected Ideas

Ideas raised during the 9-lens brainstorm or 5-perspective debate that the proposing agent (or the synthesis pass) explicitly rejected, with the rejection rationale. Recorded here so future trajectories can revisit these with fresh information rather than re-deriving them.

## Lens-by-lens rejections

### Lens 1: Developer experience

- **AI-assisted policy authoring** ("describe the policy in English, get YAML"). Tempting, but policy correctness is the load-bearing thing in Chio; an LLM author with hidden mistakes is the worst possible outcome. The right move is the LSP playground (DX-5), not generation.
- **Hosted dev sandbox / "chio.dev" cloud.** Trj4 is explicitly internal-only - no vendors, no design partners. A hosted surface violates that constraint and fragments effort against substrate hardening.

### Lens 2: Performance and scale

- **Custom executor / replace tokio.** M06 explicitly excluded this and the rationale stands: tokio is not the bottleneck per existing benches, and the integration cost across 89 crates is enormous.
- **SIMD canonical JSON.** M06 already rejected this. The win was in collapsing call count (`CanonicalBytes`), not cycles per byte. With profile data in hand (S-1) this can be revisited if canonicalisation re-emerges as a top frame; absent that data, premature.

### Lens 3: Capability extension

- **ZK proofs of policy compliance.** Tempting but cryptographic-engineering-team territory; payoff requires trj5+ and a compiler from `chio-policy`'s condition AST to a zkVM. Poor effort/impact ratio for a single trajectory; better as a research spike behind a feature flag.
- **Differential-privacy aggregate receipts.** Same shape problem: meaningful epsilon budgets need governance work that a code trajectory can't deliver alone. The receipts already redact per-payload; adding DP aggregation without an aggregator service is half a feature. Premature.

### Lens 4: Protocol evolution

- **Switch native wire to CBOR or HTTP/3.** Tempting for size budgets, but `WIRE_PROTOCOL.md:48` pins canonical JSON (RFC 8785) precisely so signing/verification has one deterministic encoder. Re-canonicalizing under CBOR/COSE costs the entire formal-methods lane (Lean models, Kani harnesses on `sign_receipt`, `verify_capability`) for marginal payoff. Revisit only when PQ signature sizes (~3.9 KB per `signature.v1.json:12`) actually break a deployment.
- **OCSP-shape revocation surface.** `chio-revocation-oracle` already has epoch + sparse-Merkle + gossip - that's CRL-shape with bounded staleness, which is the right answer. Adding a per-query OCSP responder duplicates work and adds an online-availability dependency the fail-closed posture (CLAUDE.md house rules) does not want.

### Lens 5: AI-frontier

- **Bypassing CAPTCHAs / human-verification systems on behalf of agentic browsers.** Trivially asked-for by users of computer-use agents; a hard no by Chio's privacy and safety posture, and a regulatory landmine. Not building.
- **Real-time semantic ML-based prompt-injection classifier in the kernel hot path.** Tempting, but inference latency in the verdict path violates the existing `verdict_budget_ms` contract (see `ProviderError::VerdictBudgetExceeded`) and creates a model-update governance loop. Ship the heuristic tier (A-3) first; punt the ML-classifier variant to an off-path advisory channel in trj5.

### Lens 6: TEE / hardware-attestation

- **Intel SGX EPID/DCAP backend.** Intel deprecated SGX on consumer/server CPUs in 2022 (`12th-gen Core` removed it; `Ice Lake-SP` is the last server family). Adding it now is maintenance debt for a shrinking footprint. TDX is the forward path and is already in `tdx.rs`.
- **Confidential containers (Kata-CoCo / Gramine / Occlum) wrapper.** This is a deployment recipe, not new code. The existing TDX + SEV-SNP backends already verify the underlying VM measurement; CoCo just runs a container inside one. Document it (deployment guide), don't crate it.

### Lens 7: Trust-graph / federation

- **Reputation scores (T-11 in the catalog).** Risk of becoming a soft, non-verifiable signal that gets weaponized. Today's component artifacts (clearing, conformance) are already directly verifiable. Defer until quorum + delegation are in place.
- **Cross-cloud anchor bridging (T-12 in the catalog).** High engineering surface (per-lane indexer divergence, finality semantics) for marginal incremental trust over existing per-lane anchoring. Revisit post-trj4 once multi-lane discovery is more battle-tested.

### Lens 8: Observability / SRE / operability

- **"Operator agent that watches its own metrics and remediates."** Self-remediation by an LLM agent on the trust-control plane creates a new class of failure (autonomous fail-open from confused agent reasoning) that contradicts CLAUDE.md's fail-closed invariant. Run remediation as deterministic policy, not an agent.
- **DataDog dashboard-as-code pack.** Already covered by Grafana/Tempo/Loki/Jaeger JSON in `deploy/dashboards/`. Adding a vendor-specific format triples maintenance. If a customer needs DataDog they can transform via `infra/grafana` exports.

## Rejections from the 5-perspective scope debate

These were raised by the perspective-debate agents (engineer-rigor, security-paranoid, compliance-vendor, customer-velocity, devil's-advocate) and were filtered out of trj4 scope by the user's "purely internal" rule. They live in `CLOSEOUT-BLOCKERS.md` as carry-forward to a later trajectory, not in this rejection list per se. Listed here for completeness.

- **M01 30-day production-traffic pilot.** Needs a real partner. External dependency.
- **M02 real partner cosign-OIDC sig.** Needs a real partner.
- **M08 vendor crypto review (NCC Group / Trail of Bits / Atredis).** Needs vendor SOW and 26-44 weeks of vendor calendar.
- **M09 HITRUST i1 cert.** Needs External Assessor (A-LIGN / Coalfire / Schellman) and 12-36 weeks of audit calendar.
- **M10 AWS Marketplace listing publication.** Operator action, not engineering.
- **M10 MCP Registry publication.** Operator action, not engineering.
- **TestFlight / Android internal-track public cohorts.** Customer-velocity perspective wanted these in week 1; reviewer narrowed scope as too risky absent partner contracts.
- **External red-team engagement (devil's-advocate's "reality calibration").** Needs vendor.

## Synthesis-level rejections (from SYNTHESIS-V2)

- **Multi-cloud marketplace listings beyond AWS.** Customer-velocity wanted these; D03 single-cloud was the right call per perspective debate.
- **More compliance frameworks beyond HITRUST i1 (FedRAMP, ISO 27001, SOC2 expansion).** All vendor-calendar items.
- **AWS Marketplace second listing or extended Bedrock conformance suite.** Diminishing returns vs. mobile attestation work in Tier 0.
- **Speculative new milestones M11+ or new substrate work without a named user.** Trj4 is a closeout trajectory for existing M01-M10 promises. New milestones dilute focus.
- **Demos to prospects we can't legally onboard yet.** A demo without a HITRUST letter is a demo that ends in "call us back next quarter."
