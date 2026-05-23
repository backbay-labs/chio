# Chio Strategic Roadmap

> Historical internal planning note. `v2.x` labels in this document are
> pre-release implementation milestones, not Chio-owned protocol, schema, SDK,
> or runtime versions. Current protocol posture is v1-only.

**Date:** 2026-03-27
**Status:** milestone ladder through `v2.8` executed; launch hold pending hosted workflow observation
**Primary framing source:** `docs/research/DEEP_RESEARCH_1.md`

---

## Strategic Thesis

Chio should be understood as a **trust-and-economics control plane** for
agentic systems.

The moat is not basic connectivity. MCP, A2A, and payment protocols already
cover connectivity well enough. Chio's job is the harder layer under them:

- delegated authority
- bounded spend
- verifiable receipts
- enforceable governance
- accountable cross-system and cross-org execution

That is the economic-security thesis from the deep research work:

> **Economic security = delegated authority + bounded spend + verifiable
> receipts + enforceable governance across heterogeneous agent protocols.**

Chio should therefore be positioned as the **rights and receipts layer** under
MCP, A2A, payment rails, and future enterprise identity or attestation
systems, not as a transport competitor trying to replace them.

## What Is Already Shipped

Chio is not starting from zero. The shipped base now includes:

- fail-closed kernel mediation, guard evaluation, and signed receipts
- Merkle checkpoints, DPoP, truthful budget and settlement semantics, and
  receipt query/export/reporting
- portable-trust primitives including `did:chio`, passports, verifier-policy
  artifacts, challenge/response flows, and multi-issuer composition
- certification registry publication, resolution, supersession, and revocation
- A2A and MCP adapter surfaces plus enterprise identity and federation
  administration
- governed approvals, x402/ACP payment controls, settlement reconciliation, and
  explicit invocation-plus-money budget reporting
- insurer-facing behavioral feeds and attested runtime assurance tiers
- an explicit executable-formal launch evidence boundary for scope attenuation
- production qualification, release tooling, standards drafts, and the first
  architecture decomposition wave

The active rename milestone exists because the implementation and the product
story had drifted apart. Chio needs one coherent identity before the next major
feature wave lands.

## Strategic Principles

1. **Trust claims must be runtime-backed.**
   No launch, standards, or partner claim should outrun what the code and
   qualification evidence actually prove.

2. **Governance and economics stay fused.**
   Authorization without spend control is incomplete. Payment without proof is
   unsafe. Chio wins by keeping them in one contract.

3. **Adapters beat replacement.**
   Chio should sit under MCP, A2A, and payment ecosystems rather than trying to
   replace them outright.

4. **Compatibility work is first-class work.**
   Renames, migrations, and portable-trust transitions are product work, not
   cleanup afterthoughts.

5. **Launch claims wait for evidence.**
   Conditional release-candidate posture is acceptable. Unbacked GA claims are
   not.

## Milestone Ladder

### v2.5 Chio Rename and Identity Realignment

**Goal:** make Chio the real product identity across code, packages, CLI, docs,
spec, and operator materials without breaking verifiability or operator
continuity.

**Why it matters:** the economic-security story is stronger than the old Chio
framing, but only if the rename is handled as a migration contract instead of a
search-and-replace exercise.

**Core outcomes:**

- Chio-first package, CLI, SDK, and release identity
- Chio-primary schema issuance where implemented
- explicit rejection of legacy pre-Chio artifacts and canonical `did:chio`
  identity
- one coherent migration and qualification story

### v2.6 Governed Transactions and Payment Rails

**Goal:** make Chio's economic-security thesis concrete in operator workflows.

**Must land:**

- governed transaction intent and approval artifacts
- x402 bridge with truthful policy and receipt semantics
- ACP / Shared Payment Token bridge with scoped spend semantics
- explicit pending, settled, failed, and reconciled settlement states
- operator-visible reconciliation and accounting flows

**Why it matters:** this is the shortest path from "bounded spend exists in the
kernel" to "Chio governs real machine-mediated economic actions."

### v2.7 Portable Trust, Certification, and Federation Maturity

**Goal:** finish the portable-trust and discovery story so trust can move
between organizations conservatively and visibly.

**Must land:**

- enterprise identity propagation into portable credentials and federation
  artifacts
- passport lifecycle semantics: status, revocation, supersession, and
  distribution
- certification discovery and multi-operator/public registry semantics
- conservative cross-org reputation and trust distribution backed by evidence

**Why it matters:** Chio becomes materially more valuable when trust no longer
stops at one operator boundary.

### v2.8 Risk, Attestation, and Launch Closure

**Goal:** turn Chio's evidence substrate into external trust and close the gap
between production candidate and actual launch.

**Must land:**

- insurer-facing behavioral exports and risk-oriented reporting
- attested-runtime assurance tiers that can tighten or loosen granted rights
- proof/spec cleanup or explicit scoped deferral of any remaining formal debt
- real GA decision artifacts, not just conditional release-candidate posture

**Why it matters:** this is where Chio stops being merely auditable and becomes
financable, insurable, and standards-ready.

## Ecosystem Posture

Chio should pursue a partner map that matches the control-plane thesis:

- **MCP and A2A ecosystems:** integrate beneath them and become the trust
  substrate they intentionally do not provide
- **payments and commerce:** treat x402 and ACP/SPT systems as rails that Chio
  governs, not competitors to replace
- **enterprise IAM:** integrate with OIDC/OAuth-based identity providers so
  rights are legible to security reviewers and operators
- **attestation stacks:** treat TEEs and runtime evidence as a higher-assurance
  tier once the core economic and portable-trust surface is stable
- **standards bodies and regulators:** keep Chio's claims aligned to shipping
  evidence so the project remains legible in NIST, OAuth, OpenID, and W3C
  conversations

## Commercialization Posture

Chio is the platform thesis, not the single product packaging.

That distinction matters:

- Chio remains the broad rights, receipts, governance, and trust substrate for
  consequential agent actions
- vertical products can package Chio for specific high-value markets without
  shrinking the underlying platform ambition
- the first finance-specific product layer is MERCURY
- Chio-Wall remains a separate companion product line built on the same
  substrate, not a redefinition of Chio itself

The commercial mistake would be to let a narrow first wedge redefine the full
project. The strategic goal is the opposite: use narrow wedges to prove the
broader Chio thesis in markets that can buy earlier.

## Success Conditions

Chio is on the right path if the following become true in order:

1. the product identity is coherent and migration-safe
2. governed transactions and payment rails are real and truthful
3. portable trust and certification are usable across organizations
4. risk, attestation, and launch claims are supported by evidence

That sequence matters. The endgame is not a prettier protocol name. The
endgame is a market where consequential agent actions can be approved,
bounded, audited, financed, and insured because the underlying rights and
receipts are explicit and verifiable.

## Current Decision Checkpoint

The `v2.5` through `v2.8` ladder derived from
`docs/research/DEEP_RESEARCH_1.md` is now executed locally. The current
decision is:

- local evidence says Chio is ready for launch packaging on the shipped surface
- external release publication remains on hold until hosted `CI` and `Release
  Qualification` runs are observed on the candidate commit
- the next roadmap turn should start from post-launch or next-milestone work,
  not from reopening the rename, payment, trust, or formal-closure ladder
