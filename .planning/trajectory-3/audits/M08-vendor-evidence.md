# M08 Audit: Internal Crypto + Protocol Readiness Draft

> **Disclaimer:** The artifact at
> `releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
> is a self-authored internal readiness draft, not an external vendor
> crypto-protocol review. No vendor, including NCC Group or Trail of Bits,
> has been engaged to produce a vendor-letterhead report. Real external
> review is a trajectory-4 deliverable (`M08-followup`).

**Trajectory:** trajectory-3
**Milestone:** M08
**Wave:** Wv (readiness lane; external review deferred)
**Status:** COMPLETE (internal readiness draft and internal response memo committed)
**Internal readiness date:** 2026-05-02
**External review status:** deferred to trajectory-4 `M08-followup`
**Release-gate anchor:** RELEASE_AUDIT

## 1. Internal Readiness Scope

M08 records repository-owned preparation for a future third-party crypto
and protocol review. The trajectory-3 artifact is an internal readiness
draft only. It does not assert an executed vendor engagement, an
independent reviewer finding register, external acceptance receipts, or
publication outside this repository.

The intended future review surface remains the cemented v3.0 Chio
surface:

1. Capability algebra (`spec/PROTOCOL.md` s5; `crates/chio-kernel-core/`).
2. Receipt contract and receipt log (`spec/PROTOCOL.md` s6;
   `crates/chio-otel-receipt-exporter/`).
3. PQ and hybrid signing (`spec/PROTOCOL.md` s4;
   `crates/chio-attest-verify/`).
4. Anchor binding and portable trust (`spec/PROTOCOL.md` s10).
5. Revocation oracle (`crates/chio-revocation-oracle/`).
6. TEE attest-verify (`crates/chio-attest-verify/`;
   `spec/PROTOCOL.md` s4 and s9).
7. Trust-control contract (`spec/PROTOCOL.md` s9).
8. Manifest contract (`spec/PROTOCOL.md` s7).
9. Federation and A2A adapter (`spec/PROTOCOL.md` s10 and s11).
10. Observability and certification contracts (`spec/PROTOCOL.md` s12
    and s13).

Out of scope for this internal readiness artifact: mobile attestation
(M07 lane), supply-chain review (M06 and M09 lanes), HITRUST-scoped
operational surfaces (M09 lane), and any trajectory-4 external review
deliverable.

## 2. Candidate Route Scan

Official routes checked on 2026-05-02:

- NCC Group contact route: `https://www.nccgroup.com/contact-us/`
- NCC Group cyber sales route: `https://www.nccgroup.com/contact-sales/`
- NCC Group cryptography and encryption service route:
  `https://www.nccgroup.com/technical-assurance/cryptography-encryption/cryptography-services/`
- Trail of Bits contact route: `https://trailofbits.com/contact/`
- Trail of Bits services overview: `https://www.trailofbits.com/`

These links are candidate intake references for a later procurement
process. They are not evidence of a signed statement of work, vendor
selection, active review, or vendor-authored deliverable.

| Candidate | 2026-05-02 action | Engagement state | Readiness use |
|-----------|-------------------|------------------|---------------|
| NCC Group | Official intake routes identified for future outreach. | Deferred; no executed engagement is claimed. | Primary candidate route for trajectory-4 procurement. |
| Trail of Bits | Official intake route and services overview identified for future outreach. | Deferred; no executed engagement is claimed. | Alternate candidate route for trajectory-4 procurement. |
| Galois | Substitute-ladder candidate retained from D12 planning. | Deferred; no executed engagement is claimed. | Formal-methods-oriented fallback if primary candidates are unavailable. |
| Kudelski Security | Substitute-ladder candidate retained from D12 planning. | Deferred; no executed engagement is claimed. | Protocol and hardware review fallback. |
| Cure53 | Substitute-ladder candidate retained from D12 planning. | Deferred; no executed engagement is claimed. | Calendar-rescue fallback for narrower review scope. |
| Cryptography Engineering LLC | Substitute-ladder candidate retained from D12 planning. | Deferred; no executed engagement is claimed. | Focused crypto and capability-algebra fallback. |

## 3. Readiness Artifacts

`releases.toml` reclassifies the M08 release-audit artifact as
`m08_internal_readiness_draft`:

- Release gate: `RELEASE_AUDIT`.
- Classification: `internal_readiness_draft`.
- Draft URL:
  `https://github.com/bb-connor/arc/blob/main/releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
- Draft path:
  `releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
- Draft SHA-256:
  `abcc1423018d42feb119238b394d196075853e2bd4a23a4ca62c7adedf1e723c`
- Source audit doc:
  `.planning/trajectory-3/audits/M08-vendor-evidence.md`
- Bundled audit doc:
  `compliance/hitrust/evidence-bundles/2026-05-02/M08/audit/M08-vendor-evidence.md`
- Response memo status: `internal-only`.
- External vendor engagement: deferred.
- Trajectory-4 owner: `M08-followup`.

Render validation for the internal readiness PDF:

- `pdftoppm -png -r 120` produced three readable pages with no clipped
  text or table overflow after regeneration.
- `pypdf` reported three pages and extracted the report title from page 1.

## 4. Internal Observations

The rows below are Chio readiness observations, not external reviewer
findings.

| Observation ID | Severity | Readiness observation | Status |
|----------------|----------|-----------------------|--------|
| M08-IR-001 | Medium | Exporter, report, and OpenTelemetry projections could be mistaken for authoritative receipts unless the source signed receipt is embedded and verified. | Closed in trajectory-3 by marking projections non-authoritative unless they embed and verify the full signed receipt. |
| M08-IR-002 | Low | Revocation replay fixture documentation should name malformed sparse-Merkle proof behavior. | Closed as documentation-only; the oracle denies malformed proof material. |
| M08-IR-003 | Info | Capability attenuation explanation should cite M06 invariant names for reviewer handoff. | Closed by recording `MonotoneLogApalache`, `RevocationCutCompleteness`, `ReceiptBeforeAllow`, and `KernelTransitionCancelSafe` as readiness handoff anchors. |

No Critical or High internal readiness observations remain open for the
trajectory-3 release-audit artifact.

## 5. Release Evidence Use

This document and the PDF may be cited only as the M08 internal readiness
draft. They must not be cited as a completed external crypto-protocol
audit, vendor-issued artifact, HITRUST assessor result, or external
acceptance record.

The authoritative release row is
`[release_audit] activation_evidence.m08_internal_readiness_draft`.
Repository-hosted draft artifacts are the only trajectory-3 evidence
channel for M08. Public or vendor-hosted channels are out of scope until
the trajectory-4 external review is completed and separately recorded.

## 6. Trajectory-4 Exit Criteria

Before a future external review can replace this internal readiness
draft, the follow-up lane must record:

1. Executed scope and commercial terms.
2. Reviewer roster and conflict check.
3. External deliverable on organization letterhead.
4. Reviewer-produced issue register and remediation status.
5. External acceptance records for remediated findings.
6. Updated `releases.toml` classification reviewed by the compliance
   owner.

Until those criteria are met, M08 remains internal-readiness-only.

## 7. Bundle Integrity

The HITRUST evidence bundle is generated by
`compliance/hitrust/build-evidence-pack.sh`. If this Markdown file
changes inside `compliance/hitrust/evidence-bundles/2026-05-02/`, update
the corresponding line in `SHA256SUMS` before publishing or attaching
the bundle.
