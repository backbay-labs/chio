# Chio M08 RFP: Independent Crypto + Protocol Review

**Trajectory:** trajectory-3
**Milestone:** M08
**Version:** v0
**Date:** 2026-05-02
**Audience:** NCC Group and Trail of Bits
**RFP owner:** @bb-connor
**Vendor-coord package owner:** trajectory-3 executor

## Executive summary

Chio is seeking an independent cryptography and protocol review of its
cemented v3.0 secure tool-access protocol surface. The requested review
covers capability security, canonical receipt signing, PQ and hybrid
signature wiring, sparse-Merkle revocation, TEE quote verification, and
runtime trust-boundary enforcement. The review is a trajectory-3 release
gate: the final report must be suitable for publication after remediation
and must include enough technical detail for customers and downstream
auditors to treat it as third-party evidence.

## Scope of work

### Protocol surface

Review `spec/PROTOCOL.md` sections 4 through 13:

- Serialization and identity contracts.
- Capability contract, delegation, attenuation, expiry, and revocation.
- Receipt contract and signed append-only receipt-log semantics.
- Manifest contract and signed tool-server metadata.
- Runtime surfaces and trust-control semantics.
- Portable trust, federation, and A2A adapter semantics.
- Certification and observability contracts.

### Implementation surface

Review the following repositories and crates from the Chio public repo:

- `crates/chio-attest-verify/`: TEE quote handling, PQ signing wiring,
  hybrid signatures, Sigstore bridge, and policy loading.
- `crates/chio-revocation-oracle/`: sparse-Merkle CRL-Lite, revocation
  freshness, API, signer, and passport bridge.
- `crates/chio-kernel-core/`: capability algebra, normalized request
  checks, guard results, async dispatch interfaces, revocation views, and
  receipt helpers.
- `crates/chio-otel-receipt-exporter/`: receipt-log export surface and
  observability contract alignment.
- `spec/security/chio-threat-model.v1.json`: threat register used as the
  row-level cross-check oracle for M05 and this review.

### Cryptographic primitives and constructions

Review the use and integration boundaries for:

- Ed25519 legacy signature paths.
- ML-DSA-65 PQ signature paths.
- Hybrid signature construction and verifier behavior.
- X25519 plus ML-KEM hybrid transport assumptions where referenced in
  the protocol.
- SHA-256, SHA-3, and BLAKE3 use across signed payloads and receipts.
- AEAD selection, nonce handling, and fail-closed error handling where
  protocol or implementation code touches encrypted payloads.

### Out of scope

- Trajectory-2 crates outside the cemented v3.0 review set.
- Mobile attestation and SDK packaging, which M07 owns.
- Supply-chain attestation, SBOM, cargo-vet, and CVE monitoring, which
  M06 and M09 own.
- HITRUST operational controls and assessor package evidence, which M09
  owns.
- Public bug bounty launch, ISO 42001, SOC 2 Type II, multi-cloud
  marketplace publication, and any permissionless anchor network work.

## Deliverables

The requested vendor deliverables are:

- Scoping memo that confirms final review boundaries, named reviewers,
  and schedule.
- Weekly status memo during active review.
- Preliminary findings memo by the end of the active-review window.
- Draft final report with enough detail for Chio factual correction.
- Final report PDF plus remediation-log appendix.
- Public-report PDF cleared for publication on Chio documentation and
  the vendor public reports page after remediation and any coordinated
  disclosure embargo.
- Finding-level sign-off receipts for each Critical and High remediation
  before the final report is marked complete.

## Timeline

The requested trajectory-3 calendar is:

| Week | Event |
|------|-------|
| 1 | RFP package sent to NCC Group and Trail of Bits. |
| 2-5 | Vendor questions, quote, redline, selection, and SOW signature. |
| 6-14 | Vendor booking, onboarding, and final scoping. |
| 15-30 | Active review. |
| 28-30 | Preliminary findings memo. |
| 30-40 | Chio remediation PRs and vendor sign-off receipts. |
| 40 | Draft final report. |
| 42 | Chio factual-correction window closes. |
| 44 | Final report and remediation appendix published. |

Quotes or booking slips that move a calendar interval by more than 25%
must be called out explicitly so Chio can trigger the trajectory-3 halt
13 review path.

## Materials provided

The initial handoff package includes:

- `spec/PROTOCOL.md`.
- `spec/security/`.
- `AGENTS.md`.
- `docs/README.md`.
- `.planning/trajectory-3/08-independent-crypto-protocol-review.md`.
- `.planning/trajectory-3/audits/M08-vendor-evidence.md`.
- The build and test command:
  `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check`.

Rolling addenda will be provided as M04, M05, and M06 close:

- M04 mutation gate and verdict-matrix evidence.
- M05 threat-coverage closure and dispatch-allow evidence.
- M06 Apalache, cargo-vet, SBOM, and CVE-monitoring evidence.

## IP terms

- Chio retains copyright on the codebase, specifications, diagrams,
  and remediation patches.
- Vendor retains copyright on the report deliverable unless the final
  SOW states otherwise.
- Chio receives a perpetual license to publish the final report PDF and
  remediation appendix after coordinated disclosure restrictions lift.
- Vendor receives a perpetual license to cite the engagement and publish
  the cleared public report from the vendor public reports page.
- Findings in third-party dependencies use responsible-disclosure norms
  with a 90-day default embargo unless a shorter statutory or vendor
  deadline applies.

## Public-report clause

The default report posture is public after remediation is complete.
Critical findings with CVSS 9.0 or higher follow a coordinated
90-day disclosure window. The public report may redact exploit details
or dependency identifiers until the embargo lifts, but it must preserve
the finding identifier, affected Chio surface, severity, remediation
status, and final sign-off state.

## Pricing requested

Please return:

- A fixed-price base quote.
- A time-and-materials buffer for reviewer-question follow-up and
  Critical or High re-test work.
- Any separate cost for publication rights, final-report reissue,
  after-hours incident handling, or retest extension.

D07 budget posture for M08 is $150k-$250k. Quotes outside that band
should include a clear scope explanation because they trigger a Chio
budget and calendar review.

## Reply format

Please return a response with:

- Proposed review team and named technical lead.
- Earliest practical start date.
- Active-review duration and weekly capacity assumptions.
- Scope exclusions or recommended scope changes.
- Fixed-price quote and T&M buffer.
- SOW redline.
- Public-report publication language.
- Confirmation that Critical and High remediation re-test can complete
  inside a one-week retest window.
- Confirmation of professional liability or E&O insurance posture.

## Security review requested (M08 trust-boundary)

The engagement covers Chio trust boundaries. Vendor feedback should
default to fail-closed remediation guidance: any ambiguous verifier,
revocation, capability, guard, or receipt behavior must deny access or
mark the decision unverifiable rather than silently allowing the action.
