# M08 Audit: Independent Crypto + Protocol Review (NCC Group or Trail of Bits)

**Trajectory:** trajectory-3
**Milestone:** M08
**Wave:** Wv (vendor calendar; runs parallel to all code waves)
**Status:** OPEN (P0 in progress)
**Audit start:** week 1 (RFP)
**Audit close:** week 40-44 (final report)
**Release-gate anchor:** RELEASE_AUDIT

## 1. Audit scope

M08 procures third-party crypto + protocol review per D12 vendor
shortlist (NCC Group or Trail of Bits). Substitute ladder per D12
amendment: Galois -> Kudelski -> Cure53 -> Cryptography Engineering
LLC. D07 budget posture $150k-$250k.

The reviewer's surface is the cemented v3.0 Chio surface. Top-10
priority surfaces (per M08 narrative scope):

1. Capability algebra (`spec/PROTOCOL.md` s5; `crates/chio-kernel-core/`).
2. Receipt contract + receipt log (`spec/PROTOCOL.md` s6;
   `crates/chio-otel-receipt-exporter/`).
3. PQ + hybrid signing (`spec/PROTOCOL.md` s4;
   `crates/chio-attest-verify/`).
4. Anchor binding + portable trust (`spec/PROTOCOL.md` s10).
5. Revocation oracle (`crates/chio-revocation-oracle/`).
6. TEE attest-verify (`crates/chio-attest-verify/`;
   `spec/PROTOCOL.md` s4 + s9).
7. Trust-control contract (`spec/PROTOCOL.md` s9).
8. Manifest contract (`spec/PROTOCOL.md` s7).
9. Federation + A2A adapter (`spec/PROTOCOL.md` s10 + s11).
10. Observability + certification contracts (`spec/PROTOCOL.md` s12 + s13).

Starting counts (measured 2026-04-30):

- `spec/PROTOCOL.md` line count: 2431 lines.
- `crates/chio-attest-verify/src/` line count: <pinned at P0.T9>.
- `crates/chio-revocation-oracle/src/` line count: <pinned at P0.T9>.
- `crates/chio-kernel-core/src/` line count: <pinned at P0.T9>.
- `spec/security/chio-threat-model.v1.json` row count: <pinned at
  P0.T9; re-pinned at P2 open after M05 closure>.

Out of scope: trajectory-2 surfaces outside the cemented set; mobile
attestation (M07 lane); supply-chain (M06 + M09 lanes); HITRUST-scoped
operational surfaces (M09 lane).

## 2. Vendor selection record

Sources checked 2026-05-02:

- NCC Group contact route: `https://www.nccgroup.com/contact-us/`
- NCC Group cyber sales route: `https://www.nccgroup.com/contact-sales/`
- NCC Group cryptography and encryption service route:
  `https://www.nccgroup.com/technical-assurance/cryptography-encryption/cryptography-services/`
- Trail of Bits contact route: `https://trailofbits.com/contact/`
- Trail of Bits services overview: `https://www.trailofbits.com/`

### 2a. Primary candidates (D12)

| Vendor | RFP route | RFP sent | Reply received | Quote | Lead time | Fit note | Selected |
|--------|-----------|----------|----------------|-------|-----------|----------|----------|
| NCC Group | Cyber Security sales contact form plus cryptography and encryption service page | <date> | <date> | <quote> | 8-16 weeks | Long-running cryptography and protocol review practice; published public-report posture; strongest default fit for capability and crypto review. | <yes/no> |
| Trail of Bits | Contact form or secure SendSafely route from official contact page | <date> | <date> | <quote> | 12-24 weeks | Strong software assurance, cryptography, systems, blockchain, and security engineering bench; likely higher booking pressure. | <yes/no> |

### 2b. Substitute ladder (D12 amendment, halt-13 mitigation)

| Vendor | Lead time | Engagement size band | Notes | Substitution trigger |
|--------|-----------|----------------------|-------|----------------------|
| Galois | 16-24 weeks | $150k-$400k | Strongest formal-methods fit because Cryptol, SAW, and protocol proofs pair well with M06 Apalache evidence; calendar worst of the six. | Primary vendors decline or quote cannot meet D07 and calendar remains acceptable. |
| Kudelski Security | 12-20 weeks | $120k-$280k | Strong protocol, hardware, and TEE review fit; Switzerland root adds contracting and IP-law review latency. | Primary vendors decline and Galois calendar would trigger halt 13. |
| Cure53 | 4-8 weeks | $60k-$200k | Fastest lead time; useful if calendar is failing, but crypto-primitive depth is weaker than NCC Group, Trail of Bits, and Galois. | Calendar rescue if the top three options slip past halt-13 threshold. |
| Cryptography Engineering LLC | 8-16 weeks | $80k-$220k | Boutique academic-leaning group; best for focused capability algebra and hybrid signing questions, with limited capacity risk. | Narrowed scope fallback if all larger firms decline. |

### 2c. Selection memo

[TODO M08.P0.T7 fill at week 5:]

- Selected vendor:
- SOW hash:
- SOW signed: <date>
- Calendar fit: weeks 15-30 active review; weeks 30-40 remediation;
  week 44 final report.
- Named reviewers (per vendor SOW):
- E&O insurance posture confirmed: <yes / no / N/A>
- 10-business-day right-of-reply on draft report pinned: <yes>
- 1-week post-remediation re-test on Critical / High pinned: <yes>
- Variance from D07 budget band ($150k-$250k):
- Halt-13 status: <not triggered / triggered with substitute selected>

### 2d. Calendar checkpoints

| Week | Event | Status | Note |
|------|-------|--------|------|
| 1 | Project kickoff; vendor lane opens | | |
| 2 | RFP sent to NCC Group + Trail of Bits | | |
| 3-4 | Vendor questions / clarifications | | |
| 5 | Vendor selection (D12 final pick); SOW signed | | |
| 8 | Onboarding session | | |
| 12 | Vendor scoping memo received | | |
| 14 | SOW addenda finalized | | |
| 15 | Active review begins (P2) | | |
| 22 | P2 closes | | |
| 28-30 | Preliminary findings memo | | |
| 30 | P3 closes; remediation begins (P4) | | |
| 40 | Remediation complete; draft final report received | | |
| 42 | Chio factual-correction window closes | | |
| 44 | Final report published; M08 closes | | |

## 3. Active-review log

[TODO M08 vendor-coord agent fill weekly during P0-P5. Status verbs:
`awaiting`, `received`, `redlined`, `signed`, `answered`, `deferred`.]

| Week | Direction | Question / Artifact | Status | Cross-ref |
|------|-----------|---------------------|--------|-----------|
| | | | | |

## 4. Findings + remediation log

[TODO M08 milestone agent fill at P3-P4. Severity scheme: Critical
(CVSS >= 9.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9), Info.
Remediation SLA: Critical = hot-fix PR (halt 15); High = patch within
P4; Medium = patch within trajectory-3; Low = roadmap (trajectory-4
OK); Info = documented.]

| Finding ID | Severity | Title | Surface | Status | PR cross-ref | Vendor sign-off receipt |
|------------|----------|-------|---------|--------|--------------|-------------------------|
| | | | | | | |

### 4a. Halt-15 (Critical CVE) hot-fix template

[Pre-staged at M08.P3.T-halt15-template; lives here as appendix.]

- Trigger: Critical finding (CVSS >= 9.0) lands in preliminary findings
  memo or in any reviewer-question response.
- Immediate steps:
  1. @bb-connor confirmation of halt 15 in `EXECUTION-STATE.json`.
  2. Hot-fix branch `hotfix/m08-cve-<id>` opened from `main`.
  3. Trust-boundary security x2 review on the remediation PR
     (two LLM reviewer instances + @bb-connor).
  4. Vendor sign-off receipt logged in Section 4 row before merge.
  5. CVE detail redacted from the public report until the
     90-day embargo lifts.
- Disclosure window: 90 days coordinated by default; SOW redline
  rejects any vendor request to publish before remediation merges.

### 4b. Trajectory-4 candidate findings

[TODO M08 P5 fill: any Critical / High finding requiring engineering
outside trajectory-3 scope per Risk register row 5.]

| Finding ID | Severity | Reason for deferral | trajectory-4 row |
|------------|----------|---------------------|------------------|
| | | | |

## 5. Closure attestations

[TODO M08.P5.T4 fill at week 44.]

- Final report URL:
- Final report PDF hash (sha256):
- M03 release artifact channel `releases.toml` row:
- Vendor public-reports page link:
- Chio response memo URL (M08.P5.T5):
- All Critical (CVSS >= 9.0) findings remediated: <list of PR shas>
- All High findings remediated: <list of PR shas>
- Non-critical remediation roadmap: <link to audit doc Section 4>
- M04 mutation gate cited in report: <quote + report page>
- M05 threat-coverage closure cited in report: <quote + report page>
- M06 Apalache invariants cited in report: <quote + report page>
- Calendar adherence summary:
  - P0 closed by week 5 (SOW signed): <yes / no + variance>
  - P3 closed by week 30 (preliminary findings final): <yes / no>
  - P5 closed by week 44 (final report published): <yes / no>
- D07 budget posture honoured: <yes / variance>
- Halt triggers fired during M08: <none / list>
- Substitute ladder consumed: <none / vendor name + reason>
