# trajectory-3 Execution Board

Operations document for executing the ten trajectory-3 milestones across
three code waves plus two long-clock vendor calendars on `main`. This is
the canonical operations doc; per-milestone narratives are the source of
truth for scope.

Genesis: 2026-04-30 (verdict-anchored synthesis after a two-round
seven-agent debate).
House rules: no em dashes, fail-closed, conventional commits, clippy
`unwrap_used = "deny"` and `expect_used = "deny"`.

---

## 0. Scope

This board operationalizes the ten milestones in
`.planning/trajectory-3/01-*.md` through `10-*.md`. It does not repeat
their content; it adds the layer that lets a swarm of executor +
reviewer agents land them on `main` without corrupting state.

Inputs:
- Ten milestone narrative docs + `README.md` + `STYLE.md`
- Per-phase ticket files at `tickets/M{nn}/P{n}.yml`
- Generated `tickets/manifest.yml`

Outputs:
- All eight code milestones (M01-M07, M10) merged to `main`
- M08 NCC Group or Trail of Bits report published with remediation log
- M09 HITRUST i1 certificate received
- Conformance, mutation, and threat-coverage gates green at
  trajectory-3 thresholds
- No regressions on existing trajectory-2 tests

Non-goals: ISO 42001 (deferred per D02), three-cloud distribution
(deferred per D03), full Apalache FSM (deferred per D04 to
trajectory-4), full crate consolidation 88->70 (deferred per D05 to
trajectory-4).

---

## 1. Authoring provenance

Authored 2026-04-30 by a verdict-anchored synthesis run. The synthesis
input was a two-round seven-agent debate evaluating five frames
(halt-to-stabilize, customer-led, deepen-the-substrate, audit-led,
expand-distribution). The blend frame won because it lets external
attestation sit on a stable substrate while a real customer consumes
it. See `.planning/trajectory/AUDIT-FINAL.md` (or the conversation
history of the 2026-04-30 synthesizer run) for the full verdict.

| Milestone | Phases | Wave | TB | Effort weeks (low/real/high) |
|-----------|--------|------|----|------------------------------|
| M01 opus-design-partner-pilot         | P0..P5 | W1 | yes | 4/6/9 |
| M02 ai-lab-evaluation-beachhead       | P0..P5 | W1 | yes | 6/9/13 |
| M03 hosted-ci-truth-and-reproducible-builds | P0..P5 | W1 | yes | 4/6/9 |
| M04 mutation-and-verdict-matrix-promotion | P0..P5 | W1 | yes | 6/9/13 |
| M05 threat-coverage-closure           | P0..P5 | W1 | yes | 3/5/7 |
| M06 focused-formal-and-supply-chain   | P0..P5 | W2 | yes | 7/10/14 |
| M07 chio-kernel-mobile-mvp            | P0..P5 | W2 | yes | 8/11/15 |
| M08 independent-crypto-protocol-review | P0..P5 | Wv | yes | 4/6/9 (26-44 calendar) |
| M09 hitrust-i1-assessment             | P0..P5 | Wv | yes | 5/8/12 (12-36 calendar) |
| M10 aws-bedrock-mcp-conformance       | P0..P5 | W3 | yes | 6/9/13 |

Per-milestone ticket counts and effort_days (computed from
`tickets/manifest.yml`):

| Milestone | Tickets | Effort days |
|-----------|---------|-------------|
| M01 | 32 | 30.5 |
| M02 | 26 | 28.0 |
| M03 | 26 | 19.5 |
| M04 | 17 | 19.5 |
| M05 | 12 | 16.0 |
| M06 | 28 | 26.5 |
| M07 | 27 | 37.0 |
| M08 | 32 | 22.75 |
| M09 | 48 | 32.25 |
| M10 | 31 | 29.5 |
| **Total** | **279** | **261.5** |

---

## 2. Wave plan

A wave is a saturation-of-parallelism cohort: the maximal set of
tickets whose dependency closure is satisfied AND whose file-ownership
write-sets are mutually disjoint. trajectory-3 uses three code waves
plus two vendor lanes.

### Wave 0: pre-flight

Before any P0 wave-opener runs, these artifacts must exist:

| # | Artifact | Path | Owner | Blocking |
|---|----------|------|-------|----------|
| 1 | Ownership manifest | `.planning/trajectory-3/OWNERS.toml` | sequencer | yes |
| 2 | Freeze register | `.planning/trajectory-3/freezes.yml` | sequencer | yes |
| 3 | Decisions register | `.planning/trajectory-3/decisions.yml` | sequencer | yes |
| 4 | Generated CODEOWNERS regen | `CODEOWNERS` | sequencer | yes |
| 5 | Ticket manifest | `.planning/trajectory-3/tickets/manifest.yml` | sequencer | yes |
| 6 | Per-phase ticket files | `.planning/trajectory-3/tickets/M{nn}/P{n}.yml` | per-milestone agents | yes |
| 7 | Execution-state seed | `.planning/trajectory-3/EXECUTION-STATE.json` | orchestrator | yes |
| 8 | Audit-doc skeletons | `.planning/trajectory-3/audits/M{NN}-{slug}.md` | sequencer | yes |
| 9 | M08 RFP draft + vendor shortlist | `.planning/trajectory-3/audits/M08-vendor-evidence.md` | M08 author | week 1 |
| 10 | M09 gap-assessment kickoff | `.planning/trajectory-3/audits/M09-vendor-evidence.md` | M09 author | week 1 |
| 11 | Hosted CI re-enablement plan | `.planning/trajectory-3/audits/M03-ci-restoration.md` | M03 author | yes |

### Wave 1: debt + pilot + CI (weeks 1-15)

Five milestones run in parallel after Wave 0 closes.

| Milestone | Phases | Notes |
|-----------|--------|-------|
| M03 hosted CI + reproducible builds | P0..P5 | First to reach P0 close; M01/M02/M04/M05 land their P0 wave-openers in parallel |
| M01 Opus pilot | P0..P5 | Customer-anchored; 30-day production observation closes the milestone |
| M02 AI-lab evaluation beachhead | P0..P5 | Customer named in week 1 (Anthropic / METR / Apollo) |
| M04 mutation + verdict-matrix promotion | P0..P5 | Honest-threshold gate (D08) at week 12 |
| M05 threat-coverage closure | P0..P5 | weights_hash_spoof partial->passing, dispatch_allow placeholder replaced |

### Wave 2: formal + mobile (weeks 12-26)

| Milestone | Phases | Notes |
|-----------|--------|-------|
| M06 focused formal + supply-chain | P0..P5 | 3-4 highest-leverage TLA+/Apalache invariants; cargo-vet; SBOM |
| M07 chio-kernel-mobile MVP | P0..P5 | iOS framework + Android AAR + App Attest + Play Integrity |

### Wave 3: distribution (weeks 22-30)

| Milestone | Phases | Notes |
|-----------|--------|-------|
| M10 AWS Bedrock + MCP conformance | P0..P5 | Single cloud per D03; AWS approval is the third-party evidence |

### Vendor calendars (start week 1, run parallel to all waves)

| Milestone | Lane | Calendar |
|-----------|------|----------|
| M08 NCC Group or Trail of Bits review | Wv | RFP weeks 1-5; vendor booking 6-14; active review 15-30; remediation 30-44 |
| M09 HITRUST i1 | Wv | Gap weeks 8-14; remediation 14-24; assessor 24-36 |

Vendor calendars do NOT block wave transitions; their evidence is a
trajectory-close gate.

---

## 3. Cross-milestone artefact ownership

| Artifact | Owner | Consumers |
|----------|-------|-----------|
| Opus tenant runbook + log-export schema | M01 | M09 (HITRUST scope), M07 (mobile patient-app) |
| AI-lab eval-receipt format | M02 | M04 (verdict-driver parity) |
| Hosted CI workflows + reproducible-build pipeline | M03 | every other milestone |
| Mutation lane + verdict matrix gating | M04 | the M08 reviewer cites the gate |
| Threat-coverage table | M05 | the M08 reviewer cross-checks |
| Apalache focused invariants + SBOM/cargo-vet | M06 | M09 assessor consumes SBOM |
| chio-kernel-mobile bindings | M07 | M01 mobile patient-app |
| NCC Group or Trail of Bits report | M08 | trajectory close, release narrative |
| HITRUST i1 certificate | M09 | Opus cluster procurement, release narrative |
| AWS Bedrock listing + MCP conformance entry | M10 | distribution narrative |

## 4. Freezes

See `.planning/trajectory-3/freezes.yml`. Anticipated overlaps:

- M04 + M05 both touch `crates/chio-attest-verify/**` and
  `crates/chio-conformance/**`.
- M06 touches `crates/chio-revocation-oracle/**` + supply-chain
  workflows.
- M07 touches `crates/chio-kernel-mobile/**` + `crates/chio-custody-hw/**`.

## 5. Concurrency policy

- Per milestone: soft 5, hard 8 in-flight tickets.
- Across the trajectory: soft 20, hard 30.
- All ten milestones are trust-boundary, so security x2 review
  applies on every PR.

## 6. CI budget

- M03 unlocks the "real" CI lane in Wave 1; before that, the inherited
  trajectory-2 CI runs.
- Mutation lane (M04) is advisory until M04 P3; gating from M04 P3.T1
  onward.
- Verdict matrix non-Rust drivers (M04 P5) flip from advisory to
  required after two consecutive green runs.

## 7. Failure-mode handling

- See AUTONOMOUS-PROMPT section 9.
- Trajectory-3 specific halt triggers (12-15) cover design-partner
  withdrawal, vendor calendar slip, HITRUST rejection, M08 reviewer
  critical CVE.

## 8. Audit trail

`EXECUTION-LOG.ndjson` is append-only with rotation at 100 MB.
Trajectory-3 adds two event classes:

- `vendor_calendar_event`: M08 / HITRUST checkpoints with vendor
  attribution.
- `customer_evidence_received`: Opus / AI-lab review receipts.

## 9. Trajectory close

Done when:

- Wave 3 gate passes (M10 AWS marketplace listing live + MCP
  conformance entry published).
- M08 vendor report published with remediation log.
- M09 HITRUST i1 certificate received.
- The four global gates land green on `main`:
  - mutation kill-rate at the documented threshold (D08 honest
    threshold)
  - threat-coverage table has zero `partial` or `placeholder` rows
  - verdict-matrix non-Rust drivers required-CI green
  - hosted CI green on the v3.18-Opus release commit, reproducible-build
    hash published and externally reproduced

At close, archive `EXECUTION-STATE.json` to
`.planning/trajectory-3/archive/EXECUTION-STATE-CLOSED.json`. Author
`.planning/trajectory-3/RETROSPECTIVE.md`.
