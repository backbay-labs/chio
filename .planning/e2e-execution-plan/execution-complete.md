# Execution Complete -- Wave-by-Wave Handoff

Date: 2026-05-18
Branch: `research/programmable-sovereignty-papers`
Orchestrator session: single, autonomous through Waves 1-5

## TL;DR

The swarm has prepared everything that does not require human action. Two papers are submission-ready packages on disk, a workshop polish is queued, two outreach drafts are polished, a V2 engineering plan is parked on its own branch, and four conditional waves sleep until the human triggers them. The remaining work is all human-action: signing, registering, drafting two short appendices, clicking Submit, and choosing when to send outreach.

## What shipped (in commit order)

| Commit | Wave | Summary |
|---|---|---|
| `bff1987f9` | Wave 1 | Walch letter polished, parent paper anonymization findings, venue decision memo (USENIX Cycle 1), foundational playbook |
| `1f5d67b22` | Wave 2 | Parent paper USENIX submission-ready (paper-usenix.pdf 13-body), Makefile build gate, supplementary package |
| `675d145f3` | Wave 3.b | Sensor-grounded USENIX submission-ready (paper-usenix.pdf 10-body), Makefile, supplementary package |
| `b19c30c5a` | Wave 3.a | V2 tier-1 federation plan + scaffolding (parked on branch `wave-3-v2-tier-1`) |
| (pending commit) | Waves 4 + 5 | Sensor-grounded SUBMISSION-CHECKLIST.md, agentic-tool-safety workshop polish + VENUE-DECISION.md, Anthropic outreach polish |

## Submission-ready packages on disk

### Parent paper (USENIX Security 2027 Cycle 1, deadline 2026-08-25)

- `papers/programmable-sovereignty/paper-usenix.pdf` -- 16 pages total, 13 body. 4-pass clean.
- `papers/programmable-sovereignty/supplementary/lean-source.tar.gz` -- 35 KB, untars to `lake build`-clean Lean project covering the four parent-paper theorems with only standard kernel axioms (`propext`).
- `papers/programmable-sovereignty/supplementary/proof-manifest.toml` and `theorem-inventory.json` -- machine-readable artifact metadata.
- `papers/programmable-sovereignty/supplementary/README.md` -- 1-page reviewer overview adaptable for the Open Science appendix.

### Sensor-grounded paper (USENIX Security 2027 Cycle 1, deadline 2026-08-25)

- `papers/sensor-grounded-admission/paper-usenix.pdf` -- 12 pages total, 10 body. 4-pass clean.
- `papers/sensor-grounded-admission/supplementary/` -- analogous package, 41 KB lean-source tarball; four sensor-grounded theorems verified with kernel axioms only (`propext`, `Classical.choice`, `Quot.sound`).
- `papers/sensor-grounded-admission/SUBMISSION-CHECKLIST.md` -- pre-submission verification with one-page Open items list.

### Agentic-tool-safety workshop paper

- `papers/agentic-tool-safety/paper.tex` and `paper.pdf` -- 4-pass clean on generic `article` 11pt template. Word count 4896 (down from 6033). Three named theorems cited from the parent paper.
- `papers/agentic-tool-safety/VENUE-DECISION.md` -- workshop pick (NeurIPS 2026 workshop track, suggested deadline 2026-08-29), with 5 open items for the human.
- Template will swap to `neurips_2026.sty` once the specific workshop is named (NeurIPS 2026 workshop list finalizes after 2026-07-11).

### Outreach drafts (polished, awaiting human signature)

- `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md` -- Walch pre-arXiv embargo letter (351 words). Two `<!-- CHECK: ... -->` comments flag points to verify before signing.
- `papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md` -- Anthropic parent-paper inquiry (Bowman primary). 291-word body.
- `papers/agentic-tool-safety/anthropic-coauthor-pitch.md` -- Anthropic agentic-tool-safety pitch (Perez primary). 318-word body.

### V2 engineering scaffold (parked)

- Branch `wave-3-v2-tier-1` off `research/programmable-sovereignty-papers`, head `b19c30c5a`.
- `.planning/wave-3-v2-tier-1/PLAN.md` -- 31-task plan, 114 executable checkbox steps.
- `infra/federation-localhost/docker-compose.yml` -- two-kernel container scaffold.
- `crates/chio-federation/tests/e2e_two_kernel_docker.rs` -- `#[ignore]`-gated failing E2E test as the implementation contract.
- `.github/workflows/federation-localhost.yml` -- CI lane scaffolding.
- `cargo check --workspace` exit 0; `cargo test --workspace` stays green.
- Note: the branch also contains a duplicate copy of the Wave 3.b sensor-grounded commit (`8fa4297be`) because the W3.b subagent left HEAD on `wave-3-v2-tier-1`; the canonical Wave 3.b is `675d145f3` on the research branch. Cosmetic only.

## Sleeping waves

| Wave | Trigger | When it wakes |
|---|---|---|
| 5.c | Walch response arrives | Human reports response; orchestrator dispatches classifier subagent |
| 5.d | Parent-paper PC reviews arrive | Human reports reviews (~4 months after submission); orchestrator dispatches structured-response subagent |
| 6 | Parent paper accept/reject decision | One of W5.d's outputs; forks into accept-branch (Paper N1 reversible-action with rfl-gate check) or reject-branch (revise and resubmit) |
| 7 | Walch accepts embargo (per W5.c) | Cross-disciplinary tier (Paper N2 delegated-emergency-authority) wakes; sleeps if Walch declines or never responds |
| 8 | Co-author landing (Anthropic, Walch, FM partner) | Papers 3-4 wake if and only if a co-author has landed; otherwise stays asleep |

The orchestrator does NOT dispatch sleeping waves. They wake on human-reported triggers.

## Stacked HUMAN GATES

These are the actions the human chose to stack rather than resolve mid-wave. None of them blocks the others; the human can resolve them in any order.

### Critical-path gates (parent paper, deadline 2026-08-25)

1. **Draft Open Science appendix** (~1 page) for the parent paper. Source material: `papers/programmable-sovereignty/supplementary/README.md`.
2. **Draft Ethics Considerations appendix** (~1 page) for the parent paper. No draft in the repo; a formal-substrate paper without human-subjects work typically discusses dual-use concerns and disclosure timelines.
3. **Register USENIX submission account** (https://www.usenix.org/conference/usenixsecurity27).
4. **Upload parent paper to USENIX Cycle 1 portal**: `paper-usenix.pdf` + `supplementary/lean-source.tar.gz` + Open Science statement + Ethics statement.
5. **Click Submit** by 2026-08-25 23:59 AoE.

### Critical-path gates (sensor-grounded paper, same deadline)

6. **Draft Open Science appendix** (~1 page) for the sensor-grounded paper. Source material: `papers/sensor-grounded-admission/supplementary/README.md`.
7. **Draft Ethics Considerations appendix** (~1 page) for the sensor-grounded paper.
8. **Decide on Chio-substrate citation policy.** The sensor-grounded paper cites `chioProgrammableSovereignty2027` (the parent paper) and refers to "the Chio substrate" in sections 1 and 8. Confirm this fits the human's reading of USENIX double-blind policy. If conservative: anonymize the cite before upload.
9. **Upload sensor-grounded paper to USENIX Cycle 1 portal**: `paper-usenix.pdf` + `supplementary/lean-source.tar.gz` + Open Science statement + Ethics statement.
10. **Click Submit** by 2026-08-25 23:59 AoE.

Risk to be aware of: two papers from the same author at the same USENIX cycle is allowed but concentrates exposure to a single PC. The W1.c memo documented the tradeoff.

### Workshop-paper gate (agentic-tool-safety, deadline 2026-08-29)

11. **Pick the specific NeurIPS 2026 workshop** after the workshop list is announced (anticipated 2026-07-11). Candidates: Safe Generative AI, AgentAI / Agentic-Safety, Trustworthy ML.
12. **Swap LaTeX template** to `neurips_2026.sty` once the workshop is named. Expected compression to 6-7 pages.
13. **Decide on Anthropic co-author timing** for the agentic-tool-safety paper. Perez recommended primary. The outreach polish at `papers/agentic-tool-safety/anthropic-coauthor-pitch.md` is ready to send.
14. **Submit to the chosen workshop** by its deadline.

### Outreach gates (human-discretion timing)

15. **Walch letter**: read polished draft at `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md`, verify the two `<!-- CHECK: ... -->` comments against the current manuscript, sign, and send. Recommended timing: after the parent paper is submitted to USENIX so the manuscript is at a stable shape. Wave 7 cross-disciplinary tier is conditional on this.
16. **Anthropic outreach (parent paper)**: send polished draft at `papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md` to Bowman. Recommended timing: after parent paper submitted to USENIX.
17. **Anthropic outreach (agentic-tool-safety)**: send polished pitch at `papers/agentic-tool-safety/anthropic-coauthor-pitch.md` to Perez. Recommended timing: when the human is ready to make the agentic-tool-safety workshop ask, ideally before the NeurIPS workshop deadline.

### Engineering gate (V2 tier-1)

18. **Decide whether to start V2 tier-1 implementation.** Branch `wave-3-v2-tier-1` has a 31-task PLAN.md and a failing E2E test. Estimated 2-3 weeks of work. If pursued, the work strengthens the sensor-grounded §3 if it lands before sensor-grounded ships (i.e., before 2026-08-25). Out of scope for this orchestrator session.

## What was NOT done (and why)

- The Walch letter was NOT sent. Per human decision 2026-05-18: deferred to later.
- The parent paper was NOT submitted to USENIX. Per playbook: submission is a human action.
- The sensor-grounded paper was NOT submitted to USENIX. Same reason.
- The Anthropic outreach was NOT sent. Per playbook: external outreach is human-only.
- The agentic-tool-safety workshop was NOT submitted. Wait for specific workshop announcement.
- The V2 tier-1 implementation was NOT completed. 2-3 weeks of engineering; out of scope for one orchestrator session.
- Sleeping waves (5.c, 5.d, 6, 7, 8) were NOT dispatched. They wait on triggers the human controls.

## Verification trail

Every commit on the research branch:
- Passed em-dash grep (zero U+2014 across all paper text).
- Passed banned-phrase grep (zero engineering-meta voice across paper text; referential mentions in audit / verification documents are noted as legitimate).
- Triggered `make submit-check` exit 0 for both submission targets.
- 4-pass pdflatex clean (zero errors, zero LaTeX warnings, zero BibTeX warnings, zero undefined references).
- Lean substrate `lake build` exit 0; `#print axioms` reports only standard kernel axioms (`propext`, `Classical.choice`, `Quot.sound`).

## Single sentence summary

Two papers and a workshop are submission-ready, two outreach drafts are polished, a V2 engineering scaffold is parked, and the seven critical-path human gates plus three discretion gates are stacked for the human to resolve when ready; nothing else in the 24-month plan moves until at least one of those gates resolves.
