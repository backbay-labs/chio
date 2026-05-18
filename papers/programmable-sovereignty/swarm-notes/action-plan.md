# Action plan: programmable-sovereignty paper

Source: synthesis of 5 polish-diff passes + 3 pre-swarm review rounds + 8 swarm iterations (~25 agent passes total). The iter-8 synthesizer produced a five-tier action list; this document orders that list into an executable sprint plan, integrates the iter-8 artifact-execution agent's three new findings, and resolves the swarm's open strategic forks.

## TL;DR — the decision this week

The paper is **not publishable to arXiv today**. Two integrity failures (seven hallucinated bib entries, §6 replay-corpus misrepresentation) reach a hostile reviewer in under five minutes; either alone reads as research misconduct on a charitable reading and as fabrication on a hostile one. A §9 disclaimer cannot cure an affirmative misstatement in the abstract / §6 / §8.

**Recommended sequence**: Week 1 MUST-fix sprint → Week 2 Walch pre-disclosure embargo → Week 3+ arXiv → v2 substantive lift in parallel toward NDSS 2027 / USENIX Security 2027.

**Do not**: arXiv-this-week from the current tree; hold for v2 federation work before arXiv; rename the paper without first completing the bib + §6 fixes (renames change reviewer assignment, hostile-disclosure dynamics, and Walch-letter framing).

---

## WEEK 1 — MUST-FIX sprint (gates arXiv)

Each task includes who surfaced it and the surgical fix. Sequence the days so each fix runs `pdflatex; bibtex; pdflatex; pdflatex` + `lake build` clean before the next starts.

### Day 0 — branch decision

The paper cites files on `codex/chiodos-7-8-live-treaty-buyer-closure`; on `main` those files don't exist (artifact-execution agent: `admission_hook.rs:379` and `:947` point at lines in a 273-line file because the substance moved to submodules on `main`, and the chiodos branch is 4 Lean declarations BEHIND `main` at 109 vs 113). Pick one:

- **(recommended) Merge `codex/chiodos-7-8` to `main`**, bringing the 4 missing declarations along, and ship from `main`. Update §5 line-numbers against post-merge `main`.
- (fallback) Ship arXiv from `codex/chiodos-7-8`, **update the §5 "113" headline to "109"**, accept that arXiv readers will need to check out the branch by name.

This decision precedes B1–B5 because it determines where the line-number re-anchoring (B5) lands.

### Day 1 — bibliography integrity pass (B1, B2)

| ID | Action | Source |
|---|---|---|
| B1 | **Delete `omegaTrustlets` from `bib.bib` AND the §8 sentence citing it.** The URL `arxiv.org/html/2605.03213` resolves to "When Agents Handle Secrets" by Forough/Kogias/Haddadi 2026, NOT an "Omega: TEE-Rooted Agentic Runtime" by Anonymous. (If Forough et al. was the intended citation, rewrite the §8 sentence to describe their *survey* contribution, not a competing system.) | iter-6 fact-checker; verified by iter-8 artifact-execution `curl` |
| B2 | **Re-derive six WRONG bib entries against arXiv abstract pages or DOI metadata**: `sampcertPLDI2025` (Hsu/Sato are NOT authors), `cedarOOPSLA2024` and `cedarFSE2024` (6+ invented author names each), `schneiderFMBC2025` (actual authors are Bartoletti / Crafa / Lipparini, not Schneider), `sagaNDSS2025` (Anonymous bib + wrong year: NDSS **2026**, not 2025), `eip7702` (Weiss / Ben-Sasson are NOT co-authors). Resolve `{Anonymous}` for `agenticFoundations2025` (14 public authors exist; eprint 2025/2173). | iter-6 fact-checker |
| B2′ | Fix the six WOBBLE entries in the same pass since the cost is one BibTeX rebuild either way: `compoundProposal289` ($24M vs $25M), `trillianTessera` (Sigstore mis-attribution), `ibcCosmos` (invented authors), `zksyncSecurityCouncil2025` (URL moved to zknation.io), `etsiSelectiveDisclosure2025` (per iter-5 misrepresentation, see M4 for prose fix). | iter-6 fact-checker |

After the bib pass: re-run `bibtex paper` and confirm the warning count drops from the current **64** (artifact-execution agent measured this; the polish-diff's "44" figure is stale) — add `address`, `pages`, `publisher` fields where the warnings flag them.

### Day 2 — §5 / Table 2 line-number re-anchoring (B5)

| ID | Action | Source |
|---|---|---|
| B5 | Replace every `admission_hook.rs:<line>` citation in §5 with the actual submodule path: `admission_hook/treaty_ref.rs`, `admission_hook/dsse.rs`, `admission_hook/treaty_evidence.rs`. Re-anchor Table 2's `treaty.rs:675` to `treaty.rs:420` (the actual `validate_ladder_intersection` enforcement site; `:675` is the `ladder_mode_rank` helper). | iter-4 code archaeologist |

### Day 3–4 — §6 replay-corpus rewrite (B3) + inline-tex regeneration

| ID | Action | Source |
|---|---|---|
| B3 | **Rewrite §6 replay paragraph** to (1) separate the *kernel-capability replay-gate* (50 fixtures across `allow_simple`, `allow_metered`, `allow_with_delegation`, `deny_expired`, `deny_revoked`, `deny_scope_mismatch`, `guard_rewrite`, `replay_attack`, `tampered_canonical_json`, `tampered_signature`) from the *Chiodos buyer-closure* (currently unreplayed); (2) report the actual test wall-time **1.07s** not the "277s" build-plus-test conflation; (3) drop "byte-equivalent" framing and substitute "manifest-stable across machines"; (4) acknowledge that the 50-fixture corpus does NOT exercise iter-4 bilateral-DSSE rejection codes, iter-2 constitutional-ratchet, or iter-5 cross-lane anchor attacks — those are v2 work (V6 in the deferred list). | iter-6 corpus inspector; iter-7 triage |
| B3′ | **Regenerate `bench/results/replay-corpus-inline.tex`** from the actual `replay-corpus.log` line `test result: ok. 1 passed ... finished in 1.07s`, not from the build-plus-test conflation. The misleading 277s string is currently baked into the build artifact; §6 prose rewrite alone is insufficient. | iter-8 artifact-execution |

### Day 5 — Figure 1 redesign (B4)

| ID | Action | Source |
|---|---|---|
| B4 | Redesign `figures/admission-hook.tex`: split the `Chiodos context?` diamond into stacked `context parseable?` (deny-on-fail) and `context federated?` checks. Currently malformed contexts route to `Non-Chiodos allow path`, contradicting `admission_hook.rs:81`'s fail-closed semantics and §5 prose. Color deny red, allow green. Optionally produce a shared `figures/style.tex` defining `kernelnode` / `artifact` / `decision` / `denyterm` / `allowterm` / `receipt` styles plus a legend macro, and rebuild all three figures against it (Figures 2 and 3 also have flatness issues per iter-6 visual-communication reviewer but only Figure 1 has a factual bug). | iter-6 visual-communication reviewer |

### End-of-week gate

Before declaring the sprint complete:
- `cd formal/lean4/Chio && lake build` exits 0 with 21 jobs, no warnings.
- `cd papers/programmable-sovereignty && pdflatex; bibtex; pdflatex; pdflatex` exits 0 across all four passes, zero undefined references, **BibTeX warning count < 30** (down from current 64).
- Lean declaration count matches the §5 headline (113 on main, or 109 if you accept the chiodos-branch ship).
- `grep -nE 'admission_hook.rs:(379|947)|treaty.rs:675' sections/` returns empty.
- `grep '277' bench/results/replay-corpus-inline.tex` returns empty.
- `grep -c 'omegaTrustlets' bib.bib paper.tex sections/*.tex` returns zero across all files.

---

## WEEK 2 — Walch pre-disclosure embargo (iter-3 strategic)

After the MUST-fix branch is clean, **send the manuscript to Angela Walch** (the paper's most credible legal-academic critic, already cited as `walch2017lexicon`) with a 14-day pre-disclosure invitation:

- One-page cover: project status, swarm-disclosed limitations (specifically link to this action-plan.md), explicit invitation to write a public response to be co-launched with arXiv.
- 14-day embargo before arXiv. Frames the hostile reading on the project's terms rather than ceding the frame to a 6-months-later hit piece.
- This is the only strategic decision **irrevocably foreclosed** by pushing the arXiv button (iter-3 strategic).
- Backup co-cosigners if Walch declines: Van Valkenburgh (Coin Center), De Filippi, Hildebrandt.

In parallel: also pre-Slack to one of {IC3 retreat, Paradigm internal channel, GovAI policy circle} for technical-but-private objection capture.

---

## WEEK 3+ — MAJOR tier (v1 polish-pass, gates NDSS/USENIX submission)

Each item is a paper-text fix; collectively they are ~2 weeks of focused work after the MUST-fix sprint. They can land in the arXiv v1 if Walch's response timeline permits, otherwise in v1.1 within four weeks of arXiv.

| ID | Action | Source |
|---|---|---|
| M1 | **Scope the Hart paragraph in §7 to Hart's condition (a) only.** Replace the current overclaim with: "a constructive instance of *condition (a)* of the Hartian rule of recognition — the criterion officials apply to identify which rules count as law. The practice-of-officials and internal-point-of-view conditions remain sociological obligations the construction does not discharge." Cite Hart pp.94 / 110 / 116 explicitly. Name the cosigner network as the candidate-but-undeveloped analog for Hart's "officials." Update §10 conclusion's Hart-nod to match. | iter-1 + iter-2 + iter-4 + iter-5 convergent |
| M2 | **Title decision.** Two defensible options: (a) keep "Programmable Sovereignty" but match the body's actual emphasis by adding a §1 framing sentence after the contributions ("the substrate is more precisely a constructive instance of Hart's rule of recognition over receipt admission, restated as 'sovereignty' for accessibility"); (b) promote subtitle to head ("Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts"), demote sovereignty to a single §7 reframing. Iter-7 fresh-hostile + iter-1 naive reader argue for (b); round-2 tactical + iter-3 strategic argue for (a). **Recommendation: defer until after Walch embargo response** — her reaction is the strongest evidence either way. | iter-7 fresh-hostile; round-2 tactical (split) |
| M4 | **Rewrite §8 BBS paragraph + §9 PQC bullet.** Acknowledge that ETSI TR 119 476-1 is a *comparative analysis* (SD-JWT, mdoc, BBS+, BBS#, zk-SNARK), not an endorsement; the EUDI Architecture and Reference Framework actually mandates SD-JWT VC + ISO mdoc, not BBS. Add threshold-BBS+ citations (Doerner-Kondi-Lee-shelat IEEE S&P 2023; Nof-Goyal CT-RSA 2025 non-interactive) to close the iter-3 FROST/ROAST gap on the BBS-issuer-key side. Re-frame §9 PQC bullet to name salted-hash-plus-PQC (ETSI's actual recommended migration) alongside transparent-SNARK. Rerun the BBS verification benchmark in release profile (currently 162 ms / p50 is debug-profile, ~25× release). | iter-5 BBS deployment reviewer |
| M5 | **Add positive "load-bearing" labels to §4.** After §4 paragraph 45 (treaty intersection theorem): one sentence labeling \thm{treaty_admission_iff_predicate_intersection} as "load-bearing for cross-kernel admission." After §4 paragraph 57 (ladder stability theorem): same for \thm{treaty_admission_stable_under_ladder_floor}. This mirrors line 71's negative labeling of the amendment theorems as definitional bridges and gives §1 bullet 2's "two load-bearing theorems" claim a destination in §4 prose. | iter-5 coherence auditor |
| M6 | **Rewrite §10 conclusion's "next concrete result" sentence.** Current text presumes a willing regulator co-signing counterparty; §9 admits no recognized framework cites Lean-attested receipts. Rewrite to: "willing co-signing counterparty (industry consortium, sectoral SRO, or research-led pilot)" — drop the "external regulator" specificity since the swarm found zero public evidence of regulator interest at the substrate level. | iter-1 hostile + iter-7 fresh-hostile |
| M7 | **Add §9 bullet on schema evolution.** "Cross-vendor predicate schema evolution: when two kernels operating at different schema versions exchange receipts, the substrate currently denies on `unsupported_treaty_scope_schema` without distinguishing the failure from a constitutional denial; a versioned-predicate compatibility profile and a distinct schema-mismatch denial code are required for multi-tenant deployment." | iter-2 industry practitioner |
| M8 | **Add a sentence to §3 or §4 binding the trust-store-admission predicate as non-amendable.** "The verifier-owned trust store's admission predicate is treated as a non-amendable axiom in the present construction; trajectory-invariant theorems closing the meta-stability question (constitutional-ratchet attacks lifted one level up) remain v2 work." | iter-2 adversarial brainstormer |
| M9 | **Split Table 4** into "Foundational cryptographic assumptions" (Ed25519, SHA-256, canonical-JSON correctness) and "Operational discipline" (verifier-store provenance, Lean inventory maintenance, public-witness honesty, legal-entity boundary). | iter-7 fresh-hostile |
| M10 | **Formatting fork**. Produce both USENIX and ACM (`sigconf,anonymous,review,nonacm`) builds from one source. acmart currently commits to an ACM venue while citation density is FAccT/AIES-coded; the fork costs ~half a day and lets v1 arXiv format track venue timeline. | iter-7 fresh-hostile |
| M11 | **One §3 sentence acknowledging the tile-log attack surface** inherited from the pass-5 `trillianTessera` citation. "Adopting tile-log architecture (Trillian Tessera) imports a tile-boundary inclusion-proof attack surface where a witness may sign tile-N consistent with two distinct tile-(N+1) extensions; closing this requires a per-anchor-epoch tile-boundary-consistency proof obligation that is v2 work." | iter-5 multi-lane adversary |
| M12 | **(NEW from iter-8 artifact-execution.) Update §5's declaration count headline to match the publication branch.** If shipping from main: keep 113. If shipping from chiodos-7-8: change to 109. The headline currently disagrees with the chiodos branch by 4 declarations. | iter-8 artifact-execution |
| M13 | **(NEW from iter-8 artifact-execution.) Reduce BibTeX warnings from 64 toward < 20** by adding `address`, `pages`, `publisher` fields to the 27 unique keys the bbl log flags. Polish-diff's "44" baseline is stale. | iter-8 artifact-execution |

**Additionally — cheapest single fix in the paper**: add three citations to §7's AI safety paragraph that currently name "alignment-faking" and "Constitutional AI" by phrase without citing either: `hubingerAlignmentFaking2024` (Hubinger et al. Anthropic / Redwood 2024), `baiConstitutionalAI2022` (Bai et al. Anthropic 2022), and an Apollo / Berglund situational-awareness paper. This was iter-3 cross-paper's highest-priority recommendation and remains uncosted (iter-3, FOLLOW-UP item).

---

## MONTHS 2–6 — v2 substantive lift (gates NDSS / USENIX full-paper submission)

These are not text fixes; they are systems / formal-methods work. They land in v2 of the paper or in the follow-up papers below.

| ID | Item | Source |
|---|---|---|
| V1 | **Build the syntactic `Predicate` ADT with `denote : Predicate -> ReceiptId -> Bool`** so `BackwardRefines` becomes decidable. The Cedar move. Today `ConstitutionalDelta` is essentially unconstructable for non-trivial polities because `BackwardRefines` quantifies over opaque `ReceiptId -> Bool` closures. | iter-1 PL skeptic, iter-4 synthesizer |
| V2 | **Build a real two-kernel federation** across a real network boundary. Currently `chio-chiodos-loopback` synthesizes two vendor identities in one process. Senior PC reviewer's biggest blocker. | iter-4 code archaeologist; round-3 senior PC |
| V3 | **Add `lane_quorum_policy` treaty-scope field** carrying `(required_lanes, k_of_n, witness_independence_required, settlement_floor_unix_ms)` and prove `anchor_admission_iff_lane_quorum_satisfied`. Closes iter-5's five cross-lane attacks. | iter-5 multi-lane adversary |
| V4 | **Prove the meta-stability theorem** binding the trust-store-admission predicate non-amendably across reachable amendment trajectories. Closes the constitutional-ratchet-lifted-one-level-up attack from iter-2. | iter-2 adversarial |
| V5 | **Prove the trajectory-invariant theorem** (essential-predicate preservation under amendment chains). Closes the iter-1 / iter-4 constitutional-ratchet attack at the policy layer. | iter-1 hostile; iter-4 |
| V6 | **Build the Chiodos buyer-closure replay corpus**: 30+ fixtures across `chiodos_treaty_deny`, `chiodos_bilateral_envelope`, `chiodos_amendment_ratchet`, `chiodos_cross_lane_anchor` families, wired into `tests/replay/`. The 19 negative-case mutations in `examples/chiodos-3vendor/fixtures/negative-cases.json` are a starting point. | iter-6 corpus inspector |
| V7 | **Threshold cosigning (FROST / ROAST)** for the two-key DSSE binding, posed as a 2-of-2 instance of a t-of-n threshold scheme. | iter-3 cross-paper; iter-5 BBS reviewer |
| V8 | **Issuer-rotation epoch binding for BBS derivation**. Closes the iter-2 issuer-rotation-race attack and the `draft-irtf-cfrg-bbs-signatures-10` gap. | iter-2 adversarial; iter-5 BBS |

---

## POST-PAPER strategic moves (parallel)

| Move | Why now | Source |
|---|---|---|
| **Walch pre-disclosure embargo** | Single move irrevocably foreclosed by pushing arXiv. Frame hostile-reading on project terms. | iter-3 strategic |
| **Court Anthropic as co-author** (Sam Bowman / Ethan Perez / Roger Grosse) | Constitutional AI naming collision becomes fertile via co-authorship; internal Anthropic hostile-review for free; obviates the "rename constitution" question. | iter-3 strategic |
| **Three AI-safety citations to §7** (Hubinger 2024 + Bai 2022 + Apollo situational-awareness) | Cheapest reviewer-irritant fix in the paper; currently names alignment-faking + Constitutional AI uncited. | iter-3 cross-paper |
| **Short paper to HotSec / WOOT 6 weeks ahead of long paper** | Inoculates audience; converts long paper's §8 into "extension of accepted work." Gated by V0 (short-paper §4 freestanding accept-set theorem must exist first). | iter-3 strategic + comparator |
| **NDSS 2026 / USENIX Security 2026 simultaneous-submission policy check** | Two-paper plan may trigger desk-reject independent of reviewer judgment. Read both CFPs side-by-side before further short-paper drafting. | iter-7 fresh-hostile |
| **Appendix C: Compound 289 worked retrospective** | Iter-4 case-study agent drafted what becomes Appendix C; addresses iter-1 Senate-staffer's regulator-facing-example ask. Honest verdict ("Chio would make legible, not prevent") must stay intact. | iter-4 case study |
| **Case-study pilots** | Healthcare AI compliance (tactical agent pick, Q3 2026); indigenous data sovereignty (unexpected-apps agent pick, most novel); AI cross-lab red-team attestation (UK AISI partnership, AI safety agent pick). Pick one for v2 paper; pursue the other two as follow-up artifacts. | round-2 tactical; round-3 unexpected; round-3 AI safety |
| **Three things NOT to do** | (1) Decline any Network State Conference invitation; (2) refuse all crypto-Twitter token / chain / "based" framings — "Chio has no token, no chain"; (3) defer formal regulator MoU until after one case-study pilot has held up to public adversarial scrutiny. | round-2 tactical |

---

## NEXT-PAPER pipeline (2026 → 2028)

The iter-8 next-paper-forward-looker outlined five papers this paper enables, ranked by what the swarm validated:

| # | Title (working) | Venue / deadline | Co-author target |
|---|---|---|---|
| 1 | **Federated Receipt Admission Between Two Independently-Operated Lean-Attested Kernels** (v2 of the current paper) | NDSS 2027 (Aug 2026) | Andrew Myers / Adrian Sampson |
| 2 | **Bilateral Receipt Admission with Treaty-Bound DSSE** (short paper standalone) | USENIX Security 2027 short track (Feb 2026) | Brian Behlendorf / Trevor Rosen |
| 3 | **Cosigner Officialdom: An Empirical Study of Hartian Rule-of-Recognition Practice** | *Yale JOLT* or *Harvard JOLT* (Q1 2027) | Weitzner / Nissenbaum + sociology-of-tech co-author |
| 4 | **Trajectory-Invariant Constitutions: Meta-Stability Theorems for Programmable Polities** | POPL 2028 (Jul 2027) — explicitly NOT CSF or S&P | Adam Chlipala or Andrew Appel |
| 5 | **Adversarial Replay for Federated Receipt Admission: A Reproducible Benchmark** | USENIX Security 2027 full or NSDI 2027 (Sep 2026) | Vern Paxson or Robert Beverly + artifact-eval chair |

**Most valuable by impact**: paper (4) — without trajectory invariance the sovereignty claim collapses under one adversarial meta-amendment.

**Most likely to ship by end-of-2026**: paper (2) — finished skeleton, authorized two-paper strategy, smallest gap to shipping (one freestanding theorem + one attack-ablation table + the seven MUST-fix bib re-derivations).

---

## Process notes for the next review swarm

The iter-7 meta-swarm reviewer identified three biases the next swarm must correct:

1. **Citation-by-deference**: iter-1's "Hart-on-rfl" was re-affirmed by four subsequent agents with zero independent re-derivation; iter-4's "ladder mode 5 is `quorum_required`" was cited as settled without anyone re-opening `treaty.rs:681`. **Process change**: every new citation requires primary-source re-derivation (arXiv abstract page, DOI metadata, or venue proceedings) before the pass closes.

2. **18+ stacked recommendations, zero retractions**: no agent ever flagged another agent as wrong; every "highest-priority follow-up" assumed prior follow-ups stood. **Process change**: the first agent of each iteration is explicitly empowered to retract prior swarm findings by name (e.g., iter-8 artifact-execution correctly inverted polish-diff finding #1 on the ladder-mode-5 mismatch).

3. **No agent ran anything across iterations 1–7**: zero agents executed `cargo test`, `lake build`, or `curl` against `bib.bib` DOIs until iter-8 commissioned an artifact-execution agent specifically. **Process change**: every swarm iteration includes at least one execution-only agent with a license to use Bash; the rest are readers.

---

## What to do today

If you only have 30 minutes today: read this document end to end, then **make the Day 0 branch decision** (merge chiodos-7-8 to main, or commit to shipping from chiodos with the 113 → 109 headline change). Every other Week 1 action sequences off that decision.

If you have a day today: do Day 0 + Day 1 (B1 + B2 + B2′ bib pass + BibTeX warning sweep). The bib hygiene is the most embarrassing of the seven blockers and the most mechanical.

If you have a week: complete the full Week 1 MUST-fix sprint to the end-of-week gate. The paper exits the week ready for the Walch embargo letter.

If you have a month: complete Week 1 + Walch embargo + Week 3+ MAJOR tier. The paper exits the month ready for arXiv v1.

If you have a quarter: add V1 (Predicate ADT) and V6 (Chiodos replay corpus). The paper exits the quarter with the two highest-leverage v2 lifts in flight.
