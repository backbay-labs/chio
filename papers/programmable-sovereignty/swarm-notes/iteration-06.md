# Iteration 6

Focus: close out the three remaining (C) MISSED items from the iter-4 synthesizer's list. After iter-5 addressed C3 (BBS), C4 (anchor cross-lane), and C8 (§1 coherence), the unhit items are C1 (three figures), C5 (replay corpus contents), and C6 (65 bib entries audited for prose-citation accuracy). All three are artifact-inspection tasks orthogonal to the rhetorical surfaces the swarm has already covered. The point is to finish (C) so iterations 7 and 8 can return to synthesis and dissent.

Agent sections appended below.

## Persona: Visual-communication reviewer (C1 three figures)

The most damaging problem across all three figures is visual-semantic flatness: every actor, artifact, decision, and receipt is the same rounded rectangle (or diamond), with no color, shape distinction, or legend, so a reader who covers the labels cannot tell the figures apart.

**Figure 1 -- `admission-hook.tex`** (pre-dispatch admission; federated request without treaty context denied before tool invocation).
- Accuracy: matches §3 prose and `admission_hook.rs` citations; diamonds correspond to the three denial points.
- Publication-quality: `Non-Chiodos allow path` and `Allow + signed receipt metadata` share the same box style, so bypass and success are indistinguishable.
- Caption-vs-content: caption says "denied before tool invocation" but no node names invocation; `Deny before dispatch`=pre-tool-call is left to the reader.
- Information beyond prose: adds branch structure but draws verifier-owned artifact store as passive, not as trust-pin source the admission predicate consults.
- Missing case: malformed-context denial (`admission_hook.rs:81`) routes via the `Chiodos context?` "no" arrow to `Non-Chiodos allow path` -- malformed contexts should deny, not allow.

**Figure 2 -- `treaty-handshake.tex`** (bilateral admission; both kernels sign one strict predicate over receipt and treaty bindings).
- Accuracy: tracks §4's bilateral-DSSE prose and `treaty_admission_iff_predicate_intersection` but elides the five-rejection-code path.
- Publication-quality: symmetric A/B is clean, but `pred -> siga / sigb` reads as parallel co-equal signings rather than joint evaluation over identical canonical bytes.
- Caption-vs-content: caption says the predicate is "over receipt and treaty bindings" but the figure shows it emerging *from* `Treaty scope and ladder hash` -- binding direction inverted.
- Information beyond prose: buyer-verifier usefully enumerates five checks, but BBS/selective-disclosure is invisible despite being a §3 first-class participant.
- Missing case: no deny arrow; cannot show any verifier-check failure, so the handshake appears unconditionally successful.

**Figure 3 -- `amendment-lifecycle.tex`** (political approval is not enactment; enactment requires a refinement proof).
- Accuracy: conveys the type-level enactment invariant and matches the pass-4 `enactAmendment(ConstitutionalDelta)` API.
- Publication-quality: most readable of the three, but `Reject and anchor failure` is the only "anchor" in any figure and unintroduced in lifecycle prose.
- Caption-vs-content: tightest of the three; the insufficient `vote -> candidate` arrow without the proof diamond maps directly to the caption.
- Information beyond prose: reifies proof-downstream-of-vote structure, but the iter-1 essential-predicate invariant has nowhere to land.
- Missing case: no `rejectAmendment` path, no iter-2 meta-stability attack, no edge showing backward-refinement preservation for receipts already admitted under K.

**Most in need of revision:** Figure 1 -- concrete factual bug (malformed context routes to allow) and the only figure claiming fail-closed semantics. **Redesign:** split `Chiodos context?` into stacked `context parseable?` (deny on fail) and `context federated?` (non-Chiodos allow on no, treaty-ref check on yes), color deny red and allow green, add a legend mapping diamond=check, rectangle=artifact, double-border=signed receipt.

**Highest-priority follow-up:** add a shared `figures/style.tex` defining `kernelnode`/`artifact`/`decision`/`denyterm`/`allowterm`/`receipt` styles plus a legend macro, then rebuild all three figures against it so every figure shows at least one explicit deny path and semantics stay consistent across polity/treaty/amendment vocabulary.

## Persona: Replay corpus inspector (C5)

The single most consequential gap is that the 50-fixture "replay corpus" cited in §6 evaluates the *kernel capability path*, not the Chiodos three-vendor buyer-closure loop -- and even within that scope the byte-equivalence test is a tautology rather than a kernel re-execution.

**Actual corpus composition** (`tests/replay/fixtures/` on `codex/chiodos-7-8-live-treaty-buyer-closure`, 50 manifests across 10 families):
- 19 allow-paths: `allow_simple/01..08` (8), `allow_metered/01..05` (5), `allow_with_delegation/01..06` (6).
- 15 denial-paths: `deny_expired/01..05` (5), `deny_revoked/01..04` (4), `deny_scope_mismatch/01..06` (6).
- 6 guard-rewrite: `guard_rewrite/01..06` (PII redact, URL normalize, arg clamp, chained, idempotent).
- 4 replay-attack: `replay_attack/01..04` (immediate, delayed, stale-nonce, concurrent reuse).
- 6 tampering: `tampered_canonical_json/01..03` (field-reorder, whitespace, dup-key) + `tampered_signature/01..03` (flipped-byte, wrong-signer, truncated).

**Coverage map to prior swarm findings:**
- Stale lease / missing governance receipt / subject-digest mismatch / signer-key reuse / noncanonical JSON (iter-4 §4 enumeration of `bilateral_dsse.rs:1038` rejection codes): **0 of 50** fixtures. The `deny_expired/*` family covers capability TTL expiry, not Chiodos lease-expiry; `tampered_canonical_json/01_field_reordered` exercises hash equivalence at the receipt-input layer, not bilateral envelope canonicalisation; `tampered_signature/02_wrong_signer` checks Ed25519 signer-key binding, not the bilateral two-key independence predicate.
- Constitutional-ratchet attack class (iter-2 / iter-4): **0 of 50.** No fixture mentions amendment, K' refinement, governance vote, or trust-store predicate swap; the corpus is single-constitution.
- Cross-lane anchor attacks (iter-5: lane-substitution, latency-mismatch, witness-divergence): **0 of 50.** No fixture mentions lanes, anchors, witnesses, or cross-lane consistency; `chio-multi-lane-anchor` is not exercised by the replay-gate at all.
- Three-vendor buyer-closure loop: **0 of 50.** No fixture mentions treaty, chiodos, polity, BBS, selective disclosure, or vendor. Full-corpus grep matches only "cross-authority" delegation and "authority revoked," neither of which are Chiodos primitives.

**Diversity / depth analysis:** the 277s wall-time in `bench/results/replay-corpus-inline.tex` is misleading -- `bench/results/replay-corpus.log:154` shows `all_50_goldens_match_byte_for_byte` finishes in **1.07s** (the other 276s is `cargo build` cold-cache compile of 146 crates). Per-scenario depth ~21ms, consistent with smoke-test not adversarial. More damaging: `tests/replay/tests/golden_byte_equivalence.rs:155-190` synthesises each receipt as `{scenario, verdict, nonce}` by reading `expected_verdict` directly from the manifest, then compares to the checked-in golden -- the kernel is *not invoked*. The test demonstrates the bless recipe is byte-stable across machines, not that the kernel produces a particular verdict on adversarial input.

**Re-generation parametricity:** `examples/chiodos-3vendor/src/lib.rs` is a 3-line re-export of `crates/chio-chiodos-loopback/src/lib.rs` (1546 lines), which bakes the vendor set from fixed seeds `[11..23; 32]`. The loopback emits 19 negative cases (`examples/chiodos-3vendor/fixtures/negative-cases.json`) including `missing-destructive-governance`, `unsupported-bbs-ciphersuite`, `workflow-intersection-hash-mismatch` -- exactly the rejection paths §6 prose claims, but these are **not** wired into `tests/replay/`.

**Highest-priority follow-up:** add a `tests/replay/fixtures/chiodos_*/` family (30+ fixtures across `chiodos_treaty_deny`, `chiodos_bilateral_envelope`, `chiodos_amendment_ratchet`, `chiodos_cross_lane_anchor`) that drives `chio-chiodos-loopback::verify_package` end-to-end with the 19 negative-cases mutations plus iter-2/iter-5 adversarial paths, and report it as a *separate* row in §6 ("Chiodos buyer-closure replay") so the kernel-capability replay-gate and the Chiodos buyer-closure loop are not conflated in one inline number.

## Persona: Bibliography fact-checker (C6 sample)

The single worst citation is `omegaTrustlets`: it points at arXiv 2605.03213, which is "When Agents Handle Secrets: A Survey of Confidential Computing for Agentic AI" by Forough et al. -- a survey of six TEE platforms, not an artifact called "Omega" that "evaluates a declarative policy at the TEE boundary before any tool call" as \S8 and \S7 claim. The system the prose names does not exist at the cited URL; a reviewer who clicks the link finds a different paper, by different authors, doing different work. The bib author is `{Anonymous}`. This is a fabricated artifact citation that survived five polish passes.

Sample of 15 entries (prioritized: pass-3/4/5 additions, `Anonymous` authors, fragile URLs):

1. `omegaTrustlets` -- arXiv 2605.03213 is Forough et al.'s confidential-computing survey, not "Omega". **WRONG.**
2. `sampcertPLDI2025` -- bib `Tassarotti, Hsu, Sato, others`; actual leads are de Medeiros, Naveed, Lepoint, Kahsai, Ravitch, Zetzsche, Joshi, Tassarotti, Albarghouthi, Tristan. Hsu and Sato not authors. **WRONG.**
3. `cedarOOPSLA2024` -- six invented names in bib ("Dill", "Foster", "Grosse", "McLaughlin", "Smith", "Tasiran"); real authors include Disselkoen, He, Headley, Hicks, Hietala, Ioannidis, Kastner, Mamat, McAdams, McCutchen, Wells. **WRONG.**
4. `cedarFSE2024` -- bib `Cuvillier, Eline, Cutler, Tasiran, Torlak, Rungta`; "Cuvillier" appears to be a misspelling of Disselkoen; "Cutler" and "Tasiran" are not on this paper. **WRONG.**
5. `schneiderFMBC2025` -- bib `Schneider, Daniel and others`; actual authors are Bartoletti, Crafa, Lipparini. "Schneider" not on paper. **WRONG.**
6. `sagaNDSS2025` -- bib `Anonymous (NDSS 2025)`; actual authors are Syros, Suri, Ginesin, Nita-Rotaru, Oprea; venue is NDSS *2026*. **WRONG.**
7. `agenticFoundations2025` -- bib `{Anonymous}`; eprint 2025/2173 has a public 14-author byline (Christodorescu, Fernandes, Hooda, Jha, Rehberger, et al.). **WOBBLE.**
8. `etsiSelectiveDisclosure2025` -- entry data correct; prose mismatch documented by iter-5. **WOBBLE.**
9. `compoundProposal289` -- Protos says \$25M, \S2 prose says \$24M; "Golden Boys"/Humpy actor elided; URL is fragile crypto-news. **WOBBLE.**
10. `eip7702` -- bib `Buterin, Weiss, Ben-Sasson, others`; actual co-authors are Buterin, Dietrichs, Garnett. **WRONG.**
11. `trillianTessera` -- bib `{Sigstore / Transparency.dev}`; the intro post is by Jay Hou under transparency.dev; Sigstore is a downstream consumer. **WOBBLE.**
12. `ibcCosmos` -- bib `Goes, Manian, Aggarwal, others`; repo credits "Protocol team" with no canonical authorship. **WOBBLE.**
13. `zksyncSecurityCouncil2025` -- bib URL `blog.zknation.io`; actual report at forum.zknation.io/t/zksync-security-council-report-aug-2024-sept-2025/813. **WOBBLE.**
14. `nistAIRMFAgentic` -- title slightly off; institution correct. **GOOD.**
15. `euAIActGPAICode` -- entry data correct. **GOOD.**

Also spot-checked (all **GOOD**): `hartLaw`, `razAuthority`, `schauerRules`, `crawfordStatehood`, `isolategptNDSS2025`.

**Worst:** `omegaTrustlets` (above). **Most fixable systematic problem:** five pass-3/4/5 additions (`cedarOOPSLA2024`, `cedarFSE2024`, `sampcertPLDI2025`, `schneiderFMBC2025`, `eip7702`) have author lists with confabulated names ("Tasiran", "Foster", "Dill", "McLaughlin", "Hsu", "Sato", "Schneider", "Ben-Sasson", "Weiss") that a single arXiv/DOI re-derive pass would close.

**Highest-priority follow-up:** delete `omegaTrustlets` (and the \S8 sentence citing it) until a real "Omega" paper is identified, then run one author-correction pass against arXiv/DOI for the five WRONG entries plus `{Anonymous}` -> public authors for `agenticFoundations2025` and `sagaNDSS2025`, fixing SAGA's NDSS 2025 -> NDSS 2026 venue/year.

## Iteration summary

**This iteration surfaced two existential threats to the paper's credibility, either of which can sink a hostile peer review on first inspection.** (1) Replay corpus inspector: the 50-fixture replay corpus cited in \S6 does NOT test what the prose claims it tests -- zero of 50 fixtures touch the Chiodos buyer-closure, the iter-4 rejection codes, the iter-2 constitutional-ratchet, or the iter-5 cross-lane anchor attacks; the "byte-equivalent" test does not even invoke the kernel; the 277s wall-time figure is 276s of `cargo build` cold-cache compile, not test work. (2) Bibliography fact-checker: 7 of 15 sampled citations are WRONG with hallucinated author lists (omegaTrustlets cites the wrong paper entirely; Cedar/SampCert/Schneider/EIP-7702 all have confabulated authors); the systematic root cause is that pass-3/4/5 swarm agents generated citations from memory rather than re-deriving from primary sources. Convergent meta-finding: the artifact-inspection iterations (iter-4 code archaeologist + iter-6 corpus inspector + iter-6 bibliography fact-checker) have repeatedly found that prose-vs-artifact mismatches accumulated specifically in the recent passes that added new content; the rhetorical polish was working but the underlying factual hygiene was not.
