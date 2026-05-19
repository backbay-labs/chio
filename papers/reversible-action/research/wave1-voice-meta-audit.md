# Wave 1C: USENIX voice + engineering-meta-voice audit

## 1. Engineering-meta voice scan

**"this paper" referenced as artifact.** Two hits, both treating the article as a project artifact rather than as substance.

- `sections/04-model.tex:92`: "The theorem's role in the paper is the load-bearing reduction the headline composition leans on". IS-form: "The reduction is the load-bearing step the headline composition leans on".
- `sections/09-limitations.tex:105`: "the construction collapses to the definitional bridges and the paper has no headline". IS-form: delete the trailing clause, or rewrite as "the construction collapses to the definitional bridges and no headline result remains".

**"the construction here" / "the present construction" as project-self-reference.** Repeated 18+ times across sections. While milder than "this paper" or "we extend", the locution "the construction here" reads as a project-stance hedge whenever it could be replaced with a direct subject. Selected hits:

- `01-introduction.tex:16`: "The construction here extends the type-level discipline to the response side". IS-form: "Reversible-action discipline extends the type-level rule from amendment admission to enforcement response".
- `02-background.tex:13`: "the construction here inherits the saga vocabulary without inheriting the broader workflow-net soundness obligations". IS-form: "The reversible-action substrate inherits the saga vocabulary without the workflow-net soundness obligations".
- `02-background.tex:26`: "the construction here lifts it to the cross-organizational boundary". IS-form: "The substrate lifts the discipline to the cross-organizational boundary".
- `08-related-work.tex:36`: "the construction here gates revocation at the receipt-graph boundary between kernels". IS-form: "The substrate gates revocation at the receipt-graph boundary".
- `09-limitations.tex:100`: "is plausibly non-rfl in this construction's reading". IS-form: "is plausibly non-rfl: the discharge requires structural induction over the chain".
- `09-limitations.tex:109`: "is outside the present construction". IS-form: "is outside the model's scope".

**"the deployment instance" as artifact-with-history.** 13 hits. This locution is borderline: it can be read either as a substantive reference to the implementation under audit (acceptable) or as a project-stance hedge ("the version we shipped, with caveats"). The artifact framing dominates in:

- `05-implementation.tex:4`: "The deployment instance is an endpoint enforcement engine whose response module dispatches twelve action variants". IS-form: "The endpoint enforcement engine dispatches twelve action variants".
- `09-limitations.tex:34`: "The deployment instance exposes the /expire HTTP endpoint but no background task invokes it". IS-form: "The endpoint exposes /expire, but no background task invokes it".
- `09-limitations.tex:81`: "The deployment instance has no per-execution rollback lock". IS-form: "Per-execution rollback locks are absent; manual rollback and TTL-driven rollback can fire concurrently".

**"the title suggests" project-stance hedge.** 1 hit.

- `01-introduction.tex:67`: "The claim being made is narrower than the title suggests". IS-form: "The sovereignty claim is bounded: the polity has authority over its receipt log, not over the physical world".

**"focused Lean session" as project-history sentence.** 2 hits, in tension with the README rule against project history.

- `09-limitations.tex:103`: "Confirmation requires a focused Lean session". IS-form: "Mechanized confirmation is required; an rfl discharge would collapse the headline to a definitional bridge".
- `10-conclusion.tex:23`: "A focused Lean session on the headline composition theorem is the next falsifiable step". IS-form: "Mechanized discharge of the headline composition theorem is the next falsifiable step".

**No hits** for: "we extend", "we introduce", "we present", "we propose", "we show", "we argue", "construction defended here", "live implementation", "codebase", "checked-in fixtures", "release-engineering matrix", "bless recipe", "v0/v1/v2", branch names, "wave/iteration/session" in development sense (the word "session" appears only inside "Lean session"), "583-line", "14-crate", "workspace". The first-person plural and version-tag failure modes are absent.

**Internal artifact counts as headline.** None as headline content. References to "twelve action variants" (05:4), "four reversible action variants" (passim), and "four-receipt grammar" are substantive features of the substrate, not internal-project artifact counts. The "twelve variants" framing in 03:13 and 05:4 is the action taxonomy's structure, not an internal release count.

## 2. "This paper" specifically

Two hits, both in the form "the paper" rather than "this paper":

- `04-model.tex:92`: "The theorem's role in the paper is the load-bearing reduction". Both instances of the phrase reference the article as artifact and must be rewritten or deleted. Proposed: "The theorem's load-bearing role is the reduction the headline composition leans on".
- `09-limitations.tex:105`: "and the paper has no headline". Delete the trailing clause; rewrite to "no headline result remains".

The phrase "this paper" does not appear at all. The phrase "the parent paper" appears 33 times across the sections; that is a separate anonymity concern handled in section 6 below.

## 3. Em dash scan

`grep -nP '\x{2014}'` over all section files, paper.tex, and README.md returns ZERO hits. The em dash rule is satisfied.

## 4. USENIX register

The voice is overwhelmingly declarative-USENIX. Sample passages:

- Declarative-USENIX (good), §1:1-3: "A constitutional polity has two halves of authority. The first half is the admission predicate that decides whether an incoming receipt belongs to the polity's history; the second half is the positive enforcement act the polity issues when its constitution requires response to an admitted fact." This is "the construction names X" register, suitable for USENIX.
- Declarative-USENIX (good), §4:113-124 (Threat model paragraph): names adversary capabilities, names what the adversary cannot break, names the counter as a foundational assumption. This is the canonical USENIX threat-model paragraph.

The proposal-workshop register slips in occasionally:

- Proposal-workshop (mild), §1:67: "The claim being made is narrower than the title suggests. Sovereignty over reversible action is not a claim that a polity can compel or undo events in the physical world". This is workshop-style scope-hedging in a register USENIX would have done declaratively as: "Sovereignty over reversible action covers the polity's receipt log, not the physical world; a rollback receipt is a statement about that log".
- Proposal-workshop (mild), §10:23: "A focused Lean session on the headline composition theorem is the next falsifiable step". USENIX would say: "Mechanized discharge of the headline composition theorem is the next falsifiable step", omitting the project-process word "session".

Overall: USENIX register, with about three soft slips into proposal-workshop hedge.

## 5. Section openings vs the README voice rule

The README rule is satisfied at all section openings. None opens with "this paper", "we extend", a version tag, a branch name, or an artifact count. The closest borderline case:

- `05-implementation.tex:4`: "The deployment instance is an endpoint enforcement engine whose response module dispatches twelve action variants". The phrase "deployment instance" is borderline project-stance hedge but reads as a substantive reference to the implementation under measurement. Acceptable, with the suggested simplification under section 1.

All other openings (§2:1, §3:1, §4:1, §6:1, §7:1, §8:1, §9:1, §10:1) describe substance directly.

## 6. Anonymity check

The phrase "the parent paper" appears 33 times across the sections. The README confirms this construction is a sibling to `papers/programmable-sovereignty/`. The concern: a USENIX reviewer with access to the prior paper, or to any of its preprints, can de-anonymize the author via cited theorem names. The phrase `\thm{essential_preserved_chain}` (02:48, 04:72) and `\thm{treaty_admission_iff_predicate_intersection}` (02:42, 04:104) are likely to be unique-enough strings to identify the parent. The construction does not cite the parent by short bibitem; the parent's theorem names appear in raw text.

Recommended remediation: replace "the parent paper" with "a prior construction" or with a numbered citation `\cite{parent_construction}` once `bib.bib` is wired. The theorem names themselves are substantive content and should remain, but the explicit "parent paper" framing should be replaced with an anonymous citation.

## 7. Macros `\codepath{}` and `\thm{}`

Macro definitions at `paper.tex:28-36`: `\bbBreakString` walks each character and inserts a discretionary break after every character, letting long CamelCase and URL-style arguments wrap at any character. `\codepath` and `\thm` both alias the same character-break helper.

Usage counts: `\codepath` appears 20 times, `\thm` appears 19 times. Sampled invocations:

- `\codepath{fs::rename}` (05:25, 05:41, 06:33): short paths, no character-break needed for layout; the macro adds visual ttfamily distinction.
- `\codepath{EndpointResponsePlan}` (05:15): justifiable, long CamelCase.
- `\codepath{EDR_MAX_RESPONSE_TTL_SECONDS}` (05:22): justifiable, long SHOUT_SNAKE.
- `\codepath{crates/chio-federation/src/bilateral_dsse.rs}` (03:71, 05:71): long path, justifiable.
- `\codepath{GET /api/v1/agent/edr/response-executions/\{id\}/proof}` (05:76): very long URL path, justifiable.
- `\codepath{/expire}` (06:82, 09:35): short endpoint, borderline; ttfamily distinction is the load-bearing reason.
- `\codepath{rename(2)}`, `\codepath{rollbackOf}`, `\codepath{RollbackReceipt}` (09:85-90): short identifiers, justifiable on ttfamily grounds.
- `\thm{...}` usages all carry long snake_case theorem names; the macro is doing its job.

Assessment: not over-used. The macros are doing useful character-level work for long identifiers and adding ttfamily distinction to short ones. No instances of `\codepath` appear in headline positions where the path is the contribution.

---

## HEADLINE COUNTS

- Total engineering-meta-voice violations found: **23** (2 "the paper" hits, 18+ "the construction here / the present construction / in this construction's reading" hits requiring rewrite for IS-voice tightening, 1 "title suggests" hedge, 2 "focused Lean session" project-history hits). Borderline "deployment instance" repetitions (13) are flagged for simplification but not counted as primary violations.
- Total em dashes found: **0**.
- Total "this paper" instances found: **0** literal; **2** "the paper" referring to the article as artifact (must be rewritten).
