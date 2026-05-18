# Post-execution review 1

Date: 2026-05-17
Scope: Fresh-eye review after action-plan execution completed all swarm-documented findings. Verified that none of these issues appear in `polish-diff.md` Technical-findings section, the iter-1..8 follow-up logs, or the action-plan progress tracker.

## New issues found

### Issue 1: Abstract names five operations, body names four (internal inconsistency)
**Severity**: major
**Where**: `paper.tex:27` (abstract) vs `sections/01-introduction.tex:3` and `sections/10-conclusion.tex:3`
**Problem**: The abstract states "Admission, capability attenuation, treaty intersection, ladder-floor stability, and constitutional amendment become decidable operations on this triple" -- five operations. §1 line 3 says "reducing institutional authority to four decidable operations on a polity triple $(T, C, K)$: admission ..., attenuation ..., bilateral treaty intersection ..., and amendment refinement" -- four operations, with ladder-floor stability absent. §10 echoes the §1 four-operation list. A skim-reader counts five in the abstract and four in §1; a careful reviewer reads this as the abstract overclaiming. Ladder-floor stability is a theorem about how a check composes with admission, not a separate decidable operation on the triple.
**Suggested fix**: In the abstract, drop "ladder-floor stability" from the operations list and keep it for the immediately following sentence about which theorems were proved (where it already appears).

### Issue 2: §4 cites Intersection.lean line numbers that point into unrelated proof bodies
**Severity**: major
**Where**: `sections/04-model.tex:45` (cites `Intersection.lean:100`) and `sections/04-model.tex:71` (cites `Intersection.lean:122`)
**Problem**: §4:45 says the proof of `treaty_admission_iff_predicate_intersection` is "in `Intersection.lean:100`" -- but line 100 of `formal/lean4/Chio/Chio/Treaty/Intersection.lean` is inside the `enactAmendment` docstring (`-- 'enacted' cannot be produced without the refinement witness ...`). The actual theorem starts at line 111. §4:71 says the type-level amendment invariant is captured at `Intersection.lean:122`, but line 122 is `unfold treatyAdmits treatyPredicateIntersection polityAdmits` -- inside the body of `treaty_admission_iff_predicate_intersection`, completely unrelated to amendment. The correct anchor for the amendment paragraph is line 103 (`def enactAmendment`) or line 84 (`structure ConstitutionalDelta`).
**Suggested fix**: Change `:100` to `:111` (theorem start) and `:122` to `:103` (`enactAmendment` definition) or `:84` (`ConstitutionalDelta` structure carrying `proofTerm`).

### Issue 3: bilateral_dsse.rs:1038 line-number citation does not match function start
**Severity**: minor
**Where**: `sections/05-implementation.tex:39`
**Problem**: §5 cites `crates/chio-federation/src/bilateral_dsse.rs:1038` as where `verify_chiodos_dsse_envelope` rejects malformed envelopes. On the current `main` tree (which the paper's other citations correctly resolve against), `verify_chiodos_dsse_envelope` is declared at line 996, not 1038. Line 1038 is mid-function inside the subject-count guard. This is in the same family as B5 ("§5 line-number re-anchoring") which the action plan claimed to have closed, but this particular citation slipped through.
**Suggested fix**: Re-anchor to `:996` (function declaration) or `:1034` (`validate_chiodos_predicate` call, the start of the rejection cascade).

### Issue 4: Table 2 row label "byte equivalence" contradicts inline result "manifest-stable"
**Severity**: minor
**Where**: `sections/06-evaluation.tex:22`
**Problem**: The action plan (B3) explicitly replaced "byte-equivalent" framing with "manifest-stable across machines" in §6 prose and regenerated `bench/results/replay-corpus-inline.tex` to "50 fixtures, manifest-stable across machines". But the Table 2 metric label still reads "Replay corpus byte equivalence", contradicting both the prose two paragraphs below and the inline result rendered in the adjacent cell. A reviewer who reads Table 2 will see the old framing the paper claims to have abandoned.
**Suggested fix**: Change the Table 2 row label to "Replay corpus manifest stability" (or "Replay corpus reproducibility"), matching the inline result and the §6 prose.

### Issue 5: DID is used five times without definition or citation
**Severity**: minor
**Where**: `sections/01-introduction.tex:7`, `sections/07-discussion.tex:8, 12, 14`, `sections/10-conclusion.tex:3`
**Problem**: "DID" appears in §1, §7 (three times), and §10 -- including the conclusion's load-bearing sentence "publishes a DID and a compatible predicate manifest". The term is never expanded ("Decentralized Identifier") and the W3C DID Core spec is not cited. For a security venue that reads ID/auth papers carefully, a load-bearing acronym appearing in the conclusion without ever being introduced is a clear nit a sharp reviewer would flag in the first pass.
**Suggested fix**: On first use in §1, expand to "Decentralized Identifiers (DIDs) [w3c-did-core]" and add a `@misc{w3cDidCore}` bib entry pointing at https://www.w3.org/TR/did-core/.

### Issue 6: "MAA" acronym appears once in §9 without expansion
**Severity**: nit
**Where**: `sections/09-limitations.tex:36`
**Problem**: §9's TEE bullet says "The MAA TEE verifier is label-only". "MAA" is Microsoft Azure Attestation, but the acronym is never expanded and never cited. A reviewer outside the Azure ecosystem will not know what it refers to; a reviewer inside it will note that the only place a Microsoft platform is named carries no citation. The surrounding TEE list (TDX, SEV-SNP, Nitro) is also expanded only in §8, paragraph 4, which is after §9 in reading order if a reviewer jumps to limitations first.
**Suggested fix**: Expand to "the Microsoft Azure Attestation (MAA) TEE verifier" on first use; alternatively, drop the bullet's TEE-platform name list to "one TEE lane is label-only, the others are implemented" if a citation would balloon the bullet.

### Issue 7: Figure 3 (amendment-lifecycle) depicts a runtime branch the prose says is impossible
**Severity**: major
**Where**: `figures/amendment-lifecycle.tex`; §4 prose at `sections/04-model.tex:71`
**Problem**: Figure 3 shows a diamond "Lean term $K'\Rightarrow K$?" with `no`/`yes` arrows to "Reject and anchor failure"/"Enact with delta proof" -- a runtime decision tree. §4:71 says the opposite: "The invariant is type-level rather than runtime-level: enactAmendment takes a ConstitutionalDelta ... A verdict claiming enactment without the refinement witness cannot be constructed by the well-typed runtime path." The pass-4 Lean API change made enactment type-conditioned, but the figure still depicts the pre-pass-4 Boolean-check semantics. The "no" branch is unconstructable in the model the prose describes. A formal-methods reviewer will read this as the figure undercutting §4's strongest formal claim. (Iter-6 reviewed the figure positively but that review predates the pass-4 API change in `polish-diff.md` lines 240-250.)
**Suggested fix**: Recast Figure 3 so the proof appears as a type precondition rather than a runtime check: replace the diamond with a "ConstitutionalDelta required" gate from which only the with-delta path is constructable; route rejection through `rejectAmendment` as an independent no-delta track.

### Issue 8: §8 governance paragraph cites Cosmos IBC without a stated link to governance
**Severity**: minor
**Where**: `sections/08-related-work.tex:21`
**Problem**: The §8 governance paragraph runs Compound -> Polkadot -> Helios -> Kleros -> Aragon -> Optimism -> ZKsync -> PBFT -> Stellar -> Cosmos IBC -> Move/Solidity verifiers -> Chio. Cosmos IBC is a cross-consensus messaging protocol, not a governance system; the sentence "the Cosmos IBC protocol carries cross-consensus messages as its primary contribution" gives no delta to Chio and breaks the paragraph's governance topic. A reviewer will read this as a venue-broadening citation dropped in without a contrast (or worse, as evidence the author confused IBC with the governance modules of Cosmos chains, which are entirely separate from IBC). The paragraph survives losing the sentence; if IBC is load-bearing, it deserves its own contrast (e.g., "IBC moves messages between consensus zones but does not check predicate refinement; Chio's treaty intersection is the analog at the policy layer").
**Suggested fix**: Either drop the IBC citation from §8 (the paper does not lose anything material), or rewrite the sentence to state the delta explicitly: "Cosmos IBC packets carry messages across consensus zones with on-chain verification of source-chain commitments; Chio's bilateral treaty admission is the policy-layer analog where the receiving kernel runs a predicate over a co-signed receipt rather than a chain-rooted Merkle proof."

### Issue 9: §7 economics paragraph claims "common invocation shape" without naming what is being compared
**Severity**: nit
**Where**: `sections/07-discussion.tex:20`
**Problem**: The discussion's economics paragraph closes with "Tool-invocation standards face a parallel choice: common invocation shape makes tool access portable but leaves accountability to product dashboards and audit exports." This is the residue of the earlier MCP comparison the polish-diff scrubbed (item #5 in the technical-findings list). The current sentence names neither MCP, A2A, nor any specific tool-invocation standard, so the reader is asked to take the comparative claim on faith. Either a citation is needed (MCP spec, A2A spec, OpenAI function-calling schema, Anthropic tool-use API) or the sentence should be dropped.
**Suggested fix**: Add one citation in the parenthetical: "Tool-invocation standards (MCP, A2A, OpenAI/Anthropic tool-use schemas) face a parallel choice: ..." with bib entries to one canonical reference per name. If a citation is not feasible, delete the sentence -- the contribution claim survives.

## Summary

Paper is in strong shape; the prior swarm and action plan closed every documented blocker. New findings cluster around (a) line-number citations that drifted in late revisions (Issues 2, 3), (b) an abstract-vs-body coherence gap (Issue 1), (c) a Table 2 label not updated with prose (Issue 4), (d) Figure 3 not redrawn for the pass-4 Lean API change (Issue 7), and (e) undefined acronyms / non-sequitur citations (Issues 5, 6, 8, 9). Issues 1, 2, and 7 affect coherence on a technical reading; the rest are reviewer-visible polish. None drop a borderline accept to reject alone, but Issues 1 and 7 are the kind of internal inconsistency a sharp reviewer writes up as "the model in the abstract is not the one the body and figures describe."
