# Iteration 4

Focus: mid-swarm pivot. All eight README personas have been used at least once across iterations 1-3. Iteration 4 introduces three fresh angles that no prior iteration has reached: (a) a synthesis agent that reads iter 1-3 in full and identifies what has STABILIZED (multiple agents agree), what is CONTESTED (agents disagree), and what is MISSED (coverage gaps); (b) a code archaeologist that reads the actual Rust source on the chiodos-7-8 branch (not just the §5 prose) to find what neither prose nor formal model captures; (c) a historical case-study agent that asks "what would Chio look like applied retroactively to the Compound Proposal 289 attack?" -- the paper cites Compound 289 as an example but never walks through what would have happened.

Agent sections appended below.

## Mid-swarm synthesizer (iteration 4 rollup)

The most consequential STABILIZED finding -- the one a hostile NDSS reviewer is most likely to attack -- is that the central Hartian "constructive instance of the rule of recognition" move (\S7 + conclusion + abstract) rests on theorems the swarm has shown reduce by definition against a `BackwardRefines` predicate essentially unconstructable for non-trivial polities.

### (A) STABILIZED

1. **Hart-on-`rfl`.** Iter-1 Hostile NDSS, iter-1 PL skeptic, iter-2 Foundational-theory converge: \S7 must scope to Hart's condition (a) only, or rewrite onto the two load-bearing theorems (intersection + ladder stability).

2. **Polity rhetoric vs. \S9 limitations is the buried lede.** Iter-1 Hostile (abstract contradicts \S9 portability/accreditation/key-custody) and iter-1 Senate-staffer (accreditation gap is the publishable headline) independently flag regulator framing as suppressed by polity vocabulary.

3. **`BackwardRefines` operationally vacuous.** Iter-1 PL skeptic (opaque `ReceiptId → Bool`), iter-2 Foundational-theory (concurs), iter-3 Two-paper comparator (short paper inherits). Cedar-style syntactic Predicate ADT with `denote` is the convergent fix.

4. **Trust-store layer under-acknowledged.** Iter-2 Industry (bootstrap-without-root) and iter-2 Adversarial (meta-policy self-amendment) agree iter-1's essential-predicate invariant doesn't reach the meta layer.

5. **Short paper not ready.** Iter-3 Strategic (ship FIRST to HotSec/WOOT) and iter-3 Two-paper comparator (need freestanding \S4 accept-set theorem first) agree on direction; differ only on sequencing.

### (B) CONTESTED

1. **Decoration vs. analytic work in Hart.** Iter-1 PL skeptic ("decorative") vs. iter-2 Foundational-theory ("partial -- (a) only"). Resolution: explicit Hart p.94/110/116 citations plus cosigners-as-officials analog.

2. **Keep title or rename?** Iter-3 Strategic (keep, NDSS wedge) vs. iter-1 Senate-staffer (polity vocabulary triggers regulator pushback). Evidence needed: A/B test with sympathetic readers.

3. **Schema-evolution across vendor kernels.** Only iter-2 Industry practitioner flagged versioned-predicate / canonical-JSON stability. Needs FM or adversarial adjudication.

### (C) MISSED -- iter 5-8 priorities

1. **Three figures never reviewed.** No agent read `admission-hook.tex`, `amendment-lifecycle.tex`, `treaty-handshake.tex`. Persona: visual-communication reviewer.

2. **Table 2 proof-to-code map unaudited.** Polish-diff #3 flags two amendment rows as model-only; load-bearing rows unchecked. Persona: code archaeologist.

3. **BBS deployment story unexamined.** ETSI TR 119 476-1 cited but EUDI Wallet realism untested. Persona: cryptographic-protocol reviewer.

4. **Multi-lane anchor lacks adversarial detail.** Iter-2's five attacks didn't touch cross-lane witness independence. Persona: chain-reorg / witness-bribery adversary.

5. **Buyer-closure replay corpus contents unexamined.** No agent opened `examples/chiodos-3vendor/`. Persona: corpus inspector.

6. **65 bib entries unaudited.** Existing entries (Compound 289, Omega, EIP-7702, IBC, ZKsync) untested for prose accuracy. Persona: bibliography fact-checker.

7. **chiodos-7-8 branch README/lake-build claim unconfirmed.** Polish-diff #6 flags branch-only citations; build status unchecked. Persona: code archaeologist.

8. **\S1 contribution bullets vs. TOC flow uncross-checked.** Persona: argument-coherence auditor.

### Highest-priority follow-up

Act on **(C)**. Iters 1-3 densely covered prose, threat model, and formal artifact but missed figures, the proof-to-code map, replay-corpus contents, and the chiodos-7-8 branch. Iters 5-8 should rotate at least two personas onto code-and-artifact inspection (figure reviewer + code archaeologist + corpus inspector) before further rhetorical critique. (A) is stable; (B) can wait; (C) is the only category where the swarm risks finishing eight iterations without ever looking at half the paper.

## Compound 289 case study (retrospective Chio application)

Chio would not have prevented Compound 289; it would have made the attack legible at admission time instead of after the fact, shifting the rescission catalyst from off-chain sleuthing to a constitutional denial code.

**Background.** Proposal 247 (May 6, 2024) requested 92,000 COMP into the goldCOMP vault and failed quorum after Michael Lewellen (OpenZeppelin) connected the proposer to ~228,000 COMP delegated from five Bybit-sourced wallets. Proposal 279 was a revised retry that also failed. Proposal 289 (proposed July 24; vote concluded July 28-29, 2024) authorized `_grantComp(...)` for 499,000 COMP and `grantPhase(uint8)` against a Goldenboys multisig, destination Trust Setup contract `0xb9259D9f...4925e`. Tally: 682,191 for / 633,636 against, 57 participating wallets. Cancellation followed a July 30 negotiated settlement (30%-of-reserves staking distribution), not a protocol revert.

**Q1 -- predicates that would deny admission.** A treasury-cap predicate (single transfer below a percentage of treasury) rejects 499,000 COMP outright; a sibling-sum on delegate stake (no chain exceeding X% in a trailing 30-day window) flags the Bybit-sourced delegations; a participation-floor predicate (proposals over $10M require N>k distinct voters above a stake floor) catches the 57-wallet thinness; a cross-attempt deduplication predicate flags 289 as substantively equivalent to the rejected 247/279.

**Q2 -- refinement or widening?** 289 is a widening relative to any reasonable prior treasury constitution: new authorized recipient plus a previously-absent phase permission to a non-citizen multisig. Under backward-refinement it cannot enact as an amendment at all; it must execute as a one-off treasury exit, which is exactly where the cap and sibling-sum predicates bite.

**Q3 -- ratchet defense.** Had Humpy structured the attack as narrowing refinements ("restrict distribution to {A,B,C}, then {B,C}, then {C}"), iter-2's essential-predicate invariant requires participation-floor and sibling-sum to remain in the accepted-set across every step; a refinement that drops them fails the invariant even if each step pointwise satisfies `BackwardRefines`.

**Q4 -- predicate-shaped artifacts for retrospective.** Chio would emit denial receipts naming which predicate fired, with delegate-chain provenance bound into the subject digest. Gauntlet, Wintermute, and OpenZeppelin's after-the-fact Bybit-to-delegate correlation would be a replayable predicate evaluation against canonical bytes, not a forensic narrative requiring social proof to land.

**Q5 -- honest assessment.** Recovery would be faster and more legible, not prevented. A constitution that admits a 499K-COMP treasury exit at all admits it; predicates encode prior values, and Compound had not committed to those values pre-attack. Chio's contribution is making the absence of those predicates a visible governance choice rather than an unexamined default.

**Highest-priority follow-up:** add this worked example as Appendix C of the long paper. It converts the Compound 289 background citation from a name-drop into a Chio applicability demonstration, addresses iter-1 Senate-staffer's "one-page regulator-facing worked example" ask, and lands the predicate vocabulary on a referent every NDSS reviewer already knows.

## Code archaeologist (Rust source corroboration)

The most damaging mismatch is that §5's two cited line numbers in `crates/chio-chiodos-runtime/src/admission_hook.rs` (`:379` and `:947`) point at lines that do not exist on `codex/chiodos-7-8-live-treaty-buyer-closure`: the file is 273 lines long and its largest submodule (`treaty_evidence.rs`) is only 375 lines. The substance §5 describes is in the source, but a cosigner who clicks the citation lands in nothing.

Symbol-existence check on the cited branch:
- `validate_treaty_scope` is at `treaty.rs:191`; `compute_ladder_intersection` immediately follows at `treaty.rs:264`. Both check what §5 prose claims (schema, window, participant count, hash count, duplicate-key rejection, manifest staleness). Match.
- `bilateral_invocation_binding_sha256` at `treaty.rs:84` binds every field §5 enumerates (schema, invocationId, treatyId, ladderIntersectionSha256, continuationSha256, actionClassId, consistencyModel, capabilityId, requestSha256, outcomeSha256, localReceiptSha256, remoteReceiptSha256, signerKernelIds). Match.
- `treaty.rs:455` is `evaluate_cross_boundary_admission`, the runtime obligation Table 2 maps to `treaty_admission_iff_predicate_intersection`. Match.
- `treaty.rs:675` (Table 2's anchor for `treaty_admission_stable_under_ladder_floor`) is `ladder_mode_rank`, an internal `&str -> u8` helper. The actual floor-enforcement site is `validate_ladder_intersection` near `treaty.rs:420-453`. Table 2 cites a helper, not the enforcement.
- `treaty.rs:706` is `co_sign_requirement_rank`, another scalar ordering helper.
- `treaty_ref_from_request` is a submodule re-export at `admission_hook.rs:13`; its body lives in `admission_hook/treaty_ref.rs` (183 lines), not at the paper's claimed `:379`.
- The `missing_chiodos_treaty_context` denial appears at `admission_hook.rs:170`.
- `verify_chiodos_dsse_envelope` is at `bilateral_dsse.rs:1038`. Exact match. The reused-signer-key rejection is at `bilateral_dsse.rs:1094` ("strict Chiodos requires independent Org A and Org B signer keys"), implementing §5's "reused signer keys" claim.
- `verify_chiodos_bilateral_invocation` is at `bilateral_verifier.rs:859`. Exact match.

The five rejection codes round-3's provocateur named are all distinct enum variants in `VerifierError` (`bilateral_verifier.rs:87-154`): noncanonical payload = `DsseMalformed` / `StatementMalformed` plus the `BilateralCoSigningError::CanonicalJson` path at `bilateral_dsse.rs:1059`; wrong predicate type = `PredicateTypeUnrecognised`:100; stale lease = `CapabilityLeaseExpiredOrUnknown`:132; missing governance receipt = `GovernanceReceiptRequiredMissing`:135; subject-digest mismatch = `SubjectDigestMismatch`:107. All five are real, named, fail-closed.

Fail-closed contract: `admission_hook.rs:88-240` returns `Ok(deny)` on every `Rejected` arm and propagates internal failure as `Err(KernelError::Internal)`; `crates/chio-kernel/src/kernel/mod.rs:1032` documents "or `Err` on internal failure (which the kernel treats as deny)". Honored.

`tests/runtime_admission.rs` exists with `treaty_runtime_hook_releases_continuation_after_runtime_denial` (line 836) and `treaty_runtime_hook_releases_reserved_state_after_kernel_abort` (line 884). §5's claim that the hook releases reserved continuation state after denial or abort is tested exactly there.

`examples/chiodos-3vendor/src/main.rs` (441 lines) is a CLI wrapper; `src/lib.rs` is a 3-line re-export of `chio-chiodos-loopback` (1546 lines), which holds `fresh_proof_package`, `verify_package`, `write_signed_negative_case_inputs`, and constructs the full bilateral cosignature in-process. Calling it a "generator" in §5 understates: it is both a buyer-closure simulation (synthesizes vendor keypairs, signs the bilateral envelope, runs the real strict verifier) and a fixture-emitter (writes the resulting JSON). It is not a network federation; both vendor identities live in one process.

Ladder mode 5 on Rust is `"quorum_required"` (`treaty.rs:681`), agreeing with §3 prose but disagreeing with Lean's `maintenance` constructor (polish-diff finding #1). The paper-Rust pair is internally consistent; Lean is the outlier.

**Highest-priority follow-up:** replace every `admission_hook.rs:<line>` citation in §5 with the correct submodule path (`admission_hook/treaty_ref.rs`, `admission_hook/dsse.rs`, or `admission_hook/treaty_evidence.rs`) and re-anchor Table 2's `treaty.rs:675` to `treaty.rs:420` (the actual `validate_ladder_intersection` enforcement site), since the current citations point at lines that do not exist in the file the paper names.

## Iteration summary

The iteration's biggest single finding is a concrete polish-diff correction: the code archaeologist read the Rust source on the chiodos-7-8 branch and discovered that polish-diff finding #1 (ladder mode 5 name mismatch) had the resolution direction backwards. Rust at `treaty.rs:681` says `"quorum_required"`, agreeing with paper \S3 prose; Lean's `maintenance` constructor is the outlier. The fix is to rename the Lean enum, not the paper prose. Convergent: the synthesizer's MISSED-category (C) was already being addressed in real time by the code archaeologist, which found three concrete \S5 citation errors (`admission_hook.rs:379` and `:947` point at lines that do not exist in a 273-line file; Table 2's `treaty.rs:675` points at a helper, not the enforcement site); the Compound 289 agent independently corroborated the iter-1 Senate-staffer's regulator-facing-worked-example ask by drafting what would become Appendix C. Divergent: the Compound 289 verdict ("Chio would make legible, not prevent") is more modest than the \S2 paper prose currently suggests, and that gap is itself a finding -- the paper's Compound 289 citation implicitly claims more than the worked example supports.
