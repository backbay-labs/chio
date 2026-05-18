# Brief: "Programmable Sovereignty" technical paper

You are writing a 12-page preprint titled **"Programmable Sovereignty: Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts."** Target venue: arXiv (cs.CR/cs.DC cross-list) on day one, with a follow-on submission to a workshop or program committee that a cosigner at the Cornell IC3 / Stanford / a16z Crypto Research / Paradigm Research orbit will agree to coauthor. The paper exists to be read by sophisticated practitioners and skeptical academics and to survive their first round of objections without retreat.

This is not a marketing document. It is the artifact that, when a journalist or regulator asks "is there anything serious behind the digital-nation-state claim?", you hand them. Write to that bar.

## 1. Required reading before drafting

Read these end-to-end. Skim is insufficient.

**Substrate and doctrine:**
- `AGENTS.md`
- `spec/PROTOCOL.md`
- `docs/research/CHIODOS_CONCEPT.md` (the v1.1 doctrine that retired the "agent nation-state" framing; you must engage with this directly in §8)
- `spec/CHIODOS_LADDER.md`, `CHIODOS_PHEROMONE.md`, `CHIODOS_BILATERAL_COSIGN_INVOCATION.md`, `CHIODOS_SELECTIVE_DISCLOSURE.md`
- `RELEASE_AUDIT.md` (claim-discipline doctrine; the paper must honor it)

**Working code, on the `codex/chiodos-7-8-live-treaty-buyer-closure` branch at `~/.codex/worktrees/985a/arc/`:**
- `crates/chio-chiodos-runtime/src/treaty.rs` (920 LOC, the treaty primitive)
- `crates/chio-chiodos-runtime/src/admission_hook.rs` (1,089 LOC, fail-closed pre-dispatch hook)
- `crates/chio-chiodos-runtime/src/buyer/` (1,624 LOC, buyer audit lifecycle)
- `crates/chio-federation/src/bilateral_dsse.rs` and `bilateral_verifier.rs` (+1,677 LOC)
- `examples/chiodos-3vendor/src/lib.rs` (1,074 LOC, the live three-party loop)
- `crates/chio-core/src/lib.rs`, `chio-kernel/src/lib.rs`, `chio-manifest/src/lib.rs`
- `crates/chio-selective-disclosure/` (BBS+ implementation, 882 LOC, opt-in)
- `crates/chio-anchor/` (multi-lane anchor: EVM, OTS Bitcoin, Solana memo, Rekor)

**Formal proofs:**
- `formal/lean4/` (109 theorems across 17 files, 2,669 LOC, zero `sorry`, zero `axiom`)
- `formal/lean4/theorem-inventory.json` and `proof-manifest.toml` (the mapping from theorems to Rust symbols)
- `_apalache-out/` and TLA+ specs

**Synthesis of design intent:**
- All twelve files in `.planning/chio-nation-states/` — these are the design briefs the paper is formalizing
- `.planning/chio-runtime-plan/07-chio-polity-capstone.md`
- `.planning/chio-audit/06-trust-chain.md` (the Lean / TLA+ / Kani / Aeneas survey)
- `.planning/chio-audit/05-economic-primitives.md` (settlement rails, CapitalExecutionAuthorityStep)

**Related work (use WebSearch and WebFetch to pull the actual papers; do not cite from memory):**

- Capability-based security: Mark S. Miller, *Robust Composition* (PhD thesis, 2006); KeyKOS (Hardy, 1985); EROS (Shapiro et al., 1999); seL4 (Klein et al., 2009; Sewell et al., 2013); Capsicum (Watson et al., 2010); Fuchsia capability routing
- Object-capability formalism: Murray's *Analysing the Security Properties of Object-Capability Patterns* (DPhil, 2010); Drossopoulou and Noble
- Certified compilation and verified systems: CompCert (Leroy); IronFleet (Hawblitzel et al., 2015); Verified Software Toolchain (Appel); F* / Project Everest; seL4 proof corpus
- Lean4 in production: Lean4 paper (de Moura, Ullrich); recent industrial deployments
- Certificate Transparency: RFC 6962, RFC 9162; Laurie et al.; Sigstore Rekor (Lorenc et al.)
- Selective disclosure: BBS+ (Boneh, Boyen, Shacham 2004); Camenisch–Lysyanskaya; BBS Signature Scheme draft-bbs-signatures
- On-chain governance: Compound Governance, Polkadot OpenGov (Burdges, Wood), Helios verifiable voting (Adida, 2008), Aragon Court, Kleros (Lesaege, Ast); Vitalik Buterin on quadratic voting and conviction voting
- Federated trust and gossip: PBFT and its descendants; Stellar Consensus (Mazières); Ostrom on commons governance (Nobel lecture)
- Network state literature: Balaji Srinivasan, *The Network State* (engage critically, not credulously); Hirschman *Exit, Voice, and Loyalty*; Montevideo Convention (1933) for the declarative theory of statehood
- Programmable governance critiques: Walch's *The Path of the Blockchain Lexicon*; De Filippi and Wright *Blockchain and the Law*

You will fail the cosigner review if your related-work section reads as if it was assembled from titles. Read the abstracts at minimum; quote and engage where the prior work directly informs or contradicts a Chio choice.

## 2. Audience and voice

**Audience:** a Cornell systems-PL professor; a Paradigm Research engineer; a Lean4 community member; a Sigstore TSC member; a skeptical reporter at *Wired* or the *FT*; a regulator reading on the recommendation of an aide.

**Voice:** the voice of a careful systems paper. Past tense for what the system does today; future tense only for explicitly labeled scope. Passive where active introduces unwarranted "we." No marketing register. No exclamation points. No em dashes anywhere (use parentheses or hyphens). No phrases of the form "we believe", "we are excited", "robust", "leverages", "empowers", "seamless", "interestingly", "notably", "it is worth noting", "in conclusion." No first-person plural where third-person works. Cite, do not assert. When you cannot prove a claim, mark it `[unproved]` and move it to limitations.

**Honesty constraint.** Every claim in the paper must be supported by one of: a code citation with `file:line`, a proved theorem name from `proof-manifest.toml`, a numerical microbenchmark you derived from a real run on the chiodos-7-8 branch, or a citation to prior work. Claims that do not survive this test are deleted, not softened. Numbers are real or absent.

**Engagement with v1.1 doctrine.** `docs/research/CHIODOS_CONCEPT.md` v1.1 explicitly retired the "agent nation-state" framing. The paper is the technical defense of why v1.0 was retired prematurely and what now justifies the framing's return. This must be addressed head-on in §8, not buried. Position the paper as the substrate evidence that v1.1 said was not yet present.

## 3. Structure

Twelve pages in two-column ACM `acmart` format (or single-column NDSS / USENIX format if the agent prefers; pick one and stay consistent). Sections, with target page budgets:

1. **Abstract** (200 words). State the contribution: a small set of primitives over which sovereign-like governance becomes machine-checkable; an implementation in 100 Rust crates with 109 Lean4 theorems and zero `sorry`; an evaluation showing X.
2. **§1 Introduction** (1 page). The problem: agent systems already form economies that resemble polities, yet their governance is unverifiable. The thesis: programmable sovereignty is achievable when constitutions are predicates, treaties are bilateral predicate intersections, and every state-changing action emits a signed receipt anchored to a public log. The contribution list: (1) a formal model relating capability attenuation, receipt admission, treaty satisfaction, and constitutional amendment; (2) a substrate implementation with proven safety properties; (3) the live three-party example; (4) an evaluation across latency, throughput, and conformance. Limit five contribution bullets.
3. **§2 Background** (1.5 pages). Capability-based security from KeyKOS to seL4. Certificate Transparency. On-chain governance from Compound through OpenGov. Verifiable voting from Helios forward. Federated trust gossip. Programmable governance critiques. The Network State literature engaged critically: name what Praxis, Próspera, FTX-Bahamas, and Tornado Cash got wrong, in two paragraphs, without polemic.
4. **§3 The Chio Substrate** (1.5 pages). Define the primitives the paper builds on. Capabilities, attenuation, revocation. The receipt schema. The bilateral DSSE envelope. The trust ladder's five intensity modes. Selective disclosure via BBS+. Multi-lane anchoring across EVM, Bitcoin via OTS, Solana, and Rekor. Cite the existing CHIODOS specs as the wire-level reference; the paper restates only what is needed to reason in §4.
5. **§4 Programmable Sovereignty: Formal Model** (2 pages). This is the heart. Define:
   - A **polity** as a triple `(T, C, K)` where `T` is a `PolityScope` (the closed predicate over admissible receipts), `C` is a Merkle-rooted citizenship roster, and `K` is a constitution (a finite set of Lean predicates with Rust check functions).
   - The **admission relation** `(s, r) ⊨ (T, K)`: a state `s` admits receipt `r` if and only if every predicate in `K` evaluates true on `(s, r)` and `r` is in `T`. Formalize as a theorem of the existing kernel admission hook; cite the theorem name from `proof-manifest.toml`.
   - **Attenuation refinement**: capabilities delegate only under refinement, never widening. Cite the existing Lean theorem(s).
   - **Treaty satisfaction**: a bilateral treaty `τ` between polities `P₁` and `P₂` is a `(T_τ, K_τ)` pair such that receipts admitted under `τ` satisfy both `K₁` and `K₂` restricted to their respective territorial scopes. State this as a theorem; sketch the proof; the full proof lives in `formal/lean4/Chio/Treaty/Intersection.lean` (write this file as part of the work).
   - **Amendment as Lean-checked delta**: an amendment `δ` from `K` to `K'` is admissible if and only if there exists a Lean term of type `predicates_v2 implies predicates_v1` over anchored historical receipts. State as theorem.
   - **Constitutional crisis**: a passed amendment whose delta proof fails type-checking is hard-rejected at enactment, with the failure anchored as evidence. State the well-formedness invariant.
   - Two or three figures (state-transition diagram for the admission hook; the bilateral DSSE handshake; the amendment lifecycle).
6. **§5 Implementation** (1.5 pages). The Chio workspace: 100 Rust crates, ~24,600 LOC of chiodos-specific code on the live branch. Walk the load-bearing artifacts:
   - `treaty.rs` and the `chio.chiodos.treaty-scope.v1` schema
   - `admission_hook.rs` and its fail-closed contract
   - `bilateral_dsse.rs` and the strict treaty-bound DSSE verifier
   - `buyer/` and the offline buyer-audit lifecycle
   - `examples/chiodos-3vendor` as the live three-party loop, with the CI gate that exercises it
   - The 109 Lean theorems, with theorem-inventory.json as the cross-reference. Give a small table: 6-8 named theorems, each one's statement (one line of math), the Rust symbol it covers, and the file it lives in. The reader should be able to verify any theorem in `formal/lean4/` by following the cross-reference.
7. **§6 Evaluation** (1.5 pages). Real numbers or no numbers. Pull what you can from `bench/` and from running the existing replay corpus. Targets:
   - Receipt sign latency, p50 / p99, on a baseline machine specified
   - Receipt verification latency
   - Admission hook overhead on the kernel call path
   - Treaty intersection cost (number of predicates `N`, latency as function of `N`)
   - Anchor inclusion-proof generation time per lane
   - BBS+ selective-disclosure proof size and verification time, opt-in
   - Replay corpus: 50 scenarios pass byte-equivalent under `CHIO_BLESS`; report
   
   Where you cannot produce a number from a real run, mark the cell `[unreported]` rather than guessing. The honesty of this section is what cosigners check first.

   Include one end-to-end case study: the three-vendor example from `examples/chiodos-3vendor`, with the treaty graph, the receipts emitted, and the buyer-side audit verifying the loop. Use it as the figure that motivates the formal model.
8. **§7 Discussion** (1 page). What programmable sovereignty is not. The scope of the claim: Chio polities are not Westphalian sovereigns; they cannot tax, conscript, or expel non-consenting parties from physical territory; their authority is over receipt admission within their declared scope. Why this is enough for the polity claim under the *declarative* theory of statehood (Article 3 of the Montevideo Convention) but not under the *constitutive* theory. The asymmetric relationship to human jurisdictions: a Chio polity binds the EU as a `Supranational` external peer (stacking EU jurisdiction predicates on admission) while the EU has no DID or co-signing key with which to bind a Chio polity in return. The integration with regulators is one-way until a counter-signature arrives. Engage directly with the v1.1 doctrine: name what changed between v1.1 and now (the live treaty primitive, the production admission hook, the chiodos-3vendor CI gate, the 109-theorem proof corpus). The paper is the evidence the doctrine asked for.
9. **§8 Related Work** (1 page). Position against capability OSes, certified compilers, on-chain governance, verifiable voting, network states, programmable money. For each, one paragraph stating what the prior work established, what Chio inherits, and where Chio differs. Cite at least 30 distinct prior works across the union of these areas.
10. **§9 Limitations and Threats to Validity** (0.5 pages). Be honest. The Lean tooling friction is real; mitigation is the template library at `formal/lean4/Chio/Polity/Templates/`. The Montevideo defined-territory criterion is satisfied in the declarative sense only. The multi-lane anchor's Bitcoin-via-OTS lane is verify-real, publish-advisory; tighten this in v2. The MAA TEE verifier is label-only on this branch; the TDX, SEV-SNP, and Nitro lanes are real. Hot inter-polity conflict is *structurally incoherent* in this substrate (a property, not a limitation; explain why).
11. **§10 Conclusion** (0.25 pages). One paragraph. No exhortation.
12. **References.** Real bibliography. BibTeX-ready.

Two or three appendices are acceptable: full Lean theorem statements (A), the `chio.chiodos.treaty-scope.v1` schema in canonical JSON (B), the three-vendor example transcript (C). These do not count against the 12-page body.

## 4. Specific contributions that must appear

The paper makes five concrete claims. State them explicitly in §1 and defend each one in §4–§6.

1. **The Chio admission relation is decidable and fail-closed.** Cite the proved theorem; show the type signature; demonstrate with the admission_hook tests.
2. **Capability attenuation refines safely under delegation.** Cite the existing Lean theorem; show the W1.2 sibling-sum oversubscription attack proof.
3. **A bilateral treaty's admissibility is equivalent to a predicate intersection over both parties' constitutions, and this intersection is computable and stable under the existing trust ladder.** State and prove; the proof is small (~50 lines of Lean); include it.
4. **A constitutional amendment is admissible if and only if a Lean term witnesses backward predicate refinement, and the absence of such a term hard-rejects the amendment at enactment time.** This is the "votes on theorems, not bytes" claim formalized.
5. **The multi-lane anchor produces inclusion proofs whose verifier rejects every byte-divergent counterfeit under the existing 50-scenario replay corpus.** This is the empirical claim, defended in §6.

## 5. Deliverable

Write to `~/.codex/worktrees/985a/arc/papers/programmable-sovereignty/` as a LaTeX project:

- `paper.tex` (main document)
- `bib.bib` (bibliography)
- `sections/` (one .tex per section to keep diffs reviewable)
- `figures/` (TikZ where possible; PNG for screenshots)
- `appendices/`
- `README.md` (one paragraph: how to build the paper; what license; how to cite)

License the paper CC-BY-4.0. The Lean files referenced live under the workspace's Apache-2.0 license.

If you cannot land LaTeX cleanly in one pass, draft a complete `paper.md` first to lock structure and prose, then transliterate. Do not ship a half-translated paper.

## 6. Build and verification

Before declaring the draft ready:

- `pdflatex paper.tex && bibtex paper && pdflatex paper.tex && pdflatex paper.tex` builds clean (or the equivalent `latexmk` invocation; or pandoc for the markdown intermediate)
- Page count is 12 ± 0.5 in the chosen format
- Every theorem named in §4–§6 exists in `formal/lean4/` and is listed in `theorem-inventory.json`. If you wrote a new theorem for §4 (treaty intersection), add it to the inventory and prove it; do not state it without proof
- Every code citation in §5 resolves to the named `file:line` on the chiodos-7-8 branch
- Every benchmark number in §6 has a reproducible script in `papers/programmable-sovereignty/bench/run-$NAME.sh`
- The reference list has no broken DOIs; spot-check 10 random references for accuracy
- A `grep` over `paper.tex` and `sections/` for the forbidden phrases ("we believe", "robust", "leverages", "empowers", "seamless", "interestingly", "notably", "it is worth noting", em dashes U+2014) returns nothing

## 7. Cosigner readiness

The paper is ready to send to a prospective cosigner when:

- An IC3 / Paradigm Research / a16z Crypto Research reader can read §4 and identify which theorem statements they would press on. The statements are sharp enough to invite that.
- A Lean4 community reader can follow §4's theorem statements directly into `formal/lean4/` and verify them.
- A skeptical journalist reading §7–§9 finds the discussion of Próspera, FTX, Tornado Cash, and the v1.1 doctrine engages with the failure modes head-on, not as throat-clearing.
- The contributions list in §1 is falsifiable: each item names a specific code artifact or theorem the reader can attack.

When all four hold, write the draft to `papers/programmable-sovereignty/v1.tex` and stop. Do not declare it done; declare it ready for external review.

## 8. Process

Treat this as a real paper, not an LLM artifact. Read first. Outline next. Draft sections in the order §4, §5, §6, §3, §2, §7, §8, §9, §1, §10, abstract — the technical core first, the framing last. Cite as you go; do not let citations pile up at the end.

When you finish a section, run a self-critique pass: imagine the cosigner reading it cold. What would they object to in the first paragraph? Either tighten the prose to preempt the objection or move the weak claim to §9 Limitations.

The paper succeeds when it would be embarrassing for a reviewer to dismiss it without engagement. Aim for that bar.
