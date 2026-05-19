# Wave 2 Constructive Review

Date: 2026-05-18
Scope: After Wave 1 deepening (Sections 3, 4, 6, 7 expanded); identify residual gaps and draft drop-in fixes for the Wave 3 FIX cycle.

Current state: 7 pages, 5,357 section-words, bib and build clean, six cosmetic `Overfull \hbox` warnings.

## Section-by-section gaps

### Abstract

Closes on an engineering-meta sentence: "the companion position paper defends the full polity, amendment, and Lean-attestable construction." The iter-3 comparator flagged exactly this phrasing as a salami tell. The long paper's abstract closes on what it measures; the short paper should close on what the construction defeats, not on what a different paper does.

### Section 1 Introduction

Four contribution bullets; the long paper uses five. The missing bullet is the freestanding accept-set theorem added in Wave 1. A reviewer scanning the bullets currently does not learn that the paper carries an audited Lean theorem with kernel-only axioms.

### Section 2 Receipt admission as a primitive

Positions against build-time provenance well but does not name the structural feature that distinguishes bilateral-DSSE: continuation-hash binding makes the construction stateful in a way SLSA, in-toto, and Sigstore are not.

### Section 3 Predicate schema and strict verifier

Three residuals after Wave 1. First, the rejection-code ordering is asserted ("left-to-right") but not justified. Second, the hash-domain separation question (distinct domains for binding tuple vs DSSE subject vs receipt body?) is named in the long paper but absent here. Third, the cardinality question (why five codes, not three, not seven?) is unaddressed.

### Section 4 Formal sketch

Namechecks `treaty_admission_iff_predicate_intersection` only as a follow-up obligation. Reviewers familiar with the long paper will read this as a missed bridge: the freestanding theorem sits structurally below treaty intersection, but Section 4 does not show the layering explicitly.

### Section 5 Implementation

At 632 words Section 5 was untouched in Wave 1. The five rejection codes named in Section 3 are not mapped to the Rust functions that return them. A reviewer asking "where does noncanonical-payload come from?" has to read source code.

### Section 6 Three-vendor evaluation

Wave 1 expanded to 1,007 words. The bench numbers are precise but unexplained for non-systems readers; a reader unfamiliar with Criterion p50/p99 reporting may not see why 72 us is a strong claim.

### Section 7 Attacks defeated

Wave 1 expanded to 551 words. The six classes are presented in impact order rather than the cheapest-verifier-check-to-deepest-semantic-check order a systems reviewer expects. Either reorder, or add a sentence explaining the ordering rationale.

### Section 8 Related work

Not deepened in Wave 1. Per-lineage specificity is missing: SLSA, in-toto, Sigstore, Rekor, DSSE bundled in one sentence; Cedar named with two citations but no specific Cedar theorem engaged; SAGA's Provider-vs-Chio-admission-hook delta unarticulated. Iter-3 comparator named this exact gap.

### Section 9 Limitations

154 words, the thinnest section. The long paper carries thirteen limit categories; three are directly relevant and should be inherited: schema-evolution (absent), key custody and rotation (absent), party-independence (named but the kernel-independence-attestation follow-up is buried).

## Cross-cutting opportunities

**Worked attack-defeat byte trace.** No section walks the adversary's input bytes, the canonical-bytes hash, the rejection code, and why the rejection is sound. A worked sibling-treaty trace would convert a structural claim into a reproducible artifact.

**Comparison table of related-work primitives vs bilateral-DSSE.** A 5-row table (SLSA, in-toto, Sigstore, Cedar, this paper) with columns (what it signs, what it admits, what it rejects, where the trust root lives) would compress Section 8 onto one screen.

**Anchored receipt example.** Section 7 names a multi-lane anchor policy but Section 3's worked envelope shows no anchor commitment. A one-paragraph annotation of a Rekor-anchored receipt would close the supply-chain lineage anchor.

## Drop-in drafts (with insertion points)

### Draft A: Abstract trailing sentence

Replace the trailing sentence of the abstract.

> The construction rejects sibling-treaty cross-receipt substitution, BBS stub-versus-real disambiguation, single-lane witness compromise, schema-version downgrade, and error-message oracles by structural composition of the five rejection codes with the canonical-bytes subject digest. A freestanding accept-set theorem mechanized in Lean 4 with only kernel axioms characterizes the verifier's acceptance set as the conjunction of trust-store membership and scope-predicate denotation.

(72 words; replaces 38 words; net +34.)

### Draft B: Introduction fifth contribution bullet

After the existing four bullets.

> \item A freestanding accept-set theorem in Lean 4 (`formal/lean4/Chio/Chio/Treaty/BilateralAccept.lean`) characterizing the verifier as the conjunction of trust-store membership and scope-predicate denotation, with kernel-only axioms (`propext`, `Classical.choice`, `Quot.sound`) and no dependence on the polity model, treaty-intersection construction, or amendment machinery.

(46 words.)

### Draft C: Section 2 continuation-state binding sentence

End of the "Treaty-bound co-signing" paragraph.

> The continuation hash is the structural difference from supply-chain provenance: SLSA and in-toto link statements bind an artifact to a build pipeline with no statefulness across pipeline runs, whereas the bilateral subject digest commits the envelope to a receipt-graph position, so re-grafting the same envelope onto a different graph position is a digest miss rather than a re-routable token.

(64 words.)

### Draft D: Section 3 ordering and cardinality rationale

New paragraph between "Verifier accept set" and "noncanonical-payload".

> The verifier evaluates gates left-to-right because the order tracks dependency: canonicalization is the precondition for hash determinism, predicate-type pinning is the precondition for binding-tuple shape, signer-reuse is the precondition for party-independence, lease-freshness is independent verifier-owned state, and subject-digest-mismatch is the integrity gate over the bound tuple. Five codes rather than three or seven because each gate names one constitutional precondition; folding canonicalization and predicate-type into one would conflate parser-level and semantic-level failure, and splitting subject-digest-mismatch into per-field codes would re-introduce the field-level oracle the coarse taxonomy closes.

(102 words.)

### Draft E: Section 4 bridge to treaty intersection

New paragraph between "Kernel-only axioms" and "Those three obligations".

> The freestanding accept-set theorem is the byte-level admission gate the next-level-up theorem depends on. `treaty_admission_iff_predicate_intersection` characterizes treaty admission as the Boolean intersection of treaty scope, treaty constitution, and both polities' admission relations; that statement quantifies over admission decisions the freestanding theorem characterizes per envelope. The short paper scopes to the lower layer because the freestanding statement carries on its own under any predicate language admitting denotational interpretation, whereas treaty-intersection requires the polity model the long paper develops.

(83 words.)

### Draft F: Section 5 function-to-code mapping

End of the "Strict bilateral verifier" paragraph.

> The five rejection codes map one-to-one onto failure paths in `verify_chiodos_dsse_envelope`. The `payloadType` and signature-count checks return `dsse.malformed`; the canonical-bytes comparison after `canonical_bytes` returns the noncanonical-payload code. The `predicate_type` string check against `PREDICATE_TYPE_CHIODOS_BILATERAL` returns predicate-type-mismatch. The keyid-equality test and `require_unique_signature_keyids` return signer-reuse. The operational verifier at `bilateral_verifier.rs` returns stale-lease and subject-digest-mismatch after the envelope check passes. The same gate ordering holds in the source as in the predicate of Section 3.

(86 words.)

### Draft G: Section 7 attack-class ordering sentence

Opening sentence of Section 7.

> The six attack classes below are ordered by impact rather than verifier-depth: sibling-treaty cross-receipt substitution is the canonical bilateral-admission attack and leads, followed by BBS, single-lane witness, error-oracle, schema-downgrade, and the policy-layer ratchet. Each class names the cheapest verifier-side check that defeats it; canonicalization is universally cheapest and is treated in Section 3.

(56 words.)

### Draft H: Section 8 related-work expansion

Replace the existing "Policy languages and verified authorization" and "Agent and tool isolation" paragraphs.

> Cedar establishes a Lean-plus-Rust pattern for proving policy decisions well-defined inside one trust boundary; the soundness theorem of Cutler et al.~\cite{cedarOOPSLA2024} states that the Rust evaluator and Lean specification agree on every input. The construction here adds a structural axis Cedar does not address: the accept set is over a bilateral envelope rather than a unilateral request, and `accept_conj_scope_decompose` shows that joint admission against a treaty equals the intersection of independently named predicates. SAGA distributes user-controlled tokens from a Provider to constrain agent invocations~\cite{sagaNDSS2025}; Chio places admission at the receiving kernel under a verifier-owned predicate, so SAGA's Provider and Chio's admission hook compose along the same authorization path. In-toto link statements~\cite{torres2019intoto} prove that a named build step was executed by an authorized actor; the bilateral primitive proves that a named action was admitted by two authorized kernels under identical canonical bytes. The two evidence layers are orthogonal: a bilateral envelope can cite an in-toto link as build provenance for the binary referenced by its `requestHash`. IsolateGPT~\cite{isolategptNDSS2025} and Omega~\cite{omegaTrustlets} secure tool calls inside one operator's runtime; neither produces a cross-organizational artifact a third party can replay against a treaty predicate.

(196 words; replaces ~145 words; net +51.)

### Draft I: Section 9 inherited limits

New paragraph after "Observability gap".

> Two further limits inherit from the long paper. Schema evolution: receipt schemas are pinned at v1 (`chio.bilateral-cosign-invocation.v1`); kernels at different schema versions deny on `unsupported_treaty_scope_schema` without distinguishing schema mismatch from constitutional denial, and a versioned-predicate profile with a distinct `schema_mismatch` code is required for multi-tenant deployment. Key custody and rotation: per-kernel Ed25519 signing assumes an HSM, KMS, or TEE-bound key handle the paper does not specify, and rotation and compromise recovery for fleets of cosigning kernels are outside the present construction.

(85 words.)

### Draft J: Section 8 comparison table

New tabular block after the "Supply-chain provenance" paragraph.

> \begin{table}[t]
> \footnotesize
> \caption{Provenance and authorization primitives compared.}
> \label{tab:primitives}
> \begin{tabularx}{\columnwidth}{@{}lXXXX@{}}
> \toprule
> Primitive & Signs & Admits & Rejects & Trust root \\
> \midrule
> SLSA & Build provenance & Pipeline-built artifact & Unverified build & Builder identity \\
> in-toto & Link statement & Authorized build step & Out-of-policy step & Layout signer \\
> Sigstore/Rekor & DSSE bundle & Logged signature & Unlogged signature & Fulcio root \\
> Cedar & Policy decision & In-boundary request & Out-of-policy request & Policy set \\
> This paper & Bilateral admission & Cross-kernel action & Off-treaty action & Verifier-owned store \\
> \bottomrule
> \end{tabularx}
> \end{table}

### Draft K: Anchored receipt sentence

After the worked envelope verbatim in Section 3.

> A receipt referenced by `localReceiptHash` may carry an anchor block: a Rekor SET over the receipt bytes, an OpenTimestamps `.ots` file pinning the receipt to a Bitcoin block header, a Solana memo containing the receipt hash, or an EVM event log. The anchor block sits adjacent to the bilateral envelope rather than inside it, because the multi-lane witness policy is treaty-level rather than envelope-level; the binding-tuple commitment to `localReceiptHash` is what links the bilateral statement to whichever anchors the receipt carries.

(82 words.)

## Priority queue for the FIX cycle (Wave 3)

1. **Draft H** (Section 8 expansion). Replace Cedar / SAGA / IsolateGPT paragraphs. Word delta +51. Highest impact; addresses the iter-3 comparator's per-lineage gap on the only undeepened section.
2. **Drafts A plus B** (abstract close plus contribution bullet). Word delta +80. Surfaces the freestanding theorem as a headline contribution and removes the salami tell.
3. **Draft F** (Section 5 function-to-code mapping). Word delta +86. Closes the rejection-code-to-source reproducibility gap.
4. **Draft I** (Section 9 inherited limits). Word delta +85. Raises Section 9 from 154 to ~240 words; schema evolution is a real deployment-blocker.
5. **Draft J** (comparison table). Visual delta ~7 lines. Competes with Draft H for column space; if both land, Section 8 doubles.
6. **Draft D** (Section 3 ordering and cardinality). Word delta +102. Pre-empts the "why five?" reviewer question.
7. **Draft E plus C plus G plus K**. Each closes a smaller gap. Cumulative word delta +285.

## Estimated word and page delta

Drafts A through K cumulative: ~1,070 words and one table inserted across ten paragraph-level edits.

Current paper: 7 pages, 5,357 section-words. Projected after all drafts land: ~6,425 section-words (a 20 percent increase); 8 pages, possibly with Draft J or Draft K cut for column-balance. Still inside the 8-10 page band the venue-decision memo names for USENIX Security Cycle 2.

Priority subset (Drafts H, A, B, F, I): ~370 words added; projected 7.5-8 pages, all gains preserved without table commitment.

## What sleeps (worth doing later, not now)

- **Public replay tool with five attack ablations.** Iter-8 swarm flagged this as the load-bearing artifact for the standalone-paper claim. It is a code project (a `chiodos-replay` CLI plus five YAML fixtures), not paper drafting. Belongs to the venue's artifact-evaluation phase.
- **Pre-print arXiv tagging.** Venue-decision memo recommends posting at submission time (January 2027), not before. Not Wave 3 work.
- **Co-author outreach.** Anthropic (Constitutional AI naming collision) and Angela Walch (adversarial-disclosure review) are candidates; co-authorship reopens the double-blind audit and the venue calendar. Separate decision track.
- **TEE attestation pairing prose.** The long paper names Chio receipt cosigning as complementary to TEE-rooted kernel attestation; the short paper inherits the framing implicitly. A two-sentence addition is the obvious next move but the bilateral-DSSE primitive is independent of the TEE strengthening.
- **Bilateral Lean module inventory table.** The Lean module is cited but no line count or theorem-inventory entry appears. The long paper carries inventory tables; the short paper does not need them. Sleeps to Wave 4 if a reviewer asks.
- **Tighten the schema-downgrade and ratchet attack prose in Section 7.** Added in Wave 1 but short. A second pass would not change the contribution.
