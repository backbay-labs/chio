# Wave 9 Termination Re-Check

Date: 2026-05-18
Scope: Re-certification after Waves 7 (research) + 8 (fix) + 9A (companion cleanup).

## Verdict: READY

Zero substantive findings. Build gate clean (10 pages, 0 errors, 0 undefined
references/citations, 0 BibTeX warnings). All eleven Wave 7 findings
confirmed-fixed. Wave 8 additions did not re-introduce verbatim overlap with
the parent paper, did not introduce voice leaks, and did not break internal
consistency. Recommend terminating the development cycle.

## Wave 7 finding closeout

**7A #1 (§8 SCITT) -- FIXED.** §8 line 5 adds "Transparency-service receipts
and bilateral admission" paragraph: SCITT's "single-issuer statement
countersigned by a separate service" vs bilateral DSSE's "two organizations
jointly sign the same canonical binding tuple at admission time," with
temporal-separation note and downstream-composition path. `scittArchitecture`
bibkey resolves at bib.bib:596 with publisher/address/URL.

**7A #2 (COSE Receipts) -- FIXED.** §8 line 5 cites `rfc9942` inline. Bibkey
at bib.bib:606 with IETF metadata and DOI 10.17487/RFC9942.

**7A #3 (in-toto v1.2.0) -- FIXED.** §8 line 3 cites both
`torres2019intoto` (origin) and `intotoSpec2024` (current spec). Bibkey at
bib.bib:616.

**7B R1 (§3 adaptive-oracle qualifier) -- FIXED.** §3 line 65 now reads
"...the error surface leaks at most $\log_2 5 \approx 2.32$ bits per
attempt ... Against an adaptive adversary submitting envelopes in sequence,
this bound holds per-attempt but not in aggregate: over $N$ probes ...
left-to-right gate evaluation reveals only the first refusing conjunct ...
in $O(N)$ attempts ... Adaptive bounds against the gate-ordering oracle
remain open." Wave 2 S2 / Wave 4 m4 discharged.

**7B R2 (§9 side-channel) -- FIXED.** §9 line 12 adds "Side-channel attacks
on the verifier" paragraph: "the strict verifier is treated as a constant-
time idealization ... UncoreBleed and contemporary side-channel literature
against EdDSA verifiers and TEE-resident comparators indicate that a
hardware-isolated deployment must independently mitigate against such
leaks." `uncoreBleed2026` cited inline.

**7B R3 (§9 malicious-verifier) -- FIXED.** §9 line 14 adds "Malicious
receiving kernel": "the construction defends the sender's claim ... it does
not defend against a receiver that controls its own trust store, suppresses
denial receipts, or admits envelopes outside the declared predicate set."
Sender-claim / receiver-state distinction explicit.

**7B R4 (§3 intra-lease replay) -- FIXED.** §3 line 61 closes the stale-
lease paragraph: "Intra-lease replay ... is not prevented at the verifier;
it is a constitutional concern handled by the receipt-graph deduplication
and continuation-hash discipline the related polity-layer construction
develops."

**7B R5 (§9 PQC inheritance) -- FIXED.** §9 line 16 adds "Cryptographic-
suite migration": "Ed25519 signatures and SHA-256 subject digests are not
post-quantum. A quantum-equipped adversary breaks Ed25519 signing-key
recovery directly and weakens the SHA-256 collision-resistance margin ...
the wire format does not currently version-tag for cipher-suite agility."

**7C #1 (companion-paper references) -- FIXED.** `grep -c "companion
paper\|companion construction\|companion polity"` across all .tex returns
ZERO. All seven prior occurrences are rephrased as "the related polity-
layer construction (anonymized for review)" or "the broader polity-level
formalization (anonymized for review)." USENIX anonymization convention
satisfied; implicit-knowledge gap closed.

**7C #2 (internal jargon definitions) -- FIXED.** Abstract defines inline:
"the receiving kernel (the runtime admission engine ... not an OS kernel)";
"treaty-bound predicate (the cross-organizational agreement ...)"; "receipt-
graph state (the directed graph of admitted receipts and their causal
links)"; "ladder-intersection hash (the canonical hash of the joint mode-
coverage table ...)"; "continuation hash (the linkage hash tying this
admission to the prior receipt-graph state)." §1 adds the Chiodos-predicate
definition, treaty-scope-hash gloss, verifier-owned-trust-store full
definition, and the polity definition ("a polity is a closed receipt-
admission boundary"). All nine internal-jargon terms Wave 7C named are
inline-defined on first use.

**7C #3 (§1 crux sentence) -- FIXED.** §1 line 19: "Two independent
signatures over arbitrary bytes admit only that two parties signed the same
bytes; treaty-binding admits that the two parties jointly authorized an
action under a declared predicate set on a declared receipt-graph state,
with rejection codes that distinguish each gate the verifier evaluated."

## Fresh-eye sweep

### Build gate

4-pass `pdflatex` + 1-pass `bibtex` all exit 0. paper.log: 0 errors, 0
undefined refs, 0 undefined citations, 0 LaTeX warnings (one "undefined"
hit is a T1/zi4/m/sc font-shape warning, cosmetic). paper.blg: 0 BibTeX
warnings. PDF: 10 pages, 612x792 letter, 496708 bytes. Page count at the
upper edge of the 8-10 target. Ten overfull-hbox warnings, all under 16pt
and inside `\codepath{}` / `\thm{}`; visually invisible.

### Cross-reference correctness

Every `\label{}` resolves to a `\ref{}`: `sec:predicate`, `sec:formal`,
`sec:implementation`, `tab:rejection-codes`, `sec:evaluation`,
`sec:attacks`, `sec:limits`. Four Lean theorem names exist in
`formal/lean4/Chio/Chio/Treaty/BilateralAccept.lean`. Three forward
references to polity-layer theorems correctly scoped as "anonymized for
review."

### Voice rule grep

Five matches against the substantive engineering-meta patterns, all
legitimate: `ChiodosBilateralV1` (wire-format predicate-type literal),
`v1.3.1` (ETSI TR document number in bib field), three `v1.2.0` hits (in-
toto spec version, all version-tagged citations of external standards).
Zero "V8", "we extend", "we introduce", "checked-in", "release-engineering"
hits. Zero raw "companion paper" references.

### Em-dash check

`grep -lP "\x{2014}"` returns empty. Clean.

### Abstract <-> §1 <-> §9 consistency

Abstract promises predicate type + 5 codes + Rust runtime + BBS selective
disclosure + three-vendor closure + three attack defeats + Lean kernel-
axioms. §1 contribution bullets map cleanly. §9 now adds side-channel,
malicious-verifier, PQC bullets; these expand the scope-acknowledgement
layer without contradicting the abstract's "correctness rests on the
conjunction of six gate predicates over canonical bytes." Internal
consistency holds.

### PDF render check

All 10 pages rendered to PNG at 150 DPI and visually verified. No
clipping, no overflow, no broken figures. Page-by-page: (1) title,
abstract, opening §1; (2) §1 contributions, §2, §3 opening, JSON
verbatim; (3) §3 binding-tuple, canonical-encoding, six-gate align block;
(4) per-code closes (with R1 + R4 sentences), §4 theorem; (5) §4
corollaries, kernel-axiom paragraph, §5 opening; (6) §5 verifier + Table
1, selective-disclosure, §6 opening; (7) §6 evaluation, §7 opening; (8)
§7 attack bodies, §8 supply-chain + SCITT; (9) §8 remainder, §9 with all
three new bullets; (10) bibliography. Eight overfull-hbox warnings inside
`\codepath{}` / `\thm{}` tokens are visually invisible.

### Self-plagiarism vs parent paper

Spot-checked three §3 / §5 / §7 passages: (a) bilateral §3 "The binding
tuple" vs parent §3 line 16 Chiodos profile -- parent enumerates field
names in summary form, bilateral develops per-field rationale; shared
vocabulary unavoidable, prose distinct. (b) bilateral §5 strict-verifier
paragraph vs parent §5 line 39 -- the Wave 6-verified paraphrase still
holds. (c) bilateral §7 sibling-treaty paragraph vs parent §7 polity
discussion -- different sections by name and content. The Wave 8
additions (R1-R5, SCITT, COSE) are fresh prose; parent paper contains zero
SCITT references and zero UncoreBleed references. Parent's PQC paragraph
shares the heading "Cryptographic-suite migration" but prose diverges
entirely.

### New bibkey M13 metadata check

All five Wave 8B-added bibkeys clear the M13 pattern.
`scittArchitecture`, `rfc9942`, `intotoSpec2024`: misc entries with
publisher + address + URL/DOI. `cremersComposition2026`, `dvcUSENIX2026`:
inproceedings with publisher (USENIX Association) + address (Berkeley, CA)
+ `numpages = {18}`. The USENIX `numpages` convention is the ACM-Reference-
Format-compatible workaround when volume is in press but page numbers are
not yet assigned. Acceptable.

### Gate-count taxonomy consistency

Wave 5A's six-runtime / five-codes / three-Lean taxonomy survives Wave 8
unchanged. §3 line 43 ("six gates hold in order"), §3 line 53 ("five of
the six gates produce uniquely-named rejection codes; the trust-store-
membership gate (G4) is bundled with predicate-type-mismatch"), §4 line 13
("six runtime gates ... collapse into the three structural conjuncts"),
§1 bullet 5, §3 line 65 (R1 fix: "post-signature gates" scope), §6 line 16
("outside the five rejection-code taxonomy"). All three taxonomies
reconcile cleanly; Wave 8 additions do not muddle them.

## Substantive findings

None.

## Non-substantive observations

1. Abstract names "propositional extensionality and choice" as the kernel
   axioms; §4 line 29 names `propext` + `Classical.choice` + `Quot.sound`.
   Wave 6 already flagged this; Quot.sound elision in a 220-word abstract
   is conventional. Optional one-word tightening.

2. Abstract names three attack defeats; §1 bullet 4 names four (adds
   single-lane); §7 enumerates six. Wave 6 already flagged; nested
   summarization rather than contradiction. Optional alignment.

3. Paper at 10 pages, the upper edge of the 8-10 USENIX Cycle 2 target.
   Submission system will accept 10 pages; headroom for further additions
   is zero.

## Termination recommendation

READY -- merge Wave 9 and proceed to human submission steps.

The eleven Wave 7 findings (3 Wave 7A must-add citations, 5 Wave 7B
adversary-class additions, 3 Wave 7C reader-experience additions) are all
confirmed-fixed. Build gate is clean. Voice grep, em-dash check, and
cross-reference resolution pass. The gate-count taxonomy survives the
Wave 8 additions. Abstract <-> §1 <-> §9 are internally consistent. Self-
plagiarism diffs against parent show distinct prose. The five new bibkeys
clear M13 metadata.

Hand off to human for the simultaneous-submission notification to
sec27chairs@usenix.org, the final read-aloud pass, and the upload.
