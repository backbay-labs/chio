# Execution Complete (Round 2)

Date: 2026-05-18
Paper: Bilateral Receipt Admission: Cross-Organizational Action Provenance with Treaty-Bound DSSE
Target venue: USENIX Security 2027 Cycle 2 (estimated deadline 2027-01-26)
Final state: 10 pages, 0 errors / 0 undefined citations / 0 BibTeX warnings

## Round-2 wave summary (Waves 7-9 on top of Round-1's Waves 0-6)

| Wave | Agents | Outcome |
|---|---|---|
| 7 (research) | 3 parallel (A recent prior art, B threat-model audit, C reader-experience review) | Surfaced 11 findings: §8 missing SCITT entirely, §3 adaptive-oracle bound technically wrong, 7 unresolved companion-paper references |
| 8 (fix) | 3 parallel (A §3/§9 scope + oracle qualifier, B §8 SCITT + 4 more bibkeys, C jargon + crux + 2 of 11 companion refs) | Five new bibkeys with verified author lists; §9 quadrupled (154->498w); §3 adaptive-oracle correction; 9 jargon terms defined inline; crux sentence landed |
| 9A (cleanup) | 1 (companion-paper sweep §3-§9) | 11 occurrences resolved with section-specific variants |
| 9B (recertify) | 1 (final adversarial) | READY: 0 substantive findings |

## Final paper state (after Round 2)

- **10 pages**, acmart sigconf, anonymous review mode (within USENIX 8-10 page band)
- **Build gate clean**: 0 LaTeX errors, 0 undefined citations, 0 BibTeX warnings
- **Lean substrate**: `formal/lean4/Chio/Chio/Treaty/BilateralAccept.lean` (583 lines, 1 theorem + 3 corollaries, no `sorry`, kernel-only axioms)
- **Bibliography**: 46 entries (up from 41 after Wave 8B added scittArchitecture, rfc9942, intotoSpec2024, cremersComposition2026, dvcUSENIX2026)

### Substantive improvements over Round-1 READY state

- **§3 adaptive-adversary oracle correction**: the `log_2 5 = 2.32` bits/attempt claim is now properly qualified for adaptive adversaries (O(N) probe localization via gate-ordering oracle)
- **§3 intra-lease replay sentence**: acknowledges single-lease-window vulnerability
- **§8 SCITT engagement**: closest standards-level comparator now explicitly contrasted (single-issuer-plus-transparency-service vs joint-signing models)
- **§8 in-toto v1.2.0** + **RFC 9942 COSE Receipts** + **Cremers et al. protocol-composition** + **Distributed Vector Commitments**: four additional verified citations
- **§9 quadrupled**: three new scope-disclosure bullets (side-channel scope citing UncoreBleed, malicious receiving kernel, PQC inheritance)
- **Abstract + §1 jargon defined**: 9 internal terms (kernel, treaty-bound predicate, receipt-graph state, ladder-intersection hash, continuation hash, Chiodos predicate, treaty-scope hash, verifier-owned trust store, polity) now defined inline on first use
- **§1 crux sentence**: directly answers "what does treaty-binding buy beyond two signatures"
- **11 companion-paper references resolved**: every one rewritten as "the related polity-layer construction (anonymized for review)" or section-specific variant; double-blind compliant

## Commits in Round 2

- `(Wave 7+8 combined)` — research findings + SCITT engagement + oracle correction + §9 scope disclosure + jargon definitions
- `62f80bbb2` — Wave 9A companion-paper cleanup + Wave 9B READY re-certification

## What remains for the human (unchanged from Round 1)

1. **Decide whether USENIX Sec 2027 Cycle 2 timing** is right (parent goes Cycle 1; this paper 5 months later; PC-overlap safe per VENUE-DECISION.md analysis)
2. **Draft Open Science + Ethics Considerations appendices** (USENIX requirement, ~2 short pages)
3. **Final pre-submission anonymization audit** (current `\author{Anonymous for external review}` in place; verify no remaining identifying signals slipped through Waves 0-9)
4. **Register at USENIX portal, upload, submit** when Cycle 2 CFP officially opens

## Total development arc

10 waves across 2 sessions:
- Round 1 (Waves 0-6): 6 -> 9 pages, 836 -> ~5800 words, all sections substantive
- Round 2 (Waves 7-9): 9 -> 10 pages, +5 verified bibkeys, +9 jargon definitions, adaptive-oracle correction, SCITT engagement, complete §9 scope disclosure

Paper exits the development cycle in submission-grade shape for a USENIX-tier venue. The development cycle re-terminates.
