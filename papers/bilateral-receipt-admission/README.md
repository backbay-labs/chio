# Bilateral Receipt Admission

Short paper extracted from the same Chio substrate as the 12-page *Programmable Sovereignty* paper (`papers/programmable-sovereignty/`). This artifact is the cryptographic-primitive-only paper recommended by the round-3 swarm's "fundamental framing provocateur": strip the polity / Hart / sovereignty rhetoric, defend just the bilateral-DSSE-with-treaty-bound-subject-digest construction.

## Working title

*Bilateral Receipt Admission: Cross-Organizational Action Provenance with Treaty-Bound DSSE*

## Target

6-8 pages. Venues to consider: USENIX Security short paper, NDSS short track, ACM CCS short paper, NDSS workshop, or an OpenSSF / Sigstore venue.

## Relationship to the 12-page paper

The two papers share a substrate but make different claims:

- **`papers/programmable-sovereignty/paper.tex`**: 12-page position-paper-plus-systems-contribution that frames the substrate as a constructive instance of the Hartian rule of recognition, defends the polity triple $(T, C, K)$, and engages legal-positivism and political-theory literature. Target audience: NDSS / USENIX Security with a controversial title that doubles as a rhetorical wedge.

- **`papers/bilateral-receipt-admission/paper.tex`**: 6-8 page short-paper that ships just the cryptographic primitive (DSSE predicate type, strict verifier with five rejection codes, pre-dispatch admission hook, three-vendor closure) without the polity / Hart / sovereignty rhetoric. Target audience: USENIX Security short paper or similar; reviewers who want the substrate without the political framing.

The two should cross-reference and stand on their own grounds. The Lean theorems live in the long paper; this short paper cites the Lean formalization but does not depend on it for its core claim.

## Proposed structure

1. **Abstract** (150 words). Problem, contribution, demonstration, negative result.
2. **§1 Introduction** (0.5 page). What's missing in cross-org agent provenance; why bilateral-DSSE-with-treaty-bound-subject-digest is the load-bearing primitive.
3. **§2 Receipt admission as a primitive** (1 page). The schema; the rejection-code taxonomy; the relationship to SLSA / Sigstore / in-toto / Rekor.
4. **§3 Predicate schema and strict verifier** (1.5 pages). The five rejection codes; the canonical-bytes binding; the type signature.
5. **§4 Formal sketch** (1 page). One theorem with real content (the verifier's accept set equals the intersection of canonical-bytes equality, both signers' independent acceptance, predicate-type match, and lease freshness). Cite the Lean formalization in the companion paper.
6. **§5 Implementation** (1 page). The Rust runtime, the admission hook, the federation crate.
7. **§6 Three-vendor evaluation** (1 page). Admitted + denied paths in the same canonical schema. p50 latency. Replay corpus.
8. **§7 Attacks defeated by construction** (0.5 page). Sibling-treaty cross-receipt substitution. BBS stub-vs-real disambiguation. Single-lane witness compromise. Error-message oracles. Constitutional-ratchet (forward reference to companion paper).
9. **§8 Related work** (0.5 page). SLSA, Sigstore, in-toto, Rekor, DSSE, Cedar, SAGA, IsolateGPT, Omega — narrow and sharp.
10. **§9 Limitations** (0.25 page). No live federation. Single-vendor key custody. Observability gap. Reference to companion paper for polity / amendment / Lean obligations.

## Status

Skeleton only. Sections to be drafted by extracting from the 12-page paper. The Lean theorems, polity formalism, Montevideo / Hart engagement, and political-theory citations all stay in the 12-page paper.

## License

CC-BY-4.0, matching the 12-page paper.
