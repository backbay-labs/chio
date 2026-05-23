# Wave 1D: Cross-paper consistency audit

## 1. Parent paper citation discipline

The paper cites `programmableSovereignty2026` ten times across §1, §3, §4 (three), §5 (twice), §6, and §8 (twice). Citations land at the right load-bearing sites. One gap: §4's "Action classes" paragraph asserts "An unclassified method is destructive by default (fail-closed)" and "The classification is action-dependent rather than agent-dependent, and is the substrate's commitment." This is a substrate claim with no citation. **Fix:** add `~\cite{programmableSovereignty2026}` to the second sentence of "Action classes," matching the rest of §4.

## 2. Bilateral cosignature claim coherence

The abstract claims "bilateral cosignature for irreversible variants." §4 gives only an operational gloss: "for destructive classes, a bilateral cosignature is also present from both the agent's operator polity and the tool server's host polity." The bilateral-receipt-admission paper develops the concrete primitive: DSSE predicate `chio.bilateral-cosign-invocation.v1`, ten-field binding tuple, six-gate verifier with five rejection codes (noncanonical-payload, predicate-type-mismatch, signer-reuse, stale-lease, subject-digest-mismatch). This paper engages none of that machinery. The parent paper's substrate section summarises the bilateral DSSE profile, so the parent citation partially covers it, but "bilateral cosignature" is doing real work and the reader cannot find out what it is. **Fix:** add a one-sentence forward reference at the first §4 mention: "The bilateral cosignature is a two-party DSSE attestation whose admission predicate composes six gates over canonical bytes; the construction is developed in companion work." Keep the bibliography lean (no second `Anonymous, Submitted` bibitem).

## 3. TTL claim coherence

The paper uses TTL as "the maximum duration the call's effects may stand before the substrate considers them stale" (§4). The delegated-emergency paper uses TTL identically: "the time-to-live bounding the action's period of effect" (§4 there). The parent uses "lifetime" and "expiry" for capability lifetime; the bilateral paper uses "lease" (epoch plus expiry) for envelope freshness. The terms cohere across the line. Minor friction: §3 mentions a "claimed lifetime" as one of five executive-act components, then §4 switches to "TTL by construction" without bridging. **Fix:** in §3, parenthesise "(formalised as a time-to-live (TTL) in §\ref{sec:grammar})" the first time "claimed lifetime" appears.

## 4. Voice consistency

The parent is engineering-formal (Lean proof identifiers, Rust crate paths). The bilateral paper is cryptographic-protocol (DSSE, gate algebra). The delegated paper is legal-doctrinal (Weimar Article 48, Ackerman-Sunstein). This paper's voice is AI-safety-position: argumentative, structural, references the alignment-research canon, keeps formalism abstract. The voice is internally consistent across abstract, §1, §4, §7. Two intentional seams: §3's "sunset clause" enters the delegated-emergency voice, and §4's named theorems enter the parent's engineering voice. Both read as appropriate bridges. **Fix:** none.

## 5. Typed rollback witness terminology

This paper, §4: "a typed rollback receipt slot (an opaque record reserved at admission to be filled at rollback time)" and "a destructive tool call is not constructable in the typed runtime path without a rollback witness or its destructive-equivalent." The delegated paper, §4: a typed rollback witness is "a proof, constructible at the moment of admission of $a$, that the polity's state after the execution of `act` admits a transformation back to its state before." The definitions agree: both require constructibility at admission, both name a witness over the inverse transformation, both place the type check at construction rather than audit. The agentic paper splits the witness into "rollback receipt slot" (admission-time) and "rollback receipt" (discharge); the delegated paper conflates them into $w$. A refinement, not a divergence. **Fix:** none.

## 6. Cross-paper anonymity for review

The parent citation is anonymised correctly. Companion citations say "companion work" or "the companion substrate." No author, institution, or repository leaks. One borderline phrasing in §3: "A formal grammar for bounded executive action already exists in the EDR setting~\cite{programmableSovereignty2026}." The phrase "already exists" plus a self-citation could read as a self-reference. **Fix:** soften to "has been developed for the EDR setting." Minor hedge.

## 7. Implication for citation choices

Ten parent citations are appropriate for a position paper whose load-bearing theorems live in companion work. Adding a second `Anonymous, Submitted` bibitem for the bilateral primitive could read as citation-padding. Recommendation: add the forward reference from finding 2 without a new bibitem. **If the parent is not accepted at submission time:** the paper still stands as a position paper because the structural argument (training-layer and admission-layer compose; the substrate is the verifier) does not require the parent's Lean machinery to be published. What it loses is citable formal backing for `bounded_executive_action_carries_ttl_and_rollback_slot` and `treaty_admission_iff_predicate_intersection`. Mitigation: expand each of those theorem statements by one sentence with a self-contained informal version.

## Bottom line

The paper reads coherently as part of the multi-paper line. The voice is its own, parent citation discipline is consistent except at "Action classes" in §4, and typed-rollback and TTL terminology agree with the delegated and parent papers. The single conceptual debt is that "bilateral cosignature" carries weight in the abstract, §4, §6, §7, §8 without engaging the concrete bilateral primitive; a one-sentence forward reference in §4 closes the loop. If the parent paper is not accepted at submission time the workshop paper survives as a position paper, but the two named theorems in §4 should each get a one-line informal statement so the structural argument carries without the citation resolving.
