# Wave 2C: Voice tightening and §8 related-work expansion

Scope: §1, §2, §3, §7, §8, §10, and the inline `thebibliography` in
`paper.tex`. Build verifies at 16 pages, 0 errors, 0 em dashes.

## Fix 1: Voice tightening — "the construction here" / "the present construction" / "in this construction's reading" / "the deployment instance"

Before: 7 hits of "the construction here" (01:16, 02:13, 02:26, 07:61,
08:36, 08:69, 08:76), 1 hit of "the present construction" (10:23), 1
hit of "the deployment instance" (10:18). Total: 9 violations in scope.

After: grep over the six in-scope section files returns zero hits for
the pattern `the construction here|present construction|construction's
reading|deployment instance`. Reduction: 100 percent (target was 60
percent).

Each rewrite preserved load-bearing meaning:

- §1:16 "The construction here extends" → "The reversible-action
  discipline extends".
- §2:13, §2:26 "the construction here inherits / lifts" → "the
  reversible-action substrate inherits / the substrate lifts".
- §7:61 "the construction here is the downstream substrate" → "the
  reversible-action substrate is the downstream discipline".
- §8 several hits → "the substrate" or "the reversible-action
  substrate".
- §10:18 "The endpoint deployment instance grounds the substrate" →
  "The endpoint enforcement engine grounds the substrate".
- §10:23 "obligations the present construction does not deploy" →
  "obligations the runtime does not yet deploy".

Generic "construction" survives in IS-form positions where it names the
typed object under discussion (for example §1:44 "the same
falsifiability discipline as the prior substrate" replaces "the parent
construction"; §7:23 "The substrate therefore does not claim" replaces
"The construction therefore does not claim").

## Fix 2: §10 "Focused Lean session" voice slip

Before, §10:23: "A focused Lean session on the headline composition
theorem is the next falsifiable step".

After, §10:24: "Mechanized discharge of the headline composition
theorem is the next falsifiable step". Project-process word "session"
is gone; the falsifiability framing is preserved.

## Fix 3: §8 reversible-computing paragraph

Added between Provenance and Verified-systems, three citations:
Bennett 1973, Vieri 1999, Yokoyama and Glück 2007. The paragraph
acknowledges the literature, names a structural similarity (paired
forward and inverse, history preserved as data), and distinguishes
honestly: the literature's reversibility is thermodynamic-physical and
inherits Landauer's bound, the substrate's reversibility is
structural-policy and makes no thermodynamic claim. The full text:

"Reversible computing originates with Bennett's logical-reversibility
construction, which shows that a Turing machine can be made
information-preserving by carrying a history tape so that every
forward step has a unique inverse. The Pendulum line realized the
discipline in hardware: a reversible-logic processor whose instruction
set is closed under inversion and whose thermodynamic cost per
operation is bounded by Landauer's principle rather than by the clock.
The Janus programming language formalizes the same discipline at the
source-language level: every statement has a syntactic inverse and the
language admits an invertible self-interpreter. The reversibility in
this literature is thermodynamic-physical: each forward step is
recoverable because the runtime preserves the information needed to
undo it. The reversibility carried by a reversible-action substrate is
structural-policy: each forward step is admissible at the polity's
predicates only when paired with a typed rollback witness that
references the original execution receipt and the inverse executor's
signed completion. The two senses share the word and the structural
shape (paired forward and inverse, history preserved as data), but the
substrate makes no thermodynamic claim and inherits no Landauer
bound."

## Fix 4: §8 verified-systems expansion

The Cedar / SampCert sentence was retained and extended with three
foundational systems-verification references: CompCert (Leroy 2009),
seL4 (Klein et al. 2009), and IronFleet (Hawblitzel et al. 2015). The
paragraph now distinguishes artifact-level verification (verified C
compiler, verified OS kernel, verified distributed state machine) from
substrate-policy verification (the prior substrate's treaty
intersection and amendment refinement theorems; the reversible-action
extension's TTL-bounded amendment chain theorem). The two levels are
named honestly rather than conflated. The full new text added to the
paragraph reads: "The older systems-verification line is the
foundational reference set. CompCert established that a realistic
optimizing C compiler can be verified end-to-end against a formal
semantics; seL4 extended the discipline to an operating-system kernel,
with the abstract specification, the C implementation, and the binary
all verified against each other; IronFleet extended it to a
distributed state-machine-replicated service. These verified-systems
efforts establish that formal verification at the artifact level is
feasible for production-scale code. The contribution of the prior
substrate and of the reversible-action extension is at the substrate-
policy level rather than the artifact level: the Lean theorems
condition the admission predicates and the amendment refinement
obligations on which the runtime depends, not the runtime's compiled
code itself."

## Fix 5: Anonymous citation for the prior substrate

Before: 17 hits of "the parent paper" across §1, §2, §3, §7, §8, §10.
The phrase named the sibling construction in plain text — a USENIX
reviewer with access to the prior preprint could de-anonymize.

After: zero hits of "the parent paper". Every reference now reads "the
prior substrate \cite{programmableSovereigntyAnonymous}" or "the prior
substrate's amendment trajectory", with the bibitem entry pointing at
"Anonymous, Programmable Sovereignty: Lean-Attestable Constitutions
Over Capability-Bounded Federated Receipts. Submitted for review." The
substantive theorem-name citations (`treaty_admission_iff_predicate_
intersection`, `essential_preserved_chain`, etc.) remain in the text:
they are the load-bearing primitives the discipline depends on, and
they cannot be anonymized without removing content. The
de-anonymization risk from those names persists and is documented in
the wave 1C audit; the present fix removes the strongest signal (the
explicit cross-reference to "the parent paper").

## Build verification

`pdflatex` two-pass run: 0 errors, 16 pages, no undefined-reference
warnings, no em dashes in any in-scope file. The `programmable
SovereigntyAnonymous` cite key resolves; `bennett1973logical`,
`vieri1999pendulum`, `yokoyama2007janus`, `leroy2009compcert`,
`klein2009sel4`, `hawblitzel2015ironfleet` all resolve.
