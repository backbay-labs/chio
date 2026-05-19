# Wave 2 Adversarial Review

Date: 2026-05-18
Scope: After Wave 1 deepening (7 pages, bib clean).

## Single most damaging finding

The §4 freestanding theorem is `simp`-trivial. `BilateralAccept.lean:93-100`: the entire proof is `unfold accept; simp [Bool.and_eq_true, and_assoc]`. The statement is the bi-conditional `decide(a) && decide(b) && c = true ↔ a ∧ b ∧ c = true`, structurally the conjunction-distribution lemma over `Bool` decidability. The three corollaries are one-liners over the same rewrite: `List` membership monotonicity, `denote (.conj p q) = denote p ∧ denote q`, and the contrapositive of the first conjunct.

§4's "no hidden side channel can sneak admission past the three gates" then overclaims: the theorem cannot rule out side channels because `accept` is *defined* as exactly that conjunction. The reverse direction is vacuous by construction. The "Kernel-only axioms" paragraph (`propext`, `Classical.choice`, `Quot.sound`) is true of any Lean proof that does not introduce custom axioms; emphasising it reads as defensive posturing. Compare against Cedar's denotational-equivalence theorems or seL4's functional correctness: this is not a contribution. The short paper has chosen a *less* ambitious theorem than the long paper's `amendment_admissible_iff_backward_refinement` and made it *more* visibly trivial.

## Critical findings (formal-methods reviewer)

**F1. The "freestanding" framing concedes the wrong thing.** §4 explicitly disclaims single-amendment backward refinement, polity-level admission, and Hart-condition-(a). What *does* this theorem prove that the prose at the top of §3 doesn't prove definitionally? Nothing. The Lean adds a notation layer and a `decide` lift; the mathematical content is identical. Either §4 does more work (prove signature-byte abstraction is sound against a concrete scheme, prove the denotational interpreter is equivalent to the operational Rust verifier, prove canonical-JSON is injective on the binding-tuple type) or §4 should be reframed as a definitional sanity check, not a load-bearing theorem.

**F2. Signature-byte abstraction is where the security claim lives, and Lean does not touch it.** §4: "Signature byte validity is abstracted into trust-store membership." That abstraction is the entire cryptographic security claim. The Lean theorem proves nothing about EdDSA, nothing about canonical-JSON injectivity, nothing about the relationship between the binding-tuple hash and any concrete hash function. The Rust verifier could (in principle) accept an envelope the Lean accept relation rejects because the two share no formal connection. §5's "the wire format is the load-bearing artifact; the implementation is one realization of it" papers over this.

## Critical findings (systems/security reviewer)

**S1. Hash domain separation is absent from §3.** The §3 binding tuple folds eight hashes into one subject digest with no domain separation. If `H(treatyScopeBytes)` and `H(continuationBytes)` collide for adversary-chosen inputs (each is raw SHA-256 over attacker-controlled JSON), an attacker could craft a continuation whose hash equals the target treaty-scope hash and substitute fields. The verifier reconstructs the digest from field-named hashes; a cross-field collision is undetectable structurally. JCS does not provide domain separation. §3 just says "canonical hash of that tuple" without specifying length-prefix concatenation, field tags, or HKDF-style domain separation.

**S2. The 2.32-bit rejection-code leak is wrong in the adaptive model.** §3's `log_2 5 ≈ 2.32` bits holds only against a non-adaptive adversary. An adaptive adversary chains probes: noncanonical payload to confirm the canonicalization gate reaches; canonical with wrong predicate type to confirm gate ordering; canonical, correct-predicate, single-signer to confirm signer-reuse position. Each conjunct's *position* in left-to-right order leaks more than `log_2 5` per attempt because the failing conjunct localises all prior conjuncts to "passed". After O(5) probes the attacker has learned which predicate component fails on the target. Reframe as *per-conjunct* against a *static* adversary, or address the adaptive bound.

**S3. §6 dispatch latency is not a bilateral-DSSE measurement.** The 72.051 μs measures "the local-policy path that the federated admission hook composes with", not the bilateral-DSSE primitive. §6 admits bilateral verification adds a constant cost on top but does not measure that constant. The number is identical to the long paper's local-policy bench: this paper has not measured its own contribution. Run Criterion over `verify_chiodos_dsse_envelope` (two EdDSA verifies, one SHA-256 over the binding tuple). Same for the treaty-intersection numbers (131/540/4980 μs) which measure ladder-intersection, not bilateral verification.

**S4. §6 replay corpus does not exercise the new code paths.** §6 admits the 50-fixture corpus covers "ten capability-side families" and a "Chiodos-specific corpus covering predicate-type-mismatch, signer-reuse, and stale-lease fixtures is named as follow-up work." Three of five rejection codes have no fixture coverage. How does the paper know the verifier returns `predicate-type-mismatch` rather than `subject-digest-mismatch` on wrong predicate type? §6 prose, not a fixture.

**S5. Schema-version downgrade is not defeated by construction.** §7 claims strict match "excludes implicit forward or backward compatibility." A verifier pinning exactly `v1` rejects `v2` envelopes; the deployer must upgrade the verifier before the issuer ever emits a v2 envelope. Operationally impossible across multiple verifiers. A multi-tenant verifier pinning both `v1` and `v2` is downgrade-vulnerable: an attacker presents a `v1` envelope to a verifier whose tenant-A treaty was upgraded to `v2`-only but whose tenant-B treaty still accepts `v1`. The "v2 strengthening" forward-reference to the long paper's V8 issuer-rotation work is the actual defense, but it is not in this paper. Rewrite: *strict match is brittle; multi-version coexistence requires explicit lineage that this paper does not specify.*

## Critical findings (threat-model reviewer)

**T1. BBS coverage in §7 is unmotivated by §3.** §7's BBS-stub-vs-real paragraph defends a primitive §3 does not contain. §3's `subject` and `signatures` reference Ed25519 only. §5 mentions BBS as "presentation-only commitment", but the bilateral-DSSE binding has no BBS slot. When §7 says BBS "is admissible only as a projection of an Ed25519-signed record", the reviewer asks: admissible *where*? Not in the §3 verifier. The BBS path is presentation-time, not admission-time. §7 is solving a problem the paper doesn't pose; scope-creep imported from the sibling paper.

**T2. The five rejection codes do not include signature-verification failure.** §3 enumerates noncanonical-payload, predicate-type-mismatch, signer-reuse, stale-lease, subject-digest-mismatch. None is "an Ed25519 signature failed to verify." §3 buries this in prose ("verifier never reaches the predicate gates until both bytes-level signatures verify"). §6 then mentions a "tampered-signature" fixture that "denies on signature verification, distinct from the predicate-type and signer-reuse gates." A sixth rejection code that §3's taxonomy does not name. Fold it in (six codes) or explicitly scope the taxonomy to post-signature gates. The current presentation contradicts §6.

**T3. The single-vendor-key-custody limitation is not enforced.** §9 admits one-custody collapses to single-key signing. §3's signer-reuse gate catches the trivial form (same keyid) and references "operator-resolution test, parameterized by verifier-owned attribution metadata" for the variant. But §3 does not specify what attribution metadata is, where it comes from, or how a verifier acquires the operator-to-keyid mapping. Without that mechanism, signer-reuse is keyid-equality only, and one operator running two kernels under distinct keyids passes trivially. §3 claims a defense the construction does not provide.

## Critical findings (voice / framing)

**V1. Engineering-meta voice leak in §6.** "The pre-dispatch admission hook is reused from the production Criterion bench for the allow path." "Production Criterion bench" references infrastructure rather than the construction; describe what IS, not project history.

**V2. "Short paper" framing in README contradicts venue choice.** README targets "USENIX Security short paper" (line 11). VENUE-DECISION recommends USENIX Sec 2027 Cycle 2 *expanded to 8-10 pages* with no short-paper track. At 7 pages the paper is too long for short-paper aesthetic, too short for USENIX full-paper aesthetic. The abstract's "deliberately scopes" and §1's "companion paper extends" make the paper read as a fragment, the framing the substantially-overlap rule penalises. Commit to 9-10 pages and drop short-paper-sibling framing, or pin SecDev 2027 (6-page short class) and keep it.

**V3. "By construction" is overused.** Six of seven §7 paragraphs use "rejected by construction" or "defeated by construction." A hash check is not a *construction*-level defense; it is concrete-instantiation conditional on hash-function properties. Tone down to "rejected structurally" or "rejected at the digest gate." "Fails closed" appears five times; one or two suffice.

**V4. §5 stub-disclosure is scope-creep.** §5 names the macOS Endpoint Security stub. Bilateral DSSE does not depend on ES; that is a sensor-grounded-paper concern. Either delete (the primitive is well-defined without ES telemetry) or explain how ES feeds into the receipt body (§3's binding tuple does not reference ES).

## Novel attacks not in the prior swarm-notes

**N1. Continuation-hash forking.** The binding tuple includes a continuation hash "linking to receipt-graph state." Two adversaries holding co-signed envelope `E` can each present `E` as the continuation of different downstream envelopes `E'_A` and `E'_B`. §3 says "the envelope cannot be re-grafted onto a different graph position without invalidating the digest" but the continuation hash points *backward* to `E`'s predecessor, not *forward* to successors. Verifier A sees `E` as predecessor of `E'_A`; verifier B sees `E` as predecessor of `E'_B`; both verify because `E`'s digest does not commit to its successor. The receipt graph forks at `E`. The defense is a forward witness (Rekor, anchor publication), not the bilateral DSSE. §3's "linkage to receipt-graph state" overstates.

**N2. Lease-freshness side channel via revocation-epoch probing.** The stale-lease gate compares envelope lease epoch to verifier revocation epoch. An adversary submitting crafted lease epochs and observing accept/reject can binary-search the verifier's revocation epoch in `log_2(epoch_range)` probes. Revocation epoch is verifier-owned state; leaking it tells the adversary how many revocations have occurred, which the verifier owner may not want disclosed.

**N3. Worked-envelope `..` notation hides encoding details.** The §3 verbatim block uses `"sha256:7b2a..."` for nine fields. An implementer cannot construct a test envelope from the prose, because the prose does not specify SHA-256 byte length, hex-case sensitivity, or whether the `sha256:` prefix is canonical. JCS is silent on these. Expand one example to full canonical hex or cite the encoding convention.

## What survives the worst critique

Three contributions hold. First, the *rejection-code taxonomy* (five named conjuncts as a structured audit field) is a useful protocol convention: downstream audit disambiguates which precondition failed without re-running the verifier. Second, the *binding-tuple* design (ten fields committing to ten preconditions in one subject digest) is non-obvious; most DSSE deployments bind a single artifact digest. Third, the *fail-closed federated-origin* discipline in §5 (federated origin without treaty context denies; request metadata cannot smuggle a trust root; reserved continuation releases on denial) is concrete and evaluable. §5 is the most engineering-honest part of the paper.

These three justify a paper. They do not justify a paper that claims §4 contains a load-bearing theorem.

## Minimum patch to make the paper publishable

In priority order:

1. **Rewrite §4 to honestly describe what the Lean adds.** Drop the "freestanding theorem" framing. Say: the Lean gives a machine-checkable witness that the informal §3 accept relation is the conjunction of three named conditions, in a notation `accept`; corollaries are convenience lemmas. Add a paragraph naming what the Lean does *not* prove (signature-byte soundness, hash injectivity, Rust-Lean refinement) and why those are out of scope at the primitive layer. Converts §4 from kill-shot to "the formal sketch is light." (1 page.)

2. **Specify binding-tuple canonical encoding in §3.** How are the ten hashes serialised before the final SHA-256? Length-prefixed concatenation with field tags, ordered by §3's enumeration. Without this, hash-domain-separation attacks are a paper-killer. (One paragraph.)

3. **Run the bilateral-DSSE bench and report it.** Replace §6's dispatch-latency paragraph with a Criterion measurement over `verify_chiodos_dsse_envelope` (two EdDSA verifies, one SHA-256, five-gate evaluation). 150-250 μs is fine. The current §6 borrows numbers that don't measure this paper's primitive. (Half-day bench.)

4. **Reframe rejection-code leak as non-adaptive.** §3's `log_2 5` should explicitly be "against a non-adaptive adversary" with one sentence on the adaptive O(5) localisation. (One sentence.)

5. **Cut §5 stub-disclosure paragraph** or replace with a bilateral-relevant caveat. (Delete one paragraph.)

6. **Add the missing rejection code or clarify the taxonomy.** Fold signature-verification into the taxonomy (six codes) or scope the taxonomy to post-signature gates. (One sentence.)

7. **Tone down "by construction" and "fails closed."** Concrete-mechanism language. (Sed pass.)

8. **Resolve the short-paper framing.** Expand to 9-10 pages and drop "short paper sibling" framing, or pin SecDev 2027. (Editorial.)

9. **Specify operator-resolution metadata** or weaken §3 to keyid-equality only. (One sentence.)

First three are publishability-blocking; the rest are reviewer-respect issues.
