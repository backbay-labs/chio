# Programmable Sovereignty Claim Ledger

This ledger is the authority for claim strength in the submission manuscript.
The abstract, contribution list, theorem prose, evaluation, and conclusion may
not state a claim more strongly than its row permits.

## Claim classes

| Class | Meaning |
| --- | --- |
| Production-enforced | The shipping Rust path makes the stated decision and focused behavioral tests exercise it. |
| Bounded theorem | Lean proves the statement over the explicitly named model and assumptions. |
| Differentially aligned | The bounded reference semantics and production Rust agree on an executable corpus. |
| Experimentally measured | A reproducible script reports the result from the named implementation path. |
| Executable demonstration | A deterministic scenario runs end to end and emits reviewable artifacts. |
| Operational assumption | Correctness depends on deployment discipline not enforced by the evaluated construction. |
| Future work | The repository does not yet contain evidence adequate for a submission contribution. |
| Blocked | Current evidence contradicts or is too weak for the formulation. |

## Headline claims

| ID | Claim | Class | Current evidence | Assumptions and limits | Permitted submission wording |
| --- | --- | --- | --- | --- | --- |
| PS-C01 | A receiver can deny a treaty-bound request before tool dispatch. | Production-enforced | `ChioRuntimeAdmissionHook::evaluate`; `runtime_admission.rs`; `runtime_kernel_hook.rs`; live treaty-buyer closure | The configured kernel and verifier-owned store are trusted. Local requests without Chio context retain the legacy path. | "Chio places treaty admission on the receiving kernel's pre-dispatch path." |
| PS-C02 | Federated origin without treaty context denies. | Production-enforced | `ChioRuntimeAdmissionHook::evaluate`; missing-context runtime tests | The request is classified as federated by trusted runtime state. | "A request marked as federated is denied when its treaty context is absent or malformed." |
| PS-C03 | Request metadata cannot install trust roots or dynamic trust bundles. | Production-enforced | `treaty_ref_from_request`; request-smuggling tests in `runtime_admission.rs` | Provisioning outside the request path remains an operational control. | "The evaluated path rejects request-supplied trust roots and resolves treaty evidence from verifier-owned stores." |
| PS-C04 | The strict bilateral envelope binds two signatures to one canonical invocation predicate. | Production-enforced | `verify_chio_bilateral_dsse_envelope`; `bilateral_verifier.rs`; federation and buyer-review tests | Signature verification authenticates keys, not organizational independence or honest local evaluation. | "The strict profile requires two distinct configured signer keys over the same canonical treaty-bound predicate." |
| PS-C05 | Two signatures prove that two independent organizations evaluated local policy. | Blocked | No organizational-independence or kernel-attestation proof exists. | Two keys may be controlled by one actor. A compromised kernel may sign a false summary. | Do not make this claim. State the distinct-key property and list organizational independence as an assumption. |
| PS-C06 | Treaty admission is the intersection of treaty, left-polity, and right-polity predicates. | Bounded theorem | `treaty_admission_iff_predicate_intersection` in `IntersectionSyntactic.lean`; root import; formal gate | The theorem is structural over the bounded `ReceiptView` interpreter and is not a Rust refinement proof. | "In the bounded Lean model, treaty admission is extensionally equal to the conjunction of treaty and participant predicates." |
| PS-C07 | A mode at or above the treaty floor preserves the bounded treaty decision. | Bounded theorem | `treaty_admission_stable_under_ladder_floor` in `IntersectionSyntactic.lean`; root import; formal gate | The theorem covers the finite imported ladder representation. Production ladder validation is tested independently. | "In the bounded finite-mode model, satisfying the declared floor reduces admission to the treaty predicate." |
| PS-C08 | Constitutional refinement is decidable for the current closure model. | Blocked | `Constitution` stores `List (ReceiptId -> Bool)`; `BackwardRefines` quantifies over all receipt strings; `PredicateLang.lean` explicitly identifies the category error. | A finite list of opaque predicates makes evaluation at one receipt decidable, not universal implication between arbitrary predicates. | Do not make this claim until the syntactic bridge, bounded completeness argument, and executable decision procedure are complete. |
| PS-C09 | Amendment enactment is a production Rust invariant requiring a refinement witness. | Blocked | `enactAmendment` exists only in the Lean model. No corresponding production Rust enactment surface was identified. | The Lean type establishes constructibility inside the model only. | "The companion model represents enactment with a proof-carrying type." Do not call it a runtime invariant. |
| PS-C10 | Backward refinement preserves already-admitted history. | Blocked | The current formula is `K'(r) -> K(r)`. | The formula prevents accept-set widening. It does not require `K(r) -> K'(r)` and therefore may reject receipts formerly accepted by `K`. | "Backward refinement prevents the new predicate set from widening admission on the modeled domain." |
| PS-C11 | The implemented polity is the triple `(T, C, K)`. | Blocked | Lean `Polity` contains only `scope` and `constitution`; no production polity roster participates in the evaluated admission path. | Citizenship is currently explanatory vocabulary, not a load-bearing model or runtime component. | Use `P = (T, K)` in the submission. Discuss rosters as future governance work. |
| PS-C12 | The bounded formal model accounts for the evidence and failure fields used by its treaty predicates. | Bounded theorem | `ReceiptView` and `AtomTag` in `PredicateLang.lean`; `IntersectionSyntactic.lean`; formal proof gate | The view is a deliberately bounded projection. It does not model persistence, Merkle history, transport, or all production validation. | "The bounded model gives executable semantics to predicates over participant identifiers, receipt hashes, action classes, ladder modes, live continuations, decisions, failure codes, and evidence digests." |
| PS-C13 | Lean verifies the Rust treaty implementation. | Blocked | Lean and the independent Rust reference semantics now agree with the production evaluator across 1,024 generated cases per property, but no extraction or universal refinement proof exists. | Differential testing finds disagreement on the generated domain; it does not establish semantic equivalence for every input or verify the surrounding runtime. | "The production evaluator is differentially aligned with the bounded predicate semantics on the generated corpus." Do not say "Rust verified by Lean." |
| PS-C14 | Every Chio runtime decision produces a canonically signed receipt. | Blocked | Signed admission reports and receipts exist on named paths, but early returns and internal errors have not been shown to produce the same signed artifact class. | A denial decision object is not automatically a durable signed receipt. | Name the exact path and artifact. Do not quantify over every runtime decision. |

## Implementation and evaluation claims

| ID | Claim | Class | Current evidence | Assumptions and limits | Permitted submission wording |
| --- | --- | --- | --- | --- | --- |
| PS-C15 | Continuations are consumed once and replay denies. | Production-enforced | Runtime admission tests for accepted-once, stale, replayed, and released continuation states | Store durability and atomicity depend on the configured store implementation. | "The evaluated runtime consumes a treaty continuation once and denies replay." |
| PS-C16 | Runtime denial releases reserved continuation state when dispatch does not occur. | Production-enforced | `treaty_runtime_hook_releases_continuation_after_runtime_denial`; kernel-abort release tests | Release after a potentially effectful handoff is a separate lifecycle problem. | "Pre-dispatch denial and kernel abort release the reserved continuation in the tested path." |
| PS-C17 | The buyer closure binds runtime receipts, treaty evidence, lineage, strict DSSE, and regenerated proof artifacts. | Executable demonstration | `check-chio-treaty-buyer-hero-loop.sh`; `check-chio-live-treaty-buyer-closure.sh`; runtime harness | The scenario is deterministic and local. It is not a bilateral deployment between separately administered organizations. | "A deterministic three-vendor loopback executes the complete artifact path and buyer review." |
| PS-C18 | The current generic replay corpus evaluates bilateral treaty admission. | Blocked | `run-replay-corpus.sh` now reports 50 generic replay fixtures and 20 bilateral negative cases as separate corpora. | Generic byte-equivalence fixtures remain evidence for generic replay only. | Report the two corpora separately. Do not attribute bilateral coverage to the generic 50-fixture corpus. |
| PS-C19 | Every executable adversary capability named in the bounded threat matrix maps to a checked negative case. | Executable demonstration | 20 stable `PS-TH-*` cases in `treaty-runtime-negative-corpus.json`; schema and `--matrix-only` gate; generated replay result | A single actor controlling two separately authorized keys is `PS-A-01`, an explicit non-testable assumption. Compromised honest endpoints remain outside the adversary model. | "The executable matrix covers 20 named malformed, stale, replayed, smuggled, or policy-denied cases; key-controller independence remains an operational assumption." |
| PS-C20 | Dispatch allow latency is measured. | Experimentally measured | `run-dispatch-allow.sh`; `dispatch-allow-inline.tex` | The benchmark is the local production dispatch path, not the full bilateral path. | Report as a component baseline only. |
| PS-C21 | Treaty-intersection latency is measured for `N = 1, 10, 100`. | Experimentally measured | `run-treaty-intersection.sh`; raw CSV and generated inline TeX | The current hand-written harness uses the documented local profile. | Report with hardware, profile, sample count, and raw results. |
| PS-C22 | Selective-disclosure proof size and verification latency are measured. | Experimentally measured | `run-selective-disclosure.sh`; raw CSV and generated inline TeX | BBS is secondary presentation evidence and not the authoritative receipt signature. | Report as an optional privacy-path cost, not per-dispatch overhead. |
| PS-C23 | Full bilateral admission latency and denial latency are measured. | Experimentally measured | `run-bilateral-admission.sh`; 20 release-profile path samples; 30 Criterion samples; raw CSV, JSON, environment, and generated TeX | The deterministic loopback is single-host and includes process startup and schema validation. Its SQLite stores represent the evaluated local configuration, not a wide-area deployment. | "On the stated machine, full receiver admission measured 2.288 s p50 and 2.428 s p99; the real pre-dispatch treaty-denial path measured 13.406 ms p50 and 22.826 ms p99." |
| PS-C24 | Receipt signing and verification are measured over the paper's receipt shape. | Experimentally measured | Buyer-closure-shaped real signing and verification bodies; 30 Criterion samples; generated component CSV | The receipt shape copies the closure's nested metadata. Signing keys are local Ed25519 keys; HSM and network costs are absent. | "Buyer-closure-shaped receipt signing measured 242.4 us p50, and verification measured 370.2 us p50, under the stated configuration." |
| PS-C25 | Anchor inclusion is measured and load-bearing. | Future work | No dedicated paper measurement; lane maturity is uneven. | Rekor inclusion, OTS policy, Solana finality, and EVM finality have different residual assumptions. | Exclude from the evaluated core contribution. |

## Scope and interpretation claims

| ID | Claim | Class | Current evidence | Assumptions and limits | Permitted submission wording |
| --- | --- | --- | --- | --- | --- |
| PS-C26 | Chio establishes legal or territorial sovereignty. | Blocked | The implementation controls only its own admission boundary. | Courts, regulators, counterparties, and physical jurisdictions remain external. | "Receipt-bounded sovereignty" is an interpretation of local admission authority, not a statehood claim. |
| PS-C27 | Chio instantiates Hart's complete rule of recognition. | Blocked | The model supplies a replayable criterion for receipt admission only. | Settled official practice and internal acceptance are sociological conditions outside the artifact. | "The admission predicate is a constructive analogue of Hart's identification criterion over a receipt history." |
| PS-C28 | Public witnesses prove legal truth or policy wisdom. | Blocked | Anchors can bind roots or timestamps under lane-specific assumptions. | They do not validate the underlying policy, contract, or legal consequence. | "A public witness can strengthen equivocation evidence for a specified commitment." |
| PS-C29 | Economics or an endogenous token is required for bilateral admission. | Blocked | The admission path is capability, policy, treaty, and receipt based. | Settlement may consume admission evidence downstream. | "The evaluated admission property is independent of an endogenous token or market." |
| PS-C30 | No-widening amendment is decidable for the bounded syntactic constitution on a supplied finite domain. | Bounded theorem | `SyntacticConstitution`, `refinesOnConstitution_iff`, `ofDecide`, and accepted/rejected amendment examples in `PredicateLang.lean` and `IntersectionSyntactic.lean` | The theorem does not prove that a finite sample is complete for an external deployment domain. The legacy opaque-function constitution remains undecidable in general. | "For the strict predicate syntax and an explicit finite receipt domain, no-widening refinement is executable and its positive decision is sound." |
| PS-C31 | The production bounded predicate evaluator agrees with an independent executable reference on the generated corpus. | Differentially aligned | `formal/diff-tests/tests/treaty_predicate_diff.rs`; exhaustive atom mapping and 1,024 generated cases each for predicates, constitutions, and finite refinement | Generated testing is not a proof of universal implementation equivalence. Validation and artifact construction outside the evaluator have separate tests. | "The Rust evaluator and an independent reference agree over the generated bounded-predicate corpus." |

## Replacement language for the submission

Use these formulations consistently unless later gates justify a stronger row:

- **System result:** "Chio places receiver-owned treaty verification on the
  pre-dispatch path for cross-organization agent tool calls."
- **Bilateral artifact:** "Two distinct configured keys sign the same canonical
  predicate binding the request, outcome, treaty, continuation, lineage, and
  local and remote receipts."
- **Formal result:** "A bounded Lean model characterizes treaty admission as
  predicate intersection, proves stability once the declared ladder floor is
  satisfied, and decides no-widening on an explicit finite receipt domain."
- **Amendment result:** "A companion Lean type carries a successful
  finite-domain no-widening check; the current production runtime does not
  enact amendments through that type."
- **Evidence result:** "A deterministic three-vendor loopback emits and
  re-verifies buyer-owned positive and negative evidence."
- **Interpretation:** "Programmable sovereignty names local authority over a
  receipt-admission boundary. It does not imply legal statehood or control over
  external institutions."

## Promotion rule

A blocked or future-work row may be promoted only when:

1. the named implementation or theorem exists in the current tree;
2. the focused gate exercises the exact property;
3. assumptions and counterexamples are recorded;
4. the artifact manifest pins the evidence to a commit;
5. the abstract, body, limitations, and conclusion use the same scope.
