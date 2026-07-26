# Programmable Sovereignty Paper Revision Plan

> Execute in order. Do not restore a strong paper claim until its proof,
> implementation, experiment, and artifact gates are green.

**Goal:** Turn the current Programmable Sovereignty manuscript into a
submission-ready security paper whose central claim is receiver-owned,
pre-dispatch bilateral admission for cross-organization agent tool calls.

**Working title:** `Proof-Carrying Bilateral Admission for
Cross-Organization Agent Tool Calls`. Retain `Programmable Sovereignty` as the
broader interpretation or subtitle until the formal and implementation
evidence supports stronger constitutional language.

**Core thesis:** A receiving organization executes a foreign agent tool call
only when the capability, receiver policy, treaty intersection, continuation,
lineage, and bilateral receipt bindings agree. The same path produces
replayable evidence for allow and deny.

**Execution status:** Complete. The source, proof, differential, threat-matrix,
measurement, manuscript, and workspace gates listed below passed on
2026-07-25. The final artifact commit pins the exact source snapshot.

**Architecture:** The Rust runtime admission hook remains the production source
of truth. A finite syntactic predicate language supplies the bounded Lean
semantics. Differential fixtures connect that semantics to the Rust evaluator.
The live three-vendor buyer closure supplies the end-to-end evaluation. A
claim ledger and generated artifact manifest keep the paper from presenting a
bounded theorem, operational assumption, fixture, or code pointer as something
stronger.

## Global constraints

- No em dashes in code, comments, paper text, or documentation.
- Preserve fail-closed behavior, verifier-owned trust stores,
  replay-safe continuation handling, canonical JSON, signed negative evidence,
  and the strict Chio bilateral DSSE profile.
- Do not claim that Lean verifies the Rust implementation unless an actual
  refinement or equivalence gate is added.
- Do not describe arbitrary closure implication as decidable.
- Do not describe two signing keys as independent organizations without an
  explicit operational or attestation assumption.
- Do not describe backward refinement as preserving prior admission. It
  prevents accept-set widening on the modeled domain.
- Do not use a line-number citation as durable evidence. Cite symbols and pin
  the artifact snapshot to a commit SHA.
- Every benchmark result must have a script, raw output, build profile, machine
  metadata, and an inline TeX result generated from the raw output.
- Withheld or unimplemented results remain marked. Do not estimate them.
- Keep the USENIX body at or below the configured 13-page limit.
- Run paper builds in a clean copy or verify that no generated source artifact
  changed unexpectedly.

## Submission claim classes

Every technical statement in the abstract, introduction, implementation,
evaluation, and conclusion must map to exactly one class:

| Class | Meaning | Required evidence |
| --- | --- | --- |
| Production-enforced | The shipping Rust path rejects or admits the stated case | Symbol, focused behavioral tests, full-path gate |
| Bounded theorem | Lean proves the statement over the explicitly named model | Root-imported theorem, no `sorry`, assumption list |
| Differentially aligned | Independent bounded semantics and Rust agree on a generated corpus | Differential test and retained failing seeds |
| Experimentally measured | A script reports a result from the production path | Raw output, environment metadata, generated TeX |
| Executable demonstration | A deterministic scenario runs end to end | Live closure command, artifacts, positive and negative replay |
| Operational assumption | Correctness depends on deployment discipline | Assumption ledger and failure consequence |
| Future work | No current evidence satisfies the claim | Explicitly excluded from contributions |

## Deliberate scope reductions

- Use the submission model `P = (T, K)`: receipt-admission scope plus
  constitutional predicates. Move the Merkle-rooted citizenship roster `C` to
  future governance work unless this revision adds an executable roster
  contract, a formal role for it, and tests showing that role.
- Treat proof-carrying amendment as a bounded formal extension. Do not call it a
  production runtime invariant unless a Rust enactment path consumes the same
  serialized predicate language and refinement witness.
- Treat public anchoring, partition reconciliation, multi-party treaty graphs,
  legal recognition, regulator accreditation, and post-quantum migration as
  limitations or future work, not evaluated contributions.
- Keep the bilateral case. Do not generalize the theorem or evaluation to
  arbitrary treaty graphs.

## Go or no-go checkpoints

- **After Phase 0:** If the narrower claim is not acceptable, stop. Do not
  invest in experiments for the existing overbroad abstract.
- **After Phase 1:** If the syntactic bridge and receipt semantics are not
  green, remove decidability, proof-carrying amendment, and
  Lean-attestable-constitution claims from the submission version.
- **After Phase 2:** If differential alignment is not green, describe Lean only
  as a companion model and remove proof-to-code language.
- **After Phase 3:** If the full buyer closure and threat matrix are not
  reproducible, do not present the paper as an evaluated end-to-end security
  system.
- **After Phase 5:** Submission requires a clean pinned artifact and page gate.
  A passing LaTeX build alone is not a submission verdict.

## Phase 0: Freeze the honest baseline

### Task 1: Create the claim ledger

**Files:**

- Create
  `docs/papers/programmable-sovereignty/CLAIM_LEDGER.md`.
- Inspect every claim in:
  - `docs/papers/programmable-sovereignty/paper.tex`
  - `docs/papers/programmable-sovereignty/paper-usenix.tex`
  - `docs/papers/programmable-sovereignty/sections/*.tex`
- Cross-check:
  - `formal/lean4/Chio/Chio/Treaty/Intersection.lean`
  - `formal/lean4/Chio/Chio/Treaty/PredicateLang.lean`
  - `crates/kernel/chio-runtime-core/src/admission_hook.rs`
  - `crates/kernel/chio-runtime-core/src/treaty.rs`
  - `crates/trust/chio-federation/src/bilateral_dsse.rs`
  - `crates/trust/chio-federation/src/bilateral_verifier.rs`
  - `crates/kernel/chio-runtime-harness/src/buyer_closure.rs`

**Work:**

- [x] Give every abstract sentence and contribution bullet a stable claim ID.
- [x] Record its claim class, exact scope, evidence, assumptions, and permitted
  wording.
- [x] Mark these current formulations as blocked:
  - all polity operations are decidable;
  - `(T, C, K)` is the implemented formal polity;
  - Lean discharges or verifies the Rust treaty implementation;
  - amendment enactment is a production Rust runtime invariant;
  - two signatures prove independent local policy evaluation;
  - backward refinement preserves already-admitted history;
  - every runtime denial is necessarily a signed receipt.
- [x] Record a replacement formulation for each blocked claim.
- [x] Name the strongest admissible contribution set:
  strict bilateral predicate, verifier-owned admission, pre-dispatch runtime
  integration, buyer-closure evidence, bounded syntactic model, and
  end-to-end negative evaluation.

**Gate:**

- Each abstract and introduction claim has one ledger entry.
- No claim cites only a prose section or code line number as evidence.
- A reviewer can distinguish production enforcement from a bounded theorem
  without reading the limitations section.

### Task 2: Capture the pre-revision baseline

**Files:**

- Create
  `docs/papers/programmable-sovereignty/revision-baseline.md`.

**Work:**

- [x] Record the current commit SHA, Rust toolchain, Lean toolchain, TeX
  toolchain, operating system, and machine profile.
- [x] Record the current title, abstract, body-page count, theorem list,
  benchmark results, and known missing measurements.
- [x] Record the current stale artifact pointers, including the
  `admission_hook.rs:88` and `treaty.rs:261` citations.
- [x] Run the current gates without changing paper claims.

**Gate:**

```bash
./scripts/check-formal-proofs.sh
cargo test -p chio-runtime-core --test runtime_admission
cargo test -p chio-runtime-core --test runtime_buyer_review
cargo test -p chio-runtime-harness
cargo test -p chio-federation --lib
bash scripts/check-chio-live-treaty-buyer-closure.sh
make -C docs/papers/programmable-sovereignty submit-check
```

Commit: `docs(paper): freeze programmable sovereignty claim baseline`

## Phase 1: Repair the formal core

### Task 3: Complete the PredicateLang bridge

**Dependency:** Execute
`docs/formal/plan/FV-D2-predicatelang-bridge.md`. That plan is authoritative
for theorem statements, migration sequencing, inventory updates, and the
legacy-closure deprecation step.

**Files:**

- Modify
  `formal/lean4/Chio/Chio/Treaty/PredicateLang.lean`.
- Create
  `formal/lean4/Chio/Chio/Treaty/IntersectionSyntactic.lean`.
- Create
  `formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean`.
- Modify:
  - `formal/lean4/Chio/Chio.lean`
  - `formal/proof-manifest.toml`
  - `formal/theorem-inventory.json`

**Work:**

- [x] Add `toClosure`, pointwise transport, semantic refinement, and the
  decidable-sample soundness bridge.
- [x] Prove the modeled fragment's completeness boundary and retain the
  counterexample showing why arbitrary enriched atoms need their own coverage
  argument.
- [x] Add a syntactic treaty and amendment model whose witnesses are
  constructable by decision procedures on the declared bounded domain.
- [x] Prove the syntactic intersection, ladder-floor, refinement, and
  no-witness rejection statements.
- [x] Prove equivalence between the syntactic model and the legacy closure
  model for lifted predicates.
- [x] Keep the legacy model only as an explicitly labeled representation
  artifact. Point new paper claims to the syntactic theorem set.

**Gate:**

```bash
./scripts/check-formal-proofs.sh
```

- `PredicateLang.lean` no longer says the bridge is unproved.
- A nontrivial narrowing amendment is constructable through the documented
  decision procedure.
- A widening amendment is rejected.
- Every new theorem is root-imported and inventoried.

Commit: `feat(formal): make treaty refinement decidable on bounded syntax`

### Task 4: Give the formal model the fields its claims inspect

**Files:**

- Modify
  `formal/lean4/Chio/Chio/Treaty/PredicateLang.lean`.
- Modify
  `formal/lean4/Chio/Chio/Treaty/IntersectionSyntactic.lean`.
- Modify or extend the theorem inventory and assumption registry.

**Work:**

- [x] Replace receipt-ID-only denotation with a bounded `ReceiptView` carrying
  exactly the fields used by the paper's theorem claims:
  receipt identity, action class, participant kernel IDs, ladder mode,
  continuation state, decision, failure code, and bound evidence digests.
- [x] Give every supported atom real semantics. Do not leave production-named
  atoms denoting constant false.
- [x] Model allow and deny explicitly. A denial theorem must inspect a failure
  code if the paper claims that the constitution admits specific denial
  reasons.
- [x] Keep cryptography, canonicalization, clocks, storage, and signature
  verification abstract, but list each as an assumption consumed by the model.
- [x] Re-prove the treaty, ladder, and refinement results over `ReceiptView`.
- [x] Remove `C` from the formal polity and headline equation. If the team
  chooses to retain `C`, stop this task and first add a concrete standing or
  quorum operation in both the model and production code.

**Gate:**

- No production-named predicate atom has placeholder semantics.
- The formal trace and the receipt-admission relation quantify over the same
  modeled receipt view.
- Allow and deny claims have data structures capable of expressing their
  stated conditions.
- `P = (T, K)` is used consistently in the abstract, formal definitions, and
  theorem prose.

Commit: `feat(formal): align polity admission with bounded receipt semantics`

## Phase 2: Build an honest Rust-to-model connection

### Task 5: Add a small independent predicate reference model

**Files:**

- Modify:
  - `formal/diff-tests/src/spec.rs`
  - `formal/diff-tests/src/generators.rs`
  - `formal/diff-tests/src/lib.rs`
- Create
  `formal/diff-tests/tests/treaty_predicate_diff.rs`.
- Modify the relevant architecture documentation.

**Work:**

- [x] Represent the same bounded `ReceiptView` and predicate tags used by Lean
  without importing production evaluator helpers.
- [x] Implement a small independent denotation function.
- [x] Generate valid and invalid receipt views, including boundary ladder
  modes, empty and duplicate participants, stale continuations, unknown action
  classes, allow and deny codes, and mismatched evidence digests.
- [x] Retain property-test regressions for every discovered mismatch.
- [x] Document that the reference model is the differential oracle for the
  bounded paper fragment, not for the whole runtime.

**Gate:**

```bash
cargo test -p chio-formal-diff-tests treaty_predicate_diff
```

Commit: `test(formal): add treaty predicate differential oracle`

### Task 6: Mirror only the bounded syntax in Rust

**Files:**

- Modify `crates/kernel/chio-runtime-core/src/treaty.rs`, or extract a focused
  sibling module under `crates/kernel/chio-runtime-core/src/treaty/`.
- Modify `crates/kernel/chio-runtime-core/src/lib.rs` only as needed.
- Modify `formal/diff-tests/tests/treaty_predicate_diff.rs`.
- Add focused runtime treaty tests beside the existing tests.

**Work:**

- [x] Define a strict serialized predicate representation for the bounded
  fragment. Unknown tags and versions deny.
- [x] Evaluate the syntax against a verified runtime-derived receipt view.
  Request metadata cannot construct or override the verified view.
- [x] Compare the production evaluator against the independent reference model
  across generated valid and invalid cases.
- [x] Keep existing hard-coded safety checks authoritative until migration is
  complete. Do not create an optional policy bypass.
- [x] State exactly which existing runtime checks are represented and which
  remain outside the formal fragment.

**Gate:**

```bash
cargo test -p chio-runtime-core --test runtime_treaty
cargo test -p chio-formal-diff-tests treaty_predicate_diff
./scripts/check-formal-proofs.sh
```

- Every supported Rust predicate tag has a Lean denotation and an independent
  reference-model case.
- Every Lean atom used in a paper theorem has a Rust counterpart or is labeled
  model-only.
- The paper may now say "differentially aligned on the bounded predicate
  fragment." It still may not say "Rust verified by Lean."

Commit: `feat(runtime): align bounded treaty predicates with formal semantics`

## Phase 3: Evaluate the headline admission path

### Task 7: Promote the existing live buyer closure into the paper harness

**Files:**

- Reuse:
  - `scripts/check-chio-treaty-buyer-hero-loop.sh`
  - `scripts/check-chio-live-treaty-buyer-closure.sh`
  - `crates/kernel/chio-runtime-harness/src/buyer_closure.rs`
  - `examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json`
- Create
  `docs/papers/programmable-sovereignty/bench/run-bilateral-admission.sh`.
- Create generated raw and inline results under
  `docs/papers/programmable-sovereignty/bench/results/`.

**Work:**

- [x] Run the production runtime hook, treaty store, continuation handling,
  strict DSSE verification, lineage verification, proof regeneration, and
  buyer review in one measured path.
- [x] Measure at least:
  - admitted end-to-end closure p50 and p99;
  - pre-dispatch denial p50 and p99;
  - full positive scenario wall time;
  - full negative-matrix wall time;
  - emitted proof-package size.
- [x] Use release profile for latency results. Keep debug-profile checks as
  transparent correctness runs, not performance claims.
- [x] Record toolchain, commit SHA, machine, warmup, sample count, raw
  observations, and whether stores are in-memory or SQLite.
- [x] Generate inline TeX from raw CSV or JSON. Never hand-copy a number into
  the paper.

**Gate:**

```bash
bash docs/papers/programmable-sovereignty/bench/run-bilateral-admission.sh
bash scripts/check-chio-live-treaty-buyer-closure.sh
```

- The measured allow reaches the tool path only after treaty admission.
- Every measured deny proves the tool did not run.
- Re-running the script regenerates the same result schema and paper inputs.

Commit: `bench(paper): measure bilateral admission end to end`

### Task 8: Make the threat model an executable negative matrix

**Files:**

- Modify
  `examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json`.
- Modify:
  - `scripts/check-chio-treaty-buyer-hero-loop.sh`
  - `scripts/check-chio-live-treaty-buyer-closure.sh`
  - focused tests under
    `crates/kernel/chio-runtime-core/tests/runtime_admission.rs`
  - focused tests under
    `crates/kernel/chio-runtime-core/tests/runtime_buyer_review.rs`
  - strict verifier tests in `crates/trust/chio-federation/`

**Work:**

- [x] Give each adversary capability in the paper threat model a stable threat
  ID and at least one executable case.
- [x] Cover:
  wrong treaty, stale treaty, forged intersection, missing lineage, receipt
  mismatch, request hash mismatch, outcome hash mismatch, missing or duplicate
  signature, repeated signer key, wrong predicate type, noncanonical payload,
  stale lease, missing governance receipt, replayed continuation, request
  trust-root smuggling, dynamic-trust smuggling, schema mismatch, policy
  disagreement, and signed unanimous deny.
- [x] Record expected failure code and pre-dispatch or post-dispatch phase for
  every case.
- [x] Add an explicit non-testable assumption row for two keys controlled by
  one actor. Do not count that case as defeated without organizational or TEE
  attestation.
- [x] Update the replay benchmark to report both the generic 50-fixture corpus
  and the Chio-specific bilateral corpus. Do not imply that the generic corpus
  covers bilateral admission.

**Gate:**

```bash
bash scripts/check-chio-live-treaty-buyer-closure.sh --negative-only
cargo test -p chio-runtime-core --test runtime_admission
cargo test -p chio-runtime-core --test runtime_buyer_review
cargo test -p chio-federation --lib
bash docs/papers/programmable-sovereignty/bench/run-replay-corpus.sh
```

- Every threat-model row maps to an executable case or an explicit assumption.
- No test filter is allowed to pass after matching zero tests.
- Every denial asserts both the expected code and absence of tool execution.

Commit: `test(security): execute bilateral admission threat matrix`

### Task 9: Fill only the benchmark gaps needed by the paper

**Files:**

- Repair or replace constant-body scaffolds in:
  - `crates/kernel/chio-kernel/benches/receipt_sign.rs`
  - `crates/kernel/chio-kernel/benches/receipt_append.rs`
- Add a real receipt-verification benchmark if none exists.
- Add paper scripts and generated results under
  `docs/papers/programmable-sovereignty/bench/`.

**Work:**

- [x] Measure real receipt signing and verification over the receipt shape used
  by the buyer closure.
- [x] Report receipt append only if the benchmark exercises the actual store
  path used by the evaluated configuration.
- [x] Keep anchor inclusion withheld. It is outside the narrowed core claim.
- [x] Add a component breakdown that explains where full-path latency is spent:
  treaty intersection, strict DSSE, admission evaluation, receipt
  sign/verify, and buyer verification.
- [x] Avoid comparisons to systems that do not implement the same trust
  boundary. Use an ablation of Chio's own path:
  local receipt only, bilateral binding without buyer review, and full
  receiver-owned admission.

**Gate:**

- No reported benchmark body black-boxes a constant.
- Every Table 3 row is measured, explicitly withheld, or removed as irrelevant
  to the narrowed contribution.
- The full-path measurement is the first evaluation result, not dispatch-only
  latency.

Commit: `bench(paper): replace scaffolded receipt measurements`

## Phase 4: Rewrite the paper around the security contribution

**Target body allocation:**

| Section | Page budget |
| --- | ---: |
| Introduction and motivating attack | 1.25 |
| Threat model and closest background | 1.25 |
| Bilateral admission design | 2.00 |
| Bounded formal model | 2.00 |
| Implementation | 1.50 |
| Evaluation | 3.00 |
| Discussion and limitations | 1.00 |
| Related work | 1.00 |

The allocation totals 13 pages. References and optional extended-whitepaper
appendices remain outside the submission body limit.

### Task 10: Replace the opening and contribution structure

**Files:**

- Modify:
  - `docs/papers/programmable-sovereignty/paper.tex`
  - `docs/papers/programmable-sovereignty/paper-usenix.tex`
  - `docs/papers/programmable-sovereignty/sections/01-introduction.tex`
  - `docs/papers/programmable-sovereignty/sections/02-background.tex`

**Work:**

- [x] Open with one concrete cross-organization attack:
  a signed vendor receipt that the buyer must not accept because its treaty,
  request binding, continuation, or receiver policy does not match.
- [x] State the receiver-owned admission property before introducing polity
  vocabulary.
- [x] Use the working title unless all stronger title claims pass the ledger.
- [x] Replace `(T, C, K)` with `(T, K)`.
- [x] Define receipt, treaty, bilateral predicate, receiver-owned trust store,
  and pre-dispatch admission before using constitutional metaphors.
- [x] Reduce contributions to four:
  strict bilateral predicate, production admission hook, bounded formal
  semantics with differential alignment, and end-to-end evaluation.
- [x] Move KeyKOS, capability, transparency, and closest agent-security
  comparisons to a compact background section. Move most governance and legal
  material later.

**Gate:**

- A systems reviewer can state the threat, mechanism, and contribution after
  page 1 without using the word sovereignty.
- The abstract contains no blocked claim from the ledger.
- The abstract distinguishes production enforcement, bounded theorem, and
  measured result.

### Task 11: Rewrite the model and implementation claims

**Files:**

- Modify:
  - `sections/03-substrate.tex`
  - `sections/04-model.tex`
  - `sections/05-implementation.tex`
  - `figures/admission-hook.tex`
  - `figures/treaty-handshake.tex`
  - `figures/amendment-lifecycle.tex`

**Work:**

- [x] Present one artifact flow from request to pre-dispatch verdict and signed
  evidence.
- [x] State the bounded `ReceiptView`, predicate grammar, and assumptions before
  theorem statements.
- [x] Replace "discharges the runtime side" with the exact relation:
  production counterpart, differential alignment, or model-only.
- [x] Describe the intersection and ladder theorems as structural consistency
  results, not implementation verification.
- [x] Describe amendment refinement as no accept-set widening on the modeled
  domain.
- [x] Move amendment to a short formal extension or appendix if no production
  enactment path exists.
- [x] Distinguish "two keys signed the same predicate" from "two independent
  organizations evaluated it."
- [x] Enlarge the admission and treaty figures. Remove the amendment figure from
  the body if it is no longer a primary contribution.
- [x] Replace file-line citations with symbol names and artifact-manifest IDs.

**Gate:**

- Every theorem paragraph contains a model boundary and implementation status.
- Every figure is legible at printed two-column size.
- The implementation section follows the actual runtime path, not the old
  `examples/chio-3vendor/src/main.rs` stub.

### Task 12: Rebuild evaluation, related work, discussion, and limits

**Files:**

- Modify:
  - `sections/06-evaluation.tex`
  - `sections/07-discussion.tex`
  - `sections/08-related-work.tex`
  - `sections/09-limitations.tex`
  - `sections/10-conclusion.tex`
  - `bib.bib`

**Work:**

- [x] Lead evaluation with the full bilateral path and threat matrix.
- [x] Separate research questions:
  - RQ1: Does the receiver deny mismatched or replayed cross-boundary actions
    before dispatch?
  - RQ2: Do bounded Lean semantics, the independent reference model, and Rust
    agree?
  - RQ3: What latency and evidence-size costs does receiver-owned bilateral
    admission add?
  - RQ4: Can a third party replay positive and negative buyer evidence without
    vendor-internal access?
- [x] Report failures and unsupported cases, including single-actor dual keys,
  kernel compromise, trust-store provisioning, and schema migration.
- [x] Move Montevideo, Próspera, FTX, Tornado Cash, and most Hart discussion to
  an appendix or the extended whitepaper. Retain one short paragraph explaining
  receipt-bounded sovereignty.
- [x] Compare most directly against capability systems, IsolateGPT, SAGA,
  Cedar, DSSE/in-toto, TEE-backed enforcement, and cross-domain authorization.
- [x] Remove market, settlement, anchoring, and regulator material that is not
  used by the evaluated construction.
- [x] End with the demonstrated result, not a prospective counterparty request.

**Gate:**

- Evaluation claims match generated results exactly.
- The limitations section does not carry the first disclosure of a central
  proof or implementation gap.
- The conclusion contains no future deployment claim presented as a result.
- The paper remains within the body-page limit without shrinking tables or
  figures below legibility.

Commit: `docs(paper): center programmable sovereignty on bilateral admission`

## Phase 5: Make the artifact durable

### Task 13: Generate a pinned artifact manifest

**Files:**

- Create
  `docs/papers/programmable-sovereignty/supplementary/artifact-manifest.json`.
- Create
  `scripts/generate-programmable-sovereignty-artifact.py`.
- Create
  `scripts/check-programmable-sovereignty-artifact.sh`.
- Modify:
  - `docs/papers/programmable-sovereignty/supplementary/proof-manifest.toml`
  - `docs/papers/programmable-sovereignty/supplementary/theorem-inventory.json`
  - `docs/papers/programmable-sovereignty/supplementary/README.md`
  - `docs/papers/programmable-sovereignty/README.md`

**Manifest fields:**

- paper title and target;
- source commit SHA;
- Rust and Lean toolchains;
- theorem names, modules, axiom lists, and claim classes;
- production symbol names and paths;
- behavioral test commands;
- benchmark script names and result hashes;
- positive and negative corpus hashes;
- expected body-page limit;
- excluded or withheld surfaces.

**Work:**

- [x] Resolve symbols at the pinned commit instead of storing mutable line
  numbers.
- [x] Fail generation when a claimed file, symbol, theorem, script, or result is
  missing.
- [x] Regenerate the Lean source archive from the pinned source.
- [x] Verify the archive in a clean temporary directory.
- [x] Update the supplementary date and remove the stale May 2026 snapshot.
- [x] Include one command that rebuilds proofs, experiments, and the PDF from
  the artifact package.

**Gate:**

- The manifest checker passes from a clean checkout.
- The Lean archive builds independently.
- Every paper artifact ID resolves at the pinned SHA.
- Re-running generation produces no unexplained diff.

Commit: `build(paper): pin programmable sovereignty submission artifact`

### Task 14: Run the final claim and submission audit

**Work:**

- [x] Re-read the abstract, introduction, contribution list, theorem captions,
  evaluation tables, limitations, and conclusion against the claim ledger.
- [x] Search for and classify every use of:
  `prove`, `verify`, `decidable`, `independent`, `constitutional`,
  `production`, `end-to-end`, `preserve`, and `every`.
- [x] Confirm the paper contains no stale line-number citation.
- [x] Confirm every reported number is generated.
- [x] Confirm every negative case asserts non-dispatch.
- [x] Confirm the PDF has no clipped tables, tiny figures, unresolved
  references, citation warnings, or body-page overflow.
- [x] Confirm no paper build or artifact generation leaves an unexpected source
  diff.

**Targeted gates:**

```bash
./scripts/check-formal-proofs.sh
cargo test -p chio-formal-diff-tests
cargo test -p chio-runtime-core --test runtime_treaty
cargo test -p chio-runtime-core --test runtime_admission
cargo test -p chio-runtime-core --test runtime_buyer_review
cargo test -p chio-runtime-harness
cargo test -p chio-federation --lib
bash scripts/check-chio-live-treaty-buyer-closure.sh
bash docs/papers/programmable-sovereignty/bench/run-bilateral-admission.sh
bash docs/papers/programmable-sovereignty/bench/run-replay-corpus.sh
make -C docs/papers/programmable-sovereignty submit-check
```

**Workspace gates:**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
git diff --check
```

**Final acceptance criteria:**

- The headline result is receiver-owned bilateral admission, demonstrated
  end to end on the production runtime path.
- The formal claim is decidable only over explicit bounded syntax and receipt
  semantics.
- The Rust relationship is described as differential alignment unless stronger
  verification evidence exists.
- The threat model and negative corpus have one-to-one coverage, apart from
  explicitly named operational assumptions.
- The title, abstract, contribution list, evaluation, and conclusion make the
  same claim at the same strength.
- The submission artifact reproduces proofs, tests, measurements, and the PDF
  from a pinned commit.
- The paper passes the 13-body-page submission gate with legible figures and
  tables.

Commit: `docs(paper): qualify bilateral admission submission`
