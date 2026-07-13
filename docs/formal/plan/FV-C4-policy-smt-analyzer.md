# FV-C4: `chio policy analyze` - static policy analysis as product surface

- Status: Implemented (2026-07-12)
- Theme: C - Turn verification into product surface
- Effort: L
- Depends on: none
- Feeds: shares its refinement algebra with [FV-D2](FV-D2-predicatelang-bridge.md); customer-visible product feature; findings surface in [FV-C5](FV-C5-proof-coverage-map.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md), [FV-D2](FV-D2-predicatelang-bridge.md), [FV-B3](FV-B3-budget-conservation-law.md)

## Summary

HushSpec policies are the customer's main authored security artifact, and today the only feedback a policy author gets is validation errors and runtime denials. This plan adds `chio policy analyze`: static detection of rule shadowing, unreachable rules, and contradictions, plus policy-diff refinement review ("is the new policy a strict narrowing of the old one?") with a concrete witness input when it is not - the kernel's attenuation question lifted to the policy level. Prior art by name: AWS Zelkova and Cedar's analyzer. The recommended architecture is a self-contained bounded analyzer over the decidable fragment HushSpec actually uses (globs, numeric ranges, booleans, set membership - the same algebra as the kernel's normalized subset checks), with a full SMT backend deferred to an optional feature-gated phase because a z3 binding is a heavy supply-chain dependency for a security product.

## Motivation and evidence

- Policy bugs are silent until they matter. A `tool_access.block` glob that shadows a later `allow`, an egress allowlist entry made unreachable by a broader block pattern, or a "tightening" policy update that accidentally widens a path allowlist are all invisible in review and only observable as production denials (or worse, allows).
- The attenuation question already has kernel-grade machinery one level down: `chio_kernel_core::normalized::NormalizedScope::is_subset_of` and its grant-level siblings are covered, verified symbols (formal/proof-manifest.toml `covered_rust_symbols`, L60-83) [v]. Policy diff review is the same question asked of HushSpec documents, and the analyzer should reuse that normalized subset algebra rather than invent a second one (G4, duplication drift, is the anti-pattern to avoid).
- The conceptual frame is already in the formal tree: formal/lean4/Chio/Chio/Treaty/PredicateLang.lean defines a Cedar-style syntactic `Predicate` ADT with `denote` and a decidable `refinesOn` (L44-51, L67-73, L81-82, verified this session), explicitly so refinement is decidable on syntax rather than closures. The analyzer's rule-relation lattice is the Rust-side cousin of that algebra, and FV-D2's bridge theorem work will want the two to agree.
- Product surface (Theme C): a customer can gate their own CI on `chio policy analyze` exit codes. Verification tooling the customer runs is worth more than verification prose the customer reads.

## Current state

Grounded in chio-policy source, verified this session:

- `HushSpec` (crates/guards/chio-policy/src/models.rs:45-61): `hushspec` version string, optional `name`/`description`/`extends`/`merge_strategy`, `rules: Option<Rules>`, `extensions`, governance `metadata`. `HushSpec::parse` (L65) is the hardened YAML entry point.
- `Rules` (crates/guards/chio-policy/src/models/rules.rs:37-66) carries 14 optional rule blocks, inventoried in `RULE_BLOCK_NAMES` (L18-33): forbidden_paths, path_allowlist, egress, secret_patterns, patch_integrity, shell_commands, tool_access, computer_use, remote_desktop_channels, input_injection, browser_automation, code_execution, velocity, human_in_loop.
- Representative block shapes (same file): `EgressRule { enabled, allow: Vec<String>, block: Vec<String>, default: DefaultAction }` (L134-143); `ToolAccessRule { enabled, allow, block, .. }` (L194+); `PathAllowlistRule { read, write, patch }` (L121-130); `ForbiddenPathsRule { patterns, exceptions }` (L110-117); `PatchIntegrityRule { max_additions, max_deletions, forbidden_patterns, require_balance, max_imbalance_ratio }` (L166-181). The fragment is: glob/pattern lists, allow/block pairs with a `DefaultAction`, numeric bounds, and booleans.
- Compilation: `compile_policy` / `compile_policy_with_source` (crates/guards/chio-policy/src/compiler.rs:85, 91) validate then materialize up to 12 guard types into a `CompiledPolicy { guards: GuardPipeline, post_invocation, default_scope: ChioScope, guard_names }` (L61-77). `GuardPipeline` holds boxed opaque guards - useless as an analysis IR, which is why the analyzer needs its own.
- Evaluation semantics to respect: `evaluate` (crates/guards/chio-policy/src/evaluate/engine.rs:5-54) dispatches on `action_type` and denies fail-closed for unknown action types (L44-53); `evaluate_with_context` (L57) rejects unknown condition keys fail-closed (L87-97). Matching lives in evaluate/matchers.rs. Deny dominates allow within a block (block list consulted against allow list with the block winning), and the per-block `default` decides the no-match case.
- Fuzzing already exercises parse/validate/compile with structured `Arbitrary` input plus YAML roundtrip via `fuzz_policy_parse_compile` [v] - the analyzer gets a corpus of weird-but-valid policies for free.
- `crates/guards/chio-policy/src/analyze/` now owns rule-to-rule relations,
  total lowering, bounded refinement, and evaluator-confirmed witnesses. The
  public command is documented in `docs/reference/POLICY_ANALYSIS.md`.

## Design

### Analysis IR

A purpose-built IR, not `CompiledPolicy`: each rule block lowers to a set of `RuleAtom`s:

```rust
pub struct RuleAtom {
    pub block: &'static str,        // one of RULE_BLOCK_NAMES
    pub index: usize,               // position within its list
    pub effect: AtomEffect,         // Allow | Deny
    pub matcher: AtomMatcher,       // the decidable constraint
    pub provenance: RuleRef,        // block + field + list index, for findings
}

pub enum AtomMatcher {
    Glob(GlobPattern),              // paths, tools, egress hosts
    NumericRange { lo: Option<u64>, hi: Option<u64> },
    BoolFlag(bool),
    SetMember(BTreeSet<String>),
}
```

plus the block's `DefaultAction` as an explicit bottom atom. Lowering is total over the 14 blocks; blocks with no analyzable content (for example regex-valued `secret_patterns`) lower to opaque atoms that the analyzer reports as "not analyzed" instead of silently skipping - fail-closed reporting.

### Pairwise rule relations (phase 1 capabilities)

For each block, compute the relation between every atom pair over the decidable fragment: `Disjoint`, `Equal`, `SubsetOf`, `SupersetOf`, `Overlapping`. Glob-vs-glob subset/overlap for the HushSpec glob dialect is decidable via product construction on the two patterns (bounded; the dialect has `*`, `**`, `?`, and literals). Evaluation, compilation, and analysis share one glob tokenizer, so the analyzer does not carry a lookalike dialect. Findings derived:

- Shadowed rule: atom B can never fire because an earlier-or-dominating atom A with a different effect covers it (given the engine's deny-dominates order).
- Unreachable rule: atom B is covered by same-effect atoms, so removing it changes nothing.
- Contradiction: allow and block entries with `Equal` matchers in one block; or a block whose entries cover the universe while `default` differs, making `default` dead.
- Not-analyzed notice: every opaque atom, so the report's coverage is explicit.

### Policy-diff refinement (phase 2)

`chio policy analyze --against old.yaml new.yaml` answers whether every input admitted by `new` is admitted by `old`. Per block, it computes the admitted set relation using the same pairwise algebra. When refinement fails, it emits a concrete tool name, path, or host admitted by `new` and denied by `old`, constructed from the glob product automaton's distinguishing path. This is the attenuation question (`NormalizedScope::is_subset_of`) lifted to policy documents. The implementation does not call the normalized scope helper because HushSpec supports `**` and `?`, while capability grants have a different wildcard language. It uses one exact product construction for both pairwise relations and policy witnesses, then confirms every widening witness through `evaluate`. Conceptually this is `refinesOn` from PredicateLang.lean with the sample quantifier replaced by the decidable fragment's exact relation.

### Lean algebra handoff

The Lean algebra is not a production wire format. It is a tagged `Predicate`
enum with `atom`, `top`, `bot`, `conj`, `disj`, and `neg`, evaluated over an
`AdmissionView` projection of `TreatyScope`, `LadderIntersection`,
`BilateralInvocation`, evidence, verifier-owned expected hashes, mode, time,
and joint policy state. `AtomTag` names the modeled runtime gates: current
schemas, treaty freshness, scope/intersection agreement, intersection binding,
invocation binding, allowed action class, signer pair, continuation binding,
required evidence presence and verification, joint policy allow, and a mode
floor. `.unsupported` has no denotation.

The fail-closed contract is two-stage. `supported` rejects any syntax tree
containing an unsupported atom before Boolean connectives run. `defined`
rejects a tree when a required projected value is unavailable. This means
neither `.neg (.atom (.unsupported name))` nor a negated mode predicate with an
unknown mode can produce allow.

Refinement completeness is intentionally domain-scoped:

```
refinesOnConstitution new old domain = true <->
  forall input, input in domain -> admits new input -> admits old input
```

The policy analyzer must not reinterpret this as global completeness from a
sample. Its direct glob/set/range relation can issue a global refinement result
only when that relation is exact for every analyzed atom. Opaque or unsupported
matchers produce an indeterminate result. If the analyzer serializes a future
shared predicate shape, its parser must reject unknown variants before
negation, and its witness domain must be named in any finite decision.

Two `abstraction_anchor` mirror entries bind the Lean projection to the exact
Rust record and validator symbols. They are drift tripwires, not semantic
equivalence evidence and not permission to call the Lean shape serialized
production policy.

### Why not SMT first

A z3 (or cvc5) binding is the standard route (Zelkova, Cedar both went semantic). Weighed honestly:

- Cost: z3-sys drags a large C++ codebase into the dependency tree of a security product with cargo-vet/deny discipline; auditing it is a project in itself, and static-linking it into chio-cli bloats the artifact customers are told to trust.
- Benefit today: marginal. The HushSpec fragment above is finite-alphabet globs, integer ranges, booleans, and finite sets - all decidable by direct construction with exact answers and cheap witnesses. SMT earns its keep when regex-valued patterns, arithmetic over budgets, or cross-block condition logic (`when` conditions) enter scope.

Recommendation: phase 1 and 2 are a self-contained bounded analyzer with zero new dependencies. Phase 3 adds an SMT backend behind an off-by-default feature, in a separate crate so the solver never enters the guard crate's dependency tree.

### Crate placement

- Analyzer core: a module inside chio-policy (`crates/guards/chio-policy/src/analyze/`), because it must share the private matcher semantics (evaluate/matchers.rs) and the model types; a sibling crate would either duplicate matching (G4) or force publicizing internals. Note the mutants-lane constraint: chio-policy's evaluate.rs uses `include!` for its submodules, so analyze/ should be real `mod`s to stay mutation-discoverable.
- SMT backend (phase 3): `crates/tooling/chio-policy-smt`, feature-gated, consumed only by chio-cli; never a dependency of guards or kernel crates.
- CLI: a `policy` command family in chio-cli (crates/products/chio-cli/src/cli/), sibling to the existing `trust` family (crates/products/chio-cli/src/cli/trust/, which already hosts receipt list/explain/health subcommands).

### CLI UX and product spec

```
chio policy analyze <policy.yaml> [--against <old.yaml>] [--format table|json] [--fail-on notice|warning|error]
```

- Human output: a findings table (finding id, severity, block, rule reference, one-line explanation, witness when present).
- JSON output, stable schema so customers can diff and gate on it:

```json
{
  "schema": "chio.policy-analysis.v1",
  "policy_sha256": "...",
  "against_sha256": "...",
  "findings": [
    {
      "id": "SHADOW-0001",
      "kind": "shadowed_rule",
      "severity": "warning",
      "block": "egress",
      "rule_ref": { "field": "allow", "index": 4, "pattern": "api.example.com" },
      "message": "never fires: block entry '*.example.com' (index 1) dominates it"
    },
    {
      "id": "REFINE-0001",
      "kind": "refinement_failure",
      "severity": "error",
      "block": "path_allowlist",
      "rule_ref": { "field": "write", "index": 2, "pattern": "/srv/data/**" },
      "message": "new policy admits inputs the old policy denied",
      "witness": { "action_type": "file_write", "target": "/srv/data/x.txt" }
    }
  ],
  "not_analyzed": [
    { "block": "secret_patterns", "field": "patterns", "reason": "regex-valued" }
  ],
  "summary": { "errors": 1, "warnings": 1, "notices": 0 }
}
```
- Exit codes, fail-closed: 0 = clean at the configured threshold; 1 = findings at or above threshold; 2 = the policy failed to parse or validate, or an internal analyzer error. Unparseable input is never exit 0, so `chio policy analyze` can sit directly in a customer CI job.
- Performance envelope: pairwise analysis is O(n^2) in atoms per block with a glob-product check per pair. The 1,000-literal fast path targets under 1 second. Aggregate matcher-comparison, finding, alphabet-construction, automaton-state, automaton-transition, and evaluator-confirmation budgets stop mixed-effect or wildcard inputs before quadratic work or output expands; exhaustion exits 2 rather than silently sampling. Finite action domains use exact set relations before production-evaluator confirmation.
- Findings-to-receipts mapping: the JSON report's `policy_sha256` matches the policy hash recorded in receipts, so a finding can be joined to the receipts issued under that exact policy; `--emit-attestation` (later) can wrap the report in a signed statement for governance workflows (the `GovernanceMetadata` fields `policy_version`, `approved_by` already exist in models.rs).

## Implementation plan

1. Phase 1 - IR and pairwise rule relations (shadow/unreachable/contradiction). Implemented.
   - Add `crates/guards/chio-policy/src/analyze/mod.rs`, `analyze/ir.rs` (lowering from `HushSpec`/`Rules`), `analyze/glob.rs` (product-construction subset/overlap for the matcher dialect), `analyze/report.rs`, and `analyze/tests.rs`.
   - Modify `crates/guards/chio-policy/src/lib.rs` to export the analyze API.
   - Add CLI wiring in `crates/products/chio-cli/src/cli/dispatch/policy_analysis.rs` and modify the chio-cli command tree registration.
   - Seed tests from the policy fuzz corpus and hand-written shadowing/unreachable fixtures.
2. Phase 2 - policy-diff refinement verdicts with witnesses. Implemented.
   - Add `analyze/refine.rs` for admitted-set comparison and witness synthesis from the shared glob product automaton, with confirmation through the production evaluator.
   - Add golden fixtures: policy pairs with known refine/not-refine verdicts and expected witnesses.
3. Phase 3 - optional SMT backend for the general fragment. Deferred by decision.
   - Add `crates/tooling/chio-policy-smt` (feature `smt` in chio-cli only): encodes regex-valued patterns and `when`-condition logic; cargo-vet/deny entries and a supply-chain review gate land in the same change.
   - Cross-check mode: on the decidable fragment, run both backends and fail on disagreement (the bounded analyzer becomes the oracle for the SMT encoding, in the diff-test spirit).

## CI and gating changes

- Analyzer unit and fixture tests join the normal PR `cargo test` surface.
- Add a repo self-check: run `chio policy analyze` over the in-tree example/fixture policies (rulesets shipped with chio-policy) in the PR job; findings at or above `warning` fail. This makes the repo the first customer.
- The `policy_analyze` fuzz target takes structured and raw HushSpec pairs,
  exercises bounded analyzer totality, and confirms every widening witness
  against the production evaluator.
- A future phase 3 `smt` feature remains excluded from default builds and
  requires a scheduled compile and cross-check lane when introduced.

## Acceptance criteria

- [x] Lowering is total over all 14 `RULE_BLOCK_NAMES`, with opaque atoms reported as not-analyzed (never silently dropped).
- [x] Shadowed, unreachable, and contradictory rules are detected on fixture policies with zero false positives on the shipped ruleset corpus.
- [x] Glob relation decisions match evaluate/matchers.rs semantics on a differential test (relation says SubsetOf implies every sampled match of A matches B).
- [x] `--against` produces refine/not-refine verdicts, and every not-refine verdict carries a witness that the real `evaluate` confirms (admitted by new, denied by old).
- [x] JSON schema `chio.policy-analysis.v1` is stable and documented; exit codes are fail-closed (parse failure is never 0).
- [x] A 1,000-literal policy analyzes in under 1 second, and mixed-effect wildcard and literal stress cases exhaust aggregate budgets in under 1 second on the CI runner class.
- [x] The `smt` feature is absent from default dependency trees (`cargo tree` check in CI).
- [x] Repo self-check lane runs the analyzer over in-tree policies.

## Risks and mitigations

- Analyzer disagrees with engine semantics (the fatal risk: a "refines" verdict the engine falsifies). Mitigations: evaluation, compilation, and analysis share one glob tokenizer; differential tests compare the relation engine with the real matcher; the witness-execution check closes the loop through `evaluate` itself; the fuzz target asserts witness validity continuously.
- Glob-product and pairwise blowup on pathological patterns (many `**` or repeated conflicts). Mitigations: aggregate comparison, finding, alphabet-work, evaluator-confirmation, product-state, and transition caps terminate analysis with exit code 2 instead of returning a partial verdict; the regex_safety.rs precedent in chio-policy shows the house style for bounding pattern cost.
- False-positive fatigue makes customers ignore findings. Mitigations: severity tiers with `--fail-on`; `Overlapping` (ambiguous) findings default to notice, only provable `Equal`/`SubsetOf` shadowing is warning-or-error.
- Supply-chain pressure to ship SMT early. Mitigation: the phase gate is explicit - z3 enters only behind a non-default feature in a non-guard crate with vet/deny entries reviewed, mirroring the repo's existing cargo-vet human-gate discipline.
- Semantics drift as new rule blocks land. Mitigation: `RULE_BLOCK_NAMES` is the lockstep inventory (models/rules.rs:16-18 comment); a unit test asserts the analyzer's lowering covers every name so a new block breaks the build until handled.

## Decisions

- Analyze merged effective policies because those are the documents consumed
  by the evaluator. Source documents are limited to 4 MiB and inheritance is
  limited to 32 documents.
- Treat conditions, regexes, stateful guards, and guard-only predicates as
  opaque. They appear in `not_analyzed`; a changed opaque field makes policy
  comparison inconclusive rather than successful.
- Use boundary values for supported numeric witnesses. Witness payloads carry
  optional `args_size` and `content` fields alongside the target string.
- Keep treaty embedding and signed analysis attestations outside this command.
  The report is deterministic JSON but is not itself a signed artifact.
- Keep the command focused on rule relations and refinement. Lifecycle and
  metadata linting remain separate concerns.
- Do not add an SMT dependency. The direct analyzer decides the current
  bounded fragment with no solver supply-chain addition. A future general
  backend requires a separate dependency and cross-check review.

## Manifest and registry updates

- formal/proof-manifest.toml: no change in phases 1-2 (the analyzer is tooling, not proof evidence). If phase 3's cross-check lane becomes a gate, add it to `gate_commands`.
- formal/theorem-inventory.json: not applicable now; FV-D2 owns the Lean-side refinement entries and should cite the analyzer's relation semantics.
- formal/MAPPING.md: includes an informational PredicateLang cross-reference
  to the executable analyzer without adding it to the proof boundary.
- fuzz/target-map.toml and fuzz/owners.toml: register the `policy_analyze`
  target, matcher triggers, and three calibrated seeds.
- crates/guards/chio-policy/mutants.toml: includes the analyzer modules in the
  existing policy mutation surface. The formal model mutation registry and
  its measured inventory are unchanged because no proof-model source changed.
- docs/reference/CLAIM_REGISTRY.md: registers `POLICY-ANALYZE` as
  `approved_with_scope`, limited to bounded static analysis and
  evaluator-confirmed widening witnesses. It does not license the phrase
  "formally verified policy analysis."
