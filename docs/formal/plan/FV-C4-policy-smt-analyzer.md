# FV-C4: `chio policy analyze` - static policy analysis as product surface

- Status: Proposed (2026-07-09)
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
- Nothing anywhere computes rule-to-rule relations or policy-to-policy refinement.

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

For each block, compute the relation between every atom pair over the decidable fragment: `Disjoint`, `Equal`, `SubsetOf`, `SupersetOf`, `Overlapping`. Glob-vs-glob subset/overlap for the HushSpec glob dialect is decidable via product construction on the two patterns (bounded; the dialect has `*`, `**`, `?`, and literals - the same dialect the matchers implement, and the analyzer must link against evaluate/matchers.rs semantics, not a lookalike). Findings derived:

- Shadowed rule: atom B can never fire because an earlier-or-dominating atom A with a different effect covers it (given the engine's deny-dominates order).
- Unreachable rule: atom B is covered by same-effect atoms, so removing it changes nothing.
- Contradiction: allow and block entries with `Equal` matchers in one block; or a block whose entries cover the universe while `default` differs, making `default` dead.
- Not-analyzed notice: every opaque atom, so the report's coverage is explicit.

### Policy-diff refinement (phase 2)

`chio policy analyze --against old.yaml new.yaml` answers: is `new` a strict narrowing of `old`? Per block, compute the admitted set relation using the same pairwise algebra; the policy refines iff every input admitted by `new` is admitted by `old` (deny-side monotonicity: everything `old` denied, `new` still denies). When refinement fails, emit a witness: a concrete synthesized input (tool name, path, or host string) admitted by `new` and denied by `old`, constructed from the glob product automaton's distinguishing path. This is the attenuation question (`NormalizedScope::is_subset_of`) lifted to policy documents, and the implementation reuses the normalized subset helpers where the types line up (tool/resource grants derived from `tool_access` via the compiler's `compile_scope`) instead of duplicating them. Conceptually this is `refinesOn` from PredicateLang.lean with the sample quantifier replaced by the decidable fragment's exact relation - the doc for FV-D2 should cite this section when building its bridge.

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
      "message": "never fires: block entry '*.example.com' (index 1) dominates it",
      "witness": null
    },
    {
      "id": "REFINE-0001",
      "kind": "refinement_failure",
      "severity": "error",
      "block": "path_allowlist",
      "rule_ref": { "field": "write", "index": 2, "pattern": "/srv/data/**" },
      "message": "new policy admits inputs the old policy denied",
      "witness": { "action_type": "file_write", "path": "/srv/data/x.txt" }
    }
  ],
  "not_analyzed": [{ "block": "secret_patterns", "reason": "regex-valued" }],
  "summary": { "errors": 1, "warnings": 1, "notices": 0 }
}
```
- Exit codes, fail-closed: 0 = clean at the configured threshold; 1 = findings at or above threshold; 2 = the policy failed to parse or validate, or an internal analyzer error. Unparseable input is never exit 0, so `chio policy analyze` can sit directly in a customer CI job.
- Performance envelope: pairwise analysis is O(n^2) in atoms per block with a glob-product check per pair; target under 1 second for 1,000 atoms and document a hard cap (`--max-atoms`, default 10,000) beyond which the tool exits 2 rather than silently sampling.
- Findings-to-receipts mapping: the JSON report's `policy_sha256` matches the policy hash recorded in receipts, so a finding can be joined to the receipts issued under that exact policy; `--emit-attestation` (later) can wrap the report in a signed statement for governance workflows (the `GovernanceMetadata` fields `policy_version`, `approved_by` already exist in models.rs).

## Implementation plan

1. Phase 1 - IR and pairwise rule relations (shadow/unreachable/contradiction).
   - Add `crates/guards/chio-policy/src/analyze/mod.rs`, `analyze/ir.rs` (lowering from `HushSpec`/`Rules`), `analyze/glob_rel.rs` (product-construction subset/overlap for the matcher dialect), `analyze/findings.rs`, `analyze/tests.rs`.
   - Modify `crates/guards/chio-policy/src/lib.rs` to export the analyze API.
   - Add CLI wiring: `crates/products/chio-cli/src/cli/policy/mod.rs`, `analyze.rs`; modify the chio-cli command tree registration.
   - Seed tests from the policy fuzz corpus and hand-written shadowing/unreachable fixtures.
2. Phase 2 - policy-diff refinement verdicts with witnesses.
   - Add `analyze/refine.rs` (per-block admitted-set comparison, witness synthesis from the product automaton), reusing `chio_kernel_core::normalized` subset helpers for the scope-shaped blocks via the existing compiler lowering.
   - Add golden fixtures: policy pairs with known refine/not-refine verdicts and expected witnesses.
3. Phase 3 - optional SMT backend for the general fragment.
   - Add `crates/tooling/chio-policy-smt` (feature `smt` in chio-cli only): encodes regex-valued patterns and `when`-condition logic; cargo-vet/deny entries and a supply-chain review gate land in the same change.
   - Cross-check mode: on the decidable fragment, run both backends and fail on disagreement (the bounded analyzer becomes the oracle for the SMT encoding, in the diff-test spirit).

## CI and gating changes

- Analyzer unit and fixture tests join the normal PR `cargo test` surface.
- Add a repo self-check: run `chio policy analyze` over the in-tree example/fixture policies (rulesets shipped with chio-policy) in the PR job; findings above `warning` fail. This makes the repo the first customer.
- Add the analyzer to `fuzz/target-map.toml` triggers for chio-policy paths in a later step (a `policy_analyze` fuzz target taking Arbitrary HushSpec pairs and asserting analyzer totality and witness validity: any produced witness must actually evaluate to admit-in-new/deny-in-old through `evaluate` - an executable soundness check of the analyzer against the real engine).
- Phase 3's `smt` feature is excluded from default builds; a scheduled job compiles and cross-checks it.

## Acceptance criteria

- [ ] Lowering is total over all 14 `RULE_BLOCK_NAMES`, with opaque atoms reported as not-analyzed (never silently dropped).
- [ ] Shadowed, unreachable, and contradictory rules are detected on fixture policies with zero false positives on the shipped ruleset corpus.
- [ ] Glob relation decisions match evaluate/matchers.rs semantics on a differential test (relation says SubsetOf implies every sampled match of A matches B).
- [ ] `--against` produces refine/not-refine verdicts, and every not-refine verdict carries a witness that the real `evaluate` confirms (admitted by new, denied by old).
- [ ] JSON schema `chio.policy-analysis.v1` is stable and documented; exit codes are fail-closed (parse failure is never 0).
- [ ] 1,000-atom policy analyzes in under 1 second on the CI runner class.
- [ ] The `smt` feature is absent from default dependency trees (`cargo tree` check in CI).
- [ ] Repo self-check lane runs the analyzer over in-tree policies.

## Risks and mitigations

- Analyzer disagrees with engine semantics (the fatal risk: a "refines" verdict the engine falsifies). Mitigations: link against the real matchers, never reimplement; the witness-execution check closes the loop through `evaluate` itself; the fuzz target asserts witness validity continuously.
- Glob-product blowup on pathological patterns (many `**`). Mitigations: complexity cap per pair with a fail-closed "not analyzed" finding instead of a wrong answer; the regex_safety.rs precedent in chio-policy shows the house style for bounding pattern cost.
- False-positive fatigue makes customers ignore findings. Mitigations: severity tiers with `--fail-on`; `Overlapping` (ambiguous) findings default to notice, only provable `Equal`/`SubsetOf` shadowing is warning-or-error.
- Supply-chain pressure to ship SMT early. Mitigation: the phase gate is explicit - z3 enters only behind a non-default feature in a non-guard crate with vet/deny entries reviewed, mirroring the repo's existing cargo-vet human-gate discipline.
- Semantics drift as new rule blocks land. Mitigation: `RULE_BLOCK_NAMES` is the lockstep inventory (models/rules.rs:16-18 comment); a unit test asserts the analyzer's lowering covers every name so a new block breaks the build until handled.

## Open questions

- Should `when`-condition filtering (evaluate_with_context, engine.rs:57) be in phase 1 scope as context-conditional atoms, or analyzed pessimistically (conditions treated as opaque, findings marked conditional)?
- Witness synthesis for numeric blocks: is a boundary value (max_additions + 1) an acceptable witness format alongside string witnesses?
- Does refinement across `extends`/`merge_strategy` inheritance chains (models.rs:52-54, merge.rs) analyze the merged effective policy, the delta, or both? (Proposal: merged effective policy, since that is what the engine sees.)
- Should the analyzer verdict for a policy pair be embeddable in the treaty/bilateral flow that PredicateLang models, once FV-D2's bridge lands?
- Is `chio policy analyze` also the home for lints that are not relations (unused profiles, expired `expiry_date` in metadata), or does lint scope dilute the product story?

## Manifest and registry updates

- formal/proof-manifest.toml: no change in phases 1-2 (the analyzer is tooling, not proof evidence). If phase 3's cross-check lane becomes a gate, add it to `gate_commands`.
- formal/theorem-inventory.json: not applicable now; FV-D2 owns the Lean-side refinement entries and should cite the analyzer's relation semantics.
- formal/MAPPING.md: no named-property rows; add an informational pointer from the PredicateLang cross-reference section to `analyze/refine.rs` when phase 2 lands.
- fuzz/target-map.toml and fuzz/owners.toml: add the `policy_analyze` target (crate chio-policy, triggers on `crates/guards/chio-policy/src/analyze/**` and matcher sources, seeds from the policy corpus).
- docs/reference/CLAIM_REGISTRY.md: propose claim `POLICY-ANALYZE` (approved_with_scope): "Chio ships a policy analyzer that decides rule shadowing, unreachability, contradiction, and policy-diff refinement over the decidable HushSpec fragment, with engine-confirmed witnesses for refinement failures." Evidence classes: `differential_test`, `runtime_qualification`. Do not claim "formally verified policy analysis" - no Lean artifact backs the analyzer itself until FV-D2.
