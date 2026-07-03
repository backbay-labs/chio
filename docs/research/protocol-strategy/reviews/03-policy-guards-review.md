# Review 03 - Policy and Guards Cluster

Reviewer: swarm agent 3. Scope: consistency between doc 04
(`04-policy-engine-collaborators.md`), doc 10 (`10-cedar-first-guard.md`),
the cross-references in `00-overview.md` / `00-overview-v2.md`, the latency
cross-link in `16-latency-budget-audit.md`, and the actual policy/guard
machinery in `chio-guards`, `chio-data-guards`, `chio-external-guards`,
`chio-envoy-ext-authz`, `chio-control-plane`, and `chio-core-types`.

## TL;DR

Docs 04 and 10 are unusually well-grounded for a greenfield design.
File:line citations resolve, the `ExternalGuard` machinery exists as
described, and the LOC inventory in doc 10's guard table is dead accurate.
Two real inconsistencies need fixing: (1) `policy_hash` is a `String`
(hex) in `ChioReceiptBody`, not a `[u8; 32]`, which forces doc 04's
"`policy_digest: [u8; 32]` folded into `policy_hash`" claim to specify a
hex-encoding step; doc 15 separately promotes `policy_digest` as its own
`[u8; 32]` core field, and the three docs need to agree on which is
canonical. (2) Doc 04 lists `BedrockGuardrailGuard`/`AzureContentSafetyGuard`
etc. as "already living in the tree" at `chio-external-guards/src/lib.rs:14-39`,
but the lines there are re-exports - the modules themselves are at
`crates/guards/chio-guards/src/external/{bedrock.rs,azure_content_safety.rs,...}`
included via `#[path = ...]` attributes in
`crates/guards/chio-external-guards/src/external/mod.rs:14-23`. Cosmetic, but the
implied home for `cedar.rs` is wrong: it cannot just be dropped at
`chio-external-guards/src/external/cedar.rs` without also wiring it in
`chio-guards/src/external/`.

---

## Guard inventory and ground-truth audit

Doc 10's claim: "~30 guards, only ~6 pure list-and-branch, the rest
journal-stateful or ML/heuristic."

**Count.** `chio-guards/src/lib.rs:83-167` exports ~29 named guard types
(forbidden_path, shell_command, egress_allowlist, path_allowlist,
mcp_tool, secret_leak, patch_integrity, internal_network, agent_velocity,
velocity, data_flow, behavioral_sequence, behavioral_profile,
response_sanitization, advisory + anomaly + data_transfer_advisory,
jailbreak, jailbreak_detector, prompt_injection, computer_use,
input_injection, remote_desktop, embedding_anomaly, browser_automation,
code_execution, content_review, memory_governance, post_invocation
pipeline). `chio-data-guards` adds 4 (`SqlQueryGuard`
(`crates/guards/chio-data-guards/src/sql_guard.rs:29`), result, vector,
warehouse-cost). `chio-external-guards` adds 6 cloud guards
(`BedrockGuardrailGuard`, `AzureContentSafetyGuard`, `VertexSafetyGuard`,
`SnykGuard`, `VirusTotalGuard`, `SafeBrowsingGuard`).

Total is closer to 38-40 named guards. Doc 10's **"~30"** is correct
only if you mean in-process kernel guards. Recommend rewording to
"~30 in-process kernel guards (and ~10 more cloud/data adapters)".

**LOC in doc 10's table.** Spot-checked: `egress_allowlist.rs`=196,
`forbidden_path.rs`=221, `mcp_tool.rs`=429, `path_allowlist.rs`=503,
`shell_command.rs`=815, `internal_network.rs`=452, `patch_integrity.rs`=481,
`code_execution.rs`=401, `browser_automation.rs`=559, `computer_use.rs`=525,
`input_injection.rs`=257, `remote_desktop.rs`=264, `memory_governance.rs`=378,
`content_review.rs`=535, `advisory.rs`=862, `post_invocation.rs`=359. All
sixteen match doc 10 exactly. ML/heuristic bucket LOC also in range.

**List-and-branch vs journal/ML split.** Sampling:

- `EgressAllowlistGuard` (`egress_allowlist.rs:91-110`): glob match on
  allow/block patterns. Pure list-and-branch.
- `ForbiddenPathGuard` (`forbidden_path.rs:94-138`): glob match plus
  three FS canonicalization paths (`normalize_path_for_policy`,
  `..._lexical_absolute`, `..._with_fs`). Confirmed the Cedar `like`
  operator does not cover this.
- `McpToolGuard` (`mcp_tool.rs:118-178`): five boolean predicates.
- `JailbreakDetector` (`jailbreak_detector.rs`, 682 LOC): heuristic +
  statistical + `LinearModel` layered scoring. ML, not policy.
- `ResponseSanitizationGuard` (1608 LOC): entropy + regex redaction.

"~6 pure list-and-branch" is right: egress_allowlist, forbidden_path,
mcp_tool, path_allowlist, internal_network, and arguably code_execution.

---

## Per-claim verification

### Verified

1. **`McpToolGuard`.** `crates/guards/chio-guards/src/mcp_tool.rs`, 429 LOC.
   Policy density description (block precedence, allowlist toggle,
   default action, arg-size cap, enabled flag) accurate at
   `mcp_tool.rs:118-140` and `mcp_tool.rs:154-178`.

2. **`ExternalGuard` trait.** At
   `crates/guards/chio-guards/src/external/mod.rs:119-129`: `name`, `cache_key`,
   `async eval -> Result<Verdict, ExternalGuardError>`. Matches doc 04
   verbatim.

3. **`AsyncGuardAdapter`.** `mod.rs:308-400`. Circuit breaker, TTL
   cache, token bucket, retry-with-jitter. Fail-closed defaults:
   `CircuitOpenVerdict::Deny` at line 136, `RateLimitedVerdict::Deny` at
   line 157, terminal `Verdict::Deny` on permanent-error path at line 396.

4. **`ScopedAsyncGuard` sync bridge.**
   `crates/guards/chio-external-guards/src/lib.rs:35-139`, with `block_on` and
   `block_on_fallback_thread`. Doc 10's `:66-94` citation is correct.

5. **`ChioExtAuthzService`.**
   `crates/protocol/chio-envoy-ext-authz/src/service.rs:39-82`; `EnvoyKernel` at
   line 26-31. "Chio is the PDP" framing in doc 04 line 80-83 correct.

6. **`GuardEvidence`.** `crates/core/chio-core-types/src/receipt.rs:1176`:
   `guard_name: String`, `verdict: bool`, `details: Option<String>`.

7. **Cedar / regorus / openfga-rs crates.** `cedar-policy` 4.10.0
   (2026-04-23), `regorus` 0.10.0, `openfga-rs` 0.1.0 all published.
   `Validator::validate(pset, mode) -> ValidationResult` and
   `ValidationMode::Strict` exist in Cedar 4.10. Doc 10 sketch matches
   the real API.

8. **`add_guard` boot path.**
   `crates/platform/chio-control-plane/src/lib.rs:368`. A failed
   `CedarPolicyGuard::load` returning `Err` short-circuits before
   `add_guard`, so doc 10 section 7's fail-at-load argument holds.

### Partly verified

9. **`PolicyEngineProvider` trait shape consistency between 04 and 10.**
   Field names are identical in both docs (`engine() -> &'static str`,
   `policy_digest() -> [u8; 32]`, `evaluate() -> EngineDecision`,
   `EngineDecision { verdict, decision_id, obligations, diagnostics }`).
   One latent drift: doc 04 (line 311) says the trait "lives in
   `crates/guards/chio-external-guards/src/lib.rs`"; doc 10 (line 226) places
   the concrete `CedarPolicyGuard` at
   `crates/guards/chio-external-guards/src/external/cedar.rs` but does not name
   the trait file. Both consistent, but neither doc notes that the
   cloud guards in `chio-external-guards/src/external/` are actually
   sourced from `chio-guards/src/external/*` via `#[path = ...]`
   attributes in `crates/guards/chio-external-guards/src/external/mod.rs:14-23`.
   A clean `cedar.rs` either needs the same `#[path = ...]` pattern, or
   needs to break the convention. Recommend doc 10 add a one-line note.

10. **Blanket adapter strategy.** Both docs claim a "blanket adapter wraps
    any `PolicyEngineProvider` as an `ExternalGuard`". Doc 04 line 339-343
    sketches the concept; doc 10 line 227-229 repeats it. Neither doc
    writes out the `impl<P: PolicyEngineProvider> ExternalGuard for
    AsAsyncGuard<P>` wrapper. Both leave it implicit. They imagine the
    same code, but neither doc actually pins down where the blanket
    impl lives or how `EngineDecision` is rendered into
    `GuardEvidence.details` JSON. Recommend a 10-line sketch in doc 04
    section "The PolicyEngineProvider trait".

11. **Receipt embedding.** Doc 04 says `engine_id + policy_digest` go
    into `ChioReceiptBody.policy_hash` and `GuardEvidence`. Doc 10 says
    the same. Doc 15 promotes `engine_id`, `policy_digest`,
    `decision_id` to separate current v1 core fields
    (`15-receipt-kind-v1.md`) AND also adds a
    `CedarExtension { engine_version, policy_set_id, policy_digest,
    decision_id, obligations, diagnostics }`
    (`15-receipt-kind-v1.md`). Three real issues:

    - `policy_hash` in `ChioReceiptBody` today is `String`
      (`receipt.rs:123, 168`), a SHA-256 hex string. Doc 04's
      "`policy_digest: [u8; 32]` folded into `policy_hash`" assumes
      either hex-encoding before fold or a type change. Doc 04
      should say "hex-encoded".
    - Doc 15 type for `policy_digest` is `[u8; 32]`, matching doc 04's
      trait return type. Consistent with doc 04 and doc 10. Good.
    - `CedarExtension.policy_digest` in doc 15 is partly redundant with
      the v3 core `policy_digest`. Doc 15 section "Open questions"
      acknowledges this (line 497-501). Just confirming it crosses
      cleanly.

### Unverified or open

12. **Doc 04 claim that the cloud guards live at
    `chio-external-guards/src/lib.rs:14-39`.** The cited lines are
    re-exports; the actual definitions live at
    `crates/guards/chio-guards/src/external/{bedrock.rs,azure_content_safety.rs,
    vertex_safety.rs,threat_intel/mod.rs}`. Path attribute lines:
    `chio-external-guards/src/external/mod.rs:14-23`. Doc 04 line 67-69
    should be corrected.

13. **"`unwrap_used` / `expect_used` workspace lints".** Doc 04 line 202
    cites these from CLAUDE.md. Confirmed; the lints are deny across the
    workspace per CLAUDE.md house rules. Doc 10 section 8 open question 6
    flags this as a real implementation worry; appropriate.

14. **Tetragon collaboration model.** Doc 04 is honest that this is
    forward-looking and that Tetragon should not be jammed into
    `ExternalGuard`. There is **no existing eBPF or Tetragon code**
    in the tree (grep for `tetragon`, `eBPF` returns no hits in
    `crates/`). Doc 04's analysis is principled speculation and clearly
    labeled as deferred to phase 4. Not a consistency violation; just
    flagging that nothing grounds the eventing model yet.

15. **Voice-tier classification on the policy engine provider.** Doc 14
    and doc 16 propose a voice-tier classification ("in-process Cedar
    OK, OpenFGA remote not"). Doc 04 and doc 10 do not introduce a
    `tier()` method on `PolicyEngineProvider`. Doc 04 section "Phased
    rollout" (line 386-395) discusses transport latency per engine but
    does not bind it to the trait. This is a **forward open question
    not addressed in doc 04 or doc 10**. Recommend doc 04 add either a
    `fn tier(&self) -> PolicyTier { Voice | Standard | Hybrid }` method
    or a constant on the provider type, so registration code can refuse
    OpenFGA on a voice-tier bridge at load time. Cross-link with doc 16
    line 168 ("Voice tier: ... Cedar OK ... No OpenFGA").

16. **`chio-envoy-ext-authz` as gRPC interceptor reuse.** Doc 04 line 77-83
    describes ext_authz as "the Chio service Envoy calls" (PDP role).
    That is correct. Doc 06 separately claims this transparently covers
    QUIC and gRPC. The `ChioExtAuthzService` is a Tonic service, not a
    Tonic interceptor: it implements the
    `envoy.service.auth.v3.Authorization` proto service
    (`service.rs:51-82`). Wrapping it as a Tonic interceptor on the
    server side is possible but undesigned. Doc 06's claim therefore
    needs a small qualifier; doc 04 itself is fine.

---

## Inconsistencies between doc 04 and doc 10

1. **Hex vs bytes for `policy_digest`.** Doc 04 line 322 declares
   `fn policy_digest(&self) -> [u8; 32]`. Doc 04 line 350 then says
   that digest goes into `ChioReceiptBody.policy_hash`, which is
   actually `String` in the live receipt body (`receipt.rs:168`).
   Doc 10 inherits this and is silent on the encoding step. **Fix:**
   doc 04 should state the digest is hex-encoded when written into
   `policy_hash` (which is what doc 15 implicitly assumes by promoting
   the typed `[u8; 32]` field as a parallel artifact).

2. **Location of the new trait and the Cedar guard.** Doc 04 line 311
   places `PolicyEngineProvider` in
   `chio-external-guards/src/lib.rs`. Doc 10 line 226 places
   `CedarPolicyGuard` in `chio-external-guards/src/external/cedar.rs`.
   Today, `chio-external-guards/src/external/` is mostly re-exports
   from `chio-guards/src/external/*` with `endpoint_security.rs` as the
   only original module. Either doc 10 should follow the existing
   pattern (file at `chio-guards/src/external/cedar.rs` plus a
   `#[path = ...]` re-export) or doc 04 should explicitly call out a
   convention break.

3. **Number "~30" in doc 10 vs the actual count.** Doc 10 line 17 says
   "~30 guards"; the actual count across `chio-guards`,
   `chio-data-guards`, and `chio-external-guards` is closer to 38-40.
   Recommend clarify scope.

4. **Default cache TTL.** Doc 04 line 257 suggests 5 s TTL for OpenFGA;
   doc 10 line 300 hardcodes `Duration::from_secs(60)` for the Cedar
   port. Both are reasonable per engine; just note that doc 10 should
   reference doc 04's per-engine TTL table once it exists, so the
   defaults are not implicit per-author choices.

---

## Cross-cluster references

- **C4 (receipt schema, doc 15) agreement.** Field names align:
  `engine_id: String`, `policy_digest: [u8; 32]`, `decision_id: String`,
  `obligations: serde_json::Value`, `diagnostics: Option<String>`.
  The only friction is the `policy_hash` (existing `String`) vs the new
  v3 `policy_digest: [u8; 32]` (typed). Recommend doc 15 explicitly
  note that the v3 `policy_digest` is the canonical byte form and that
  v2 `policy_hash` becomes hex of the same bytes.
- **C2 (latency, doc 16) agreement.** Doc 16 line 180-196 reconciles doc
  04 line 200-201 ("sub-microsecond" optimism) with realistic Cedar
  benchmarks (30-80 us). Doc 04 should be softened to "tens of
  microseconds" or just point at doc 16 line 195
  ("`< 150 us` after warmup").
- **C5 (voice / E3 bridge).** Voice tier classification is unaddressed
  in doc 04 and doc 10; both should add a forward-link to doc 14 and
  doc 16's tier scheme so the next iteration of `PolicyEngineProvider`
  carries a tier method.

---

## Recommended edits

### Doc 04

- Line 67-69: replace `chio-external-guards/src/lib.rs:14-39` with the
  actual definition sites in `chio-guards/src/external/` and the
  `#[path = ...]` line range in `chio-external-guards/src/external/mod.rs`.
- Line 322 + 350-356: explicitly state that
  `policy_digest: [u8; 32]` is hex-encoded when folded into the
  current v2 `policy_hash: String`; cross-reference doc 15 for the
  v3 typed `policy_digest`.
- Add a 10-line blanket-adapter sketch in section "The
  `PolicyEngineProvider` trait" so the implementation contract with
  `AsyncGuardAdapter` is unambiguous.
- Add a `fn tier(&self) -> PolicyTier` (or equivalent constant) on
  the trait, with `Voice` / `Standard` / `Hybrid` variants, cross-
  linking doc 16 line 165-172.
- Soften the "sub-microsecond" line at 200-201 to "tens of microseconds
  for small policysets per doc 16".

### Doc 10

- Line 17 + table heading: clarify the "~30 guards" scope ("~30
  in-process kernel guards; cloud and data guards add roughly 10
  more").
- Line 226: state the convention for where `CedarPolicyGuard` lives -
  either follow the `#[path = ...]` re-export pattern used by the
  existing cloud guards or note the convention break.
- Section 3.4: ensure `policy_digest` rendering uses hex when
  written into `GuardEvidence.details` or `policy_hash`; spell out
  the encoding.
- Section 6: add explicit cross-reference to doc 15's v3 core
  `policy_digest: [u8; 32]` and reconcile redundancy with
  `CedarExtension.policy_digest`.
- Section 8 open question 1: cite the actual Cedar 4.10
  `ValidationResult::validation_passed` (and successor) so the next
  implementer knows the API surface.

### Overviews

- `00-overview.md` line 37: the bullet says `policy_hash` /
  `GuardEvidence` at `receipt.rs:159` - `159` is the
  `ChioReceiptBody` struct start, not the `policy_hash` field
  (line 168). Cosmetic but worth fixing to keep the cluster's
  citations exact.
