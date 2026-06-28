# Rust File Decomposition Spec (Chio)

Design spec. Date: 2026-06-26. Status: proposed (awaiting owner approval).

This spec defines how Chio breaks down its oversized hand-maintained Rust files
so that every production module lands under a 1,200-line soft target (2,000 hard
ceiling; 1,000 for `lib.rs`). It pairs with the reusable pattern catalog in
`2026-06-26-rust-modularization-patterns.md`: every file below cites a pattern
number from that catalog. The decompositions were derived from a read-only,
first-hand analysis pass over each file (structure, responsibility seams, public
surface, test seam, launch-criticality).

House rules honored throughout: no em dashes; fail-closed (errors deny, invalid
input rejects at load); `unwrap_used`/`expect_used` denied in non-test Rust. Every
split is a behavior-preserving move behind a facade `mod.rs`, proven by the full
test suite plus `scripts/check-rust-file-hygiene.py`.

---

## 1. Goals and non-goals

### Goals
1. Clear the 33-entry hygiene allowlist by splitting the files it waives, not by
   raising caps.
2. Lower the bar repo-wide: add a non-failing WARN tier at 1,200 lines so files
   stop creeping toward the 2,000 hard ceiling.
3. Make each module describable in one sentence (one purpose, clear interface,
   independently testable), which also makes the code easier for agents to edit.
4. Do it without destabilizing PR #937: launch-critical files are sequenced after
   the launch lands.

### Non-goals
- No behavior, protocol, wire, or schema changes. Decomposition commits are pure
  moves plus facade wiring; any real fix is a separate, separately-tested commit.
- No public-path changes. Facades re-export the prior surface verbatim, so callers
  do not change.
- Test-file decomposition is catalogued but out of this execution scope.

## 2. The hygiene gate: today and the change

Today `scripts/check-rust-file-hygiene.py` enforces (FAIL): production <= 2,000,
`src/lib.rs` <= 1,000, tests <= 2,000, with a 33-entry per-file allowlist
(expiring 2026-07-31) for current offenders.

Change: add a non-failing WARN tier so creep is visible without new red CI.
```python
WARN_LIMIT = 1_200        # production WARN (non-failing)
LIB_WARN_LIMIT = 900      # lib.rs WARN (non-failing)
# PRODUCTION_LIMIT = 2_000 / LIB_ROOT_LIMIT = 1_000 stay as hard FAIL
```
The checker prints one `warning:` line per file in the 1,200-2,000 band and a
summary count, so a PR that pushes a file over 1,200 is visible in the log but
does not break CI. As each file below is split under 1,200 its allowlist entry is
removed. No allowlist churn is forced by the WARN tier itself.

## 3. Methodology (per file)

Each split follows the catalog: identify the responsibility tangle, pick the
pattern, move along seams behind a facade `mod.rs` that re-exports the prior
public surface. Done-when, per file: `cargo build --workspace` +
`cargo test --workspace` green, `cargo clippy --workspace -- -D warnings` +
`cargo fmt --all -- --check` green, hygiene check shows the file under target, and
its allowlist entry (if any) is removed. One file per commit; no behavior change
in a decomposition commit.

## 4. Launch-safe sequencing

Three waves. Wave 1 (48 files): non-launch crates, start now. Wave 2 (9 files): PR #937 launch-critical, gated behind the #937 merge. Wave 3 (3 deep + the 1,200-1,500 index tail): opportunistic.

**Wave 2 (gated behind #937 merge):**

- `crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs` (6139)
- `crates/products/chio-cli/src/cli/dispatch/proof.rs` (3349)
- `crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs` (2308)
- `crates/kernel/chio-swarm-authority/src/verifier.rs` (2279)
- `xtask/src/fixtures_facets.rs` (1994)
- `crates/products/chio-cli/src/cli/dispatch/proof/doctor.rs` (1697)
- `crates/products/chio-proof-room/src/source_verifier.rs` (1656)
- `crates/economy/chio-web3/src/settlement_proof.rs` (1632)
- `xtask/src/fixtures.rs` (1603)

## 5. Deep blueprints (files > 1,500 lines)

60 files, grouped by subsystem cluster. Each: current lines, target module tree (pattern #), why, API impact, test seam, wave.

### `cli` (9 files)
_Shared module for this cluster:_ cli_proof_support - shared utilities for proof fixture/verification operations including JSON I/O, hashing, path normalization, signature generation, report formatting, and error code processing used by proof.rs, fixture.rs, and doctor.rs

**`crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs`** - 6139 lines, ~5 modules. Pattern 4 (Generator stages) + 1 Facade tree. Wave 2 (launch-critical).
- Why: Proof fixture generation, enumeration, and normalization tangled with multiple fixture types (commerce passports, disclosure agent-web, disclosure lineage, disclosure BBS material, crypto context, runtime nonces, join receipts) plus manifest/bundle refresh and signature management
- Target tree:
  - `fixture_list` (~450) - Enumerate available fixtures, list fixtures with metadata, query fixture catalog by ID and kind
  - `fixture_generate` (~1200) - Generate a single fixture from template sources; orchestrate fixture creation by kind (commerce passport, disclosure agent-web, recursive runtime swarm)
  - `fixture_normalize` (~2800) - Normalize/transform fixture artifacts post-generation for multiple domains: commerce (mandate projection edges), disclosure (lineage BBS material, agent-web envelope resigning), runtime (nonce reuse, join receipt signing), crypto context signing
  - `fixture_verify` (~650) - Generate proof fixture verification reports; write and embed generated verifier reports; validate fixtures against expected verdicts
  - `fixture_support` (~700) - Shared helpers for fixture operations: path resolution, evidence graph artifact root discovery, file collection, manifest/bundle path handling, JSON read/write, hashing, signing
- API impact: none (facade)
- Test seam: Generate fixture, list fixtures, verify normalization of specific types (commerce_transaction_passport, disclosure_agent_web, runtime_join_receipt)

**`crates/products/chio-cli/src/cli/dispatch/proof.rs`** - 3349 lines, ~4 modules. Pattern 2 (Dispatch split) + 3 Verifier pipeline. Wave 2 (launch-critical).
- Why: Proof subcommand dispatcher mixed with failure code processing utilities (normalization, slug generation, semantic checking, dotted code detection) and verification orchestration (requirement enforcement, claim extraction, family report merging, evidence graph validation, parity checks)
- Target tree:
  - `proof_codes` (~350) - Failure code processing: negative failure code matching, boundary detection, semantic normalization, stable canonicalization, slug generation, dotted code detection, context stripping
  - `proof_verify` (~1100) - Verification orchestration: requirement enforcement (manifest claims, family claims, runtime authority, delegation, runtime parity), report generation, exit code mapping, verify methods for transaction passports
  - `proof_verify_claims` (~550) - Claim extraction and composition: verified claim extraction, family report merging, claim results generation, provenance attribution, checker mapping for claims
  - `proof_evidence_graph` (~700) - Evidence graph operations: standalone artifact indexing, runtime parity evidence graph loading, regeneration hash validation, artifact byte loading from graph
- API impact: none (facade) - dispatch_proof and dispatch_commerce remain public at mod level
- Test seam: Verify transaction passport with various requirement combinations, test failure code normalization and detection

**`crates/products/chio-cli/src/cli/session.rs`** - 1909 lines, ~5 modules. Pattern 5 (Service-handler). Wave 1.
- Why: Session message handling tangled with capability selection, tool call response generation (streaming support), error receipt generation, and extensive test stubs for multiple tool server types
- Target tree:
  - `session_handler` (~450) - Agent message handling: normalize agent messages to session operations, invoke kernel evaluation, error handling and recovery from kernel evaluation failures
  - `session_capability` (~200) - Capability selection: match request parameters to available capabilities, fallback to first capability if no exact match
  - `session_response` (~350) - Response generation and streaming: construct kernel messages from tool call responses, handle streaming chunks, map verdict to terminal states, collect response metadata
  - `session_errors` (~180) - Error receipt generation: construct signed error receipts when kernel evaluation fails internally, maintain audit trail for denied operations
  - `session_stats` (~100) - Session statistics: track request counts, allow/deny decisions, summary reporting in human and JSON formats
- API impact: none (facade)
- Test seam: Message handling (heartbeat, list_capabilities, tool_call), response mapping for various verdict outcomes, streaming chunks before terminal response

**`crates/products/chio-cli/src/cli/dispatch.rs`** - 1895 lines, ~2 modules. Pattern 2 (Dispatch split). Wave 1.
- Why: Dispatcher has thin routing layer but includes utility functions for binary I/O and JSON formatting alongside command dispatch to 8 subcommands (api_mcp, trust, receipt_evidence, certify, did_passport, proof, workflow, reputation_guard, settle_arena)
- Target tree:
  - `dispatch_main` (~300) - Route to subcommand handlers based on CLI command enum; thin match-only dispatcher
  - `dispatch_utils` (~50) - Shared utilities: write bytes with error context, write pretty JSON line for streaming output
- API impact: none (facade) - run() remains public
- Test seam: Dispatch to each subcommand type with CLI arguments, verify error handling paths

**`crates/products/chio-cli/src/cli/trust/receipt.rs`** - 1874 lines, ~4 modules. Pattern 5 (Service-handler). Wave 1.
- Why: Receipt operations split across list/query, structural analysis/explain, and JSON/human formatting, with multiple receipt arg types and report schemas
- Target tree:
  - `receipt_list` (~500) - List and query receipts: filter by capability, tool, outcome, time range, cost range; pagination with cursor; multi-tenant support
  - `receipt_explain` (~650) - Explain receipt structure: walk evidence graph with depth/fanout limits, bilateral verification with inspection mode, render explanation tree
  - `receipt_format` (~350) - JSON envelope formatting and human-readable output: schema wrapping, receipt operator JSON envelope, writer counter formatting, optional value helpers
  - `receipt_health` (~250) - Receipt store health checks: checkpoint operations, flush operations, writer counter inspection
- API impact: none (facade)
- Test seam: List receipts with various filters, explain receipt structures at different depths, verify JSON envelope schema

**`crates/products/chio-cli/src/main.rs`** - 1755 lines, ~1 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Entry point with distributed module declarations for 12+ CLI subcommands, re-exports for control-plane/kernel/capability types, CLI arg parsing, tracing setup, and test suite for parsing edge cases
- Target tree:
  - `mod` (~1755) - Central module facade: aggregate all CLI subcommand modules, re-export key control-plane types (CliError, policy, build_kernel, etc.), main() entry point
- API impact: none (facade)
- Test seam: CLI argument parsing for all command variants, stack size test for large clap AST

**`crates/products/chio-cli/src/guard.rs`** - 1750 lines, ~5 modules. Pattern 5 (Service-handler). Wave 1.
- Why: Guard operations mixed across: verification/testing/benchmarking, publishing/registry/credentials, WASM manifest handling, project scaffolding with templates, and utility formatting functions
- Target tree:
  - `guard_verify` (~280) - Guard evaluation and testing: execute guards, check verdicts, fixture-based testing, test result aggregation
  - `guard_publish` (~480) - Publishing and registry: publish artifacts, registry client interaction, credentials handling, signer key resolution, package signing
  - `guard_build` (~350) - WASM building and manifest validation: pack WASM from directory, compute and validate SHA256, manifest path updates, Wasm manifest parsing
  - `guard_new` (~280) - Project scaffolding: create new guard project, write Cargo.toml template, src/lib.rs template, manifest.yaml template, sanitize package names
  - `guard_format` (~130) - Formatting utilities: format byte sizes, durations, numbers; percentile/mean calculation for benchmarks
- API impact: none (facade) - public entry points: cmd_guard_new, cmd_guard_test, cmd_guard_publish, cmd_guard_build
- Test seam: Guard verification with test fixtures, project scaffolding, WASM hashing and manifest validation

**`crates/products/chio-cli/src/cli/dispatch/proof/doctor.rs`** - 1697 lines, ~4 modules. Pattern 3 (Verifier pipeline) + 1 Facade tree. Wave 2 (launch-critical).
- Why: Proof doctor diagnostics with multiple scenario types: transaction passport verification, workflow preflight checks, crypto context validation, proof room bundle checks, Docker quickstart evidence, and enterprise export negative cases
- Target tree:
  - `doctor_scenarios` (~750) - Core diagnostic scenarios: transaction passport checks (structure, digest, validity), workflow preflight checks (fixture expectations), single-call-authority scenario, and scenario orchestration
  - `doctor_enterprise` (~280) - Enterprise export diagnostics: check exported negative cases, verify fixture component safety, read and validate enterprise export negative case metadata
  - `doctor_docker` (~320) - Docker quickstart checks: verify Docker endpoints (manifest, fixtures, UI static files), fetch and parse evidence, validate quickstart bundle integrity
  - `doctor_checks` (~220) - Shared check utilities: passport validity, policy digest validation, terminal receipt checks, verifier report validation, schema file checking, passed/failed check reporting
- API impact: none (facade) - run_proof_doctor() remains public
- Test seam: Run doctor for each scenario type (transaction_passport, workflow_preflight, single_call_authority), verify check pass/fail reporting

**`crates/products/chio-cli/src/cli/chio/dispatch/pheromone/assurance.rs`** - 1605 lines, ~4 modules. Pattern 4 (Generator stages) + 5 Service-handler. Wave 1.
- Why: Relay alert assurance operations mixed across: packaging/assembling alert reports, archive export/restore, package verification, and report I/O parsing (multiple relay report types)
- Target tree:
  - `assurance_package` (~380) - Alert assurance packaging: assemble package from multiple input reports (alert, trend, handoff, normalization, delivery, acknowledgement, drift), generate package, export package with field preservation
  - `assurance_archive` (~450) - Archive operations: export assurance archive, restore archive from package, verify archive integrity and sidecar reports, write verified archive
  - `assurance_reports` (~400) - Report parsing and loading: read relay report documents from disk, find reports by canonical hash, parse archive restore input reports, validate report format and schema
  - `assurance_support` (~300) - Shared I/O and utilities: sorted file enumeration, trusted packager resolution from signing key, archive limits configuration, file name suffix matching
- API impact: none (facade) - public entry points: cmd_chio_pheromone_relay_alert_assurance_package, cmd_chio_pheromone_relay_alert_assurance_export, etc.
- Test seam: Package creation from reports, archive export/restore round-trip, report sidecar verification

### `chio-transaction-passport` (1 file)
**`crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs`** - 2308 lines, ~11 modules. Pattern 1 (Facade tree) + 3 Verifier pipeline. Wave 2 (launch-critical).
- Why: Tangled responsibilities: (1) 16 artifact data types with schemas (355 lines), (2) 15 independent validator functions each with its own signature verification and body construction helpers (1600+ lines), (3) trust root validation logic shared across lease/policy/sandbox/attestation (150+ lines), (4) utility helpers for parsing/validation (150+ lines)
- Target tree:
  - `mod.rs` (~60) - Facade module: re-exports all public validators and types (ExecutionLeaseContext, all Runtime* types, all validate_* functions) so callers importing from artifacts:: do not change
  - `schemas.rs` (~355) - All data type definitions: 16 pub(super) struct (RuntimeExecutionLease, RuntimeRequestDigest, RuntimePolicyActivationReceipt, RuntimeAttackSimulationReport, RuntimeChaosRunReport, RuntimeRoutePlanReceipt, RuntimeTaskGraph, RuntimeBudgetPool, RuntimeJoinReceipt, RuntimeTrustRoot, RuntimeRevocationFreshnessProof, RuntimeSandboxAttestation, RuntimeToolServerAck, RuntimeTrustedTimeProof, RuntimeTerminalReceipt, ExecutionLeaseContext) + private nested types + 11 const schema strings
  - `execution_lease.rs` (~530) - Execution lease validation pipeline: validate_execution_lease + validate_execution_lease_context (core flow checks, field validation, digest binding, budget allocation, join receipt, route plan binding); validate_request_digest_binding; verify_execution_lease_signature + verify_task_graph_signature + verify_join_receipt_signature; RuntimeExecutionLeaseSignatureBody construction; validate_execution_lease_trust_root + ensure_runtime_identity_is_trusted + validate_trust_root + ensure_runtime_trust_root_signer_is_pinned + verify_runtime_trust_root_signature (trust chain verification shared across lease/policy/sandbox)
  - `policy.rs` (~100) - Policy activation receipt validation: validate_policy_activation_receipt (schema, field validation, policy digest check, activation mode/direction validation, trust verification); verify_policy_activation_receipt_signature + RuntimePolicyActivationReceiptSignatureBody construction
  - `reports.rs` (~150) - Attack simulation and chaos run report validation: validate_attack_simulation_report (expected denial claim, fixture path, report digest matching); validate_chaos_run_report (case id, attack class support); verify_attack_simulation_report_signature + verify_chaos_run_report_signature; signature body construction for both report types
  - `route_plan.rs` (~130) - Route plan receipt validation: validate_route_plan_receipt (schema check, field validation, task id binding); verify_route_plan_receipt_signature + RuntimeRoutePlanReceiptSignatureBody construction
  - `freshness.rs` (~150) - Revocation freshness proof validation: validate_revocation_freshness (proof id binding, epoch matching, capability digest matching, staleness check); validate_revocation_freshness_at_ack (freshness boundary verification); verify_revocation_freshness_signature + RuntimeRevocationFreshnessSignatureBody construction
  - `attestation.rs` (~130) - Sandbox attestation validation: validate_sandbox_attestation (attestation id binding, tool server/instance/manifest binding, sandbox lifecycle vs lease lifetime check, attester trust); verify_sandbox_attestation_signature + RuntimeSandboxAttestationSignatureBody construction
  - `tools.rs` (~150) - Tool server ack and trusted time proof validation: validate_tool_server_ack (lease/sandbox binding, terminal status check, nonce match); validate_trusted_time_proof (schema/field validation, trust verification); verify_tool_server_ack_signature + verify_trusted_time_proof_signature; signature body construction for both
  - `terminal.rs` (~150) - Terminal receipt and claim validation: validate_terminal_receipt (schema, field validation, issuer trust, terminal status checks, nonce matching); validate_nonce_uniqueness (dedup check); validate_allow_receipt (receipt totality check); verify_terminal_receipt_signature + RuntimeTerminalReceiptSignatureBody construction; ensure_runtime_public_key_is_trusted helper
  - `helpers.rs` (~150) - Cross-cutting utility functions: self_certifying_public_key (DID parsing); parsing functions (parse_rfc3339_utc); validation functions (validate_digest_field, require_non_empty, validate_* predicates); predicate functions (is_terminal_receipt_status, is_supported_attack_class, is_supported_chaos_case, is_governed_side_effect_class, is_lower_hex_byte)
- API impact: none (facade)
- Test seam: Each module exports its primary public validator (validate_execution_lease, validate_policy_activation_receipt, etc.) which can be unit-tested independently with mock trust roots, signature verification stubs, and artifact fixtures. Integration tests in parent runtime_security module drive complete validation pipelines.

### `chio-swarm-authority verifier pipeline decomposition` (1 file)
**`crates/kernel/chio-swarm-authority/src/verifier.rs`** - 2279 lines, ~9 modules. Pattern 1 (Facade tree) + 3 Verifier pipeline. Wave 2 (launch-critical).
- Why: Monolithic verifier orchestrator mixing: (1) signing/minting API (8 pub fn sign_*, 2 pub fn mint_*), (2) budget operations (2 pub fn reserve/release), (3) main orchestrator (1 pub fn verify_swarm_authority_bundle), (4-10) seven independent validation stages (task graph structure, route plan receipts, join receipt logic, budget pool accounting, revocation epoch revocation state, terminal graph completion, continuation token freshness), each with multiple private validators.
- Target tree:
  - `verifier/mod.rs (facade)` (~180) - Public API re-exports; main verification orchestrator verify_swarm_authority_bundle; orchestration helpers swarm_authority_hop_reports, require_signed_swarm_delegation_evidence, require_trusted_witness_issuer_keys; delegates to stage modules.
  - `verifier/signer.rs` (~310) - Cryptographic signing and token minting: sign_swarm_delegation_witness_hop, sign_swarm_task_graph, sign_swarm_continuation_token, mint_swarm_continuation_token, sign_swarm_join_receipt, mint_swarm_join_receipt, sign_swarm_route_plan_receipt, sign_swarm_revocation_epoch, sign_swarm_terminal_graph_receipt. All 10 pub fn signers/minters.
  - `verifier/budget.rs` (~140) - Budget fanout/fanin operations and validation: reserve_swarm_budget_fanout (pub), release_swarm_budget_fanin (pub), validate_budget_pool, validate_budget_allocation_units (private). Accounts for unit state transitions.
  - `verifier/graph.rs` (~350) - Task graph structural validation: validate_task_graph orchestrator, verify_task_graph_signature, ensure_task_graph_issuer_is_pinned, task_index, edge_set, validate_roots, validate_edges, validate_edge_depths, validate_graph_limits, validate_joins, validate_route_refs, validate_acyclic, visit_task (DFS cycle detection). Ensures DAG structure and constraints.
  - `verifier/route.rs` (~200) - Route plan receipt validation: validate_route_plan_receipts, validate_route_plan_egress_constraints, validate_route_plan_target (bridge/protocol/egress matching), verify_route_plan_signature, ensure_route_plan_issuer_is_pinned. Verifies egress policy and bridge consistency.
  - `verifier/join.rs` (~320) - Join receipt validation: validate_join_receipts, validate_join_receipt_schema, validate_join_predicate (all_success/any_success/quorum), validate_join_parent_task_receipts, validate_actual_parent_receipt_subset, expected_actual_parent_receipt_pairs, join_parent_set_hash, join_parent_set_hash_from_parts, verify_join_receipt_signature, ensure_join_issuer_is_pinned. Handles join consensus logic.
  - `verifier/revocation.rs` (~140) - Revocation epoch validation: validate_revocation_epoch (checks subjects and tasks are not revoked), verify_revocation_epoch_signature, RevocationEpochListRoot struct, revocation_epoch_list_root_hash. Ensures authority and subject validity.
  - `verifier/terminal.rs` (~280) - Terminal graph receipt validation: validate_terminal_graph_receipts orchestrator, validate_terminal_graph_receipt_schema, validate_terminal_graph_receipt_refs (task/join/route set completeness), BudgetRollupTotals struct + impl, validate_terminal_budget_rollups (dimension-wise rollup checking), totals_from_rollup, verify_terminal_graph_receipt_signature, ensure_terminal_receipt_issuer_is_pinned. Verifies graph completion.
  - `verifier/continuation.rs` (~390) - Continuation token validation: ContinuationValidationContext struct, validate_continuation_tokens orchestrator, validate_continuation_token, validate_continuation_witness_chain (binding check), validate_continuation_parent (single parent or join), validate_continuation_route, validate_continuation_budget (allocation state), verify_continuation_token_signature, ensure_continuation_issuer_is_pinned. Validates token freshness and parent/route/budget consistency.
- API impact: none (facade)
- Test seam: Unit tests per stage module; integration tests via pub verify_swarm_authority_bundle and pub signer/minter functions; existing AGENTS.md test fixtures exercise full orchestrator.

### `pheromone-relay` (3 files)
**`crates/trust/chio-pheromone-relay/src/delivery.rs`** - 1998 lines, ~5 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Tangled responsibilities: public types for delivery pipeline (status enums, profile documents, evidence/result structs, multiple report types, input types), JSON parsing helpers, 6 major evaluation functions (delivery, acknowledgement, handoff drift, normalization, delivery drift, route review), extensive validation functions for profiles/evidence/reports, and mapping/helper utilities for receivers and routes.
- Target tree:
  - `delivery/mod.rs (facade)` (~150) - Re-export all public types and functions from submodules to preserve the public API path
  - `delivery/types.rs` (~320) - All public struct and enum definitions: DeliveryStatus, DeliveryReceiver, DeliveryProfileDocument, DeliveryEvidence, DeliveryResult, DeliveryReport, Acknowledgement, AcknowledgementReport, HandoffDrift, HandoffDriftReport, NormalizationProfileDocument, NormalizationReport, DeliveryDrift, DeliveryDriftReport, RouteOwner, RouteOwnerProfileDocument, RouteReview, RouteReviewPacket, and all input struct types
  - `delivery/evaluators.rs` (~420) - Public evaluation and report generation functions: evaluate_relay_alert_delivery, evaluate_relay_alert_acknowledgement, generate_relay_alert_handoff_drift_report, normalize_relay_alert_delivery_evidence, generate_relay_alert_delivery_drift_report, generate_relay_alert_route_review_packet, plus the relay_alert_*_from_json JSON parsing helpers
  - `delivery/validators.rs` (~520) - Validation functions for profiles, evidence, reports, and review chains: validate_delivery_profile, validate_delivery_evidence_shape, validate_delivery_labels, validate_delivery_handoff_report, validate_delivery_report, validate_delivery_result, validate_route_owner_profile, validate_review_source_chain, validate_normalization_profile, validate_delivery_token, and related internal validators
  - `delivery/helpers.rs` (~300) - Mapping and utility functions: route_owner_map, delivery_receiver_map, handoff_route_map, normalization_receiver_map, and smaller helper functions used by evaluators and validators
- API impact: none (facade)
- Test seam: tests/relay/delivery.rs  -  existing integration tests that verify the pub fn APIs will continue to pass as the facade preserves all public paths

**`crates/trust/chio-pheromone-relay/src/archive/report.rs`** - 1716 lines, ~5 modules. Pattern 1 (Facade tree) + 4 Generator stages. Wave 1.
- Why: Tangled responsibilities: 6 major report generators (archive, closeout, restore drill, physical archive drill, retention handoff, external retention review) spanning ~650 lines; complex external retention review pipeline (~400 lines of external_retention_* helper functions implementing a multi-stage evaluation; extensive validation functions for archive profiles, restore profiles, physical evidence, retention handoff, external retention); and review/status helper functions for quarantine/blocking/state transitions. The external retention review is a distinct generator stage with cross-cutting helpers (status checking, sample coverage, freshness checks).
- Target tree:
  - `archive/report/mod.rs (facade)` (~100) - Re-export all public types and functions from submodules to preserve the public API path under archive::*
  - `archive/report/generators.rs` (~680) - The 6 public report generator functions: generate_relay_alert_assurance_archive_report, generate_relay_alert_assurance_closeout_report, generate_relay_alert_assurance_archive_restore_drill_report, generate_relay_alert_assurance_physical_archive_drill_report, generate_relay_alert_assurance_retention_handoff_report, generate_relay_alert_assurance_external_retention_review_report, plus relay_alert_assurance_external_retention_profile_from_json loader
  - `archive/report/external_retention.rs` (~380) - External retention review pipeline stage: external_retention_check, external_retention_fail (cross-cutting check helpers), external_retention_report_status, external_retention_restore_status (status evaluation), external_retention_physical_reports, external_retention_handoffs (evidence matching), external_retention_sample_coverage, external_retention_fresh (validation helpers for a complex multi-stage evaluation)
  - `archive/report/validators.rs` (~280) - Validation functions for archive/restore/physical/retention: validate_archive_profile, validate_closeout_profile, validate_archive_restore_profile, validate_physical_archive_evidence, validate_retention_handoff_profile, validate_retention_handoff_evidence, validate_external_retention_profile, validate_external_retention_schema_token, validate_archive_candidates, validate_archive_input_roots
  - `archive/report/helpers.rs` (~260) - Review and bundle review helper functions: review_archive_candidate (main bundle review orchestrator), archive_quarantine_review, archive_blocked_review, closeout_review_from_archive (state transition helpers), archive_package_report_integrity_failure, has_matching_physical_readback, has_matching_retention_handoff
- API impact: none (facade)
- Test seam: tests/relay/archive.rs  -  existing integration tests that verify the pub fn APIs will continue to pass as the facade preserves all public paths through archive:: module hierarchy

**`crates/trust/chio-pheromone-relay/src/alerts.rs`** - 1502 lines, ~5 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Tangled responsibilities: 28+ type definitions spanning alert routing (RouteKind, Severity, Route, Rule, RoutingProfileDocument), alert suppression (SuppressionEntry, SuppressionStateDocument), handoff escalation (HandoffSinkKind, HandoffReceiver, HandoffEscalation, HandoffProfileDocument, HandoffRouteReadiness, HandoffReport), alert evaluation (Alert, AlertReport, AlertCheck), trend tracking (TrendPoint, TrendReport), and evaluation input types; 3 major evaluators; 10+ validation functions; and 15+ helper/utility functions for mapping, parsing, and converting.
- Target tree:
  - `alerts/mod.rs (facade)` (~150) - Re-export all public types and functions from submodules to preserve the public API path
  - `alerts/types.rs` (~380) - All public struct and enum definitions: RelayEventReport, RelayAlertRouteKind, RelayAlertSeverity, RelayAlertRoute, RelayAlertRule, RelayAlertRoutingProfileDocument, RelayAlertSuppressionEntry, RelayAlertSuppressionStateDocument, RelayAlertCheck, RelayAlert, RelayAlertReport, RelayTrendPoint, RelayTrendReport, RelayAlertHandoffSinkKind, RelayAlertHandoffReceiver, RelayAlertHandoffEscalation, RelayAlertHandoffProfileDocument, RelayAlertHandoffRouteReadiness, RelayAlertHandoffReport, RelayAlertDrill, RelayAlertDrillReport, and all input struct types
  - `alerts/evaluators.rs` (~280) - Public evaluation and report generation functions: evaluate_relay_alerts, evaluate_relay_alert_handoff, generate_relay_trend_report
  - `alerts/validators.rs` (~480) - Validation functions: validate_alert_profile, validate_alert_route, validate_handoff_profile, validate_handoff_token, validate_handoff_receiver, validate_observability_source, validate_suppression_state, validate_handoff_sources, and related internal checkers
  - `alerts/helpers.rs` (~420) - Mapping and utility functions: alert_route_map, alert_rule_map, handoff_escalation_map, handoff_receiver_route_map, matching_event_evidence, active_suppression_until, alert_labels, bump_trend_point, relay_alert_severity_from_str, is_bounded_code, is_bounded_route_token, validate_handoff_token, and other token/code validation utilities
- API impact: none (facade)
- Test seam: tests/relay/alerts.rs  -  existing integration tests that verify the pub fn APIs will continue to pass as the facade preserves all public paths

### `chio-provider-conformance` (2 files)
**`crates/protocol/chio-provider-conformance/src/replay.rs`** - 1998 lines, ~8 modules. Pattern 2 (Dispatch split) + 4 Generator stages. Wave 1.
- Why: replay.rs tangles provider-specific replay orchestration (OpenAI, Anthropic, Bedrock, Gemini, Mistral, Groq, Ollama, Cohere) with common payload extraction, stream processing, assertion verification, and fixture loading. Each provider has parallel batch/stream replay paths, but cross-cutting utilities (payload parsing, SSE processing, assertions) are inlined.
- Target tree:
  - `fixture` (~420) - Fixture loading, validation, and ProviderCaptureFixture implementation; fixture path functions for all 8 providers; core types ReplayMode and ReplayOutcome
  - `payload` (~280) - Payload extraction helpers (org_id_from_payload, anthropic_workspace_id_from_payload, bedrock_principal_from_payload); response checking functions (response_has_no_tool_calls, anthropic_response_has_no_tool_uses, bedrock_response_has_no_tool_uses, bedrock_content_blocks); header extraction utilities
  - `assert` (~320) - Assertion and verification functions: assert_replayed_invocations, assert_replayed_verdicts, comparable_invocation construction; assert_openai/anthropic/bedrock_lowered_responses; captured_redactions and captured_deny_reason extraction
  - `openai` (~260) - OpenAI-specific replay: replay_openai_fixture, replay_openai_batch, replay_openai_stream; feature-gated entrypoint stubs; lowered response assertion
  - `anthropic` (~330) - Anthropic-specific replay: replay_anthropic_fixture, replay_anthropic_batch, replay_anthropic_stream; anthropic_adapter and anthropic_server_tool_manifest construction; anthropic_tool_result_payload; lowered response assertion
  - `bedrock` (~320) - Bedrock-specific replay: replay_bedrock_fixture, replay_bedrock_batch, replay_bedrock_stream; bedrock_adapter construction; bedrock_tool_result_payload; BedrockFixturePrincipal type; lowered response assertion
  - `stream` (~220) - SSE and stream processing: fixture_sse_bytes, fixture_bedrock_stream_bytes, fixture_ollama_ndjson_bytes; event parsing (event_name, stream_event_item); stream event utilities
  - `mod` (~80) - Facade re-exporting all public replay API: public entry points for all providers, fixture operations, and types; preserves module path
- API impact: none (facade)
- Test seam: Public functions tested via replay module integration tests; test fixtures in crates/protocol/chio-provider-conformance/fixtures/

**`crates/protocol/chio-provider-conformance/src/bin/record.rs`** - 1513 lines, ~10 modules. Pattern 2 (Dispatch split) + 4 Generator stages. Wave 1.
- Why: record.rs (binary) tangles CLI argument parsing, provider-specific recording orchestration (OpenAI, Anthropic, Bedrock), credentials management, HTTP request handling, invocation extraction from provider responses, fixture assembly, and record construction. Each provider has distinct payload parsing and recording paths; cross-cutting fixture writing, record transformation, and header stamping logic is inlined throughout.
- Target tree:
  - `cli` (~140) - CLI argument parsing (Cli struct, ProviderArg enum), main entry, run orchestration, scenario loading, fixture validation, scenario id validation
  - `credentials` (~110) - Credentials enum variants (OpenAi, Anthropic, Bedrock); credentials_for provider dispatch; environment variable loading (required_env helper)
  - `http` (~60) - HTTP transport: curl_json_post wrapper for making authenticated requests to provider APIs
  - `invoke` (~300) - Invocation extraction from provider responses: extract_openai/anthropic/bedrock_invocations; openai_invocation_from_stream_record and openai_invocation_from_item; anthropic_invocation_from_stream_record and anthropic_invocation_from_block; bedrock_invocation_from_tool_use; tool_invocation constructor; allow_verdict and receipt_id resolution
  - `openai` (~240) - OpenAI-specific recording: record_openai orchestration; openai_batch_invocations and openai_stream_invocations extraction; OpenAI payload construction
  - `anthropic` (~240) - Anthropic-specific recording: record_anthropic orchestration; anthropic_batch_invocations and anthropic_stream_invocations extraction; Anthropic payload construction
  - `bedrock` (~280) - Bedrock-specific recording: record_bedrock orchestration; bedrock_batch_invocations extraction; bedrock_caller_identity (AWS STS); bedrock_converse (AWS Bedrock API call); BedrockIdentity type
  - `fixture` (~280) - Fixture assembly and writing: assemble_records, write_records_atomic; lowered_records orchestration; lowered_openai_records and lowered_sequential_records; lowered_bedrock_records; lowered_record_from_body; RecordedFixture type
  - `record` (~220) - Record construction and payload manipulation: live_request_record, capture_record; stamp_openai/anthropic/bedrock_headers; headers_mut; insert_payload_field; request_body and anthropic_version extraction
  - `util` (~140) - Utility helpers: sanitize_id, now_ts, required_json_str; seed_family, seed_api_snapshot; sse_records parsing, parse_sse_payloads, push_sse_payload; invalid_fixture and validation error construction
- API impact: none (facade)
- Test seam: Binary tested via CLI invocation (cargo run --bin record -- --provider <provider> --scenario <scenario>); fixture integration tests rely on recorded fixtures from this tool

### `chio-attest-verify` (1 file)
**`crates/trust/chio-attest-verify/src/sigstore.rs`** - 1996 lines, ~9 modules. Pattern 1 (Facade tree). Wave 1.
- Why: File combines verifier struct initialization, three trait methods (verify_blob/verify_bytes/verify_bundle), X.509 certificate parsing and validation, OIDC identity matching with regex, async bundle verification with tokio runtime detection, Rekor metadata extraction, protobuf compatibility layer, custom verification policy type, and 1340 lines of comprehensive test coverage. Responsibilities span cryptography (sigstore-rs integration), certificate chain validation (webpki), time-window checking, SAN/issuer parsing, async bundling, and protocol error mapping.
- Target tree:
  - `mod.rs` (~50) - Facade: module declaration, public re-exports of SigstoreVerifier and AttestVerifier trait, test module conditional inclusion
  - `core.rs` (~280) - Verifier type definition (SigstoreVerifier struct), embedded trust root initialization (with_embedded_root, build_trust_root, build_bundle_verifier), and complete AttestVerifier trait implementation (verify_blob, verify_bytes, verify_bundle methods)
  - `validators.rs` (~180) - X.509 certificate chain validation via webpki, webpki error mapping, signature verification (cosign base64 vs raw), certificate validity extraction, validity-window boundary checking (inclusive bounds on both ends)
  - `bundle_verify.rs` (~140) - Async bundle verifier orchestration (tokio runtime nesting detection and thread delegation), bundle DER extraction, Rekor metadata and log-index extraction, Rekor inclusion status (currently always false per spec gap), bundle verification error mapping from sigstore-rs result codes
  - `parse.rs` (~70) - Certificate format conversion (PEM vs raw DER detection), OIDC issuer extension value decoding (DER UTF8String vs raw UTF-8 with control-byte rejection)
  - `identity.rs` (~70) - Identity matching: SAN regex extraction (RFC822Name, URI, OtherName), OIDC issuer extension retrieval, caller-supplied regex anchoring with ^...$ bounds, issuer exact-string comparison
  - `policy.rs` (~50) - IssuerOnlyPolicy struct implementing sigstore::bundle::verify::VerificationPolicy; isolates issuer-only check from SAN matching (deferred to match_identity for regex support)
  - `compat.rs` (~30) - Protobuf compatibility: leaf_der extraction from X509CertificateChain or single Certificate variant, rekor_metadata (log_index and integrated_time) extraction from tlog_entries; isolates sigstore_protobuf_specs field walking
  - `tests.rs` (~1340) - Unit test module with ~30 tests covering: synthetic cert generation (rcgen with SAN variants), match_identity SAN matching (URI/RFC822/OtherName, regex anchoring, issuer validation), decode_oidc_issuer (DER vs raw UTF-8 paths), certificate_validity round-trip, validity-window boundary checks (inclusive inclusive), signature rejection, webpki error mapping, bundle_rekor_metadata timestamp logic, bundle_leaf_certificate_der extraction, IssuerOnlyPolicy verification, OID constant validation
- API impact: none (facade)
- Test seam: Existing unit tests in sigstore_internal_tests can be moved to tests.rs module as-is. All tested functions are made pub(crate) or pub as appropriate. Synthetic certificate generation via rcgen and x509_cert DER utilities remain available to tests. No integration test changes required (integration tests already live in tests/integration.rs).

### `xtask` (3 files)
**`xtask/src/fixtures_facets.rs`** - 1994 lines, ~8 modules. Pattern 1 (Facade tree) + 3 Verifier pipeline. Wave 2 (launch-critical).
- Why: Handler implementation file (included into fixtures.rs via include!) containing pre-schema guards, per-facet metadata assertions, and imperative handler bodies for the 15 pheromone facets. Responsibilities tangled across four domains: (1) Pre-schema guards (retired-marker checks for transit/relay/assurance-relay); (2) Metadata assertions keyed by Facet::kind (transit fixture linking, relay policy/batch/commitment validation, runtime query/frame code verification, relay observability/alert routing); (3) Imperative handler dispatch (15 match arms, each calling a kind-specific handler); (4) Large relay CLI orchestration (status/tick/enqueue/catchup commands, auditor batch building, policy signing, peer directory traversal). The relay orchestration alone spans 600+ lines with deep fixture assembly, JSON manipulation, signing key generation, and report path resolution.
- Target tree:
  - `facets/mod.rs (facade/entry point)` (~120) - Public entry points from fixtures.rs perspective: pre_schema_guard dispatcher, run_metadata_block handler, handlers for the pheromone facet kinds (transit, relay, relay_ops, directory_lifecycle, relay_observability, archive_chain, generic); exports to be called by fixtures/dispatch.rs
  - `facets/guards.rs` (~150) - Pre-schema guards: retired-marker runtime assembly, guard_no_marker_in_file case-insensitive checks for transit and relay runbooks, guard_assurance_no_legacy_marker for relay alert assurance fixtures, walk_files recursive directory traversal
  - `facets/metadata.rs` (~350) - Per-facet metadata assertions: dispatch by Facet::kind (metadata_transit, metadata_relay, metadata_runtime, metadata_directory_lifecycle, metadata_relay_observability, metadata_relay_alert_routing, metadata_generic). Each assertion validates fixture structure (schema fields, cost commitments, transit chains, policy bindings).
  - `facets/handlers.rs` (~600) - Imperative handler implementations: handle_transit, handle_relay, handle_relay_ops, handle_directory_lifecycle, handle_relay_observability, handle_archive_chain (alerts), handle_generic; these orchestrate CLI, cargo test, npm, and recursion invocations
  - `facets/relay.rs` (~700) - Relay-specific orchestration: relay_cli_orchestration (status/tick/enqueue/catchup command sequence), relay_build_auditor_inputs (derived fixture generation from source batch/policy), relay_ops_lint_orchestration, relay_ops_tick; JSON mutation and signing key helpers (write_signing_key, set_str, set_i64, canonical_json, policy hash computation)
  - `facets/json_support.rs` (~200) - JSON and file I/O helpers: load_json, write_json, JSON field access (str_field), JSON mutation (set_str, set_i64, set_value, remove_key), file comparison (cmp_files), canonical JSON/SHA256 formatting for policy hashing, signing key generation
  - `facets/scratch.rs` (~40) - Temporary directory and cleanup: ScratchDir struct with Drop cleanup (best-effort, ignores errors), scratch_counter atomic for unique naming, join helper for path construction within temp dir
  - `facets/assertions.rs` (~150) - Report/result assertions: assert_detail_contains (grep-like search in JSON reports), assert_catchup_returned_one_frame, runtime-specific frame code assertions, directory promotion assertions, auditor report validation
- API impact: none (facade): Converts from include! (compile-time code merging) to a proper module hierarchy. Public exports (pre_schema_guard, run_metadata_block, and handler names) remain callable from fixtures/dispatch.rs via facets:: path. Callers of fixtures module see no change; this is purely internal refactoring.
- Test seam: facets/mod.rs: Integration tests in fixtures/tests.rs exercise pre_schema_guard and per-facet handlers indirectly by calling fixtures::run(facet_name). Relay orchestration can be tested via fixtures/tests.rs::relay_schema_block_and_metadata_pass_against_committed_fixtures without fixture execution; deep handler logic relies on committed example fixtures (examples/chio-3vendor/) which are part of CI gate execution (not unit-testable in isolation without running the full gate).

**`xtask/src/main.rs`** - 1931 lines, ~9 modules. Pattern 1 (Facade tree) + 4 Generator stages. Wave 1.
- Why: Entangles five distinct responsibilities: scenario validation with schema indexing, vector freezing/manifest generation, codegen orchestration for four languages (Rust/Go/TS/Python), and error registry regeneration. The Python codegen alone spans ~755 lines with 19 helper functions across multiple generation stages: datamodel-codegen invocation, file hardening, subpackage rewriting, and top-level init building. Helper utilities (TempDir, schema walking, byte comparison) scatter throughout.
- Target tree:
  - `main/mod.rs (facade)` (~150) - Entry point, CLI dispatch to subcommands, workspace_root derivation, error handling and formatting
  - `main/validate_scenarios.rs` (~180) - Conformance scenario validation: schema URI indexing, resolution via $id registry and strip-prefix fallback, scenario collection, per-scenario validation against resolved schemas
  - `main/freeze_vectors.rs` (~120) - Vector manifest generation: SHA256 digestion of test vectors under tests/bindings/vectors/, manifest writing and --check verification
  - `main/codegen_rust.rs` (~110) - Rust codegen orchestration: invoke chio_spec_codegen::codegen_rust, --check staging/comparison, manifest drift reporting
  - `main/codegen_go.rs` (~130) - Go codegen shim: shell out to scripts/regen-types.sh with OpenAPI bundling, --check git diff verification
  - `main/codegen_ts.rs` (~280) - TypeScript codegen: json2ts invocation per schema, namespace wrapping, header/footer, schema digestion for auditing, --check memory vs on-disk comparison
  - `main/codegen_python.rs` (~750) - Python codegen pipeline: datamodel-codegen invocation, file hardening (receipt, capability, jsonrpc, provenance), subpackage init rewriting with top-level star-exports, schema digestion, --check drift detection
  - `main/errors_regen.rs` (~90) - Error registry regeneration: load spec/errors/registry.yaml, invoke chio_spec_codegen::codegen_error_codes, write output and mod file, --check staging comparison
  - `main/support.rs` (~220) - Shared utilities: TempDir (temp directory lifecycle), schema file walking, byte digestion (SHA256, hex encoding), manifest drift formatting, display path helpers
- API impact: none (facade): Public entry functions (validate_scenarios, freeze_vectors, run_codegen, errors_regen, run_snippets) remain in main/mod.rs re-exports; callers see no change. Workspace_root and display_path remain public via support module.
- Test seam: main/mod.rs: #[cfg(test)] mod tests; all unit tests remain inline in the facade or distributed per-module. No external test fixtures required; validation is direct file I/O.

**`xtask/src/fixtures.rs`** - 1603 lines, ~13 modules. Pattern 1 (Facade tree) + 2 Dispatch split. Wave 2 (launch-critical).
- Why: Core orchestration file (1603 lines) for the 15-facet pheromone + 8-facet runtime gate system. Includes five additional files via compile-time include! (fixtures_facets.rs 1994L, fixtures_facets_meta.rs 382L, fixtures_facets_alert.rs 623L, fixtures_facets_assurance.rs 784L, fixtures_runtime.rs 923L), logically merging ~6300 lines. Responsibilities span: manifest loading and enumeration, mode resolution, schema/metadata block orchestration, per-facet handler dispatch (15 pheromone facet kinds + 8 runtime kinds), subprocess runners (cargo test, CLI, npm, bash, sre-metrics), JSON/fs helpers (globbing, assertions, JSON mutations), and unit tests (28 test cases).
- Target tree:
  - `fixtures/mod.rs (facade)` (~400) - Public entry points: run() and load_manifest() dispatch logic, manifest loaders, mode enumeration, compile-time facet enumeration (KNOWN_FACETS, RUNTIME_KNOWN_FACETS), orchestration of schema/metadata blocks, pre-schema guards
  - `fixtures/types.rs` (~160) - Struct definitions: Manifest, Facet, SchemaEntry, ValidatePair, ValidateGlob, RecurseEdge, RuntimeManifest, RuntimeFacet, SchemaCheck enum, Mode enum, method implementations
  - `fixtures/manifest.rs` (~120) - Manifest enumeration assertions, fail-closed validation that pheromone and runtime manifests list exactly their known facets, facet_by_name lookup, loaders (load_manifest_from, load_runtime_manifest_from)
  - `fixtures/schema.rs` (~240) - Schema validation block: schema loading from registry, schema shape assertions (strict-object, frozen-object), validate_pairs and validate_glob execution, document path resolution (root-relative vs fixture-relative), registry loading and per-facet schema entry checks
  - `fixtures/dispatch.rs` (~80) - Handler dispatch: dispatch_handler router to per-facet handlers (matches on Facet::kind), run_recursion for facet edges, runtime handler dispatcher, mode-aware early exits for NegativeOnly
  - `fixtures/facets.rs (replaces fixtures_facets.rs)` (~900) - Pheromone facet handlers and metadata: handle_transit, handle_relay, handle_relay_ops, handle_directory_lifecycle, handle_relay_observability, handle_archive_chain, handle_generic; per-facet metadata assertions (transit, relay, observability, alert routing); pre-schema retired-marker guards; ScratchDir temp directory management
  - `fixtures/facets_meta.rs (replaces fixtures_facets_meta.rs)` (~200) - Generic metadata assertions shared across facets: collect_case_field, assert_required_present, metadata_negative_codes/ids/case_ids, external_retention assertions
  - `fixtures/facets_alert.rs (replaces fixtures_facets_alert.rs)` (~500) - Relay alert facet handlers: handle_alert_with_npm (routing/handoff/delivery), handle_alert_assurance, per-facet metadata assertions for alert subsystems (archive-hardening, archive-package, export, external-retention)
  - `fixtures/facets_assurance.rs (replaces fixtures_facets_assurance.rs)` (~600) - Relay alert assurance deep handlers: fixture validation for assurance-archive flows, journaling and evidence-graph checks, multi-step admission orchestration (build auditor inputs, validate reports, check frame codes)
  - `fixtures/runtime/mod.rs (replaces fixtures_runtime.rs)` (~450) - Runtime facet handlers: handle_runtime (multi-stage admission/orchestration), dispatch_runtime_handler, run_runtime_validate_pairs, run_runtime_cargo_tests; runtime-specific assertions (receive query, frame code, query persisted)
  - `fixtures/runtime/ops.rs (replaces fixtures_runtime_ops.rs)` (~750) - Runtime ops handler details: multi-step proof-room and spine operations, frame code assertions, report path resolution, deep fixture validation for runtime policy/ops hardening/chaos/attack simulation
  - `fixtures/support.rs` (~350) - Subprocess helpers: run_cargo_test, run_cargo_test_filtered, run_cli, require_cli, reject_cli, run_bash, run_npm, run_dashboard_test_and_build, run_sre_metrics; JSON/fs helpers: load_json, glob_documents, glob_matches, walk_files, file comparison; assertion helpers
  - `fixtures/tests.rs` (~460) - Unit tests (28 tests): manifest enumeration verification, facet resolution, schema block and metadata block parity against committed fixtures, mode flag validation, manifest/workflow invariants
- API impact: none (facade): Public entry functions (run, load_manifest, load_runtime_manifest, KNOWN_FACETS, RUNTIME_KNOWN_FACETS, Mode enum) remain accessible via fixtures::* re-exports in mod.rs facade. Callers see no change.
- Test seam: fixtures/tests.rs: Unit tests do not require fixtures running in parallel or external orchestration; each test loads the committed manifests and validates one facet's schema/metadata block against checked-in fixtures. Tests are gated to committed fixture parity (relay, observability, etc. against examples/ fixtures).

### `control-plane/certify` (1 file)
**`crates/platform/chio-control-plane/src/certify.rs`** - 1979 lines, ~8 modules. Pattern 1 (Facade tree). Wave 1.
- Why: File tangles 8 responsibilities: schema/version constants and validators, 50+ data type definitions (structs/enums for checks, registries, discovery, search, transparency, consumption), utility helpers, certification body building and complex evaluation logic, signature verification and integrity checks, registry CRUD operations (publish/resolve/revoke/dispute), and 8 command handlers with parsing helpers.
- Target tree:
  - `types` (~490) - All public and internal data structures: enums (CertificationVerdict, CertificationRegistryState, CertificationDisputeState, CertificationTransparencyEventKind, CertificationResolutionState), structs (CertificationCheckBody, SignedCertificationCheck, CertificationRegistry, CertificationRegistryEntry, all Request/Response types for discovery/search/transparency/consumption), and helper struct EvaluationArtifacts.
  - `schema` (~100) - Schema constants (CERTIFICATION_SCHEMA, CERTIFICATION_REGISTRY_VERSION, CRITERIA_PROFILE_ALL_PASS_V1, evidence/metadata/search/transparency/consumption/provenance constants) and schema validators (is_supported_certification_schema, is_supported_certification_registry_version, is_supported_evidence_profile).
  - `artifact` (~280) - Certification artifact construction and evaluation: build_certification_body (assembles body from scenarios/results with evidence hashing), evaluate_all_pass_profile (complex evaluation producing verdict, criteria, findings, summary from scenario/result matching), and sign_artifact (wraps body in SignedCertificationCheck with signature).
  - `verify` (~100) - Signature and integrity verification: verify_signed_certification_check (validates body signature and schema compliance), verify_certification_registry_entry (validates 9 invariants: artifact_id match, sha256 match, tool_server_id consistency, checked_at/verdict consistency, superseded/revoked state requirements), and certification_artifact_id (derives artifact id from signed check).
  - `validators` (~180) - Domain validation: validate_certification_evidence (checks profile, sha256 fields, report bytes/media-type/provenance), validate_certification_artifact_body (checks schema, criteria profile, target, evidence), validate_public_certification_metadata (checks schema, publisher URLs, expiry, discovery flag, supported profiles, path constraints), and helper validators (require_non_empty_field).
  - `registry` (~340) - CertificationRegistry persistence and query operations: load/save (file I/O with version validation), get (direct lookup), publish (deduplicates by ID, marks existing entries superseded), resolve (finds current active/revoked/superseded state for tool_server_id), revoke (marks entry revoked with reason/timestamp), dispute (records dispute state/note, conditionally revokes), search_public (filters by tool_server_id/criteria/evidence/status with sorting), transparency (generates timeline events for published/superseded/revoked/disputed artifacts).
  - `commands` (~400) - CLI command handlers: cmd_certify_verify (loads and validates artifact), cmd_certify_check (builds, signs, and saves certification), cmd_certify_registry_* family (publish_local, list_local, get_local, resolve_local, revoke_local, search, transparency, consume, dispute with local/remote dispatch), plus helper functions (emit_registry_entry, parse_registry_state_filter, parse_dispute_state, certification_resolution_label).
  - `helpers` (~140) - Utility functions: unix_now (current timestamp), normalize_registry_url (strip whitespace/trailing slash), require_certification_discovery_path (error if path missing), require_existing_dir (validate path is existing directory), ensure_parent_dir (create parent directories), and load_signed_certification_check (load and verify artifact from file).
- API impact: none (facade)
- Test seam: certify::artifact::evaluate_all_pass_profile (existing tests transfer; core evaluation logic), certify::registry::CertificationRegistry (load/publish/resolve/revoke/dispute operations), certify::verify::verify_signed_certification_check (signature validation), certify::validators::* (domain validation). Command handlers testable via certify::commands module. All tests preserved in-module after split.

### `mercury` (3 files)
**`crates/products/chio-mercury/src/commands/shared.rs`** - 1978 lines, ~5 modules. Pattern 7 (Typed sections) + 1 Facade tree. Wave 1.
- Why: Aggregates foundational utilities (time, file I/O, JSON ops, receipt/proof builders) alongside 40+ struct definitions (Config, Summary, and Report types) for all Mercury packages. Mixes low-level I/O operations with high-level orchestration types.
- Target tree:
  - `utils.rs` (~320) - Time utilities, file I/O (read/write JSON, ensure_empty_directory, copy_file), path operations, bundle manifest validation, and low-level receipt store population
  - `types.rs` (~650) - Type definitions: PilotInquiryConfig, PilotRunPaths, ExportRunPaths, PilotExportSummary, SupervisedLiveExportSummary, and 30+ summary/decision/validation/acknowledgement/manifest struct types grouped by feature area
  - `builders.rs` (~550) - Package builder functions: build_proof_package, build_inquiry_package, pilot_capability_with_id, pilot_receipt, and struct-specific builders (build_assurance_package, build_governance_review_package, build_assurance_disclosure_profile, etc.). Converts configs into validated packages.
  - `doc_refs.rs` (~180) - Documentation reference getter functions: reviewer_doc_refs, downstream_review_doc_refs, governance_workbench_doc_refs, and 5 others. Each returns a DocRefs struct with file paths to documentation artifacts.
  - `mod.rs` (~50) - Facade module. Re-exports all public utilities, types, and builder functions from submodules, preserving the module path so callers of shared:: do not change.
- API impact: none (facade)
- Test seam: write_bundle_manifests_rejects_bundle_id_path_separator, write_bundle_manifests_rejects_bundle_id_control_character (moved to utils_tests module)

**`crates/products/chio-mercury/src/commands/assurance_release.rs`** - 1885 lines, ~2 modules. Pattern 4 (Generator stages) + 1 Facade tree. Wave 1.
- Why: Implements a pipeline of 7 generator stages, each building a higher-level package by invoking the previous stage and orchestrating file copies, profile building, package validation, and summary generation. Pipeline: export_assurance_suite -> export_embedded_oem -> export_trust_network -> export_release_readiness -> export_controlled_adoption -> export_reference_distribution -> export_broader_distribution. Each stage replicates similar patterns: ensure directory, invoke previous stage, build profiles, copy files, construct packages, write summaries.
- Target tree:
  - `exports.rs` (~1885) - Seven generator stages, each producing a higher-level package: export_assurance_suite (reviewer population loop), export_embedded_oem (single partner embed), export_trust_network (checkpoint witness chain), export_release_readiness (partner launch delivery), export_controlled_adoption (design-partner renewal), export_reference_distribution (landed-account expansion), export_broader_distribution (selective account qualification).
  - `mod.rs` (~30) - Facade module (optional for private module). Re-exports export_* functions for internal use by core_cli and other command modules.
- API impact: none (facade)
- Test seam: No tests in current file. These are internal generators tested via core_cli command tests. After split, could add integration tests that verify stage ordering and artifact consistency.

**`crates/products/chio-mercury/src/commands/core_cli.rs`** - 1808 lines, ~3 modules. Pattern 2 (Dispatch split) + 5 Service-handler. Wave 1.
- Why: Mixes low-level export orchestrators (export_supervised_live_qualification, export_downstream_review, export_governance_workbench, export_mercury_run, export_pilot_scenario, export_supervised_live_capture) with 28 public command functions (cmd_mercury_proof_export through cmd_mercury_broader_distribution_validate). Each cmd function wraps one or more export functions, duplicating validation and decision-record generation logic across similar export patterns.
- Target tree:
  - `exports.rs` (~620) - Internal export orchestrators: export_supervised_live_qualification, export_downstream_review, export_governance_workbench, export_mercury_run, export_pilot_scenario, export_supervised_live_capture. These compose lower-level utilities with JSON artifact writing and discovery.
  - `commands.rs` (~1080) - Public CLI command entry points: 28 cmd_mercury_* functions grouped by workflow stage (proof, inquiry, verify, pilot, supervised-live, downstream-review, governance-workbench, assurance-suite, embedded-oem, trust-network, release-readiness, controlled-adoption, reference-distribution, broader-distribution). Each wraps an export or validation function with human-readable output.
  - `mod.rs` (~40) - Facade module. Re-exports all pub cmd_* functions from commands.rs, preserving the module path so callers of core_cli::cmd_mercury_* do not change.
- API impact: none (facade)
- Test seam: No tests in current file; all export_* functions are tested implicitly through cmd_* functions. After split, export_* functions should be tested directly in exports_tests module.

### `kernel` (5 files)
**`crates/kernel/chio-kernel/src/kernel/responses.rs`** - 1956 lines, ~5 modules. Pattern 2 (Dispatch split) + 4 Generator stages. Wave 1.
- Why: Tangled response builders across four verdict types (Deny, Allow, Cancelled, Incomplete), combined with tool output finalization, receipt signing and persistence, and checkpoint management. Each verdict family has 3-5 variants (with/without metadata, with different contexts), plus finalization and persistence logic.
- Target tree:
  - `deny_responses` (~650) - Deny response builders for all deny cases: monetary budget exhaustion, pre-execution failures, runtime admission rejection, negotiation failures, emergency stop, receipt persistence failures, standard denials. Consolidates build_monetary_deny_response*, build_pre_execution_*, build_runtime_admission_deny*, build_negotiation_*, build_emergency_stop_*, build_receipt_persistence_failclosed_*, and build_deny_response* methods.
  - `allow_responses` (~250) - Allow response builders: standard tool call allow response and execution nonce preflight allow response. Handles build_allow_response, build_allow_response_with_metadata, and build_execution_nonce_preflight_allow_response_with_metadata.
  - `terminal_responses` (~200) - Terminal state response builders for cancelled and incomplete states. Handles build_cancelled_response, build_incomplete_response, and variants with output/metadata.
  - `finalization` (~550) - Tool output finalization with monetary cost tracking and stream truncation. Handles finalize_tool_output variants with cost/metadata injection and apply_stream_limits.
  - `receipt_persistence` (~400) - Receipt signing, federation recording, and checkpoint management. Handles build_and_sign_receipt, record_chio_receipt_with_federation, record_chio_receipt, and checkpoint trigger logic.
- API impact: none (facade)
- Test seam: All builders return Result<ToolCallResponse, KernelError>. Test by providing request/capability/timestamp and asserting receipt structure in response.

**`crates/kernel/chio-kernel/src/operator_report.rs`** - 1851 lines, ~7 modules. Pattern 7 (Typed sections). Wave 1.
- Why: Dominated by two large concerns: (1) 25 related query/report structs for different operational reporting domains (budget utilization, settlement, metered billing, authorization context, behavioral anomalies), and (2) 30+ OAuth/authorization configuration structs with defaults. Each domain has its own filter query, row type, summary, and report types.
- Target tree:
  - `constants` (~90) - Schema identifiers, authorization profile constants, OAuth field names, and reporting limits. All pub const definitions (CHIO_OAUTH_*, MAX_*_LIMIT).
  - `queries` (~400) - Filter surfaces for operator reports: OperatorReportQuery, BehavioralFeedQuery, SharedEvidenceQuery with their defaults and conversion methods to other query types.
  - `budget_report` (~150) - Budget utilization and compliance reporting types: BudgetUtilizationSummary, BudgetDimensionUsage/Profile, BudgetUtilizationRow/Report, ComplianceReport.
  - `settlement_report` (~200) - Settlement and metered billing reconciliation types: SettlementReconciliationReport, MeteredBillingReconciliationReport, EconomicReceiptProjectionReport, EconomicCompletionFlowReport.
  - `authorization_context` (~650) - OAuth authorization context and governed transaction types: ChioOAuthAuthorizationProfile, ChioOAuthRequestTimeContract, ChioOAuthSenderConstraintProfile, AuthorizationContextReport, GovernedAuthorizationDetail, GovernedTransactionDiagnostics.
  - `behavioral_analysis` (~120) - Behavioral anomaly score calculation and types: EmaBaselineState, BehavioralAnomalyScore, behavioral_anomaly_score function for guard-exposed anomaly metrics.
  - `operator_report_types` (~100) - Top-level operator report aggregation and OperatorReport struct that combines all domain reports. Bridge between query filters and individual report types.
- API impact: none (facade)
- Test seam: Query normalization (limit clamping), conversion methods (to_receipt_analytics_query, to_evidence_export_query), and schema defaults. Test by constructing queries with extreme values and asserting defaults.

**`crates/kernel/chio-kernel/src/kernel/evaluation.rs`** - 1835 lines, ~4 modules. Pattern 4 (Generator stages) + 2 Dispatch split. Wave 1.
- Why: Monolithic evaluation orchestrator combining: (1) capability validation surface (validate_non_tool_capability), (2) async entry point with full evaluation core (~900 lines of nested error handling, budget mutation, guard evidence, dispatch, and finalization), (3) blocking/sync variants, and (4) long-form evaluation cores for both paths with deeply nested error handlers and metadata merging.
- Target tree:
  - `evaluation_entry` (~250) - Public entry points for async and blocking evaluation: evaluate_tool_call (async variants), evaluate_tool_call_blocking/sync (blocking variants), validate_non_tool_capability (read-only resource access), and sign_planned_deny_response. Orchestrate but do not implement the core logic.
  - `async_evaluation_core` (~900) - Async evaluation logic after entry point dispatch: handle capability verification, budget pre-execution, guard evidence collection, runtime admission, monetary admission, dispatch, finalization, and error unwinding. Core async path with all state machines.
  - `sync_evaluation_wrapper` (~200) - Synchronous evaluation wrapper that blocks on async core using tokio/blocking runtime. Handle sync entry points by delegating to async core with appropriate runtime context.
  - `evaluation_helpers` (~150) - Extracted helper functions for evaluation pipeline: error classification (dispatch_error_precedes_tool_side_effect), pre-dispatch cleanup builders, and common error path handlers.
- API impact: none (facade)
- Test seam: Entry points accept ToolCallRequest; test with varying request states (expired, revoked, exceeding budget, guard denial). Core returns ToolCallResponse with receipt. Mock dispatch via NestedFlowClient trait.

**`crates/kernel/chio-kernel/src/receipt_support.rs`** - 1716 lines, ~4 modules. Pattern 7 (Typed sections) + 1 Facade tree. Wave 1.
- Why: Five semi-independent concerns bundled: (1) thread-local scopes for call chain evidence (~100 lines), (2) runtime attestation record scopes (~50 lines), (3) pre/post-invocation guard evidence scopes (~100 lines), (4) receipt metadata assembly from five sources (governed, financial, request, attribution, provenance) (~300 lines), and (5) receipt content hashing and stream truncation (~200 lines). Also houses signing.rs submodule.
- Target tree:
  - `receipt_scopes` (~350) - All thread-local RAII scope guards and accessors: ScopedGovernedCallChainReceiptEvidence, ScopedGovernedRuntimeAttestationRecord, ScopedPreInvocationGuardEvidence, ScopedPostInvocationGuardEvidence, and FixedRuntimeScope. Manages call chain context, attestation records, and guard evidence threads locals.
  - `receipt_metadata` (~300) - Receipt metadata assembly from multiple sources: governed_call_chain_receipt_evidence (inject call chain context), receipt_attribution_metadata, governed_economic_authorization_metadata, request_receipt_metadata, request_model_metadata_receipt_metadata, child_receipt_metadata, receipt_provenance_metadata.
  - `receipt_content` (~200) - Receipt content hashing and payload canonicalization: receipt_content_for_output (value/stream dispatch), stream_receipt_content (chunk hashing), truncate_stream_to_byte_limit. Produces ReceiptContent with SHA256 hashes and canonical bytes.
  - `receipt_building` (~150) - Child receipt and receipt ID generation: build_child_request_receipt, next_receipt_id, child_receipt_metadata, child_terminal_state, child_outcome_payload. Constructs child request receipts and manages receipt ID allocation.
- API impact: none (facade)
- Test seam: Receipt metadata builders return Option<serde_json::Value>. Test by injecting scopes, building metadata, and asserting presence of required fields. Content hashing test by providing stream and asserting chunk_hashes in metadata.

**`crates/kernel/chio-kernel/src/kernel/mod.rs`** - 1607 lines, ~3 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Module facade that owns the ChioKernel struct definition (~300 lines) plus thread-local scope management for multi-tenant receipt isolation and federation admission (~400 lines), plus post-admission drop guard state machine (~350 lines), plus submodule declarations. The scopes and guards are tightly coupled to receipt emission and should be factored into receipt_support.
- Target tree:
  - `kernel_struct` (~400) - ChioKernel struct definition with all fields (store, signing keypair, guards, hooks, federation, session management, checkpoint state, emergency stop flag, etc.) and fundamental accessors/mutators (session_mut, with_session, etc.).
  - `kernel_scopes` (~200) - Thread-local scope management for multi-tenant receipt isolation (ScopedReceiptTenantId, scope_receipt_tenant_id, current_scoped_receipt_tenant_id) and federation admission context (ScopedReceiptFederationAdmission, scope_receipt_federation_admission). Move to receipt_support eventually.
  - `kernel_drop_guard` (~200) - Post-admission drop guard and context structures (PostAdmissionReceiptContext, PostAdmissionDropGuard, ScopedKernelReceiptTenantId, ScopedKernelReceiptFederationAdmission) that ensure monetary invocations are unwound if evaluation future is dropped.
- API impact: none (facade)
- Test seam: ChioKernel constructor (with required store, signing backend, etc.). Session accessor (with_session) returns error on missing session. Scope guards test by setting and asserting thread-local state.

### `control-plane/trust_control` (8 files)
**`crates/platform/chio-control-plane/src/trust_control/cluster.rs`** - 1928 lines, ~5 modules. Pattern 2 (Dispatch split) + 5 Service-handler. Wave 1.
- Why: Cluster replication handlers (consensus view, snapshots, delta sync, partition management) tangled with view rendering, replication state management, and auth validation across 11 async handlers
- Target tree:
  - `cluster/consensus.rs` (~300) - Cluster consensus view, status response, leader election state
  - `cluster/partition.rs` (~250) - Partition management, peer blocking, consensus recomputation
  - `cluster/snapshots.rs` (~350) - Authority snapshot, cluster snapshot building, snapshot response views
  - `cluster/deltas.rs` (~800) - Replication delta handlers: revocations, tool receipts, child receipts, budgets, lineage
  - `cluster/mod.rs` (~300) - Facade re-exporting all handlers; build_cluster_state, run_cluster_sync_loop, cluster initialization
- API impact: none (facade)
- Test seam: Mock cluster state, fake peer health, revocation/receipt/budget stores

**`crates/platform/chio-control-plane/src/trust_control/service_runtime.rs`** - 1875 lines, ~3 modules. Pattern 2 (Dispatch split). Wave 1.
- Why: Router initialization and route registration for ~150+ endpoints; handler dispatch mixed with state construction and async runtime setup
- Target tree:
  - `service_runtime/router.rs` (~800) - Thin axum router builder; route registration for all ~150 endpoints by concern domain
  - `service_runtime/init.rs` (~200) - serve_async entry point, registry loading, state construction, listener binding
  - `service_runtime/mod.rs` (~150) - Module facade, submodule declarations, re-exports of serve_async and state types
- API impact: none (facade)
- Test seam: Mock TrustServiceState, fake registries, test router extraction

**`crates/platform/chio-control-plane/src/trust_control/service_runtime/client.rs`** - 1852 lines, ~4 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Client builder functions mixed with cluster peer auth, endpoint validation, and TrustControlClient construction logic across 1852 lines
- Target tree:
  - `service_runtime/client/factory.rs` (~200) - build_client, build_public_client, build_cluster_peer_client; client instantiation
  - `service_runtime/client/auth.rs` (~300) - Cluster peer auth signing, ClusterPeerClientAuth, auth header building
  - `service_runtime/client/validation.rs` (~250) - Endpoint URL normalization, token validation, endpoint health checks
  - `service_runtime/client/mod.rs` (~100) - Facade re-exporting client builders and TrustControlClient
- API impact: none (facade)
- Test seam: Mock HTTP client, fake endpoints, signature validation mocks

**`crates/platform/chio-control-plane/src/trust_control/service_types.rs`** - 1826 lines, ~5 modules. Pattern 7 (Typed sections) + 1 Facade tree. Wave 1.
- Why: Wire types and constants tangled together: TrustServiceConfig (with 14+ fields and validation logic), 50+ request/response structs, 100+ route path constants, cluster budget types, delegated policies, queries, and views
- Target tree:
  - `service_types/paths.rs` (~250) - All HTTP path constants (~100 routes), CSP security header, list limits
  - `service_types/config.rs` (~450) - TrustServiceConfig struct, validation, registry path helpers, credential issuer setup
  - `service_types/requests.rs` (~350) - All request structs: FederatedIssueRequest, CreditFacilityIssueRequest, UnderwritingDecisionIssueRequest, PassportRequest types, etc.
  - `service_types/responses.rs` (~300) - All response structs: EnterpriseProviderListResponse, RevokeCapabilityResponse, ChildReceiptQuery, RevocationQuery, views
  - `service_types/mod.rs` (~150) - Facade re-exporting paths, config, requests, responses; cluster_budget submodule; public type re-exports
- API impact: none (facade)
- Test seam: Config fixtures, request builders, response assertion helpers

**`crates/platform/chio-control-plane/src/trust_control/risk_finance_handlers.rs`** - 1683 lines, ~6 modules. Pattern 2 (Dispatch split) + 5 Service-handler. Wave 1.
- Why: 51 HTTP handlers for risk-and-finance surface (exposure, credit, capital, liability, reputation, attestation appraisal) tangled with report building, signing, and auth validation
- Target tree:
  - `handlers/exposure.rs` (~200) - handle_exposure_ledger_report, handle_behavioral_feed_report; ledger view building
  - `handlers/credit.rs` (~350) - handle_credit_scorecard_report, handle_credit_facility_report, handle_credit_bond_report, handle_credit_backtest_report
  - `handlers/capital.rs` (~250) - handle_capital_book_report, handle_issue_capital_execution_instruction, handle_issue_capital_allocation_decision
  - `handlers/liability.rs` (~500) - All liability handlers: provider, quote-request/response, pricing authority, placement, bound-coverage, auto-bind, claims, disputes, adjudications, payouts, settlements
  - `handlers/attestation.rs` (~200) - handle_runtime_attestation_appraisal_report, handle_runtime_attestation_appraisal_result_export, handle_runtime_attestation_appraisal_import
  - `handlers/mod.rs` (~150) - Facade re-exporting all 51 handlers by domain
- API impact: none (facade)
- Test seam: Mock receipt stores, fake reports, signed artifact builders, auth validation stubs

**`crates/platform/chio-control-plane/src/trust_control/underwriting_and_support.rs`** - 1626 lines, ~5 modules. Pattern 1 (Facade tree) + 4 Generator stages. Wave 3.
- Why: Credit facility queries, bond term/finding calculations, underwriting decision building, loss lifecycle accounting, and policy support tangled across 1626 lines
- Target tree:
  - `underwriting_support/credit_facility.rs` (~150) - latest_credit_facility_snapshot, latest_active_granted_credit_facility, facility state queries
  - `underwriting_support/credit_bond.rs` (~450) - build_credit_bond_terms, build_credit_bond_findings, bond prerequisites, disposition logic
  - `underwriting_support/credit_loss.rs` (~200) - compute_credit_loss_lifecycle_accounting; loss state accumulation by event kind
  - `underwriting_support/underwriting.rs` (~450) - build_signed_underwriting_policy_input, build_underwriting_decision_report, build_underwriting_simulation_report, issue_signed_underwriting_decision, list/appeal functions
  - `underwriting_support/mod.rs` (~100) - Facade re-exporting credit facility/bond/loss/underwriting functions; policy_support submodule
- API impact: none (facade)
- Test seam: Mock receipt store queries, report fixtures, credit bond term calculators

**`crates/platform/chio-control-plane/src/trust_control/config_and_public.rs`** - 1545 lines, ~4 modules. Pattern 1 (Facade tree) + 2 Dispatch split. Wave 3.
- Why: Configuration loading (serve, 9 registry loaders, path validators) mixed with public endpoint handlers, passport credential issuer setup, and generic listing domain logic
- Target tree:
  - `config_bootstrap/loaders.rs` (~500) - load_enterprise_provider_registry, load_*_registry_for_admin functions; registry file I/O and deserialization
  - `config_bootstrap/validators.rs` (~250) - configured_*_path helpers, credential issuer setup, path validation, registry existence checks
  - `config_bootstrap/startup.rs` (~150) - serve() function, async runtime setup, service state initialization
  - `config_bootstrap/mod.rs` (~100) - Facade re-exporting serve, loaders, validators; generic_listing submodule
- API impact: none (facade)
- Test seam: Fixture registry files, mock path validators, fake credential issuers

**`crates/platform/chio-control-plane/src/trust_control/capital_and_liability.rs`** - 1510 lines, ~6 modules. Pattern 1 (Facade tree) + 5 Service-handler. Wave 3.
- Why: Capital book building, credit facility/bond/loss lifecycle queries and issuance, liability provider logic, and cross-domain settlement/backtest reports tangled together
- Target tree:
  - `capital_domain/capital_book.rs` (~600) - build_capital_book_report_from_store; capital source/event/accounting logic; currency/facility/bond validation
  - `capital_domain/credit_facilities.rs` (~300) - build_credit_facility_report, issue_signed_credit_facility, list_credit_facilities; facility queries
  - `capital_domain/credit_bonds.rs` (~300) - build_credit_bond_report, issue_signed_credit_bond, list_credit_bonds; bond queries and lifecycle
  - `capital_domain/credit_loss.rs` (~200) - build_credit_loss_lifecycle_report, issue_signed_credit_loss_lifecycle, list_credit_loss_lifecycle; loss event queries
  - `capital_domain/reports.rs` (~250) - build_credit_bonded_execution_simulation_report, build_credit_backtest_report, build_signed_credit_provider_risk_package
  - `capital_domain/mod.rs` (~100) - Facade re-exporting capital/credit/loss functions; liability submodule
- API impact: none (facade)
- Test seam: Mock receipt stores, exposure/facility/bond/loss fixtures, currency validation stubs

### `chio-credit` (1 file)
**`crates/economy/chio-credit/src/credit/capital_and_execution.rs`** - 1918 lines, ~6 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Four distinct domain responsibilities tangled together: (1) capital book ledger types and reports for financial tracking, (2) capital execution instruction types with comprehensive authority validation logic, (3) capital allocation decision types for governed fund distribution, (4) bond execution simulation types with control policies; plus 100+ lines of shared validation helpers and 1100+ lines of comprehensive test suite covering all domains
- Target tree:
  - `capital_and_execution/mod.rs` (~50) - Facade module that declares submodules and re-exports all public types with original names to preserve public API. Declares mod capital_book, mod capital_execution, mod capital_allocation, mod bond_execution, mod validators; re-exports via pub use statements
  - `capital_and_execution/capital_book.rs` (~250) - Capital book ledger types: enums CapitalBookSourceKind, CapitalBookRole, CapitalBookEventKind, CapitalBookEvidenceKind; structs CapitalBookEvidenceReference, CapitalBookSupportBoundary, CapitalBookSource, CapitalBookEvent, CapitalBookSummary, CapitalBookReport; type alias SignedCapitalBookReport; Default impl; unit and integration tests
  - `capital_and_execution/capital_execution.rs` (~400) - Capital execution instruction types and validation: enums CapitalExecutionInstructionAction, CapitalExecutionRole, CapitalExecutionRailKind, CapitalExecutionIntendedState, CapitalExecutionReconciledState; structs CapitalExecutionWindow, CapitalExecutionRail, CapitalExecutionObservation, CapitalExecutionInstructionSupportBoundary, CapitalExecutionInstructionArtifact; type alias SignedCapitalExecutionInstruction; impl validate() on artifact; public validation functions: validate_capital_execution_envelope, ensure_capital_execution_owner_authority, ensure_capital_execution_custodian_authority; Default impl; unit tests for validation and round-trip signature verification
  - `capital_and_execution/capital_allocation.rs` (~150) - Capital allocation decision types: enums CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode; structs CapitalAllocationInstructionDraft, CapitalAllocationDecisionFinding, CapitalAllocationDecisionSupportBoundary, CapitalAllocationDecisionArtifact; type alias SignedCapitalAllocationDecision; Default impl; unit and integration tests
  - `capital_and_execution/bond_execution.rs` (~180) - Bond execution simulation types: enums CreditBondedExecutionDecision, CreditBondedExecutionFindingCode; structs CreditBondedExecutionSimulationQuery, CreditBondedExecutionControlPolicy, CreditBondedExecutionFinding, CreditBondedExecutionSupportBoundary, CreditBondedExecutionEvaluation, CreditBondedExecutionSimulationDelta, CreditBondedExecutionSimulationRequest, CreditBondedExecutionSimulationReport; impl validate() on query; Default impls on policy and support boundary; unit tests for validation
  - `capital_and_execution/validators.rs` (~80) - Shared validation helper functions: validate_capital_instruction_action_shape, validate_capital_instruction_reconciliation, validate_present_clean, validate_non_empty_clean, validate_positive_amount; used by capital_execution module
- API impact: none (facade)
- Test seam: Unit tests colocated with respective modules (capital_book.rs, capital_execution.rs, capital_allocation.rs, bond_execution.rs have dedicated test sections); integration tests for round-trip signature verification use signed artifact constructors available through pub use in facade; test mods are conditional with #[cfg(test)] and access helpers via crate:: paths

### `store-sqlite` (3 files)
_Shared module for this cluster:_ No cross-file shared module needed within cluster. Each file decomposes independently along responsibility seams. Claim_log submodules are shared across support/ and reports/ modules through re-exports via claim_log/mod.rs facade. Bootstrap pool/schema utilities used internally by bootstrap module only.

**`crates/platform/chio-store-sqlite/src/receipt_store/bootstrap.rs`** - 1910 lines, ~5 modules. Pattern 1 (Facade tree) + 7 Typed sections. Wave 1.
- Why: Combines six tangled responsibilities: DDL schema creation (all tables/indexes/triggers), SQLite pragma configuration, connection pool management, receipt query methods (tool/child receipts with context validation), and federated evidence share operations (import/lookup/corpora/lineage).
- Target tree:
  - `bootstrap/mod.rs` (~50) - Facade module re-exporting public SqliteReceiptStore::open/pool methods and delegating to submodules; preserves public API path
  - `bootstrap/schema.rs` (~900) - Database schema creation: all CREATE TABLE/INDEX statements, triggers, pragma configuration, schema validation, and initial setup logic
  - `bootstrap/pool.rs` (~100) - Connection pool configuration and management: pool building, connection flag handling, durability pragma validation, per-connection initialization
  - `bootstrap/queries.rs` (~250) - Receipt and child receipt listing methods: list_tool_receipts*, list_child_receipts*, list_*_after_seq functions with optional context validation
  - `bootstrap/federation.rs` (~400) - Federated evidence operations: import_federated_evidence_share, get_federated_share_for_capability, list_federated_share_subject_corpora, lineage bridge management
- API impact: none (facade)
- Test seam: receipt_store::tests::{bootstrap,query,lineage} - unit tests already separated; bootstrap functions called indirectly via SqliteReceiptStore::open

**`crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log.rs`** - 1777 lines, ~7 modules. Pattern 7 (Typed sections). Wave 1.
- Why: Tangles seven domain responsibilities: claim receipt log validation/backfill, enum state conversions/label functions (settlement, metered billing, underwriting, credit, liability), query matching predicates for different entity types (underwriting decision, credit facility, bond, liability provider, market, claim), authorization profile validation and derived constraint construction, metadata extraction and analysis, receipt aggregation logic, and schema migration/backfill helpers.
- Target tree:
  - `claim_log/mod.rs` (~50) - Facade module re-exporting public validation, parsing, matching, and schema helper functions from submodules
  - `claim_log/validation.rs` (~100) - Claim receipt log projection validation and backfill: validate_claim_receipt_log_entries, backfill, row matching, projection drift detection
  - `claim_log/state_converters.rs` (~200) - State enum to/from string conversions: *_label, parse_* functions for settlement, metered billing, underwriting, credit, liability, and appeal status enums
  - `claim_log/query_matching.rs` (~450) - Domain-specific query predicate functions: *_matches_query for underwriting decision, credit facility/bond, liability provider/market/claim workflows; effective lifecycle state calculations
  - `claim_log/authorization.rs` (~350) - Chio OAuth authorization profile validation and constraint derivation: validate_chio_oauth_authorization_*, resolve_sender_constraint_*, derive_authorization_sender_constraint, call chain binding checks
  - `claim_log/metadata.rs` (~200) - Receipt metadata extraction and analysis: extract_receipt_attribution, extract_financial/governed_transaction/economic_authorization metadata, authorization detail/transaction context builders, metered billing reconciliation analysis
  - `claim_log/schema.rs` (~150) - Schema migration and backfill for evolving receipt store: ensure_tool_receipt_attribution_columns, ensure_receipt_lineage_statement_columns, backfill_tool_receipt_attribution_columns, backfill_provenance_lineage_tables, backfill_claim_receipt_log_entries
- API impact: none (facade)
- Test seam: receipt_store::tests::support, tests/claim_log.rs - functions called from receipt store insert/query/report operations; imports used throughout support/ and reports/ modules

**`crates/platform/chio-store-sqlite/src/receipt_query.rs`** - 1594 lines, ~2 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Public interface method (query_receipts) is trivial (~20 lines), but file embeds ~1550 lines of comprehensive test cases covering all receipt query filters (capability_id, tool_server/name, outcome, time range, cost range, agent_subject), pagination with cursor semantics, limit capping, and combined filter intersections.
- Target tree:
  - `receipt_query.rs` (~20) - Public query interface facade: query_receipts method that delegates to query_receipts_impl in receipt_store.rs; preserves SqliteReceiptStore public API
  - `tests/receipt_query.rs` (~1570) - Comprehensive integration tests for receipt query functionality: filters, pagination, cursor semantics, limit handling, combined filters; follows Rust convention of separate test module
- API impact: none (facade)
- Test seam: Move all #[cfg(test)] mod tests to tests/receipt_query.rs; test helpers (unique_db_path, make_receipt, make_receipt_with_metadata) become shared test utilities; SqliteReceiptStore::query_receipts remains integration point

### `mcp-remote` (2 files)
**`crates/protocol/chio-mcp-remote/src/remote_mcp/oauth.rs`** - 1902 lines, ~5 modules. Pattern 7 (Typed sections). Wave 1.
- Why: OAuth authorization server (LocalAuthorizationServer impl), bearer token authentication (JwtBearerVerifier, IntrospectionBearerVerifier), JWT verification infrastructure, request validation, and helper utilities all tangled in one file. Responsibilities: authorization server lifecycle, bearer authentication, JWT signature/claims verification, OAuth request validation, cryptographic helpers.
- Target tree:
  - `oauth/local_server.rs` (~480) - OAuth authorization server lifecycle and token issuance - authorization page generation, approval processing, authorization code and subject token exchange, token validation and response generation
  - `oauth/bearer_auth.rs` (~450) - Bearer token authentication dispatch and session context building - token extraction, JwtBearerVerifier and IntrospectionBearerVerifier implementations, session auth context validation and construction
  - `oauth/jwt_support.rs` (~300) - JWT signature verification and claims parsing infrastructure - JwtVerificationKeySource and JwtJwksKeySet resolution, JwtResolvedJwkPublicKey signature verification, JwtClaims utility methods, JWT token parsing
  - `oauth/request_validation.rs` (~150) - OAuth request validation and scope resolution - authorization request validation, redirect URI validation, scope parsing and intersection logic
  - `oauth/helpers.rs` (~210) - Cryptographic and utility helpers - PKCE S256 computation, authorization code generation, JWT signing primitives, JWK key IDs, HTML escaping, error response builders, time utilities, header validators
- API impact: none (facade)
- Test seam: Tests can import oauth::local_server, oauth::bearer_auth, oauth::jwt_support, oauth::request_validation, oauth::helpers independently; test_seam is the LocalAuthorizationServer and bearer verifier implementations.

**`crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs`** - 1891 lines, ~7 modules. Pattern 7 (Typed sections) + 5 Service-handler. Wave 1.
- Why: Session lifecycle state machine (RemoteSession), factory/creation logic (RemoteSessionFactory), ledger/tracking (RemoteSessionLedger), state type definitions, auth mode definitions, configuration, and event broadcasting all tangled. Responsibilities: session core state management, session creation and restoration, active/terminal session tracking and cleanup, state type definitions, auth mode configuration, event distribution.
- Target tree:
  - `session_core/session.rs` (~380) - Core session lifecycle state machine - RemoteSession struct with lifecycle transitions (mark_ready, touch, begin_draining, mark_deleted/expired/closed), event notification handling, resume/restore record management, session snapshot and diagnostic generation
  - `session_core/factory.rs` (~410) - Session creation and restoration - RemoteSessionFactory, spawn_session and restore_session methods, upstream MCP server building, kernel configuration, capability issuance and validation
  - `session_core/ledger.rs` (~260) - Session tracking and lifecycle coordination - RemoteSessionLedger active and terminal session storage, session insertion/lookup/removal, lifecycle transitions, idle expiry detection, drain deadline enforcement, tombstone retention and cleanup
  - `session_core/state.rs` (~280) - Session state types and enums - RemoteSessionState, RemoteSessionLifecycleSnapshot, RemoteSessionDiagnosticRecord, RemoteSessionResumeRecord, RemoteSessionOwnershipSnapshot, isolation mode and identity profile enums
  - `session_core/config.rs` (~100) - Configuration and lifecycle policy - RemoteServeHttpConfig (pub), RemoteAppState, SessionLifecyclePolicy, environment variable parsing for session parameters
  - `session_core/auth_types.rs` (~180) - Authentication mode and verifier type definitions - RemoteAuthMode enum (Static, JWT, Introspection), JwtBearerVerifier and IntrospectionBearerVerifier struct definitions, JwtSignatureAlgorithm, JwtVerificationKeySource, JWT type definitions (header, claims, JWKS, discovery)
  - `session_core/event.rs` (~100) - Event broadcasting to session streams - BroadcastJsonRpcWriter for JSON-RPC message distribution, notification event retention and serialization, event ID generation
- API impact: RemoteServeHttpConfig (pub struct) preserved at same path via facade
- Test seam: Tests can import session_core::session, session_core::factory, session_core::ledger independently; test_seam is RemoteSession state machine, factory creation, and ledger cleanup logic.

### `chio-mcp-adapter` (1 file)
**`crates/protocol/chio-mcp-adapter/src/transport.rs`** - 1864 lines, ~5 modules. Pattern 1 (Facade tree) + 5 Service-handler. Wave 1.
- Why: Tangles four responsibilities: (1) subprocess lifecycle and stdio protocol management (StdioMcpTransport, spawn, handshaking), (2) nested-flow task runtime (create/exec/track background tasks), (3) upstream request routing (roots/list, sampling/createMessage, elicitation/create, tasks/* dispatch), (4) parsing and formatting utilities (JSON-RPC, timestamps, error codes, metadata)
- Target tree:
  - `transport/utils.rs` (~280) - Parsing, formatting, error mapping, and I/O helpers: parse_cursor, parse_task_id, parse_requested_task, parse_create_elicitation_operation, json_rpc_result/error, send_line, read_line, send_upstream_cancellation, map_nested_flow_error_code, build_related_task_meta, iso8601_now, etc. Also holds MCP constants.
  - `transport/nested_flow.rs` (~430) - Self-contained task management subsystem: RequestedTask, NestedFlowTaskStatus/Operation/FinalOutcome, NestedFlowTask (state and lifecycle), NestedFlowTaskRuntime (task queue, execution, background processing). Imports utils for timestamps and error mapping.
  - `transport/handlers.rs` (~210) - Upstream request/notification dispatching: respond_to_upstream_nested_flow (roots/list, sampling/createMessage, elicitation/create, tasks/list/get/cancel/result), respond_to_upstream_roots_without_bridge, forward_upstream_notification, service_active_request_runtime. Routes incoming messages and orchestrates task runtime ticks.
  - `transport/stdio.rs` (~570) - Core transport lifecycle and McpTransport trait: StdioMcpTransport struct, spawn/initialize/shutdown, send_request/send_request_with_nested_flow (the request/response loop), queue_notification, McpTransport impl (list_tools, call_tool, list_resources, list_prompts, etc.), Drop impl. Coordinates subprocess I/O with handlers for nested-flow support.
  - `transport/mod.rs` (~50) - Facade re-exporting public API (StdioMcpTransport, any needed struct declarations) and module organization. Imports and re-exports from submodules to maintain unchanged public path.
- API impact: none (facade)
- Test seam: MockNestedFlowBridge trait and mutable access to NestedFlowTaskRuntime in tests; each module keeps unit tests for its functions (e.g., NestedFlowTask tests in nested_flow.rs, utility function tests in utils.rs); integration test in stdio.rs for full round-trip with mock server. All tests remain valid since internal structure is unchanged.

### `chio-policy` (2 files)
**`crates/guards/chio-policy/src/compiler.rs`** - 1857 lines, ~7 modules. Pattern 2 (Dispatch split) + 4 Generator stages. Wave 1.
- Why: Tangles rule compilation dispatch (10+ guard types across three pipelines: rule-driven, detection-extension, origin-budget), tool-constraint generation logic, and pattern-matching utilities. The compile_policy orchestrator coordinates five distinct responsibilities: rule blocks → rule-driven guards (ForbiddenPath through CodeExecution), detection blocks → detection guards (PromptInjection, Jailbreak, SpiderSense), budget aggregation → AgentVelocity, tool_access rules → scope constraints with conditional widening, and glob pattern matching for tool names.
- Target tree:
  - `rules.rs` (~270) - Compile rule-driven guards (ForbiddenPath, Velocity, ShellCommand, Egress, Mcp/Tool, SecretLeak, PatchIntegrity, PathAllowlist, ComputerUse, RemoteDesktop, InputInjection, BrowserAutomation, CodeExecution) from rules blocks. Handles per-rule-type configuration mapping (e.g., ComputerUseRule → ComputerUseConfig). Includes VelocityRule compilation, all compile_*_rule helper functions.
  - `detection.rs` (~145) - Compile detection-extension guards (PromptInjectionGuard, JailbreakGuard, SpiderSenseGuard) from extensions.detection blocks. Handles pattern DB loading with asset path resolution, detection-level to score-threshold mapping, jailbreak threshold normalization, config defaults.
  - `budgets.rs` (~50) - Compile origin-budget velocity guards from extensions.origins profiles. Aggregates per-origin tool_calls budgets to determine per-agent request ceiling within 60-second window.
  - `scope.rs` (~240) - Compile default ChioScope from tool_access rules. Encodes tool allowlist/blocklist, confirmation requirements, max_args_size, and runtime assurance tiers as ToolGrant constraints. Handles conditional widening to wildcards, selective confirmation detection, constraint accumulation. Complex gates permit only representable scopes.
  - `patterns.rs` (~90) - Tool-pattern matching utilities for glob expansion, overlap detection, literal-prefix extraction. Glob-to-regex conversion with wildcard and double-wildcard support. Used by scope and confirmation-matching logic. Confirmation-overlap validation.
  - `mod.rs` (~90) - Facade, public API, and orchestrator. Exports compile_policy, compile_policy_with_source, CompileError, CompiledPolicy. Houses PipelineBuilder (guard name tracking) and ensure_compilable_policy. Orchestrator calls compile_rule_guards, compile_detection_guards, compile_budget_guards, compile_scope; assembles CompiledPolicy.
  - `tests.rs` (~900) - Test suite covering compilation paths: empty policies, validation error propagation, per-guard compilation, scope narrowing/widening logic, tool pattern overlap detection, velocity config, detection level mapping. ~40 test cases. Threat-intel fixture helpers.
- API impact: none (facade)
- Test seam: Integration tests via compile_policy and compile_policy_with_source; unit tests per sub-module. Threat-intel pattern_db fixtures in tests.rs.

**`crates/guards/chio-policy/src/models.rs`** - 1564 lines, ~6 modules. Pattern 7 (Typed sections). Wave 1.
- Why: Tangles three orthogonal concerns: (1) YAML parser safety validation (~300 lines of helper functions for malformed scalars, unclosed quotes, overflow-risk detection), (2) HushSpec schema types (14 rule structs, 85 lines enums), (3) extension schema definitions (6 domains: Detection, Reputation, RuntimeAssurance, Chio, Posture, Origins; ~360 lines). YAML safety is cross-cutting validation; rules and extensions are distinct policy domains with separate concerns and defaults.
- Target tree:
  - `enums.rs` (~85) - All simple enums: Severity, DefaultAction, ComputerUseMode, TransitionTrigger, OriginDefaultBehavior, DetectionLevel, Classification, LifecycleState, MergeStrategy. Pure data; derived traits (serde, clone, copy, debug, partial_eq, ord).
  - `rules.rs` (~260) - Rules struct and 14 rule type definitions: ForbiddenPathsRule, PathAllowlistRule, EgressRule, SecretPatternsRule, PatchIntegrityRule, ShellCommandsRule, ToolAccessRule, ComputerUseRule, RemoteDesktopChannelsRule, InputInjectionRule, BrowserAutomationRule, CodeExecutionRule, VelocityRule, HumanInLoopRule. Plus helpers WorkloadIdentityMatch, SecretPattern, HumanInLoopTimeoutAction.
  - `extensions.rs` (~360) - Extensions struct and all extension-domain hierarchies: DetectionExtension (PromptInjectionDetection, JailbreakDetection, ThreatIntelDetection), ReputationExtension (ScoringConfig, Weights, Tiers, Promotion, Demotion, Triggers, TierScope, RequiredMetrics), RuntimeAssuranceExtension (TierRule, VerifierRule), ChioExtension (MarketHours, Signing, K8sNamespaces, Rollback, HumanInLoopAdvanced), PostureExtension (State, Transition), OriginsExtension (Profile, Match, DataPolicy, Budgets, BridgePolicy, BridgeTarget).
  - `yaml_safety.rs` (~300) - YAML parser safety helpers preventing libyml crashes and DoS: has_non_mapping_document_start, has_unclosed_double_quoted_value_scalar, has_libyml_scalar_join_overflow_risk, plain_scalar overflow detection, structural_mapping_colon_index, quote/escape tracking, whitespace-run detection. Stateful scanning before serde_yml.
  - `mod.rs` (~180) - Facade and root schema. HushSpec struct, parse/to_yaml methods, GovernanceMetadata, default value helpers (default_true, default_block, default_allow, default_imbalance_ratio, etc.). Re-exports all public types. HushSpec::parse orchestrates yaml_safety validators then serde_yml with panic recovery.
  - `tests.rs` (~19) - Test suite (models/tests.rs already exists; preserve or integrate). Tests for rule blocks, metadata, extension parsing, round-tripping. Can expand to cover YAML safety edge cases.
- API impact: none (facade)
- Test seam: Unit tests per sub-module (enums, rules, extensions, yaml_safety); integration tests via HushSpec::parse. Existing models/tests.rs can remain or be split. Full YAML safety edge case coverage (quoted scalar overflow, unclosed quotes, plain scalar joins).

### `control-plane/policy` (1 file)
**`crates/platform/chio-control-plane/src/policy.rs`** - 1830 lines, ~10 modules. Pattern 1 (Facade tree) + 7 Typed sections. Wave 1.
- Why: File conflates nine distinct responsibilities: policy type definitions, guard configuration types, capability configuration types, policy I/O and parsing, HushSpec materialization, guard pipeline construction, capability building, tool access pattern matching, and hashing utilities. All tangled in a single ~1830-line module.
- Target tree:
  - `policy/types.rs` (~280) - Core policy type definitions (LoadedPolicy, ChioPolicy, PolicyError, PolicyIdentity, PolicyFormat, KernelPolicyConfig, and issuance policy types). Public contracts for policy structure.
  - `policy/guard_config.rs` (~330) - All guard-specific configuration structs (GuardPolicyConfig, ForbiddenPathConfig, EgressAllowlistConfig, ToolAccessConfig, PatchIntegrityConfig, external adapter configs, cloud guardrails configs). Default helper functions for guard parameters.
  - `policy/capability_config.rs` (~80) - Capability-related configuration types: CapabilityPolicyConfig, DefaultCapabilityConfig, and grant configs (ToolGrantConfig, ResourceGrantConfig, PromptGrantConfig). Default functions for capability parameters.
  - `policy/loader.rs` (~160) - Policy I/O and parsing: load_policy(), load_hushspec_policy(), parse_policy(). HushSpec resolution helpers: hushspec_auxiliary_asset_digests(), resolve_policy_asset_path(), hushspec_source_hash_with_assets().
  - `policy/issuance.rs` (~160) - Materialize reputation and runtime assurance policies from HushSpec specifications: materialize_reputation_issuance_policy(), materialize_runtime_assurance_policy(). Isolated transformation logic.
  - `policy/guards.rs` (~380) - Guard pipeline construction: build_guard_pipeline(), build_post_invocation_pipeline(). Guard-specific builders (build_azure_content_safety_guard, build_safe_browsing_guard). External guard adapter configuration and validation helpers.
  - `policy/capabilities.rs` (~140) - Capability building from policy grants: build_runtime_default_capabilities(), build_default_capabilities(). Internal builders for capability map construction and scope synthesis.
  - `policy/tool_access.rs` (~215) - Tool access pattern matching and constraint compilation: synthesize_tool_access_scope(), compile_tool_constraints(), tool_patterns_overlap(). Glob pattern overlap detection with memoization and budget validation.
  - `policy/util.rs` (~65) - Utility functions: parse_operations(), runtime_hash_for_chio_yaml(), runtime_hash_for_hushspec(), hash_json_value(), hash_bytes(). Pure functions with no policy-specific logic.
  - `policy/mod.rs` (~50) - Facade module. Re-exports all public items from submodules to preserve the public module path (chio_control_plane::policy::*) so callers don't change.
- API impact: none (facade)
- Test seam: policy/tests.rs uses `use super::*;` and re-exports from mod.rs facade. No changes needed to test module after split  -  tests continue to import from the facade.

### `chio-mcp-edge` (2 files)
**`crates/protocol/chio-mcp-edge/src/runtime.rs`** - 1788 lines, ~6 modules. Pattern 2 (Dispatch split) + 3 Verifier pipeline. Wave 1.
- Why: Monolithic request dispatcher mixing event loop orchestration (serve_stdio, serve_inbound_loop), request/notification handlers (handle_initialize, handle_tools_list, handle_resources_*, handle_prompts_*, handle_completion), session/state management, client request forwarding (send_client_request), and background event handling (forward_runtime_events, emit_log). Each domain should be a separate concern.
- Target tree:
  - `runtime/mod.rs` (~150) - Facade re-exporting ChioMcpEdge, McpEdgeConfig, McpExposedTool, and constants. Orchestrates submodule imports. Callers see no path change.
  - `runtime/orchestrator.rs` (~400) - ChioMcpEdge struct definition, new(), restoration, and initialization. Session auth/peer capability management. Helper methods (ready_session_id, current_ready_session_id, has_completion_support, visible_tools, next_request_id).
  - `runtime/dispatcher.rs` (~850) - Request routing and operation handlers: handle_request, handle_initialize, handle_tools_list, handle_resources_list/read/subscribe/unsubscribe/templates, handle_prompts_list/get, handle_completion, handle_logging_set_level, handle_known_notification, handle_notification.
  - `runtime/loop.rs` (~280) - Event loop and transport integration: serve_stdio, serve_message_channels, serve_inbound_loop, handle_jsonrpc and transport variants (handle_jsonrpc_with_transport, handle_jsonrpc_with_transport_channel), CLIENT_IDLE_POLL_INTERVAL polling.
  - `runtime/events.rs` (~350) - Background event processing and notification management: forward_runtime_events, forward_tool_server_events, forward_upstream_notifications, handle_upstream_transport_notification, emit_log methods, queue_session_tool_server_event, flush_session_late_events, process_pending_actions_with_channel, queue_roots_refresh, refresh_roots_from_client_with_channel, drain_runtime_notifications.
  - `runtime/client_flow.rs` (~280) - Client communication and nested flow sampling: send_client_request, send_client_request_with_channel (blocking request loops), create_message (nested sampling flow), take_deferred_client_message, take_pending_notifications, flush_pending_notifications, notification queuing.
- API impact: none (facade)
- Test seam: Existing test modules (runtime/execution_nonce_tests.rs, runtime/runtime_tests.rs, runtime/source_receipt_tests.rs) remain unchanged; import from runtime::{orchestrator, dispatcher, loop, events, client_flow} as needed.

**`crates/protocol/chio-mcp-edge/src/runtime/protocol.rs`** - 1566 lines, ~10 modules. Pattern 7 (Typed sections) + 1 Facade tree. Wave 1.
- Why: Giant utility collection mixing JSON-RPC protocol parsing, tool result conversion with streaming, task/request metadata parsing, capability selection, serialization helpers, pagination, response builders, frame I/O, and cancellation logic. Split by functional area: (1) envelope/RPC validation, (2) tool result conversion, (3) request parsing/extraction, (4) capability selection, (5) serialization/pagination, (6) JSON-RPC response building, (7) frame I/O and message pumping, (8) metadata attachment.
- Target tree:
  - `runtime/protocol.rs` (~80) - Facade re-exporting all protocol submodules. Preserves existing pub use paths so callers see no change.
  - `runtime/protocol/envelope.rs` (~130) - JSON-RPC envelope parsing and validation: parse_jsonrpc_envelope, ensure_known_request_params_object, known_request_method, known_notification_method, JsonRpcEnvelope struct.
  - `runtime/protocol/tool_results.rs` (~220) - Tool result conversion and streaming support: kernel_response_to_tool_result, queue_tool_stream_chunk_notifications, streamed_notification_tool_result, collapsed_stream_tool_result, tool_stream_structured_content, value_to_tool_result, tool_error_result, terminal_state_label/reason functions.
  - `runtime/protocol/tasks.rs` (~180) - Task-related parsing and helper functions: parse_requested_task, parse_task_id, RequestedTask struct, edge_task_status_label, tool_result_is_error, cancellation_reason_from_tool_result, task_status_message, explicit_task_cancel_reason.
  - `runtime/protocol/metadata.rs` (~200) - Metadata attachment and elicitation helpers: attach_related_task_meta_to_result, attach_execution_nonce_meta_to_result, attach_related_task_meta_to_message, capture_accepted_url_elicitation, make_elicitation_completion_notification, build_related_task_meta, tool_call_outcome_to_jsonrpc, task_outcome_to_jsonrpc.
  - `runtime/protocol/parsing.rs` (~300) - Request field extraction and parsing: parse_request_model_metadata, parse_request_execution_nonce, parse_request_governed_intent, parse_request_extra_metadata, parse_progress_token, parse_peer_capabilities, parse_completion_reference, parse_completion_argument, parse_protocol_identifier, parse_cursor, build_operation_context.
  - `runtime/protocol/serialization.rs` (~140) - Serialization and pagination helpers: serialize_resources, serialize_resource_templates, serialize_resource_contents, serialize_prompts, paginate_response, paginate_named_response, KernelResponseToToolResultArgs struct.
  - `runtime/protocol/response.rs` (~160) - JSON-RPC response and error builders: jsonrpc_result, jsonrpc_error, jsonrpc_error_with_data, adapter_jsonrpc_error, write_jsonrpc_line, read_jsonrpc_line, progress_token_to_value, queue_progress_notification.
  - `runtime/protocol/capabilities.rs` (~80) - Capability selection and matching: select_capability_for_request, select_capability_for_resource, select_capability_for_resource_subscription, select_capability_for_prompt, select_capability_for_resource_pattern, tool_is_authorized, matches_server, matches_name.
  - `runtime/protocol/messaging.rs` (~200) - Message pumping and cancellation handling: pump_client_messages, pump_channel_messages, next_client_message, is_cancellation_side_channel_signal, cancellation_matches_request, cancellation_matches_client_request, task_cancel_matches_related_task, cancellation_reason.
- API impact: none (facade)
- Test seam: Existing tests in protocol.rs (lines 1370-1565) split and moved alongside their tested functions. Import testing utilities from submodules; keep integration tests in runtime/runtime_tests.rs.

### `chio-guards` (1 file)
**`crates/guards/chio-guards/src/response_sanitization.rs`** - 1761 lines, ~9 modules. Pattern 1 (Facade tree) + 7 Typed sections. Wave 1.
- Why: Two API layers (simple Guard + full OutputSanitizer) with tangled pattern detection (regex registry, multi-detector pipeline, fail-closed validation), validation strategies (Luhn, SSN, entropy), large sanitize_text() orchestration logic, overlap resolution, token vault state management, and text formatting helpers all in one file.
- Target tree:
  - `types.rs` (~160) - Configuration and result types: SensitiveCategory, RedactionStrategy, Span, SensitiveDataFinding, Redaction, ProcessingStats, SanitizationResult, SanitizedValue, all *Config structs, and OutputSanitizerConfigError.
  - `simple.rs` (~260) - Backwards-compatible simple API: SensitivityLevel, SensitivePattern, SanitizationAction, ResponseSanitizationGuard, ScanResult, helper functions (level_ord, default_patterns, build_pattern), and Guard trait impl. Includes tests for simple API.
  - `detectors.rs` (~200) - Built-in pattern registry: CompiledPattern struct, build_compiled_patterns() with all 15+ detectors (secrets, PII, internal), compiled_patterns() lazy singleton, redact_all_finding(), HIGH_ENTROPY_TOKEN_PATTERN constant, fail-closed compilation logic.
  - `validators.rs` (~150) - Validation functions: shannon_entropy_ascii(), is_luhn_valid_card_number(), is_valid_ssn_fragments(), is_valid_ssn_compact(), is_candidate_secret_token(). Includes validator unit tests.
  - `formatting.rs` (~80) - Text formatting and hashing: preview_redacted() for display, truncate_to_char_boundary() for limits, fingerprint() for SHA256 identifiers.
  - `vault.rs` (~50) - TokenVault and TokenVaultInner: Mutex-protected HashMap for Tokenize strategy state. Methods: new(), insert(), get(), len(), is_empty().
  - `overlap.rs` (~80) - Overlap resolution for conflicting findings: strategy_rank(), redaction_strategy_for_finding(), is_mandatory_redaction_finding(), non_keep_redaction_strategy(), resolve_overlaps() (longest-match-wins with strategy tiebreaker), detect_service_account_object() JSON object detection.
  - `sanitizer.rs` (~500) - Core OutputSanitizer implementation: struct definition, sanitize_text() multi-detector orchestration and redaction application, sanitize_value() JSON recursion, sanitize_value_inner() depth-first traversal, replacement_for() strategy dispatch, Clone/Debug/Default impls. Includes OutputSanitizer unit tests.
  - `mod.rs` (~50) - Facade module: re-exports all public items (types, guards, strategies, configs, vaults, etc.) preserving the public API path so external callers see no change.
- API impact: none (facade)
- Test seam: Module-level #[cfg(test)] blocks in each module (integrated with code), particularly validators.rs (Luhn/SSN/entropy tests), simple.rs (Guard API tests), and sanitizer.rs (OutputSanitizer functional tests). Integration tests can live in parent tests/ if needed.

### `chio-federation` (1 file)
**`crates/trust/chio-federation/src/bilateral_dsse.rs`** - 1713 lines, ~5 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Five distinct responsibilities tangled: (1) type definitions and wire-format constants for DSSE envelopes and bilateral predicates; (2) policy evaluation validation; (3) envelope predicate and statement building; (4) signing operations (both legacy and strict Chio profiles); (5) verification and schema validation logic with 15+ helper utilities
- Target tree:
  - `bilateral_dsse/types.rs` (~380) - Type definitions (Keyid, StatementSubject, SubjectDigest, KernelIdentity, BilateralPredicate, CapabilityLeaseRef, HashRecord, PolicyVerdict, PolicyEvaluationSummary, GovernanceReceiptRef, TreatyBindingRef, DsseStatement, DsseSignature, DsseEnvelope, BilateralPredicateExtensions), wire-format constants, and impl blocks for DsseStatement and DsseEnvelope
  - `bilateral_dsse/policy.rs` (~70) - Policy evaluation validation: validate_policy_evaluation_summary, require_policy_evaluation_allow_admission (public); internal validators for policy verdicts and field non-emptiness
  - `bilateral_dsse/builder.rs` (~200) - DSSE envelope building and predicate construction: pae encoding, receipt_subject_name, build_predicate variants (basic and full), build_chio_bilateral_invocation_predicate, build_statement variants
  - `bilateral_dsse/sign.rs` (~310) - Envelope signing operations: sign_dsse_envelope (basic and full), sign_chio_bilateral_dsse_envelope, sign_dsse_envelope_with_cosigner variants with remote signer support
  - `bilateral_dsse/verify.rs` (~570) - DSSE envelope verification (signature-slice and strict Chio profiles), schema validation (validate_signature_slice_predicate, validate_chio_predicate, validate_treaty_binding_ref), and 10+ helper utilities (digest computation, signature decoding, field validation, treaty binding validation)
- API impact: none (facade)
- Test seam: Leverage existing separate test file bilateral_dsse/tests.rs for integration tests; add unit tests per module for builder and verify logic; sign module tests can validate round-trips with verify

### `chio-proof-room` (1 file)
**`crates/products/chio-proof-room/src/source_verifier.rs`** - 1656 lines, ~8 modules. Pattern 1 (Facade tree) + 3 Verifier pipeline. Wave 2 (launch-critical).
- Why: This file tangles seven distinct responsibilities: orchestration pipeline (choosing which domain-specific verifiers to invoke), report transformation (normalization/merging/sorting claims), context loading and validation (passport/evidence-graph I/O with SHA256 checks), evidence graph processing (scoping graphs by node type filters), claim management (requirement parsing/verification/deduplication), runtime parity handling (specialized proof regeneration validation), and artifact loading. Each domain has grown to 150-380 lines with few seams between them.
- Target tree:
  - `source_verifier/mod.rs` (~120) - Facade re-exporting all pub(crate) items and main entry point for report verification (dispatches to family vs standalone paths)
  - `source_verifier/orchestrator.rs` (~380) - Family report generation pipeline with conditional domain routing (commerce, disclosure, swarm, settlement, agent-web, enterprise, runtime, risk). Includes trust market context extraction and report pushing helpers
  - `source_verifier/context.rs` (~250) - SourceVerifierContext struct, context loading/validation from passport files, evidence graph artifact discovery and loading, enterprise export sidecar handling, SHA256 digest validation
  - `source_verifier/report_transform.rs` (~180) - Report normalization (claim ordering, field insertion, recursive family handling), family report merging, unwrapped single-family matching. JSON transformation utilities
  - `source_verifier/evidence_graph.rs` (~180) - Evidence graph scoping and filtering by node type predicates. Node classification functions (trust_market, agent_web, enterprise, runtime). Graph structure preservation during filtering
  - `source_verifier/claims.rs` (~180) - SourceVerifierClaimRequirements struct, claim requirement parsing from policy, claim deduplication, verified claims extraction, claim-to-checker mapping, required claim validation
  - `source_verifier/runtime_parity.rs` (~270) - Runtime proof parity report attachment, regeneration artifact validation (with 7 required artifact types), hash matching for parity/package/report, workflow step binding verification
  - `source_verifier/standalone.rs` (~120) - Standalone risk report generation (SourceRiskRoute evaluation), standalone passport file verification without family reports, basic passport artifact validation
- API impact: none (facade)
- Test seam: Each module has natural unit-test boundaries: orchestrator tests for domain routing/conditional branching, context tests for passport/artifact loading, report_transform tests for normalization idempotence, evidence_graph tests for scoping preservation, claims tests for requirement parsing/deduplication, runtime_parity tests for hash validation/workflow binding, standalone tests for risk evaluation. Integration tests at orchestrator level verify end-to-end family report generation.

### `chio-web3` (1 file)
**`crates/economy/chio-web3/src/settlement_proof.rs`** - 1632 lines, ~10 modules. Pattern 3 (Verifier pipeline) + 1 Facade tree. Wave 2 (launch-critical).
- Why: Monolithic verifier combining 25+ data types with 15+ independent verification stages (signature, provenance, trust keys, policy, witness, snapshots, order binding, finality/dispute) orchestrated sequentially into a single file.
- Target tree:
  - `types` (~700) - All struct and enum definitions: PublicSettlementProofBundle, VerifierReport, 8 snapshot types, trust context, witness context, finality/dispute context, dispute posture, witness mode.
  - `orchestrator` (~300) - Main verify_public_settlement_proof function, bundle header validation, chain binding validation, required_* accessor helpers, settlement_state_id and push_claim_once utilities.
  - `signature` (~70) - validate_public_settlement_bundle_signature, public_settlement_bundle_signature_body, public_settlement_witness_body_hash calculation with PublicSettlementWitnessBody struct.
  - `provenance` (~90) - validate_deployment_provenance: contract package, registry, escrow, bond vault, manifest hash validation.
  - `trust` (~130) - validate_public_settlement_trust, require_trusted_public_settlement_key (capital signer, anchor kernel, beneficiary identity), validate_trust_market_refs, validate_expected_trust_market_context.
  - `policy` (~100) - validate_public_settlement_verifier_policy: chain allow-list, mainnet blocking, minimum confirmations enforcement; public_settlement_chain_is_mainnet helper.
  - `witness` (~120) - validate_public_witness: mode validation (Advisory rejection, VerifiedCache age checks), body hash verification, chain/registry/tx hash consistency.
  - `snapshots` (~350) - validate_chain_snapshot orchestrator, validate_escrow_snapshot, validate_bond_snapshot, validate_block_snapshot, validate_independent_chain_head, required_chain_anchor/bond_snapshot/block_snapshot/beneficiary_identity_binding/dispute_snapshot accessors.
  - `binding` (~130) - validate_order_binding, validate_order_binding_tuple (9-field tuple validation), validate_beneficiary_identity_binding (purpose scope, chain scope, time validity).
  - `finality` (~180) - validate_finality, validate_dispute_posture, validate_finality_settlement_state, validate_dispute_snapshot, active_dispute_posture, finality_report_status (8-way state + posture mapping).
- API impact: none (facade)
- Test seam: verify_public_settlement_proof(bundle: &PublicSettlementProofBundle, trust: &PublicSettlementVerifierTrust) -> Result<PublicSettlementVerifierReport, Web3ContractError>; test harness mocks external crate::settlement::validate_web3_settlement_execution_receipt and crate::anchors::verify_oracle_conversion_evidence_signature, provides fixture bundles with nested snapshots.

### `chio-anchor-evm` (1 file)
**`crates/economy/chio-anchor/src/evm.rs`** - 1612 lines, ~9 modules. Pattern 1 (Facade tree). Wave 1.
- Why: File mixes 9 distinct responsibilities: data structures (5 pub structs), hashing/encoding utilities, EVM input validation, RPC egress contract management, root publication preparation, low-level JSON-RPC communication, publication state inspection/confirmation, on-chain verification, and record building. Additionally contains ~888 lines of test infrastructure (MockJsonRpcServer, MockRawHttpServer, sample generators, HTTP parsing helpers) and 24 test cases.
- Target tree:
  - `types` (~130) - Data structure definitions: EvmAnchorTarget, ValidatedEvmAnchorTarget, PreparedEvmRootPublication, PreparedDelegateRegistration, EvmPublicationReceipt, EvmPublicationGuard, JsonRpcEnvelope, JsonRpcError; includes validate() impl on EvmAnchorTarget
  - `hashing` (~25) - Cryptographic and encoding utilities: operator_key_hash, operator_key_hash_hex (derive operator identifier), hash_to_b256 (alloy type conversions), parse_hex_u64 (RPC payload parsing)
  - `validation` (~70) - EVM anchor target validation pipeline: validate_evm_chain_id (enforce eip155 format), validate_evm_rpc_url (HTTP/HTTPS URL structure), parse_nonzero_evm_address (checksum and zero-address checks), parse_validated_evm_anchor_target (orchestrator)
  - `egress` (~100) - HttpEgressContract lifecycle and enforcement: validate_rpc_egress_contract (policy enforcement), devnet_rpc_egress_contract_for_url (loopback-only builder), normalized_rpc_authority (IPv6-aware normalization), rpc_host_is_loopback (address-class check), evm_anchor_devnet_rpc_egress_contract (public entry)
  - `preparation` (~90) - Transaction preparation: prepare_root_publication (assemble publishRoot calldata with binding validation and sequence metadata), prepare_delegate_registration (assemble registerDelegate calldata with expiry validation)
  - `rpc` (~80) - Low-level JSON-RPC dispatch: rpc_call (envelope handling, error surface), publish_root (gas estimation + eth_sendTransaction), estimate_publication_gas (eth_estimateGas with safety multiplier)
  - `publication` (~140) - Publication state lifecycle: confirm_root_publication (receipt parsing, contract state verification), inspect_publication_guard (read authorization + sequence guard), ensure_publication_ready (readiness checks: authorization + sequence monotonicity)
  - `verification` (~70) - On-chain proof verification: verify_inclusion_onchain (merkle proof validation via eth_call to contract, operator binding checks)
  - `records` (~20) - Finalized record construction: build_chain_anchor_record (map receipt + checkpoint into Web3ChainAnchorRecord for downstream use)
- API impact: none (facade)
- Test seam: Existing #[cfg(test)] mod tests (~888 lines) can be preserved in-place, distributed per module, or migrated to tests/ directory. Test infrastructure (MockJsonRpcServer, MockRawHttpServer, read_http_request, parse_json_request, write_http_json_response, http_status_text, etc.) are tightly coupled to RPC responsibilities; distribute alongside rpc.rs. Sample generators (sample_primary_proof, sample_binding, sample_checkpoint, sample_target, sample_delegate_target, sample_rpc_contract) belong with types.rs.

### `chio-ag-ui-proxy` (1 file)
**`crates/protocol/chio-ag-ui-proxy/src/proxy.rs`** - 1601 lines, ~8 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Configuration + core authorization logic + classification derivation + scope/constraint matching + budget tracking + error handling + comprehensive test suite all in one file; no existing submodules
- Target tree:
  - `config.rs` (~130) - Configuration types (AgUiProxyConfig, ParentBudgetSnapshot, AdmittedChildBudget) and their serde defaults
  - `decision.rs` (~15) - Public decision and error types (ProxyDecision enum, AgUiProxyError enum)
  - `classify.rs` (~40) - Event classification derivation from event type and payload (derive_server_classification, derive_lifecycle_classification)
  - `clock.rs` (~10) - System clock implementation for capability verification (SystemClock struct, Clock trait)
  - `helpers.rs` (~170) - Utility functions for scope/constraint matching, error messages, tool name mapping, and budget error construction
  - `budget.rs` (~35) - Budget registry initialization and parent/child budget snapshot seeding
  - `core.rs` (~280) - AgUiProxy struct, constructor methods, core authorization (decide/decide_capability_bound_event/admit_capability_budget), receipt building, and config accessor
  - `mod.rs` (~50) - Facade re-exports of all public types; module declarations; test helpers and full test suite (preserved for comprehensive coverage)
- API impact: none (facade)
- Test seam: Tests stay in mod.rs test module; test helpers (make_event, make_capability, etc.) are internal fixtures used by all test cases

### `chio-core` (1 file)
**`crates/core/chio-core/src/identity_network.rs`** - 1572 lines, ~6 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Monolithic file mixes 6 distinct responsibilities: schema constants, public type definitions (8 enums, 8 structs, 4 type aliases), error enum, 4 public validation orchestrators, 12 private helper validators, and ~820 lines of tests with fixture builders. No separation between data contracts, error handling, validation logic tiers, or tests.
- Target tree:
  - `identity_network/mod.rs` (~50) - Facade re-exporting public API (constants, all types, error, 4 public validators). Preserves the current public module path so callers do not change: use chio_core::identity_network::{ValidateFn, ErrorType, ArtifactType}.
  - `identity_network/types.rs` (~270) - Data contracts: 4 schema string constants (CHIO_PUBLIC_*_SCHEMA), 8 public enums (IdentityArtifactKind, IdentityDidMethod, IdentityCredentialFamily, IdentityProofFamily, WalletTransportMode, IdentityInteropScenarioKind, IdentityQualificationOutcome), 8 public structs with Serialize/Deserialize (IdentityArtifactReference, IdentityBindingPolicy, PublicIdentityProfileArtifact, WalletDirectoryLookupGuardrails, PublicWalletDirectoryEntryArtifact, WalletRoutingGuardrails, PublicWalletRoutingManifestArtifact, IdentityInteropQualificationCase, IdentityInteropQualificationMatrix), 4 type aliases (SignedPublicIdentityProfile, etc.), Default impls for policy structs.
  - `identity_network/error.rs` (~20) - Error type: IdentityNetworkContractError enum with 6 variants (UnsupportedSchema, MissingField, DuplicateValue, InvalidReference, InvalidProfile, InvalidDirectoryEntry, InvalidRouting, InvalidQualificationCase). Single-purpose error module for clarity.
  - `identity_network/validation.rs` (~245) - Public validation orchestrators: validate_public_identity_profile, validate_public_wallet_directory_entry, validate_public_wallet_routing_manifest, validate_identity_interop_qualification_matrix. Each function coordinates checks specific to its artifact domain (e.g., profile validation calls binding_policy, ref validation, method checks, credential family checks). Imports validators module for private helpers.
  - `identity_network/validators.rs` (~175) - Private helper validators: 12 focused validation functions (validate_identity_artifact_reference, validate_identity_binding_policy, validate_wallet_directory_lookup_guardrails, validate_wallet_routing_guardrails, validate_https_url, validate_hex_digest, contains_non_chio_method, ensure_required_transports, ensure_refs_present, ensure_non_empty, ensure_unique_strings, ensure_unique_copy_values). No public exports; purely internal re-used validation primitives.
  - `identity_network/tests.rs` (~820) - All test infrastructure: 5 test fixture builders (hex, sample_reference, sample_profile, sample_directory_entry, sample_routing_manifest, sample_matrix), 1 expect_contract_err helper, 12 test functions (profile_validation*, profile_requires_*, wallet_directory*, routing_manifest*, qualification_matrix*, identity_helper*, reference_artifacts_parse*). Comprehensive coverage of all validators and error cases.
- API impact: none (facade)
- Test seam: identity_network::tests module; test fixtures (sample_profile, sample_reference, etc.) become test-only helpers within tests; private validators accessed via super::validators from tests

### `control-plane/issuance` (1 file)
**`crates/platform/chio-control-plane/src/issuance.rs`** - 1543 lines, ~7 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Five independent policy enforcement concerns tangled together: (1) capability authority wrapping and delegation orchestration; (2) reputation corpus building and inspection with tier resolution; (3) runtime attestation verification with binding validation; (4) scope ceiling enforcement with type-specific grant validation; (5) tier-based scope constraints and runtime assurance tier binding.
- Target tree:
  - `issuance/types.rs` (~80) - Data type definitions: ReputationScoringSource, ProbationaryStatus, LocalReputationTierView, LocalReputationInspection, ImportedTrustReport. No behavior, only serde-annotated structures for serialization and policy result reporting.
  - `issuance/util.rs` (~15) - Utility functions: unix_now() for current timestamp, and any shared helper constants. No domain logic.
  - `issuance/authority.rs` (~140) - Capability authority wrapping: PolicyBackedCapabilityAuthority struct, wrap_capability_authority() factory, and CapabilityAuthority trait implementation. Orchestrates reputation policy, runtime assurance policy, and receipt storage. Does not implement policy checks itself, delegates to specialized modules.
  - `issuance/attestation.rs` (~70) - Runtime attestation validation and verification: validate_runtime_attestation_binding() for local workload identity consistency checks, verify_runtime_attestation_for_issuance() to verify evidence against optional trust policy with delegated chio_appraisal verification.
  - `issuance/reputation.rs` (~280) - Reputation scoring and corpus building: inspect_local_reputation[_with_read_context]() for reputation inspection; build_local_reputation_corpus[_with_read_context]() to assemble receipts, capabilities, and budget usage from SQLite stores; enforce_reputation_policy() to check subject against policy tiers; resolve_tier() and scoring_context() for tier matching and config merging; all reputation-specific policy enforcement logic.
  - `issuance/scope.rs` (~220) - Scope and grant enforcement: enforce_scope_ceiling() common ceiling check, enforce_tool_grant/enforce_resource_grant/enforce_prompt_grant() for type-specific grant validation, enforce_runtime_assurance_policy() to resolve runtime assurance tier and inject minimum attestation constraints, resolve_runtime_assurance_tier(), grant_is_economically_sensitive() for cost-aware constraint injection, enforce_tier_scope() for reputation tier ceiling.
  - `issuance/mod.rs` (~80) - Facade and re-exports. Exposes all public types and public functions (wrap_capability_authority, inspect_local_reputation, build_local_reputation_corpus, and variants) at the same path chio_control_plane::issuance::*. Minimal internal re-export paths for cross-module testing. Contains integration tests exercising the full issuance flow.
- API impact: none (facade)
- Test seam: wrap_capability_authority() is the primary integration test entry point; inspect_local_reputation[_with_read_context]() and build_local_reputation_corpus[_with_read_context]() are secondary integration seams. Unit tests per module (types has few tests, util has none, authority exercises delegation, attestation exercises verification, reputation exercises corpus and inspection, scope exercises ceiling and grant enforcement). Test helpers (test_policy, test_runtime_assurance_policy, make_receipt, make_subject_capability) are shared or duplicated as needed.

### `control-plane/passport_verifier` (2 files)
_Shared module for this cluster:_ None required within this cluster. However, note that shared helpers (SQLite conversion, timestamp, validation) are extracted to shared.rs and internally used. The chio_core::Keypair and chio_credentials imports remain external cross-crate dependencies.

**`crates/platform/chio-control-plane/src/passport_verifier.rs`** - 1530 lines, ~6 modules. Pattern 1 (Facade tree) + 6 Store split. Wave 1.
- Why: File tangles six distinct responsibilities: (1) verifier policy registry lifecycle, (2) passport status registry & lifecycle state management, (3) issuance offer registry with OID4VCI state machine, (4) SQLite-backed verifier challenge store with schema & queries, (5) SQLite-backed OID4VP transaction store with schema & queries, (6) shared validation, time, conversion, and serialization helpers. No single module has a cohesive purpose under 1200 lines.
- Target tree:
  - `policy_registry` (~100) - VerifierPolicyRegistry type and impl: load/save, get, active_policy, upsert, remove. Manages signed verifier policy documents and their lifecycle.
  - `status_registry` (~290) - PassportStatusRegistry type and impl: load/save, get, publish, resolve, revoke, portable_status_reference_for_passport. Manages passport lifecycle records (Active/Superseded/Revoked/Stale states) and status distribution.
  - `issuance_offer_registry` (~330) - PassportIssuanceOfferState enum, PassportIssuanceOfferRecord struct, PassportIssuanceOfferRegistry impl. Manages OID4VCI pre-authorized code offers, token redemption, and credential issuance state transitions.
  - `challenge_store` (~220) - PassportVerifierChallengeStore impl with SQLite schema, register/fetch_active/consume operations, challenge_identifier, challenge_hash. Manages verifier challenge lifecycle (issued/consumed/expired states).
  - `oid4vp_transaction_store` (~302) - Oid4vpVerifierTransactionStore impl with SQLite schema, register/fetch_active/snapshot/consume operations. Manages OID4VP presentation request-response transaction lifecycle and state.
  - `shared` (~150) - Shared helpers: SQLite i64/u64 converters, wallet_exchange_status_from_store, build_wallet_exchange_transaction_state, stored_challenge_row, stored_oid4vp_request_row, unix timestamp conversions, verify_passport_lifecycle_record, passport_lifecycle_resolution_from_record, passport_lifecycle_is_stale, verify_passport_issuance_offer_record, refresh_passport_issuance_offer_state, normalize_credential_issuer, KeyId generator.
- API impact: none (facade)
- Test seam: JSON serialization for registries (load/save), SQLite in-memory or temp files for stores, validation functions (verify_* functions), passport verification integration.

**`crates/platform/chio-control-plane/src/passport_verifier/mod.rs`** - 0 lines, ~0 modules. Pattern 1 (Facade tree). Wave 1.
- Why: Facade module created to re-export all public items from submodules, preserving the public path passport_verifier::* so callers do not change. mod.rs includes: pub use statements for VerifierPolicyRegistry, PassportStatusRegistry, PassportStatusListResponse, PublishPassportStatusRequest, PassportStatusRevocationRequest, PassportIssuanceOfferState, PassportIssuanceOfferRecord, PassportIssuanceOfferRegistry, PassportVerifierChallengeStore, Oid4vpVerifierTransactionStore, Oid4vpTransactionSnapshot, and challenge_identifier fn.
- Target tree:
- API impact: none (facade)
- Test seam: Public API unchanged; callers import from passport_verifier:: without modification.

### `chio-core-types` (1 file)
**`crates/core/chio-core-types/src/session.rs`** - 1520 lines, ~12 modules. Pattern 7 (Typed sections). Wave 1.
- Why: Large type definition file combining session identifiers, authentication contexts, session anchors with cryptographic signing, request lineage tracking, operation metadata, root/URI normalization logic, and operation payloads for various resource/prompt/message types
- Target tree:
  - `session/mod.rs` (~45) - Facade re-exporting all public types and constants; preserves public module path for callers
  - `session/identifiers.rs` (~80) - SessionId, RequestId, ProgressToken newtype wrappers with Display, AsRef, From trait impls
  - `session/ownership.rs` (~75) - SessionTransport, WorkOwner, StreamOwner, RequestOwnershipSnapshot, TaskOwnershipSnapshot - ownership and stream lifecycle enums/structs
  - `session/auth.rs` (~325) - SessionAuthMethod variants, OAuthBearerFederatedClaims, EnterpriseIdentityContext, ChioIdentityAssertion with validation, SessionAuthContext with builder constructors and hash methods, OAuthBearerSessionAuthInput
  - `session/anchor.rs` (~225) - SessionProofBinding, SessionAnchorReference, SessionAnchorBody, SessionAnchorContext, SessionAnchor with sign/verify/anchor_hash/matches_context methods
  - `session/lineage.rs` (~130) - RequestLineageMode, RequestLineageRecord with builder pattern (with_parent_request_id, with_capability_attribution, with_intent_hash, etc.) and mode predicates
  - `session/operation.rs` (~90) - OperationTerminalState with is_completed/is_cancelled/is_incomplete predicates, OperationKind enum with as_str method, OperationContext struct
  - `session/normalization.rs` (~260) - RootDefinition, NormalizedRoot with from_root_definition/is_enforceable_filesystem/normalized_filesystem_path, ResourceUriClassification with from_uri, plus internal helpers normalize_local_file_uri_path/normalize_absolute_filesystem_path/split_windows_drive/extract_uri_scheme
  - `session/resources.rs` (~170) - ToolCallOperation, ResourceDefinition, ResourceTemplateDefinition, ResourceContent, PromptArgument, PromptDefinition, PromptMessage, PromptResult, CompletionReference, CompletionArgument, CompletionResult, SamplingMessage, SamplingTool, SamplingToolChoice
  - `session/messages.rs` (~80) - CreateMessageOperation, CreateMessageResult, ElicitationAction enum, CreateElicitationOperation with Form/Url variants, CreateElicitationResult
  - `session/payloads.rs` (~35) - ReadResourceOperation with classify_uri_for_runtime, GetPromptOperation, CompleteOperation - capability-bearing operation payload wrappers
  - `session/session_op.rs` (~50) - SessionOperation enum with kind/content variants for all operation types; kind() dispatcher to OperationKind; root object orchestrating all operation payload types
- API impact: none (facade)
- Test seam: tests/ directory (separate test files or integrated into existing test structure)

## 6. Classified index (files 1,200-1,500 lines; Wave 3)

One row each: apply the cited catalog pattern. WARN-tier (does not fail CI); split opportunistically.

| Lines | File | Pattern | Target modules |
|---|---|---|---|
| 1497 | `crates/kernel/chio-kernel/src/checkpoint.rs` | 7 Typed sections | core, publication, proofs, transparency, equivocation, continuity |
| 1494 | `crates/platform/chio-transaction-passport/src/evidence_graph.rs` | 3 Verifier pipeline | node_validation, edge_validation, binding_validation, signature_validation, graph_traversal, artifact_parsing |
| 1491 | `crates/platform/chio-control-plane/src/trust_control/credit_and_loss.rs` | 4 Generator stages | facility, bond, execution, loss_lifecycle, helpers |
| 1482 | `crates/platform/chio-agent-web-interop/src/artifacts.rs` | 2 Dispatch split | a2a, acp_client, acp_commerce, ag_ui, ap2, asyncapi, browser_automation, calendar, cloudevents, email, graphql_http, mcp, oauth2, openapi, openid_connect, rpa, scim, slack, spiffe, standard_webhooks, x402 |
| 1472 | `crates/trust/chio-custody-hw/src/revocation.rs` | 7 Typed sections | cascade, inmemory, sqlite |
| 1468 | `crates/core/chio-core-types/src/crypto.rs` | 7 Typed sections | algorithm, keypair, public_key, signature, signed_payload, ed25519, fips, helpers |
| 1450 | `crates/products/chio-api-protect/src/proxy/sidecar.rs` | 2 Dispatch split | evaluate, verify, mint, release, submit_receipt, capabilities, validate, control, scope, operations, helpers |
| 1439 | `crates/protocol/chio-a2a-adapter/src/invoke.rs` | 2 Dispatch split | discovery, auth, task_operations, notifications, invocation, streaming, subscriptions, messages, trait_impl |
| 1439 | `crates/economy/chio-settle/src/evm/mod.rs` | 1 Facade tree | decode, finalize, prepare, sign, types |
| 1436 | `crates/tooling/chio-conformance/src/native_suite.rs` | 1 Facade tree | types, execution, fixtures, report |
| 1436 | `crates/products/chio-cli/src/passport.rs` | 1 Facade tree | registry, transport, lifecycle, trust_tier |
| 1432 | `crates/products/chio-cli/src/cli/types/trust.rs` | 2 Dispatch split | serve, provider, federation_policy, evidence_share, scim, verifier_policy, passport, certification |
| 1431 | `crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs` | 5 Service-handler | metadata, issuance, presentation, lifecycle, challenges |
| 1427 | `crates/guards/chio-policy/src/evaluate/matchers.rs` | 3 Verifier pipeline | tool_call, file_ops, shell, computer_use, path, posture, origin |
| 1425 | `crates/economy/chio-anchor/src/witness/rekor.rs` | 8 Transport layering | client, envelope, verification, support |
| 1410 | `crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs` | 5 Service-handler | provider, quote, placement, claim, settlement |
| 1405 | `crates/kernel/chio-kernel/src/approval.rs` | 5 Service-handler | types, guard, store, filters |
| 1402 | `crates/economy/chio-settle/src/payments.rs` | 4 Generator stages | x402, eip3009, circle, paymaster, nonce_store |
| 1400 | `crates/core/chio-core-types/src/canonical.rs` | 7 Typed sections | canonical/mod.rs, canonical/numbers.rs, canonical/strings.rs, canonical/value.rs |
| 1390 | `crates/products/chio-mercury/src/commands/account_delivery.rs` | 4 Generator stages | account_delivery/mod.rs, account_delivery/export.rs, account_delivery/validation.rs, account_delivery/types.rs |
| 1385 | `crates/kernel/chio-kernel/src/session.rs` | 1 Facade tree | session/mod.rs, session/registries.rs, session/state.rs, session/handlers.rs |
| 1374 | `crates/platform/chio-control-plane/src/trust_control/cluster_and_reports.rs` | 1 Facade tree | cluster_and_reports/mod.rs, cluster_and_reports/tests.rs |
| 1372 | `crates/platform/chio-control-plane/src/evidence_export.rs` | 6 Store split | evidence_export/mod.rs, evidence_export/types.rs, evidence_export/operations.rs, evidence_export/verification.rs |
| 1369 | `crates/products/chio-proof-room/src/fixture_b.rs` | 4 Generator stages | fixture_b/mod.rs, fixture_b/embedded_graph.rs, fixture_b/schema_verification.rs, fixture_b/helpers.rs |
| 1362 | `crates/kernel/chio-kernel/src/budget_store/in_memory.rs` | 6 Store split | in_memory/mod.rs, in_memory/store.rs, in_memory/holds.rs, in_memory/mutations.rs |
| 1359 | `crates/products/chio-cli/src/cli/dispatch/trust.rs` | 2 Dispatch split | trust/mod.rs, trust/serve.rs, trust/provider.rs, trust/federation_policy.rs, trust/evidence_share.rs, trust/authorization_context.rs, trust/appraisal.rs, trust/behavioral_feed.rs, trust/exposure_ledger.rs, trust/credit_scorecard.rs, trust/capital_book.rs, trust/facility.rs, trust/bond.rs, trust/loss.rs |
| 1357 | `crates/platform/chio-workflow/src/authority.rs` | 1 Facade tree | authority/mod.rs, authority/execution.rs, authority/validation.rs, authority/finalization.rs |
| 1356 | `crates/platform/chio-risk-comptroller/src/lib.rs` | 3 Verifier pipeline | lib.rs, facility.rs, coverage.rs, reconciliation.rs, capital.rs, appeals.rs |
| 1350 | `crates/trust/chio-pheromone-relay/src/assurance.rs` | 7 Typed sections | types.rs, generation.rs, export.rs, reporting.rs |
| 1346 | `crates/trust/chio-selective-disclosure/src/lib.rs` | 7 Typed sections | lib.rs, projection.rs, bbs_signing.rs, proof.rs |
| 1328 | `crates/platform/chio-store-sqlite/src/receipt_store/liability_market.rs` | 6 Store split | mod.rs, providers.rs, quotes.rs, placements.rs, binding.rs |
| 1320 | `crates/guards/chio-guard-registry/src/oci.rs` | 5 Service-handler | lib.rs, reference.rs, client.rs, http.rs, artifact.rs |
| 1302 | `crates/kernel/chio-kernel/src/kernel/validation.rs` | 5 Service-handler | mod.rs, capability.rs, budget.rs, payment.rs, session.rs |
| 1301 | `crates/platform/chio-store-sqlite/src/budget_store/store.rs` | 6 Store split | mod.rs, usage.rs, mutations.rs, holds.rs, validation.rs |
| 1290 | `crates/protocol/chio-provider-adapter-core/src/http.rs` | 8 Transport layering | lib.rs, auth.rs, transport.rs, mock.rs, validation.rs |
| 1283 | `crates/products/chio-wall/src/commands.rs` | 2 Dispatch split | mod.rs, export.rs, validate.rs, evidence.rs |
| 1282 | `crates/guards/chio-wasm-guards/src/runtime/wasmtime_backend.rs` | 1 Facade tree | instance_pool, backend, guard_loader, mod.rs |
| 1281 | `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` | 7 Typed sections | capability_verify, receipt_sign, delegation, budget, scope, mod.rs |
| 1280 | `crates/guards/chio-policy/src/validate.rs` | 3 Verifier pipeline | rules, posture, detection, reputation, runtime_assurance, mod.rs |
| 1272 | `crates/trust/chio-disclosure-lineage/src/verifier.rs` | 3 Verifier pipeline | capsule, privacy_profile, lineage, leakage_ledger, bundle_bindings, hidden_predicates, mod.rs |
| 1265 | `crates/products/chio-cli/src/cli/runtime.rs` | 1 Facade tree | setup, session, message_loop, mod.rs |
| 1244 | `crates/products/chio-proof-room/src/fixture_a.rs` | 4 Generator stages | source, report, helpers, mod.rs |
| 1237 | `crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs` | 5 Service-handler | rate_limiter, handlers, mcp_protocol, mod.rs |
| 1235 | `tests/replay/src/bless.rs` | 1 Facade tree | providers, stubs, mod.rs |
| 1228 | `crates/products/chio-cli/src/cli/runtime/trust_reports.rs` | 2 Dispatch split | evidence, authorization, behavioral_feed, exposure, capital, credit_facility, credit_bond, mod.rs |
| 1223 | `crates/platform/chio-store-sqlite/src/receipt_store.rs` | 6 Store split | actor, query, write, checkpoint |
| 1223 | `crates/economy/chio-market/src/insurance_flow.rs` | 7 Typed sections | types, claim, policy |
| 1220 | `crates/platform/chio-control-plane/src/attestation/verification.rs` | 3 Verifier pipeline | azure_maa, google_confidential_vm, aws_nitro |
| 1218 | `crates/protocol/chio-mcp-remote/src/remote_mcp/http_service_auth.rs` | 2 Dispatch split | session, bearer_tokens, metadata, authorization_details, dpop |
| 1215 | `crates/kernel/chio-kernel-core/src/capability_verify.rs` | 3 Verifier pipeline | verify, trust_resolution, binding |
| 1206 | `crates/kernel/chio-kernel/src/kernel/construction.rs` | 5 Service-handler | accessors, stores, federation, nonce, registration |
| 1206 | `crates/guards/chio-wasm-guards/src/hot_reload.rs` | 7 Typed sections | canary, watchdog, engine |
| 1205 | `xtask/src/launch_acceptance.rs` | 4 Generator stages | stages, validation, reports, support |
| 1201 | `crates/economy/chio-open-market/src/bidding.rs` | 7 Typed sections | types, bid, settlement |

## 7. Risks and mitigations

- **Silent behavior change during a move** (esp. a verifier check turning
  advisory, pattern 3). Mitigation: pure-move commits only; the full test suite +
  negative fixtures + the launch-acceptance gate must stay green; review each
  verifier split against its `RejectReason` set.
- **Merge conflicts with PR #937 WIP.** Mitigation: Wave 2 is gated behind the
  #937 merge; Waves 1/3 touch non-launch files.
- **Facade misses a re-export.** Mitigation: `cargo build` fails closed on a
  missing item; no `pub use *` globs.
- **Canonical-bytes drift in type splits** (pattern 7). Mitigation: keep field
  order and serde attrs; canonical-JSON/schema tests pin the wire form.

## 8. Verification strategy

Per file: build + test + clippy + fmt + hygiene, allowlist entry removed. Per
wave: full `cargo test --workspace` and (for Wave 2) `cargo xtask verify
launch-acceptance` green. Repo-wide done: the allowlist is empty, the WARN-tier
count trends down, and a re-run of the hygiene check is green with no production
file over 2,000 / no `lib.rs` over 1,000.

## 9. Open decisions for the owner

1. WARN-tier values: 1,200 / 900 as proposed, or different?
2. Execute Wave 1 now as a batch, or file-by-file PRs?
3. Want a writing-plans implementation plan generated next, or keep this as
   spec + catalog only?
