# Codebase Hygiene Baseline

Generated: 2026-06-06

Branch and head at scan time: `codex/chio-next-10-remediation` at `d253a8faa`

This baseline records the current file-size and stub-surface hotspots before
the codebase hygiene modularization plan is executed. It uses the current
worktree as authoritative, not the older line counts embedded in the plan.

## Commands

```bash
git ls-files '*.rs' | while read f; do lines=$(wc -l < "$f"); printf "%5d %s\n" "$lines" "$f"; done | sort -nr | sed -n '1,100p'
find crates -path '*/src/lib.rs' -print | while read f; do lines=$(wc -l < "$f"); printf "%5d %s\n" "$lines" "$f"; done | sort -nr
rg -n "bbs-stub|not_yet_implemented|stub|placeholder|advisory only|TODO|FIXME|HACK|XXX" crates tests examples scripts docs | sed -n '1,240p'
cargo metadata --no-deps --format-version 1 > /tmp/chio-metadata.json
```

`cargo metadata` completed and wrote `/tmp/chio-metadata.json` with 128
packages and 588,730 bytes of metadata.

## Category Summary

| Category | Current evidence | Planned handling |
| --- | ---: | --- |
| Generated Rust | 4 tracked generated Rust files. Largest is `crates/chio-core-types/src/_generated/chio_wire_v1.rs` at 30,223 lines. | Phase 8 quarantines generated Rust behind generator and check boundaries. |
| Production Rust | 1,089 tracked production Rust files. 44 hand-maintained production files are currently at or above 2,000 lines. | Phases 1 through 6 split crate roots, core protocol files, control-plane slabs, runtime slabs, and remaining production hotspots. |
| Test Rust | 556 tracked test Rust files. 18 test files are currently at or above 2,000 lines. | Phase 7 splits test aggregates by behavior family without deleting coverage. |
| Example Rust | 26 tracked example Rust files. Largest is `examples/chio-3vendor/src/commands.rs` at 935 lines. | No immediate split required by the Rust hygiene threshold. |
| Large docs and structured data | Large tracked Markdown, JSON, TOML, YAML, and workflow files include `spec/PROTOCOL.md` at 3,073 lines, `docs/operations/ROADMAP.md` at 1,608 lines, and `docs/architecture/CHIO_FINAL_ARCHITECTURE.md` at 1,235 lines. | Phase 8 classifies large docs into live, reference, research, roadmap, and archive buckets. |
| Local untracked clutter | `.codex/` contains PR patches, logs, review JSON, and cleanup metadata. `docs/superpowers/` contains local plan files. | Preserve as unrelated local state unless a later task explicitly owns a file. |

## Hotspot Table

| File | Lines | Category | Owner crate or area | Planned phase |
| --- | ---: | --- | --- | --- |
| `crates/chio-core-types/src/_generated/chio_wire_v1.rs` | 30,223 | generated | `chio-core-types` | Phase 8.1 |
| `crates/chio-cli/tests/receipt_query.rs` | 16,159 | test | `chio-cli` | Phase 7.1 |
| `crates/chio-kernel/src/kernel/tests/all.rs` | 11,910 | test | `chio-kernel` | Phase 7.2 |
| `crates/chio-store-sqlite/src/receipt_store/tests.rs` | 7,028 | test | `chio-store-sqlite` | Phase 7.3 |
| `crates/chio-acp-proxy/src/tests/all.rs` | 6,941 | test | `chio-acp-proxy` | Phase 7.3 |
| `crates/chio-cli/tests/mcp_serve_http.rs` | 6,316 | test | `chio-cli` | Phase 7 follow-up after receipt split |
| `crates/chio-a2a-adapter/src/tests/all.rs` | 6,259 | test | `chio-a2a-adapter` | Phase 7.3 |
| `crates/chio-core-types/src/capability.rs` | 5,495 | production | `chio-core-types` | Phase 3.1 |
| `crates/chio-control-plane/src/trust_control/cluster_and_reports.rs` | 5,458 | production | `chio-control-plane` | Phase 4.2 |
| `crates/chio-cli/tests/passport.rs` | 5,387 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-control-plane/src/trust_control/service_runtime.rs` | 5,310 | production | `chio-control-plane` | Phase 4.1 |
| `crates/chio-cli/tests/mcp_serve.rs` | 4,496 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-store-sqlite/src/budget_store/tests.rs` | 1,451 | test | `chio-store-sqlite` | split from `budget_store.rs` in Phase 6.1 |
| `crates/chio-mcp-edge/src/runtime/runtime_tests.rs` | 4,346 | test | `chio-mcp-edge` | Phase 7 follow-up |
| `crates/chio-cli/src/cli/trust/receipt.rs` | 1,874 | production | `chio-cli` | split from `trust_commands.rs` in Phase 6.1 |
| `crates/chio-cli/src/cli/types/trust.rs` | 1,433 | production | `chio-cli` | split from `types.rs` in Phase 6.1 |
| `crates/chio-cli/tests/certify.rs` | 3,639 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-control-plane/src/attestation/verification.rs` | 1,221 | production | `chio-control-plane` | split from `attestation.rs` in Phase 6.1 |
| `crates/chio-federation/src/bilateral_verifier/cosign.rs` | 837 | production | `chio-federation` | split from `bilateral_verifier.rs` in Phase 6.1 |
| `crates/chio-core-types/src/receipt.rs` | 3,438 | production | `chio-core-types` | Phase 3.2 |
| `crates/chio-wasm-guards/src/runtime.rs` | 3,357 | production | `chio-wasm-guards` | Phase 5.1 |
| `crates/chio-mcp-edge/src/runtime.rs` | 3,310 | production | `chio-mcp-edge` | Phase 5.2 |
| `crates/chio-control-plane/src/policy.rs` | 1,830 | production | `chio-control-plane` | split inline tests to `policy/tests.rs` in Phase 6.1 |
| `crates/chio-mercury/tests/cli.rs` | 3,262 | test | `chio-mercury` | Phase 7 follow-up |
| `crates/chio-cli/tests/trust_cluster.rs` | 3,208 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-attest-buyer-core/src/lib.rs` | 3,200 | production lib root | `chio-attest-buyer-core` | Phase 2.1 |
| `crates/chio-mcp-remote/src/remote_mcp/session_core.rs` | 3,194 | production | `chio-mcp-remote` | Phase 6.1 |
| `crates/chio-api-protect/src/proxy/tests.rs` | 2,973 | test | `chio-api-protect` | split from `proxy.rs` in Phase 6.1 |
| `crates/chio-control-plane/src/evidence_export.rs` | 3,039 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/capital_and_liability.rs` | 2,914 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-acp-edge/src/tests/all.rs` | 2,881 | test | `chio-acp-edge` | Phase 7 follow-up |
| `crates/chio-federation/src/lib.rs` | 2,803 | production lib root | `chio-federation` | Phase 2.2 |
| `crates/chio-a2a-edge/src/tests/all.rs` | 2,702 | test | `chio-a2a-edge` | Phase 7 follow-up |
| `crates/chio-control-plane/src/trust_control/service_types.rs` | 2,690 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-cross-protocol/src/lib.rs` | 2,651 | production lib root | `chio-cross-protocol` | Phase 2.3 |
| `crates/chio-control-plane/src/trust_control/underwriting_and_support.rs` | 2,625 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-federation/src/bilateral_dsse.rs` | 2,610 | production | `chio-federation` | Phase 6.1 |
| `crates/chio-control-plane/src/certify.rs` | 2,572 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-cli/src/passport.rs` | 2,468 | production | `chio-cli` | Phase 6.1 |
| `crates/chio-mcp-remote/src/remote_mcp/http_service.rs` | 2,456 | production | `chio-mcp-remote` | Phase 6.1 |
| `crates/chio-kernel/src/kernel/validation.rs` | 2,423 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-cli/src/cli/runtime.rs` | 2,387 | production | `chio-cli` | Phase 6.1 |
| `crates/chio-core-types/src/session.rs` | 2,354 | production | `chio-core-types` | Phase 6.1 |
| `crates/chio-mcp-adapter/src/lib.rs` | 2,304 | production lib root | `chio-mcp-adapter` | Phase 2.4 |
| `crates/chio-cli/tests/federated_issue.rs` | 2,294 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-open-market/src/lib.rs` | 2,285 | production lib root | `chio-open-market` | Phase 1.2 |
| `crates/chio-autonomy/src/lib.rs` | 2,226 | production lib root | `chio-autonomy` | Phase 6.2 |
| `crates/chio-credentials/src/tests.rs` | 2,164 | test | `chio-credentials` | Phase 7 follow-up |
| `crates/chio-policy/src/models.rs` | 2,157 | production | `chio-policy` | Phase 6.1 |
| `crates/chio-kernel/src/budget_store.rs` | 2,153 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-http-core/src/authority.rs` | 2,122 | production | `chio-http-core` | Phase 6.1 |
| `crates/chio-governance/src/lib.rs` | 2,116 | production lib root | `chio-governance` | Phase 1.1 |
| `crates/chio-control-plane/src/trust_control/credit_and_loss.rs` | 2,094 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-runtime-core/tests/runtime_buyer_review.rs` | 2,062 | test | `chio-runtime-core` | Phase 7 follow-up |
| `crates/chio-core/src/extension.rs` | 2,061 | production | `chio-core` | Phase 6.1 |
| `crates/chio-web3/src/lib.rs` | 2,055 | production lib root | `chio-web3` | Phase 1.3 |
| `crates/chio-kernel/src/kernel/mod.rs` | 2,040 | production | `chio-kernel` | Phase 6.1 |
| `xtask/src/main.rs` | 2,022 | production | `xtask` | Phase 6.1 |
| `crates/chio-kernel/src/session.rs` | 2,012 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/config_and_public.rs` | 2,009 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-mcp-remote/src/remote_mcp/tests.rs` | 2,008 | test | `chio-mcp-remote` | Phase 7 follow-up |
| `crates/chio-kernel/src/receipt_support.rs` | 2,007 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-mercury/src/commands/core_cli.rs` | 2,002 | production | `chio-mercury` | Phase 6.1 |

## Lib Root Inventory

The current `src/lib.rs` inventory shows 27 crate roots over 1,000 lines:

| File | Lines | Planned phase |
| --- | ---: | --- |
| `crates/chio-attest-buyer-core/src/lib.rs` | 3,200 | Phase 2.1 |
| `crates/chio-federation/src/lib.rs` | 2,803 | Phase 2.2 |
| `crates/chio-cross-protocol/src/lib.rs` | 2,651 | Phase 2.3 |
| `crates/chio-mcp-adapter/src/lib.rs` | 2,304 | Phase 2.4 |
| `crates/chio-open-market/src/lib.rs` | 2,285 | Phase 1.2 |
| `crates/chio-autonomy/src/lib.rs` | 2,226 | Phase 6.2 |
| `crates/chio-governance/src/lib.rs` | 2,116 | Phase 1.1 |
| `crates/chio-web3/src/lib.rs` | 2,055 | Phase 1.3 |
| `crates/chio-attest-loopback/src/lib.rs` | 1,920 | Phase 6.2 |
| `crates/chio-runtime/src/lib.rs` | 1,742 | Phase 6.2 |
| `crates/chio-pheromone/src/lib.rs` | 1,740 | Phase 6.2 |
| `crates/chio-appraisal/src/lib.rs` | 1,705 | Phase 6.2 |
| `crates/chio-egress-contract/src/lib.rs` | 1,692 | Phase 6.2 |
| `crates/chio-federation-authority/src/lib.rs` | 1,661 | Phase 6.2 |
| `crates/chio-listing/src/lib.rs` | 1,641 | Phase 6.2 |
| `crates/chio-pheromone-runtime/src/lib.rs` | 1,579 | Phase 6.2 |
| `crates/chio-kernel-browser/src/lib.rs` | 1,563 | Phase 6.2 |
| `crates/chio-underwriting/src/lib.rs` | 1,560 | Phase 6.2 |
| `crates/chio-credit/src/lib.rs` | 1,560 | Phase 6.2 |
| `crates/chio-market/src/lib.rs` | 1,551 | Phase 6.2 |
| `crates/chio-openai/src/lib.rs` | 1,428 | Phase 6.2 |
| `crates/chio-link/src/lib.rs` | 1,396 | Phase 6.2 |
| `crates/chio-openapi-mcp-bridge/src/lib.rs` | 1,277 | Phase 6.2 |
| `crates/chio-cpp-kernel-ffi/src/lib.rs` | 1,148 | Phase 6.2 |
| `crates/chio-groq-tools-adapter/src/lib.rs` | 1,077 | Phase 6.2 |
| `crates/chio-selective-disclosure/src/lib.rs` | 1,050 | Phase 6.2 |
| `crates/chio-mistral-tools-adapter/src/lib.rs` | 1,046 | Phase 6.2 |

## Stub Surface Snapshot

The first 240 stub-surface hits show the expected mix of docs, scripts, tests,
and production markers. The production hits that need explicit policy are:

| File | Current hit | Planned handling |
| --- | --- | --- |
| `crates/chio-federation/src/selective_disclosure.rs` | Documents and exports the `bbs-stub` feature surface, including the `.stub` schema suffix. | Task 0.3 allowlists only because it is honestly feature-gated. Phase 2.2 keeps it isolated. |
| `crates/chio-federation/src/lib.rs` | Root docs and exports for `#[cfg(feature = "bbs-stub")]`. | Task 0.3 allowlists only because it names the explicit feature gate. |
| `crates/chio-api-protect/src/proxy/sidecar.rs` | `Capability attenuation (501 not_yet_implemented stub)` marker. | Task 0.3 must initially fail or flag this unless Task 5.3 replaces it with real attenuation or fail-closed unsupported behavior. |
| `crates/chio-custody-hw/src/capability.rs`, `issuer.rs`, and `mint.rs` | `new_stub_unsigned` helpers are used around unsigned passkey capability construction. | Task 0.3 must either prove these are test or explicit bootstrap surfaces, or require a production cleanup before final close. |
| `crates/chio-config/src/interpolation.rs` | Parser leaves a placeholder to allow later resolution. | Task 0.3 must classify whether this is a legitimate domain term or an actionable placeholder surface. |
| `crates/chio-metering/src/export.rs` | Timestamp fallback uses a placeholder. | Task 0.3 must classify whether the fallback is acceptable production behavior. |
| `crates/chio-lineage/src/anchor.rs` | PQ signature language says stub. | Task 0.3 must classify or force cleanup. |
| `crates/chio-guard-registry/src/pull.rs` | Mentions placeholder JSON. | Task 0.3 must classify or force cleanup. |
| `crates/chio-policy/src/detection.rs` | Uses `stub` as a detector name in policy tests and logic. | Task 0.3 must avoid a false positive if this is domain data, not unfinished behavior. |

Large non-production hit families include replay fixture placeholders under
`tests/replay`, threat-coverage test stubs under `scripts/tests`, and research
or archive documentation under `docs/research` and `docs/archive`.

## Large Document Snapshot

Large docs and structured files over 1,000 lines are already separated from
production Rust for the cleanup plan. The main live or reference document
targets are:

| File | Lines | Category | Planned phase |
| --- | ---: | --- | --- |
| `spec/PROTOCOL.md` | 3,073 | live protocol contract | Phase 8.2 classification |
| `docs/protocols/FUTURE-MOATS-AND-RESEARCH.md` | 1,720 | research or reference | Phase 8.2 classification |
| `docs/operations/ROADMAP.md` | 1,608 | roadmap | Phase 8.2 classification |
| `docs/research/CHIO_ANCHOR_RESEARCH.md` | 1,539 | research | Phase 8.2 classification |
| `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md` | 1,531 | reference | Phase 8.2 classification |
| `docs/research/flink-jvm/04-implementation-plan.md` | 1,499 | research plan | Phase 8.2 classification |
| `docs/protocols/DATA-LAYER-INTEGRATION.md` | 1,332 | reference | Phase 8.2 classification |
| `docs/reference/AGENT_ECONOMY.md` | 1,296 | reference | Phase 8.2 classification |
| `docs/architecture/CHIO_FINAL_ARCHITECTURE.md` | 1,235 | live architecture contract | Phase 8.2 classification |
| `docs/guards/13-CODE-EXECUTION-GUARDS.md` | 1,227 | reference | Phase 8.2 classification |
| `spec/CHIO_LADDER.md` | 1,198 | protocol reference | Phase 8.2 classification |
| `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` | 1,177 | reference | Phase 8.2 classification |
| `docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md` | 1,151 | reference | Phase 8.2 classification |
| `docs/research/CHIO_SETTLE_RESEARCH.md` | 1,141 | research | Phase 8.2 classification |
| `docs/reference/AGENT_REPUTATION.md` | 1,141 | reference | Phase 8.2 classification |
| `docs/protocols/DX-AND-ADOPTION-ROADMAP.md` | 1,130 | roadmap | Phase 8.2 classification |
| `docs/research/CHIO_WEB3_CONTRACT_ARCHITECTURE.md` | 1,120 | research | Phase 8.2 classification |
| `docs/operations/EXECUTION_PLAN.md` | 1,116 | roadmap or historical execution | Phase 8.2 classification |

Large lockfiles, supply-chain config, test vectors, generated registries, and
workflow files are not hand-maintained prose targets for Phase 8.2, but they
remain visible in the raw line-count command output.

## Local Dirty State At Baseline

The baseline was created with existing unrelated state present:

```text
 M docs/README.md
?? .codex/
?? docs/superpowers/
```

The modified `docs/README.md` links a separate June 5 remediation plan.
The untracked `.codex/` tree contains PR review and cleanup artifacts. The
untracked `docs/superpowers/` tree contains local plan files, including the
codebase hygiene modularization plan that drives this cleanup. These files are
not part of Task 0.1 and should remain unstaged unless a later task explicitly
owns them.
