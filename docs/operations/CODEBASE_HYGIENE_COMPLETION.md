# Codebase Hygiene Review-Repair Evidence

Generated: 2026-06-06

Branch and code head before this review-repair evidence refresh:
`codex/chio-next-10-remediation` at `36d62f10b`.

This document records the current codebase hygiene state after review repair.
It does not claim the test-suite decomposition is complete. The remaining
oversized test suites are now explicit, capped hygiene debt rather than hidden
by the test-file classification.

The earlier full workspace CI evidence was collected before the review-repair
commits that tightened stub allowlists, generated-file validation, whitespace
cleanliness, crate-root modularity, and oversized-test debt caps. Current
targeted verification commands are listed below.

## Baseline Commands Re-run

```bash
git ls-files '*.rs' | while read f; do lines=$(wc -l < "$f"); printf "%5d %s\n" "$lines" "$f"; done | sort -nr | sed -n '1,100p'
find crates -path '*/src/lib.rs' -print | while read f; do lines=$(wc -l < "$f"); printf "%5d %s\n" "$lines" "$f"; done | sort -nr | sed -n '1,80p'
rg -n "not_yet_implemented|stub|placeholder|advisory only|TODO|FIXME|HACK|XXX" crates tests examples scripts docs | sed -n '1,240p'
cargo metadata --no-deps --format-version 1 > /tmp/chio-metadata-final.json
```

`cargo metadata` completed with 128 packages and wrote
`/tmp/chio-metadata-final.json` at 592,096 bytes.

## Current Summary

| Check | Result |
| --- | --- |
| Generated Rust files | 4 tracked files. Largest remains `crates/chio-core-types/src/_generated/chio_wire_v1.rs` at 30,223 lines and is generated/quarantined. |
| Production Rust files | 1,198 tracked production files. No hand-maintained production Rust file exceeds 2,000 lines. |
| Production `src/lib.rs` roots | No production lib root exceeds 1,000 lines. Review-repair split `crates/chio-attest-buyer/src/lib.rs` from 999 to 50 lines and `crates/chio-kernel-browser/src/lib.rs` from 997 to 69 lines. |
| Rust hygiene allowlist | 15 capped test-only entries in `scripts/check-rust-file-hygiene.py`; production allowlist remains empty. |
| Test Rust files | 715 tracked test files. 15 test files remain at or above 2,000 lines. They now fail the hygiene gate if they grow past their recorded cap, and any new oversized test file fails. |
| Example Rust files | 24 tracked example files. Largest is `examples/chio-3vendor/src/commands.rs` at 938 lines. |
| Stub-surface gate | `python3 scripts/check-stub-surfaces.py` passed. Production hits are restricted to explicit allowlist entries plus per-hit reviewed match patterns; path-only amnesty now fails. |
| Current targeted verification | Passed. Full workspace CI was not rerun after the review-repair commits. |

## Original Hotspots

The table below starts from the tracked baseline hotspot table and records the
final line count for every original hotspot entry.

| File | Baseline lines | Final lines | Category | Owner crate or area | Planned phase |
| --- | ---: | ---: | --- | --- | --- |
| `crates/chio-core-types/src/_generated/chio_wire_v1.rs` | 30,223 | 30,223 | generated | `chio-core-types` | Phase 8.1 |
| `crates/chio-cli/tests/receipt_query.rs` | 16,159 | 103 | test | `chio-cli` | Phase 7.1 |
| `crates/chio-kernel/src/kernel/tests/all.rs` | 11,910 | 1 | test | `chio-kernel` | Phase 7.2 |
| `crates/chio-store-sqlite/src/receipt_store/tests.rs` | 7,028 | 18 | test | `chio-store-sqlite` | Phase 7.3 |
| `crates/chio-acp-proxy/src/tests/all.rs` | 6,941 | 1 | test | `chio-acp-proxy` | Phase 7.3 |
| `crates/chio-cli/tests/mcp_serve_http.rs` | 6,316 | 6,316 | test | `chio-cli` | Phase 7 follow-up after receipt split |
| `crates/chio-a2a-adapter/src/tests/all.rs` | 6,259 | 1 | test | `chio-a2a-adapter` | Phase 7.3 |
| `crates/chio-core-types/src/capability.rs` | 5,495 | removed | production | `chio-core-types` | Phase 3.1 |
| `crates/chio-control-plane/src/trust_control/cluster_and_reports.rs` | 5,458 | 1,374 | production | `chio-control-plane` | Phase 4.2 |
| `crates/chio-cli/tests/passport.rs` | 5,387 | 5,390 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-control-plane/src/trust_control/service_runtime.rs` | 5,310 | 1,876 | production | `chio-control-plane` | Phase 4.1 |
| `crates/chio-cli/tests/mcp_serve.rs` | 4,496 | 4,496 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-store-sqlite/src/budget_store/tests.rs` | 1,451 | 1,431 | test | `chio-store-sqlite` | split from `budget_store.rs` in Phase 6.1 |
| `crates/chio-mcp-edge/src/runtime/runtime_tests.rs` | 4,346 | 4,349 | test | `chio-mcp-edge` | Phase 7 follow-up |
| `crates/chio-cli/src/cli/trust/receipt.rs` | 1,874 | 1,874 | production | `chio-cli` | split from `trust_commands.rs` in Phase 6.1 |
| `crates/chio-cli/src/cli/types/trust.rs` | 1,433 | 1,433 | production | `chio-cli` | split from `types.rs` in Phase 6.1 |
| `crates/chio-cli/tests/certify.rs` | 3,639 | 3,639 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-control-plane/src/attestation/verification.rs` | 1,221 | 1,220 | production | `chio-control-plane` | split from `attestation.rs` in Phase 6.1 |
| `crates/chio-federation/src/bilateral_verifier/cosign.rs` | 837 | 836 | production | `chio-federation` | split from `bilateral_verifier.rs` in Phase 6.1 |
| `crates/chio-core-types/src/receipt.rs` | 3,438 | removed | production | `chio-core-types` | Phase 3.2 |
| `crates/chio-wasm-guards/src/runtime.rs` | 3,357 | 637 | production | `chio-wasm-guards` | Phase 5.1 |
| `crates/chio-mcp-edge/src/runtime.rs` | 3,310 | 1,779 | production | `chio-mcp-edge` | Phase 5.2 |
| `crates/chio-control-plane/src/policy.rs` | 1,830 | 1,830 | production | `chio-control-plane` | split inline tests to `policy/tests.rs` in Phase 6.1 |
| `crates/chio-mercury/tests/cli.rs` | 3,262 | 3,264 | test | `chio-mercury` | Phase 7 follow-up |
| `crates/chio-cli/tests/trust_cluster.rs` | 3,208 | 3,209 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-attest-buyer-core/src/lib.rs` | 3,200 | 19 | production lib root | `chio-attest-buyer-core` | Phase 2.1 |
| `crates/chio-mcp-remote/src/remote_mcp/session_core.rs` | 1,891 | 1,891 | production | `chio-mcp-remote` | split identity, resume, shared-upstream, and form includes in Phase 6.1 |
| `crates/chio-api-protect/src/proxy/tests.rs` | 2,973 | 2,971 | test | `chio-api-protect` | split from `proxy.rs` in Phase 6.1 |
| `crates/chio-control-plane/src/evidence_export.rs` | 1,372 | 1,372 | production | `chio-control-plane` | split verification/package loading and inline tests in Phase 6.1 |
| `crates/chio-control-plane/src/evidence_export/verification.rs` | 800 | 800 | production | `chio-control-plane` | split from `evidence_export.rs` in Phase 6.1 |
| `crates/chio-control-plane/src/evidence_export/tests.rs` | 873 | 872 | test | `chio-control-plane` | split from `evidence_export.rs` in Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/capital_and_liability.rs` | 1,511 | 1,510 | production | `chio-control-plane` | split liability workflows in Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/capital_and_liability/liability.rs` | 1,410 | 1,410 | production | `chio-control-plane` | split from `capital_and_liability.rs` in Phase 6.1 |
| `crates/chio-acp-edge/src/tests/all.rs` | 2,881 | 2,881 | test | `chio-acp-edge` | Phase 7 follow-up |
| `crates/chio-federation/src/lib.rs` | 2,803 | 42 | production lib root | `chio-federation` | Phase 2.2 |
| `crates/chio-a2a-edge/src/tests/all.rs` | 2,702 | 2,702 | test | `chio-a2a-edge` | Phase 7 follow-up |
| `crates/chio-control-plane/src/trust_control/service_types.rs` | 1,819 | 1,826 | production | `chio-control-plane` | split cluster and budget wire types in Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/service_types/cluster_budget.rs` | 876 | 869 | production | `chio-control-plane` | split from `service_types.rs` in Phase 6.1 |
| `crates/chio-cross-protocol/src/lib.rs` | 2,651 | 20 | production lib root | `chio-cross-protocol` | Phase 2.3 |
| `crates/chio-control-plane/src/trust_control/underwriting_and_support.rs` | 1,626 | 1,626 | production | `chio-control-plane` | split policy input and runtime support in Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/underwriting_and_support/policy_support.rs` | 1,006 | 1,006 | production | `chio-control-plane` | split from `underwriting_and_support.rs` in Phase 6.1 |
| `crates/chio-federation/src/bilateral_dsse.rs` | 1,713 | 1,713 | production | `chio-federation` | split inline DSSE tests in Phase 6.1 |
| `crates/chio-federation/src/bilateral_dsse/tests.rs` | 898 | 897 | test | `chio-federation` | split from `bilateral_dsse.rs` in Phase 6.1 |
| `crates/chio-control-plane/src/certify.rs` | 1,979 | 1,979 | production | `chio-control-plane` | split cross-operator certification network surface in Phase 6.1 |
| `crates/chio-control-plane/src/certify/network.rs` | 601 | 601 | production | `chio-control-plane` | split from `certify.rs` in Phase 6.1 |
| `crates/chio-cli/src/passport.rs` | 1,432 | 1,432 | production | `chio-cli` | split verifier policy, challenge, OID4VP, and status commands in Phase 6.1 |
| `crates/chio-cli/src/passport/verifier.rs` | 1,040 | 1,040 | production | `chio-cli` | split from `passport.rs` in Phase 6.1 |
| `crates/chio-mcp-remote/src/remote_mcp/http_service.rs` | 1,237 | 1,237 | production | `chio-mcp-remote` | split HTTP auth and session support in Phase 6.1 |
| `crates/chio-mcp-remote/src/remote_mcp/http_service_auth.rs` | 1,218 | 1,218 | production | `chio-mcp-remote` | split from `http_service.rs` in Phase 6.1 |
| `crates/chio-kernel/src/kernel/validation.rs` | 2,423 | 1,302 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-cli/src/cli/runtime.rs` | 2,387 | 1,167 | production | `chio-cli` | Phase 6.1 |
| `crates/chio-core-types/src/session.rs` | 2,354 | 1,511 | production | `chio-core-types` | Phase 6.1 |
| `crates/chio-mcp-adapter/src/lib.rs` | 2,304 | 32 | production lib root | `chio-mcp-adapter` | Phase 2.4 |
| `crates/chio-cli/tests/federated_issue.rs` | 2,294 | 2,295 | test | `chio-cli` | Phase 7 follow-up |
| `crates/chio-open-market/src/lib.rs` | 2,285 | 32 | production lib root | `chio-open-market` | Phase 1.2 |
| `crates/chio-autonomy/src/lib.rs` | 2,226 | 29 | production lib root | `chio-autonomy` | Phase 6.2 |
| `crates/chio-credentials/src/tests.rs` | 2,164 | 2,164 | test | `chio-credentials` | Phase 7 follow-up |
| `crates/chio-policy/src/models.rs` | 2,157 | 1,564 | production | `chio-policy` | Phase 6.1 |
| `crates/chio-kernel/src/budget_store.rs` | 2,153 | 803 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-http-core/src/authority.rs` | 2,122 | 929 | production | `chio-http-core` | Phase 6.1 |
| `crates/chio-governance/src/lib.rs` | 2,116 | 22 | production lib root | `chio-governance` | Phase 1.1 |
| `crates/chio-control-plane/src/trust_control/credit_and_loss.rs` | 2,094 | 1,491 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-runtime-core/tests/runtime_buyer_review.rs` | 2,062 | 2,067 | test | `chio-runtime-core` | Phase 7 follow-up |
| `crates/chio-core/src/extension.rs` | 2,061 | removed | production | `chio-core` | Phase 6.1 |
| `crates/chio-web3/src/lib.rs` | 2,055 | 26 | production lib root | `chio-web3` | Phase 1.3 |
| `crates/chio-kernel/src/kernel/mod.rs` | 2,040 | 1,585 | production | `chio-kernel` | Phase 6.1 |
| `xtask/src/main.rs` | 2,022 | 1,954 | production | `xtask` | Phase 6.1 |
| `crates/chio-kernel/src/session.rs` | 2,012 | 1,385 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-control-plane/src/trust_control/config_and_public.rs` | 2,009 | 1,545 | production | `chio-control-plane` | Phase 6.1 |
| `crates/chio-mcp-remote/src/remote_mcp/tests.rs` | 2,008 | 2,008 | test | `chio-mcp-remote` | Phase 7 follow-up |
| `crates/chio-kernel/src/receipt_support.rs` | 2,007 | 1,650 | production | `chio-kernel` | Phase 6.1 |
| `crates/chio-mercury/src/commands/core_cli.rs` | 2,002 | 1,808 | production | `chio-mercury` | Phase 6.1 |

## Remaining Rust File Allowlist

`scripts/check-rust-file-hygiene.py` now has 15 test-only allowlist entries.
Each entry has a `max_lines` cap set to the current file size. The gate fails
if any of these suites grows, and it fails any new unallowlisted test file over
2,000 lines.

This is not completion of test-suite decomposition. It is a stop-loss gate that
makes the residual debt explicit until the suites are split.

| File | Cap | Expires |
| --- | ---: | --- |
| `crates/chio-cli/tests/mcp_serve_http.rs` | 6,316 | Phase 10 test decomposition |
| `crates/chio-cli/tests/passport.rs` | 5,390 | Phase 10 test decomposition |
| `crates/chio-cli/tests/mcp_serve.rs` | 4,496 | Phase 10 test decomposition |
| `crates/chio-mcp-edge/src/runtime/runtime_tests.rs` | 4,349 | Phase 10 test decomposition |
| `crates/chio-cli/tests/certify.rs` | 3,639 | Phase 10 test decomposition |
| `crates/chio-mercury/tests/cli.rs` | 3,264 | Phase 10 test decomposition |
| `crates/chio-cli/tests/trust_cluster.rs` | 3,209 | Phase 10 test decomposition |
| `crates/chio-api-protect/src/proxy/tests.rs` | 2,971 | Phase 10 test decomposition |
| `crates/chio-acp-edge/src/tests/all.rs` | 2,881 | Phase 10 test decomposition |
| `crates/chio-a2a-edge/src/tests/all.rs` | 2,702 | Phase 10 test decomposition |
| `crates/chio-cli/tests/federated_issue.rs` | 2,295 | Phase 10 test decomposition |
| `crates/chio-credentials/src/tests.rs` | 2,164 | Phase 10 test decomposition |
| `crates/chio-core-types/src/capability/tests.rs` | 2,141 | Phase 10 test decomposition |
| `crates/chio-runtime-core/tests/runtime_buyer_review.rs` | 2,067 | Phase 10 test decomposition |
| `crates/chio-mcp-remote/src/remote_mcp/tests.rs` | 2,008 | Phase 10 test decomposition |

Remaining generated Rust is classified separately and now validated against a
known generator header for every generated prefix:

| File | Lines | Reason |
| --- | ---: | --- |
| `crates/chio-core-types/src/_generated/chio_wire_v1.rs` | 30,223 | generated from the schema/codegen boundary and verified by `chio_spec_codegen::GENERATED_HEADER` |
| `crates/chio-errors/src/_generated/error_codes.rs` | 1,312 | generated error-code projection verified by `chio_spec_codegen::errors_pass::ERROR_CODES_GENERATED_HEADER` |
| `crates/chio-core-types/src/_generated/mod.rs` | 16 | generated module boundary verified by the wire generated header |
| `crates/chio-errors/src/_generated/mod.rs` | 9 | generated module boundary verified by the error-code generated header |

## Remaining Stub-Surface Allowlist

The stub-surface gate is no longer path-level. Each production allowlist entry
must have:

- a non-empty reason,
- a non-empty expiry phase,
- at least one reviewed regex in `ALLOWLIST_MATCHES`,
- an actual hit whose text matches one of those reviewed regexes.

An unrelated `TODO`, `stub`, or `placeholder` in an otherwise allowlisted file
now fails with `production stub-surface hit does not match reviewed allowlist
patterns`. Regression tests cover both the removed federation
selective-disclosure placeholder surface and `crates/chio-cli/src/guard.rs`.

Current scan evidence: `python3 scripts/check-stub-surfaces.py` passed with
133 production hits, all matched to reviewed allowlist patterns.

## Touched Crates

The branch diff touches 79 crates:

- `chio-a2a-adapter`
- `chio-a2a-edge`
- `chio-acp-edge`
- `chio-acp-proxy`
- `chio-ag-ui-proxy`
- `chio-anchor`
- `chio-api-protect`
- `chio-appraisal`
- `chio-arena`
- `chio-attest-buyer`
- `chio-attest-buyer-core`
- `chio-attest-loopback`
- `chio-attest-verify`
- `chio-autonomy`
- `chio-binding-helpers`
- `chio-cli`
- `chio-conformance`
- `chio-control-plane`
- `chio-core`
- `chio-core-types`
- `chio-cpp-kernel-ffi`
- `chio-credentials`
- `chio-credit`
- `chio-cross-protocol`
- `chio-data-guards`
- `chio-egress-contract`
- `chio-eval-receipt`
- `chio-external-guards`
- `chio-federation`
- `chio-federation-authority`
- `chio-governance`
- `chio-groq-tools-adapter`
- `chio-guard-registry`
- `chio-guards`
- `chio-hosted-mcp`
- `chio-http-core`
- `chio-http-session`
- `chio-kernel`
- `chio-kernel-browser`
- `chio-kernel-core`
- `chio-kernel-mobile`
- `chio-lineage`
- `chio-link`
- `chio-listing`
- `chio-manifest`
- `chio-market`
- `chio-mcp-adapter`
- `chio-mcp-edge`
- `chio-mcp-remote`
- `chio-mercury`
- `chio-mercury-core`
- `chio-metering`
- `chio-mistral-tools-adapter`
- `chio-open-market`
- `chio-openai`
- `chio-openapi-mcp-bridge`
- `chio-otel-receipt-exporter`
- `chio-pheromone`
- `chio-pheromone-relay`
- `chio-pheromone-runtime`
- `chio-policy`
- `chio-reputation`
- `chio-revocation-oracle`
- `chio-runtime`
- `chio-runtime-core`
- `chio-runtime-harness`
- `chio-selective-disclosure`
- `chio-settle`
- `chio-siem`
- `chio-spec-codegen`
- `chio-store-sqlite`
- `chio-tee`
- `chio-tower`
- `chio-underwriting`
- `chio-wall`
- `chio-wasm-guards`
- `chio-web3`
- `chio-web3-bindings`
- `chio-workflow`

## Verification Commands

Review-repair verification through code head `36d62f10b`:

```bash
python3 -m py_compile scripts/check-stub-surfaces.py scripts/check-rust-file-hygiene.py
python3 scripts/check-stub-surfaces.py
python3 scripts/check-rust-file-hygiene.py
bash scripts/tests/check-stub-surfaces.test.sh
bash scripts/tests/check-rust-file-hygiene.test.sh
cargo fmt --all -- --check
cargo test -p chio-attest-buyer
cargo test -p chio-kernel-browser
cargo clippy -p chio-attest-buyer -p chio-kernel-browser --all-targets -- -D warnings
git diff --check origin/codex/chio-next-10-remediation..HEAD
git diff --check
```

All commands above passed during review repair. Full workspace CI was not rerun
after the review-repair commits. The earlier full workspace CI evidence in this
branch predates these review-repair commits and should not be treated as current
full-CI proof.

## Final Status Snapshot

The review-repair code/gate state before this evidence refresh had only the
unrelated dirty state that existed at baseline:

```text
 M docs/README.md
?? .codex/
?? docs/superpowers/
```

Those paths remain intentionally unstaged by this evidence commit.
