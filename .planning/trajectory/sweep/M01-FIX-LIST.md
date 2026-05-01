# M01 P0/P1/P2 Sweep Fix List

Source inventory: 29 unresolved Codex-bot review threads across M01 PRs #310, #318, #330, #337, #342, #370, and #371. No `.planning/trajectory-2/deferred/m01-*.md` files exist.

| Source | Severity | File path | Intended fix one-liner | Gate command |
| --- | --- | --- | --- | --- |
| PR #310 comment 3163467997 | P2 | `.planning/audits/M01-error-taxonomy.md` | Correct starting wire-schema baseline to count files, not directories. | `find spec/schemas/chio-wire/v1 -name '*.schema.json' | wc -l` |
| PR #310 comment 3163467999 | P2 | `.planning/audits/M01-error-taxonomy.md` | Make audit reproduce commands copy-paste runnable by removing escaped pipes in shell examples. | `rg '\\\|' .planning/audits/M01-error-taxonomy.md` |
| PR #310 comment 3163528882 | P2 | `.planning/audits/M01-error-taxonomy.md` | Align CLI error baseline predicate with `CliError::Other(format!(`. | `grep -rF 'CliError::Other(format!(' crates/chio-cli/src/ crates/chio-control-plane/src/ crates/chio-hosted-mcp/src/ | wc -l` |
| PR #310 comment 3163565737 | P2 | `.planning/audits/M01-error-taxonomy.md` | Track distinct legacy string codes separately from raw mentions. | `rg -o '"CHIO-[^"]+' crates/chio-control-plane/src/lib.rs | sort -u | wc -l` |
| PR #318 comment 3164329510 | P1 | `crates/chio-errors/src/_generated/error_codes.rs` | Add a generated `lookup_legacy_string_code_matches` iterator so duplicate legacy strings cannot be hidden by first-match lookup. | `cargo test -p chio-errors -p chio-spec-codegen` |
| PR #318 comment 3164329516 | P2 | `crates/chio-spec-codegen/src/main.rs` | Anchor `--errors-only` registry and generated output paths to the workspace root. | `(cd crates/chio-spec-codegen && cargo run -p chio-spec-codegen -- --errors-only)` |
| PR #330 comment 3165132918 | P2 | `crates/chio-cli/src/cli/trust_commands.rs` | Verified already addressed on current main: missing local backend args now use CLI-domain errors. | `rg -n 'CAPABILITY_SCOPE_EXCEEDED|capability_scope' crates/chio-cli/src/cli/trust_commands.rs` |
| PR #330 comment 3165132920 | P2 | `crates/chio-cli/src/passport.rs` | Map mutually exclusive passport CLI flags to CLI-domain errors. | `cargo test -p chio-cli passport --quiet` |
| PR #330 comment 3165194407 | P2 | `crates/chio-cli/src/passport.rs` | Map missing local passport registry and issuer prerequisites to CLI-domain errors. | `cargo test -p chio-cli passport --quiet` |
| PR #330 comment 3165194408 | P2 | `crates/chio-cli/src/cli/trust_commands.rs` | Map invalid underwriting outcome CLI literals to CLI-domain errors. | `cargo test -p chio-cli trust --quiet` |
| PR #337 comment 3165755281 | P2 | `crates/chio-cli/src/policies/mod.rs` | Preserve CLI I/O classification for preset materialization write failures. | `cargo test -p chio-cli policies --quiet` |
| PR #337 comment 3165755282 | P2 | `crates/chio-cli/src/guards/sign.rs` | Preserve CLI I/O classification for signature sidecar write failures. | `cargo test -p chio-cli guard --quiet` |
| PR #337 comment 3165925502 | P2 | `crates/chio-cli/src/guards/sign.rs` | Preserve CLI I/O classification for sidecar read failures while keeping missing or invalid signatures in manifest-signature domain. | `cargo test -p chio-cli guard --quiet` |
| PR #337 comment 3165925508 | P2 | `crates/chio-cli/src/guards/sign.rs` | Report malformed local signing seed files as CLI input errors. | `cargo test -p chio-cli guard --quiet` |
| PR #342 comment 3168487152 | P2 | `crates/chio-cli/src/cli/replay/bless/fixture_layout.rs` | Verified already addressed on current main: preflight uses `validate_m04_scenario_dir`. | `cargo test -p chio-cli replay_bless_layout --quiet` |
| PR #342 comment 3168637380 | P1 | `crates/chio-kernel/src/observability/metrics.rs` | Verified already addressed on current main: scalar renderer reads `signing_queue_block_total()`. | `cargo test -p chio-kernel signing_queue_block --quiet` |
| PR #342 comment 3168637385 | P1 | `.github/workflows/bench-regression.yml` | Verified already addressed on current main: AWK skips benches with `required-features`. | `awk` inspection of `.github/workflows/bench-regression.yml` |
| PR #342 comment 3168793534 | P2 | `crates/chio-cli/src/evidence_export.rs` | Verified already addressed on current main: local export path checks use CLI-domain errors. | `cargo test -p chio-cli evidence --quiet` |
| PR #342 comment 3168964154 | P1 | `crates/chio-cli/src/cli/replay.rs` | Verified already addressed on current main: missing TEE tenant key routes through replay exit 20. | `cargo test -p chio-cli replay_ --quiet` |
| PR #342 comment 3168964161 | P1 | `crates/chio-cli/src/cli/replay/bless.rs` | Verified already addressed on current main: bless missing tenant key routes through replay exit 20. | `cargo test -p chio-cli replay_ --quiet` |
| PR #342 comment 3168964164 | P1 | `crates/chio-cli/src/cli/replay/traffic.rs` | Verified already addressed on current main: traffic `--against` missing tenant key routes through replay exit 20. | `cargo test -p chio-cli replay_ --quiet` |
| PR #342 comment 3169280434 | P1 | `crates/chio-cli/src/cli/replay.rs` | Verified already addressed on current main: missing trusted kernel key routes through replay exit 40. | `cargo test -p chio-cli replay_ --quiet` |
| PR #342 comment 3169280439 | P2 | `crates/chio-cli/src/cli/conformance.rs` | Verified already addressed on current main: local scenario/result loads use CLI I/O errors. | `cargo test -p chio-cli conformance --quiet` |
| PR #370 comment 3169974118 | P1 | `crates/chio-lsp/src/completion/mod.rs` | Verified already addressed on current main: completion columns convert UTF-16 to bytes before slicing. | `cargo test -p chio-lsp non_ascii_prefix --quiet` |
| PR #370 comment 3169974123 | P1 | `crates/chio-lsp/src/definition/resolver.rs` | Verified already addressed on current main: definition lookup converts UTF-16 to byte offsets before slicing. | `cargo test -p chio-lsp extract_urn_handles_non_ascii_prefix --quiet` |
| PR #370 comment 3169974126 | P2 | `crates/chio-lsp/src/definition/resolver.rs` | Verified already addressed on current main: definition target ranges emit UTF-16 columns. | `cargo test -p chio-lsp locate_in_text_emits_utf16_columns --quiet` |
| PR #371 comment 3170078390 | P2 | `editors/vscode-chio/package.json` | Verified already addressed on current main: VSCode manifest contributes generated snippets. | `cd editors/vscode-chio && npm test -- --run` |
| PR #371 comment 3170078394 | P2 | `editors/zed-chio/src/lib.rs` | Verified already addressed on current main: Zed command builder honors path and args overrides. | `cargo test -p zed-chio --test integration` |
| PR #371 comment 3170078397 | P2 | `xtask/src/snippets_subcommand.rs` | Verified already addressed on current main: snippet regen validates YAML through JSON Schema. | `cargo run -p xtask --quiet -- snippets regen --check` |
| Audit follow-on item | P2 | `.planning/audits/M01-error-taxonomy.md` | Add tracking notes for live-host VSCode and Zed wasm follow-ons. | `rg -n 'Tracking note' .planning/audits/M01-error-taxonomy.md` |
