# M02 Carried-Forward Items

These are P1/P2 residuals from the M02 audit that are not fixed by the sweep
because they need external nightly evidence or non-Rust SDK capability work.

| Source | Severity | Original blocker | Owning artifact | Current disposition |
| --- | --- | --- | --- | --- |
| Mutation activation kill score | P1 | No two consecutive `mutants-nightly` full sweeps have met the configured >= 80 percent caught ratio across `chio-policy`, `chio-credentials`, `chio-attest-verify`, `chio-kernel-core`, `chio-guards`, and `chio-anchor`. | `releases.toml: activation_evidence` plus this file | Carried forward. `cycle_end_tag` remains empty and `observed_consecutive_nightly_successes` remains 0, so `scripts/mutants-gate.sh` stays advisory by design. |
| Python SDK verdict driver | P2 | `python-sdk` is registered as `partial-capability`; only capability-subset scenarios emit local tuples. | `crates/chio-conformance/verdict_matrix/manifest.toml` and `drivers/python/run_scenarios.py` | Carried forward to SDK parity work that adds a full local verdict-emitting surface. |
| TypeScript node-http verdict driver | P2 | `typescript-node-http` is a transport-client driver and reports all 48 scenarios as unsupported without a live sidecar. | `crates/chio-conformance/verdict_matrix/drivers/typescript/run_scenarios.ts` | Carried forward to operator sidecar wiring before promoting it to a tuple-emitting required driver. |
| Go HTTP SDK verdict driver | P2 | `go-http-sdk` is registered as `unsupported-no-local-verdict-emitter`; the SDK does not expose a local semantic verdict entrypoint. | `crates/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go` | Carried forward to Go SDK verdict-emitter work. |
| WASM browser verdict driver | P2 | `wasm-browser` covers 12 capability-subset scenarios; the remaining 36 require revocation store, execution nonce store, and guard pipeline support in the browser kernel. | `crates/chio-kernel-browser/tests/verdict_matrix_wasm.rs` | Carried forward to browser-kernel capability expansion. |
