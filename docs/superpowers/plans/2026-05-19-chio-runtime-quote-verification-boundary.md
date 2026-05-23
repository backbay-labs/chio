# Chio Runtime Quote Verification Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion for this trust-boundary change.

**Goal:** Prevent `chio attest runtime-quote verify` from accepting report-data equality as complete runtime quote verification, and expose the full quote/collateral path through `chio-attest-verify`.

**Architecture:** `chio-attest-verify` is the sole owner of TEE quote backends. The CLI may compute expected report-data for diagnostics, but accepted runtime quote verification requires a backend-verified quote.

**Tech Stack:** Rust, clap, `chio-cli`, `chio-attest-verify`, optional `tee-quotes` feature.

---

### Task 1: Pin the Trust-Boundary Regression

- [x] Add a focused CLI regression proving matching report-data alone returns an unresolved failure, not success.
- [x] Run the regression red against the existing implementation.

### Task 2: Expose Full Quote Inputs

- [x] Add `--tee-kind`, `--quote`, and `--collateral` to `chio attest runtime-quote verify`.
- [x] Keep `--report-data` as an optional diagnostic comparison, not an acceptance source.
- [x] Add a `tee-quotes` CLI feature that forwards to `chio-attest-verify/tee-quotes`.

### Task 3: Route Backends Without Default-Build Overclaiming

- [x] Make report-data-only mode write `accepted: false`, `verificationState: unresolved`, and `failureCode: quote_evidence_missing`.
- [x] In default builds, reject quote verification with `tee_quote_feature_disabled` semantics instead of pretending to verify.
- [x] Under `tee-quotes`, route Intel TDX, AMD SEV-SNP, and AWS Nitro to the corresponding `chio-attest-verify` backend with collateral JSON.

### Task 4: Verify

- [x] `cargo test -p chio-cli chio_attest_runtime_quote --bin chio`
- [x] `cargo check -p chio-cli --features tee-quotes`

Note: feature-build verification passes locally when the cargo registry is hydrated. Initial sandbox runs were blocked by crate fetches from `static.crates.io`; once cached, `cargo check -p chio-cli --features tee-quotes` completes green. The dispatch sites that call `verifier.verify_quote(&quote_bytes, &context)` now adapt the backend `AttestError` into `CliError::cli_other_error` since `CliError` lives outside `chio-attest-verify`'s dependency boundary.
