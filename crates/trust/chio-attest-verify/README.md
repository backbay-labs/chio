# chio-attest-verify

The workspace's sole caller of `sigstore-rs`. Verifies Sigstore keyless
signatures (bundles and detached blob signatures) against an embedded
Fulcio/Rekor trust root, verifies TEE quotes from Intel TDX, AMD SEV-SNP, and
AWS Nitro and binds them to a kernel signing key and receipt root, and loads
signed per-tenant identity policies. Lives under `crates/trust/`.

## Responsibilities

- Own every direct `sigstore-rs` call in the workspace; no other crate
  declares the `sigstore` dependency.
- Verify Sigstore bundles and detached blob/byte signatures against the
  embedded Sigstore Public Good Instance trust root (`SigstoreVerifier`).
- Verify TEE quotes for Intel TDX, AMD SEV-SNP, and AWS Nitro, binding each
  into the kernel signing key and receipt root (`tee-quotes` feature).
- Parse, structurally validate, and (via `TenantPolicyLoader`) signature- and
  staleness-verify per-tenant `ExpectedIdentity` policy files.
- Ship the embedded Sigstore TUF trust root under `sigstore-root/` and the
  `tuf-rebake` binary that refreshes it from the public-good TUF repository.

## Public API

- `AttestVerifier` - `verify_blob`, `verify_bytes`, `verify_bundle`;
  `SigstoreVerifier::with_embedded_root()` is the production implementation.
- `QuoteVerifier::verify_quote` - implemented by `nitro::NitroVerifier`,
  `sev_snp::SevSnpVerifier`, `tdx::TdxDcapVerifier` (all behind `tee-quotes`).
- `ExpectedIdentity`, `VerifiedAttestation`, `AttestError` - request, result,
  and fail-closed (`#[non_exhaustive]`) error type for `AttestVerifier`.
- `TeeKind`, `QuoteTcbStatus`, `QuoteVerificationContext`, `VerifiedQuote`,
  `expect_report_data` - shared TEE quote shapes and the kernel-key /
  receipt-root binding function.
- `policy::TenantPolicy`, `policy_loader::TenantPolicyLoader`,
  `TenantPolicyResolver`, `StaticTenantPolicyMap` - signed per-tenant
  identity-policy schema, loader, and resolver trait.
- `BOOTSTRAP_TENANT_ID`, `TENANT_POLICY_SCHEMA_VERSION`,
  `DEFAULT_STALENESS_HORIZON` - policy constants re-exported at the crate root.

## Usage

```rust
use chio_attest_verify::{AttestVerifier, ExpectedIdentity, SigstoreVerifier};

let verifier = SigstoreVerifier::with_embedded_root()?;
let expected = ExpectedIdentity {
    certificate_identity_regexp:
        r"https://github\.com/backbay-labs/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"
            .into(),
    certificate_oidc_issuer: "https://token.actions.githubusercontent.com".into(),
};
let claims = verifier.verify_bundle(&artifact_bytes, &bundle_json_bytes, &expected)?;
assert!(!claims.rekor_inclusion_verified);
```

## Feature flags

| Flag | Effect |
|------|--------|
| `pq` | Enables `chio-core-types/pq` and pulls in `fips204`. No ML-DSA certificate-verification path is wired in this crate; `TenantPolicy::pq_identity_regexps` is a reserved, currently-unused schema field. |
| `tee-quotes` | Compiles the `nitro`, `sev_snp`, `tdx`, and `tee_signature` modules (TEE quote backends and their shared ECDSA verification helpers). |
| `kani` | Opts in to the `#[cfg(kani)]`-gated `kani_public_harnesses` module for tooling that wants its doc comments without invoking the Kani toolchain. Production builds never compile the module regardless of this flag. |

## Testing

```
cargo test -p chio-attest-verify
cargo test -p chio-attest-verify --features tee-quotes
cargo test -p chio-attest-verify --features pq
```

`tests/nitro_unit.rs`, `tests/sev_snp_unit.rs`, `tests/tdx_unit.rs`,
`tests/nitro_root_rotation.rs`, and `tests/cross_backend_conformance.rs`
require `tee-quotes`; `tests/v318_migration.rs` and `tests/migration.rs`
require `pq`. The pinned fixture corpora under `fixtures/quotes/` regenerate
via `cargo run -p chio-attest-verify --example generate_<backend>_fixtures
--features tee-quotes`.

## See also

- `chio-guard-registry` - wraps `AttestVerifier` to verify guard-image
  signatures (`GuardSigstoreVerifier`).
- `chio-weights` - wraps `SigstoreVerifier::verify_bundle` to verify model-card
  bundles.
- `chio-cli`, `chio-bedrock-converse-adapter` - consume `AttestVerifier` for
  release-artifact and signed-config verification.
- `chio-core-types` - supplies `canonical_json_bytes` and `crypto::PublicKey`
  used by the policy and quote-binding paths.
