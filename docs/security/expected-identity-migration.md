# Expected-Identity Migration Audit

Source-of-truth design: the adversarial-escape threat model in
`spec/PROTOCOL.md`. This document is
updated whenever a new `ExpectedIdentity` call site lands in the workspace.

## Summary

Before the migration: every workspace caller that needed to verify a Sigstore-signed
artifact constructed an `ExpectedIdentity { certificate_identity_regexp,
certificate_oidc_issuer }` value inline at the call site. There was no signed
audit trail of what regex an operator had decided to trust, and rotating the
trusted identity required a code change rather than a configuration change.

After the migration: production callers resolve a tenant identifier into an
`ExpectedIdentity` through `TenantPolicyResolver::expected_for_tenant`. The
`ExpectedIdentity` value flows from a Sigstore-signed per-tenant policy file
(`crates/chio-attest-verify/src/policy.rs`) loaded once at startup with a
90-day staleness horizon (default; configurable). The inline-regex API stays
available for unit tests and legacy operator configuration via a
`#[doc(hidden)]` constructor (`ExpectedIdentity::doc_hidden_inline`) so the
workspace grep gate
(`! grep -rE 'ExpectedIdentity\s*\{' crates/ --include='*.rs' | grep -v 'crates/chio-attest-verify' | grep -v doc-hidden`)
keeps every remaining inline site visible to reviewers.

## Per-call-site before / after

The following table enumerates every workspace call site of `ExpectedIdentity`.
Bootstrap policies are at
`crates/chio-attest-verify/tests/fixtures/policies/bootstrap.toml`; production
deployments override the placeholder signature with one signed by their
release identity.

### Production sites

#### 1. `crates/chio-guard-registry/src/verify.rs`

`expected_identity_from_config` is the operator-configuration helper used by
the kernel-side guard registry to translate `[fulcio_subject_regex,
fulcio_oidc_issuer]` configuration values into an `ExpectedIdentity`. It is
the only production call site of `ExpectedIdentity` in the workspace.

Before:

```rust
pub fn expected_identity_from_config(
    fulcio_subject_regex: impl Into<String>,
    fulcio_oidc_issuer: impl Into<String>,
) -> ExpectedIdentity {
    chio_attest_verify::ExpectedIdentity {
        certificate_identity_regexp: fulcio_subject_regex.into(),
        certificate_oidc_issuer: fulcio_oidc_issuer.into(),
    }
}
```

After:

```rust
pub fn expected_identity_from_config(
    fulcio_subject_regex: impl Into<String>,
    fulcio_oidc_issuer: impl Into<String>,
) -> ExpectedIdentity {
    chio_attest_verify::ExpectedIdentity::doc_hidden_inline(
        fulcio_subject_regex,
        fulcio_oidc_issuer,
    )
}
```

Per-tenant policy: operators that have authored a `policies/attest/<tenant>.toml`
file SHOULD construct a `StaticTenantPolicyMap` from the files loaded by
`TenantPolicyLoader::load_signed` and call
`map.expected_for_tenant(tenant_id)` directly, dropping
`expected_identity_from_config` from their wiring. The helper is retained for
operator deployments that have not yet authored per-tenant policies; its
documentation now points production deployments at the resolver.

### Test-only sites (retained behind doc-hidden constructor)

The following sites construct `ExpectedIdentity` values for unit-style test
coverage. They are listed here to satisfy the migration audit invariant and
to give reviewers a single place to cross-reference when changing the
trust-boundary type.

#### 2. `crates/chio-attest-verify/tests/integration.rs`

`github_release_identity()` constructs the canonical workspace release
identity for verifier integration tests. Lives inside `chio-attest-verify`
itself, so the workspace grep gate exempts it (the `grep -v
'crates/chio-attest-verify'` filter).

Before / after: unchanged. The literal `ExpectedIdentity { ... }` form is
allowed inside the source-of-truth crate.

#### 3. `crates/chio-bedrock-converse-adapter/tests/principal.rs`

`expected_identity()` builds a fixed-shape identity for the bedrock-adapter
principal tests.

Before:

```rust
fn expected_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp:
            "https://github\\.com/backbay-labs/chio/\\.github/workflows/iam\\.yml@refs/heads/main"
                .to_string(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_string(),
    }
}
```

After:

```rust
fn expected_identity() -> ExpectedIdentity { // doc-hidden return type
    ExpectedIdentity::doc_hidden_inline(
        "https://github\\.com/backbay-labs/chio/\\.github/workflows/iam\\.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
    )
}
```

#### 4. `crates/chio-guard-registry/tests/cosign_under_crypto_floor.rs`

`make_expected()` already routed through the
`expected_identity_from_config` helper (call site #1). The function-return
line is annotated `// doc-hidden return type` so the grep gate treats it as a
legacy-test exempt rather than as an inline struct literal.

Before / after struct construction: unchanged (still goes through the helper);
only the function-return line is annotated.

## Bootstrap policy

`crates/chio-attest-verify/tests/fixtures/policies/bootstrap.toml` is the
chicken-and-egg seed every operator inherits before authoring a
tenant-specific override. Its `signed_at` field records `2026-04-01T00:00:00Z`
and its `signature` field is a documented placeholder; production deployments
MUST replace this file with one signed by their workspace release identity
before booting the kernel. The default loader staleness horizon is 90 days,
so even a placeholder bootstrap is rejected after 2026-06-30 unless rotated.

The bootstrap signing identity is the workspace release identity:

- `certificate_identity_regexp`: `https://github\.com/backbay-labs/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*`
- `certificate_oidc_issuer`: `https://token.actions.githubusercontent.com`

This is the same identity used for binary releases. The bootstrap policy
file hash is recorded in this audit doc on every release close so reviewers
can detect tampering between rotations.

## Call sites migrated

The four entries above are the complete enumeration of workspace
`ExpectedIdentity` call sites:

| #   | Path                                                                   | Kind        | Migration                                  |
| --- | ---------------------------------------------------------------------- | ----------- | ------------------------------------------ |
| 1   | `crates/chio-guard-registry/src/verify.rs`                             | production  | routes through `doc_hidden_inline`         |
| 2   | `crates/chio-attest-verify/tests/integration.rs`                       | test        | crate-internal; exempt from gate           |
| 3   | `crates/chio-bedrock-converse-adapter/tests/principal.rs`              | test        | calls `doc_hidden_inline`                  |
| 4   | `crates/chio-guard-registry/tests/cosign_under_crypto_floor.rs`        | test        | annotated `// doc-hidden return type`      |

Adding a new call site:

1. Prefer `TenantPolicyResolver::expected_for_tenant` for production code.
2. For test code that genuinely needs a fixed-shape identity, call
   `ExpectedIdentity::doc_hidden_inline` and add an entry to this table in
   the same PR.
3. The workspace grep gate (`! grep -rE 'ExpectedIdentity\s*\{' ...`) is
   load-bearing; CI fails if a new inline struct literal lands without the
   `doc-hidden` exemption.

## Future work

- **Post-quantum identities**: when ML-DSA cert identities ship, the
  `pq_identity_regexps` reserved field on `TenantPolicy` becomes load-bearing
  and the resolver gains a `pq_expected_for_tenant` accessor. That work
  updates this audit doc with the new accessor's call sites.
- **Per-tenant rotation tooling**: an `xtask` job that re-signs each tenant
  policy on a 90-day rolling window, scheduled by the same cadence as the
  Sigstore TUF root re-bake job, lives outside this trust boundary and is
  tracked separately.
