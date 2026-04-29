# M06 chio-wasm-guards migration to chio-attest-verify

Status: open. Owners: M06 (consumer) and M09 (producer of `chio-attest-verify`).
Tracked-by: this document. Closed-by: the M06 P2 ticket that lands cosign
keyless verification through `chio_attest_verify::AttestVerifier`
(see `.planning/trajectory/06-wasm-guard-platform.md` Phase 2, task P2.T4
"Wire cosign keyless verification through `chio-attest-verify` (M09)").

## Why this exists

M09 Phase 3 lands `crates/chio-attest-verify/`, the single source of truth
for Sigstore verification across the chio workspace. The crate's lib doc
states the rule plainly: "no other crate is permitted to call `sigstore-rs`
directly". M06 Phase 2 will add OCI-published WASM guards with cosign
keyless signatures, and the obvious-but-wrong path is to call `sigstore-rs`
from inside `chio-wasm-guards` (or a sibling `chio-guard-registry` crate).
This tracking document exists so that path is closed off before the M06 P2
work starts.

The shared crate is also where the OIDC-identity-and-issuer regex lives.
Forking a parallel verifier in `chio-wasm-guards` would mean two regexes,
two trust roots, and two failure modes that audit cannot reconcile. M09
Phase 3 task 6 (this doc) and the M09 phase doc's "Risks and mitigations"
section both pin this as a fail-closed invariant.

## Current state in `crates/chio-wasm-guards/**`

As of M09.P3.T6 landing, `crates/chio-wasm-guards/` does not yet call
`sigstore-rs`, `cosign`, Fulcio, or Rekor. The crate today loads `.wasm`
guard modules with fuel metering and an Ed25519 manifest signature
(`ed25519-dalek` in `Cargo.toml`). There is no Sigstore code path at all.

The migration framing is therefore preventative rather than reactive: when
M06 P2 introduces signature verification for OCI-published guards, the only
permitted entry point is `chio_attest_verify::AttestVerifier`. The
"migration off raw `sigstore-rs`" worded in the M09.P3.T6 ticket title
covers two cases:

1. Code that lands in `crates/chio-wasm-guards/` or its sibling
   `chio-guard-registry` (M06 P2.T1) and reaches for `sigstore-rs`
   directly. This must be rewritten against `AttestVerifier` before merge.
2. Any prototype or scratch branch that already hard-codes `sigstore-rs`
   verification calls. M06 P2 must rebase such branches onto the
   `AttestVerifier` trait surface.

Either case lands the same code shape, so the rest of this document treats
them uniformly.

## Target state

`chio-wasm-guards` (or, more precisely, the `chio-guard-registry` crate
introduced by M06 P2.T1) consumes `chio_attest_verify::AttestVerifier`
through dependency injection. The crate adds a `chio-attest-verify =
{ path = "../chio-attest-verify" }` line to its `Cargo.toml` and never adds
`sigstore` or `sigstore-rs` to its own dep tree.

Invariants the target state must satisfy:

- Every Sigstore verification call in M06 code paths goes through
  `AttestVerifier::verify_blob`, `AttestVerifier::verify_bytes`, or
  `AttestVerifier::verify_bundle`.
- The OIDC issuer and identity regex are constructed by populating
  `chio_attest_verify::ExpectedIdentity`. M06 must not re-declare those
  fields locally.
- Failure paths return one of the existing `chio_attest_verify::AttestError`
  variants (`SignatureMismatch`, `IdentityMismatch`, `IssuerMismatch`,
  `RekorInclusion`, `CertificateExpired`, `TrustRoot`, `Malformed`, `Io`).
  M06 maps these into `chio.guard.verify` events with `result=fail` and
  the `mode` field (`sigstore` or `dual`) per
  `.planning/trajectory/06-wasm-guard-platform.md` Section "Prometheus
  metric families".
- The cached `sigstore-bundle.json` in the M06 offline cache layout
  (`${XDG_CACHE_HOME}/chio/guards/<digest>/sigstore-bundle.json`) is
  passed to `verify_bundle` verbatim; M06 does not pre-parse the bundle.
- Streamed-from-network loads use `verify_bytes` with the artifact bytes,
  detached signature bytes, and PEM-encoded leaf certificate bytes. The
  cert chain to Fulcio is reassembled inside `chio-attest-verify` from the
  embedded trust root; M06 does not pass intermediates.

## Migration steps for M06 P2

These steps are written so a reviewer can grep the M06 P2 PR and confirm
the migration is complete. They map onto the M06 P2 task list verbatim.

### Step 1: dep wiring (M06 P2.T1)

When `chio-guard-registry` is scaffolded:

- Add `chio-attest-verify = { path = "../chio-attest-verify" }` to
  `crates/chio-guard-registry/Cargo.toml`.
- Do NOT add `sigstore` or `sigstore-rs` to `chio-guard-registry` or to
  `chio-wasm-guards`. A `cargo tree -p chio-guard-registry | grep sigstore`
  must return zero hits.
- Re-export the trait surface needed by callers from
  `chio-guard-registry::attest`:

  ```rust
  pub use chio_attest_verify::{
      AttestError, AttestVerifier, ExpectedIdentity, SigstoreVerifier,
      VerifiedAttestation,
  };
  ```

  Re-exporting (not re-implementing) keeps the "single source of truth"
  invariant inspectable by `cargo doc`.

### Step 2: bundle path swap (M06 P2.T4)

The verbatim cosign command in
`.planning/trajectory/06-wasm-guard-platform.md` Section "Pull and verify"
is:

```
cosign verify-blob \
  --bundle ${cache}/<digest>/sigstore-bundle.json \
  --certificate-identity-regexp '^https://github\.com/chio-protocol/.+/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ${cache}/<digest>/module.wasm
```

The Rust equivalent inside `chio-guard-registry` is a single
`AttestVerifier::verify_bundle` call. Type mapping:

| cosign argument                       | `AttestVerifier::verify_bundle` parameter           |
| ------------------------------------- | --------------------------------------------------- |
| `${cache}/<digest>/module.wasm` bytes | `artifact: &[u8]`                                   |
| `${cache}/<digest>/sigstore-bundle.json` bytes | `bundle_json: &[u8]`                       |
| `--certificate-identity-regexp ...`   | `expected.certificate_identity_regexp: String`      |
| `--certificate-oidc-issuer ...`       | `expected.certificate_oidc_issuer: String`          |

The cached on-disk path is preferred. Use `verify_bundle` whenever the
guard was resolved via `chio guard pull` (the common path). The returned
`VerifiedAttestation::rekor_inclusion_verified` MUST be `true` for the
on-disk bundle path; M06's `chio.guard.verify` event with `mode=sigstore`
asserts this and falls into `result=fail` if it is not.

### Step 3: streamed-network path (M06 P2.T4)

For the streamed-from-network case (no bundle on disk yet), use
`AttestVerifier::verify_bytes`:

| Source                                | `AttestVerifier::verify_bytes` parameter |
| ------------------------------------- | ---------------------------------------- |
| streamed `module.wasm` bytes          | `artifact: &[u8]`                        |
| detached `.sig` bytes                 | `signature: &[u8]`                       |
| PEM leaf cert bytes (`.crt`)          | `certificate_pem: &[u8]`                 |
| `ExpectedIdentity { ... }`            | `expected: &ExpectedIdentity`            |

The streamed path returns `VerifiedAttestation` with
`rekor_inclusion_verified` possibly `false`; per the trait doc, audit
consumers MUST treat that as a weaker assertion. M06's structured event
records `mode=sigstore` with a `rekor_inclusion=false` field so dashboards
can distinguish bundle-verified from raw-blob-verified loads.

### Step 4: ExpectedIdentity construction (M06 P2.T4)

Construct `ExpectedIdentity` exactly once per `chio-guard-registry`
process, derived from operator config:

```rust
let expected = chio_attest_verify::ExpectedIdentity {
    certificate_identity_regexp: cfg.fulcio_subject_regex.clone(),
    certificate_oidc_issuer: cfg.fulcio_oidc_issuer.clone(),
};
```

Do NOT inline literal regex strings inside per-call sites. Do NOT define a
local `ExpectedIdentity` shadow type. `cargo doc -p chio-guard-registry`
should show `ExpectedIdentity` documented as a re-export from
`chio_attest_verify`.

### Step 5: error mapping (M06 P2.T4 and P2.T5)

`chio-guard-registry` maps `chio_attest_verify::AttestError` variants
into the deny-by-default failure-mode table in
`.planning/trajectory/06-wasm-guard-platform.md` Section "Failure modes".
The mapping is one-to-one and must be exhaustive at the match site (with
a `_ => deny` arm for the `#[non_exhaustive]` enum):

| `AttestError` variant   | M06 failure mode classification                   |
| ----------------------- | ------------------------------------------------- |
| `SignatureMismatch`     | "tampered artifact" (P2.T6 integration test name) |
| `IdentityMismatch`      | "wrong subject" (Fulcio SAN regex mismatch)       |
| `IssuerMismatch`        | "wrong issuer" (OIDC issuer mismatch)             |
| `RekorInclusion`        | "missing Rekor proof"                             |
| `CertificateExpired`    | "cert expired"                                    |
| `TrustRoot`             | "trust root stale" (operator must re-bake)        |
| `Malformed(_)`          | "bundle malformed"                                |
| `Io(_)`                 | "io" (cache or network)                           |
| `_` (future variants)   | deny (treat unknown as fail-closed)               |

Every arm emits a `chio.guard.verify` event with `result=fail` and
returns `Err(...)` to the load path. There is no log-and-continue arm.

### Step 6: offline mode reconciliation (M06 P2.T5)

For the dual-mode path (Ed25519 manifest sig PLUS Sigstore bundle), call
both verifiers and reject on any disagreement. The Sigstore half of the
dual-mode call is exactly the same `verify_bundle` invocation as Step 2.
The Ed25519 half stays inside `chio-wasm-guards::manifest` and is not
affected by this migration.

### Step 7: integration-test wiring (M06 P2.T6)

The zot-registry integration suite in M06 P2.T6 covers
"tampered-artifact rejection" and "wrong-subject rejection". Both
fixtures must be triggered by `chio_attest_verify::AttestError`
variants surfacing through the `chio-guard-registry` API; do not assert
against `sigstore-rs` types directly in M06 tests. If a future
`chio-attest-verify` change renames a variant, the M06 test suite must
update through the trait surface, not by reaching into `sigstore-rs`.

## Forbidden patterns (review checklist)

When reviewing the M06 P2 PR, reject the diff if any of the following
appears in `crates/chio-wasm-guards/**` or `crates/chio-guard-registry/**`:

- `use sigstore::` or `use sigstore_rs::`.
- `sigstore = ` or `sigstore-rs = ` in a `Cargo.toml` under those crates.
- A locally-defined `ExpectedIdentity` struct with the same shape as
  `chio_attest_verify::ExpectedIdentity`.
- Any `cosign verify-blob` shell-out (the verifier is in-process Rust).
- A `_ => Ok(())` arm on a match over `AttestError` (must be `_ => deny`).
- Any path that returns `Ok(VerifiedAttestation { .. })` constructed
  inside M06 code (the type is constructible only inside
  `chio-attest-verify`; M06 always receives it via the trait return).

## Closing this document

This document closes when the M06 P2 PR (the one whose first commit is
`feat(guard-registry): cosign keyless verify with Fulcio subject and
Rekor proof gating`, M06 phase doc Phase 2 task P2.T4) merges and
satisfies all four conditions:

1. `chio-guard-registry`'s **direct** dependencies do not include
   `sigstore` or `sigstore-rs`. A bare
   `cargo tree -p chio-guard-registry | grep sigstore` is **not** a
   valid gate, because the required `chio-attest-verify` dependency
   itself depends on `sigstore` (`crates/chio-attest-verify/Cargo.toml`),
   so the transitive grep would always fire and keep the migration
   permanently red even when M06 follows the intended architecture
   (cleanup-c11d; PR #74 review thread r3143034863). Use a
   direct-dependency check instead, e.g.
   `cargo tree -p chio-guard-registry --depth 1 | grep -E 'sigstore(-rs)?'`
   or, equivalently, `awk` on the `[dependencies]` block of
   `crates/chio-guard-registry/Cargo.toml`.
2. `rg -n 'use sigstore' crates/chio-wasm-guards crates/chio-guard-registry`
   returns nothing.
3. `cargo doc -p chio-guard-registry` shows `ExpectedIdentity`,
   `AttestVerifier`, and `VerifiedAttestation` only as re-exports from
   `chio_attest_verify`.
4. The M06 P2.T6 integration suite asserts the `AttestError` variant
   table in Step 5 above (tampered artifact -> `SignatureMismatch`,
   wrong subject -> `IdentityMismatch`, etc.).

When all four are green, append a `closed_ts` note to this file in the
same PR and update the M06 phase doc's "Cross-milestone coordination"
bullet to reference the merged commit SHA.
