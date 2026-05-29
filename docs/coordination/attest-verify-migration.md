# chio-wasm-guards migration to chio-attest-verify

Status: open. Owners: the guard consumer (`chio-wasm-guards` / `chio-guard-registry`) and the producer of `chio-attest-verify`.
Tracked-by: this document. Closed-by: the consumer change that lands cosign
keyless verification through `chio_attest_verify::AttestVerifier`.

## Why this exists

The producer change lands `crates/chio-attest-verify/`, the single source of truth
for Sigstore verification across the chio workspace. The crate's lib doc
states the rule plainly: "no other crate is permitted to call `sigstore-rs`
directly". The consumer change will add OCI-published WASM guards with cosign
keyless signatures, and the obvious-but-wrong path is to call `sigstore-rs`
from inside `chio-wasm-guards` (or a sibling `chio-guard-registry` crate).
This tracking document exists so that path is closed off before the consumer
work starts.

The shared crate is also where the OIDC-identity-and-issuer regex lives.
Forking a parallel verifier in `chio-wasm-guards` would mean two regexes,
two trust roots, and two failure modes that audit cannot reconcile. This
document and the producer's "Risks and mitigations" notes both pin this as a
fail-closed invariant.

## Current state in `crates/chio-wasm-guards/**`

As of the producer change landing, `crates/chio-wasm-guards/` does not yet call
`sigstore-rs`, `cosign`, Fulcio, or Rekor. The crate today loads `.wasm`
guard modules with fuel metering and an Ed25519 manifest signature
(`ed25519-dalek` in `Cargo.toml`). There is no Sigstore code path at all.

The migration framing is therefore preventative rather than reactive: when
the consumer change introduces signature verification for OCI-published guards, the only
permitted entry point is `chio_attest_verify::AttestVerifier`. The
"migration off raw `sigstore-rs`" goal covers two cases:

1. Code that lands in `crates/chio-wasm-guards/` or its sibling
   `chio-guard-registry` and reaches for `sigstore-rs`
   directly. This must be rewritten against `AttestVerifier` before merge.
2. Any prototype or scratch branch that already hard-codes `sigstore-rs`
   verification calls. The consumer change must rebase such branches onto the
   `AttestVerifier` trait surface.

Either case lands the same code shape, so the rest of this document treats
them uniformly.

## Target state

`chio-wasm-guards` (or, more precisely, the `chio-guard-registry` crate
introduced for the consumer) consumes `chio_attest_verify::AttestVerifier`
through dependency injection. The crate adds a `chio-attest-verify =
{ path = "../chio-attest-verify" }` line to its `Cargo.toml` and never adds
`sigstore` or `sigstore-rs` to its own dep tree.

Invariants the target state must satisfy:

- Every Sigstore verification call in consumer code paths goes through
  `AttestVerifier::verify_blob`, `AttestVerifier::verify_bytes`, or
  `AttestVerifier::verify_bundle`.
- The OIDC issuer and identity regex are constructed by populating
  `chio_attest_verify::ExpectedIdentity`. The consumer must not re-declare those
  fields locally.
- Failure paths return one of the existing `chio_attest_verify::AttestError`
  variants (`SignatureMismatch`, `IdentityMismatch`, `IssuerMismatch`,
  `RekorInclusion`, `CertificateExpired`, `TrustRoot`, `Malformed`, `Io`).
  The consumer maps these into `chio.guard.verify` events with `result=fail` and
  the `mode` field (`sigstore` or `dual`) per the guard Prometheus
  metric families defined in `spec/PROTOCOL.md`.
- The cached `sigstore-bundle.json` in the consumer offline cache layout
  (`${XDG_CACHE_HOME}/chio/guards/<digest>/sigstore-bundle.json`) is
  passed to `verify_bundle` verbatim; the consumer does not pre-parse the bundle.
- Streamed-from-network loads use `verify_bytes` with the artifact bytes,
  detached signature bytes, and PEM-encoded leaf certificate bytes. The
  cert chain to Fulcio is reassembled inside `chio-attest-verify` from the
  embedded trust root; the consumer does not pass intermediates.

## Migration steps for the consumer

These steps are written so a reviewer can grep the consumer PR and confirm
the migration is complete.

### Step 1: dep wiring

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

### Step 2: bundle path swap

The verbatim cosign command for the guard "pull and verify" flow is:

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
`VerifiedAttestation::rekor_inclusion_verified` is currently `false`
because `chio-attest-verify` validates Sigstore bundle consistency but
does not yet verify Rekor Merkle inclusion or the Signed Entry Timestamp
(SET). The consumer's `chio.guard.verify` event with `mode=sigstore` MUST fall into
`result=fail` for policies that require Rekor inclusion until that field is
truthfully `true`.

### Step 3: streamed-network path

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
consumers MUST treat that as a weaker assertion. The consumer's structured event
records `mode=sigstore` with a `rekor_inclusion=false` field so dashboards
can distinguish verification that lacks Chio-verified Rekor inclusion.

### Step 4: ExpectedIdentity construction

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

### Step 5: error mapping

`chio-guard-registry` maps `chio_attest_verify::AttestError` variants
into the deny-by-default guard failure-mode table defined in
`spec/PROTOCOL.md`.
The mapping is one-to-one and must be exhaustive at the match site (with
a `_ => deny` arm for the `#[non_exhaustive]` enum):

| `AttestError` variant   | Failure mode classification                       |
| ----------------------- | ------------------------------------------------- |
| `SignatureMismatch`     | "tampered artifact" (integration test name)       |
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

### Step 6: offline mode reconciliation

For the dual-mode path (Ed25519 manifest sig PLUS Sigstore bundle), call
both verifiers and reject on any disagreement. The Sigstore half of the
dual-mode call is exactly the same `verify_bundle` invocation as Step 2.
The Ed25519 half stays inside `chio-wasm-guards::manifest` and is not
affected by this migration.

### Step 7: integration-test wiring

The zot-registry integration suite covers
"tampered-artifact rejection" and "wrong-subject rejection". Both
fixtures must be triggered by `chio_attest_verify::AttestError`
variants surfacing through the `chio-guard-registry` API; do not assert
against `sigstore-rs` types directly in consumer tests. If a future
`chio-attest-verify` change renames a variant, the consumer test suite must
update through the trait surface, not by reaching into `sigstore-rs`.

## Forbidden patterns (review checklist)

When reviewing the consumer PR, reject the diff if any of the following
appears in `crates/chio-wasm-guards/**` or `crates/chio-guard-registry/**`:

- `use sigstore::` or `use sigstore_rs::`.
- `sigstore = ` or `sigstore-rs = ` in a `Cargo.toml` under those crates.
- A locally-defined `ExpectedIdentity` struct with the same shape as
  `chio_attest_verify::ExpectedIdentity`.
- Any `cosign verify-blob` shell-out (the verifier is in-process Rust).
- A `_ => Ok(())` arm on a match over `AttestError` (must be `_ => deny`).
- Any path that returns `Ok(VerifiedAttestation { .. })` constructed
  inside consumer code (the type is constructible only inside
  `chio-attest-verify`; the consumer always receives it via the trait return).

## Closing this document

This document closes when the consumer PR (the one whose first commit is
`feat(guard-registry): cosign keyless verify with Fulcio subject and
Rekor proof gating`) merges and
satisfies all four conditions:

1. `chio-guard-registry`'s **direct** dependencies do not include
   `sigstore` or `sigstore-rs`. A bare
   `cargo tree -p chio-guard-registry | grep sigstore` is **not** a
   valid gate, because the required `chio-attest-verify` dependency
   itself depends on `sigstore` (`crates/chio-attest-verify/Cargo.toml`),
   so the transitive grep would always fire and keep the migration
   permanently red even when the consumer follows the intended architecture. Use
   a direct-dependency check instead, e.g.
   `cargo tree -p chio-guard-registry --depth 1 | grep -E 'sigstore(-rs)?'`
   or, equivalently, `awk` on the `[dependencies]` block of
   `crates/chio-guard-registry/Cargo.toml`.
2. `rg -n 'use sigstore' crates/chio-wasm-guards crates/chio-guard-registry`
   returns nothing.
3. `cargo doc -p chio-guard-registry` shows `ExpectedIdentity`,
   `AttestVerifier`, and `VerifiedAttestation` only as re-exports from
   `chio_attest_verify`.
4. The consumer integration suite asserts the `AttestError` variant
   table in Step 5 above (tampered artifact -> `SignatureMismatch`,
   wrong subject -> `IdentityMismatch`, etc.).

When all four are green, append a `closed_ts` note to this file in the
same PR and update the producer's coordination notes to reference the merged
commit SHA.
