# chio-attest-verify architecture

## Overview

`chio-attest-verify` is the workspace's trust boundary for supply-chain and
hardware-attestation verification: it is the only crate permitted to call
`sigstore-rs`, and it owns Sigstore keyless verification, TEE quote
verification (Intel TDX, AMD SEV-SNP, AWS Nitro), and signed per-tenant
identity-policy loading. It is a library with no ambient trust: every public
entry point takes its expected identity, collateral, or policy signer as an
explicit argument, and every verification path is fail-closed by contract
(documented on `AttestVerifier` and `QuoteVerifier`). `#![forbid(unsafe_code)]`
and a crate-wide `unwrap`/`expect` ban hold at the crate root.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `AttestVerifier` and `QuoteVerifier` traits, `ExpectedIdentity`, `VerifiedAttestation`, `AttestError`, `TenantPolicyResolver` and `StaticTenantPolicyMap`. |
| `src/sigstore/mod.rs` | Private module wiring; embedded trust-root bytes (`include_bytes!`) and the Fulcio/SAN OIDs. |
| `src/sigstore/core.rs` | `SigstoreVerifier`: embedded-root construction, `verify_blob`/`verify_bytes`/`verify_bundle`. |
| `src/sigstore/bundle_verify.rs` | Drives the async `sigstore-rs` bundle verifier from a sync trait method; error mapping to `AttestError`. |
| `src/sigstore/identity.rs` | OIDC-issuer extension read and SAN regex identity matching against the Fulcio leaf cert. |
| `src/sigstore/parse.rs` | PEM/DER certificate parsing; Fulcio OIDC-issuer extension value decoding. |
| `src/sigstore/policy.rs` | `IssuerOnlyPolicy`, a `sigstore-rs` `VerificationPolicy` that checks OIDC issuer only (SAN matching happens separately in `identity.rs`). |
| `src/sigstore/validators.rs` | Fulcio chain validation via `webpki`, certificate validity window, signature verification. |
| `src/sigstore/compat.rs` | Sigstore protobuf-bundle field extraction (leaf cert DER, Rekor log index / integrated time). |
| `src/policy.rs` | `TenantPolicy` schema (TOML on disk, canonical JSON for signing) and structural validation. |
| `src/policy_loader.rs` | `TenantPolicyLoader`: signature verification plus staleness check for `TenantPolicy`. |
| `src/quote.rs` | `QuoteVerifier` trait, `TeeKind`, `QuoteTcbStatus`, `QuoteVerificationContext`, `VerifiedQuote`, `expect_report_data`. |
| `src/tee_signature.rs` (`tee-quotes`) | Shared P-256/P-384 signature verification against an attestation key, including the AMD SEV-SNP raw `r` / `s` / reserved signature encoding. |
| `src/nitro.rs` (`tee-quotes`) | AWS Nitro NSM backend: `COSE_Sign1`/CBOR parsing, PCR0 and chain checks. |
| `src/sev_snp.rs` (`tee-quotes`) | AMD SEV-SNP backend: fixed-offset envelope parsing, VCEK/VLEK chain selection. |
| `src/tdx.rs` (`tee-quotes`) | Intel TDX DCAP backend: v4 quote header/body parsing, PCK chain validation. |
| `src/kani_public_harnesses.rs` (`cfg(kani)`) | Model-checked harnesses over `expect_report_data` and a model of the three backends' fail-closed algebra. |
| `src/bin/tuf-rebake.rs` | `tuf-rebake` binary: refreshes the embedded Sigstore TUF trust root from the public-good TUF repository. |
| `build.rs` | Fails the build if `sigstore-root/root.json` or `sigstore-root/trusted_root.json` is missing. |

## Verification paths

- **Sigstore bundle** (`verify_bundle`): parse the `Bundle` JSON, run
  `sigstore-rs`'s async bundle verifier under `IssuerOnlyPolicy` (on a helper
  tokio runtime, or a spawned thread if already inside one), extract the leaf
  cert DER, match the SAN identity against `ExpectedIdentity`, and return
  `VerifiedAttestation` with `rekor_inclusion_verified = false`.
- **Sigstore detached blob/bytes** (`verify_blob`/`verify_bytes`): parse the
  leaf cert (PEM or DER), chain-validate against the embedded Fulcio root via
  `webpki`, match OIDC issuer and SAN identity, check the certificate validity
  window, then verify the signature (base64 or raw) over the artifact bytes.
- **TEE quote** (`verify_quote`, `tee-quotes`): each backend parses its wire
  envelope, checks its collateral chain terminates at the configured root and
  the TCB status is acceptable, verifies the envelope signature against the
  leaf attestation key, and byte-compares the full 64-byte `report_data` slot
  against `expect_report_data(kernel_pk, receipt_root)`.
- **Tenant policy** (`TenantPolicyLoader::load_signed`): parse and
  structurally validate the TOML, verify the canonical-JSON signing bytes
  through the caller-supplied `AttestVerifier`, then reject if `signed_at` is
  in the future or older than the staleness horizon (default 90 days).

## Invariants and failure modes

- Every public verification method is fail-closed: `Ok(_)` only after every
  documented precondition holds. `AttestError` is `#[non_exhaustive]` so
  callers cannot pattern-match past a future variant and silently accept.
- `rekor_inclusion_verified` is `false` on every current path. `sigstore-rs`
  confirms transparency-entry consistency, but this crate does not yet verify
  Rekor Merkle inclusion or the Signed Entry Timestamp itself.
- TEE chain checks (`chain_terminates_at_root`, one copy per backend) reject
  chains shorter than two links, chains containing an empty link, and chains
  whose leaf equals the configured root.
- The `report_data` binding is a full 64-byte compare (digest in bytes
  `0..32`, zero padding in `32..64`); a quote that stuffs unrelated bytes into
  the padding is rejected rather than ignored.
- SEV-SNP additionally rejects when `sig_algo` and `key_select` disagree on
  which endorsement key (VCEK vs VLEK) signed the report, closing a
  type-confusion path.
- `TenantPolicy` is `#[serde(deny_unknown_fields)]`; every text and list field
  rejects empty and surrounding-whitespace values before regex compilation or
  signature verification runs.
- `ExpectedIdentity::doc_hidden_inline` is the sanctioned inline constructor
  for tests and direct operator configuration; production call sites are
  expected to resolve identities through `TenantPolicyResolver` instead of
  constructing `ExpectedIdentity` literals.
- `#![forbid(unsafe_code)]`, `#![forbid(clippy::unwrap_used)]`, and
  `#![forbid(clippy::expect_used)]` hold at the crate root; no
  `todo!`/`unimplemented!`/`panic!` in any verification path.

## Dependencies

Internal: `chio-core-types` supplies `canonical_json_bytes` (policy signing
bytes) and `crypto::PublicKey` (the kernel-key half of `expect_report_data`).

External: `sigstore` for the keyless bundle flow and embedded trust-root
parsing (no other workspace crate depends on it); `x509-cert`, `pem`, and
`const-oid` for certificate parsing; `pki-types` (crate `rustls-pki-types`)
and `webpki` (crate `rustls-webpki`) for Fulcio chain validation; `sha2` for
digesting; `regex` for identity-SAN and policy-regex matching; `toml` for the
on-disk `TenantPolicy` format; `tokio` (`rt` feature only) to drive the async
`sigstore-rs` verifier from a synchronous trait method; `tough`,
`futures-util`, and `url` for the `tuf-rebake` binary's TUF client. Behind
`tee-quotes`: `coset` (`COSE_Sign1`/CBOR for Nitro) and `p256`/`p384` (ECDSA
verification of TEE attestation keys).

## Extension points

- `AttestVerifier` - implement against a non-Sigstore signing backend;
  `SigstoreVerifier` is the only production implementation shipped.
- `QuoteVerifier` - implement for a TEE family beyond TDX/SEV-SNP/Nitro; every
  implementation must bind `report_data` via `expect_report_data`.
- `TenantPolicyResolver` - implement to plug in tenant-id resolution other
  than the shipped `StaticTenantPolicyMap`.
