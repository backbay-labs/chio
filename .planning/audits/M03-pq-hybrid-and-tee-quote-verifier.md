# M03 PQ Hybrid And TEE Quote Verifier Audit

## Scope

This audit records the P0 wave-opener state for the PQ hybrid signing and TEE
quote verifier work. P0 is limited to dependency pins, default-off feature
plumbing, baseline measurements, and threat-register entries. It does not add
hybrid signature APIs, quote verifier APIs, verifier source changes, kernel
signing changes, TEE container changes, frame schema changes, or P1 surfaces.

## Starting Counts

starting counts measured on 2026-04-30 from branch
`wave/W2/m03/p0.bundle-pq-tee-wave-opener` after rebasing onto current
`origin/main`.

| Surface | Live measurement | Command |
| --- | ---: | --- |
| `crates/chio-attest-verify/src/lib.rs` | 131 lines | `wc -l crates/chio-attest-verify/src/lib.rs` |
| `crates/chio-attest-verify/src/sigstore.rs` | 626 lines | `wc -l crates/chio-attest-verify/src/sigstore.rs` |
| `crates/chio-core-types/src/crypto.rs` | 1252 lines | `wc -l crates/chio-core-types/src/crypto.rs` |
| `SignatureMaterial` variants | 3 variants (`Ed25519`, `P256`, `P384`) | `awk '/enum SignatureMaterial/,/^}/' crates/chio-core-types/src/crypto.rs \| rg -c '^\s+(Ed25519\|P256\|P384\|Hybrid)'` |
| quote fixture binaries | 0 | `find crates/chio-attest-verify -path '*/fixtures/*' -name '*.bin' \| wc -l` |
| `crates/chio-tee/src` files | 10 files | `find crates/chio-tee/src -type f \| wc -l` |
| `crates/chio-tee-frame/src` files | 3 files | `find crates/chio-tee-frame/src -type f \| wc -l` |

## Dependency Recheck

Crates.io recheck on 2026-04-30 confirmed the current approved patch set:

| Crate | Current result | Evidence command |
| --- | --- | --- |
| `fips204` | `0.4.6` | `cargo search fips204 --limit 5` |
| `ml-dsa` | `0.1.0-rc.9` | `cargo search ml-dsa --limit 10` |
| `dcap-rs` | `0.1.0` | `cargo search dcap-rs --limit 5` |
| `sev` | `7.1.0` | `cargo search sev --limit 5` |
| `coset` | `0.4.2` | `cargo search coset --limit 5` |

The workspace pins use:

- `fips204 = "0.4.6"` with default features disabled and `ml-dsa-65` enabled.
- `dcap-rs = "0.1.0"`.
- `sev = "7.1.0"` with default features disabled and `snp` plus
  `crypto_nossl` enabled.
- `coset = "0.4.2"` with default features disabled.

`fips204` metadata from `cargo info fips204@0.4.6` reports Rust 1.70, default
features `default-rng`, `ml-dsa-44`, `ml-dsa-65`, and `ml-dsa-87`, with
individual algorithm feature flags. The P0 pin keeps only `ml-dsa-65` enabled
so later work consumes the approved algorithm without enabling unused variants.

`sev` metadata from `cargo info sev@7.1.0` reports Rust 1.85 and default
features that include `openssl?/vendored`. The P0 pin disables defaults and
enables the SNP and no-OpenSSL crypto feature path to avoid introducing a
vendored OpenSSL build into the verifier opener.

## fips204 Recheck

fips204 re-check 2026-04-30: D08 remains binding. The RustCrypto `ml-dsa`
crate is still published as `0.1.0-rc.9`, so this opener keeps the approved
pure-Rust `fips204` dependency and only updates the patch pin to `0.4.6`.
Switching to `ml-dsa` would require an explicit D08 amendment before
implementation proceeds.

## Threat Register

P0 adds exactly these threat IDs to the JSON register and public security
document:

- `pq_signature_downgrade`
- `tee_quote_forgery`

All new controls are marked planned because hybrid signature verification,
cryptographic-floor enforcement, and TEE quote verification have not landed in
this opener.

## Freeze Check

The P0 window starts before the M03 freeze triggers. This change avoids the
future frozen implementation paths:

- no edits under `crates/chio-attest-verify/src/**`
- no edits to `crates/chio-core-types/src/crypto.rs`
- no edits to kernel signing paths
- no edits to TEE container code
- no edits to frame schemas

## P1 Progress - PQ Hybrid Primitives And TEE Scaffold

Measured on 2026-04-30 from branch
`wave/W2/m03/p1.bundle-pq-primitives`.

P1 lands the default-off PQ primitive surface:

- `M03.P1.T1` / `M03.P1.T2`: `Signature`, `PublicKey`, and
  `SigningAlgorithm` now support a `Hybrid` variant behind the `pq` feature,
  with `MlDsa65Backend` and `HybridBackend` in `chio-core-types`.
- `M03.P1.T3`: `chio-core` has ML-DSA-65 KAT replay coverage pinned to the
  NIST-derived fixture hashes recorded in `pq_kats.rs`.
- `M03.P1.T4`: hybrid signatures reject bit flips in either classical or PQ
  half, reject alg-set tampering, and reject malformed ML-DSA-65 lengths.
- `M03.P1.T5`: hybrid canonical JSON roundtrip coverage is locked under
  `crates/chio-core/tests/golden/` with deterministic seed-derived public-key
  and canonical-string hashes. Classical Ed25519 encodings are not changed.
- `M03.P1.T6`: `spec/PROTOCOL.md` and `spec/schemas/signature.v1.json`
  document the `hybrid:<classical>:<pq>:<alg_set>` wire prefix.

The same branch also carries a TEE primitive scaffold required by the phase
bundle:

- `expect_report_data` binds a quote to the kernel public key and receipt
  root by hashing the kernel key wire bytes plus the receipt root into the
  first 32 report-data bytes, then zero-padding the remaining 32 bytes.
- `QuoteVerifier`, `QuoteVerificationContext`, `VerifiedQuote`, `TeeKind`, and
  `QuoteTcbStatus` define the verifier-facing scaffold.
- `TdxDcapVerifier` currently parses a minimal Intel TDX v4 quote envelope,
  checks report-data binding, rejects missing or unanchored collateral,
  rejects stale collateral windows, rejects low recovery event IDs, and
  rejects unacceptable TCB states.

This is scaffold and primitive work only. It does not claim full Intel DCAP
certificate validation, a pinned TDX quote corpus, SEV-SNP or Nitro quote
backends, kernel policy rollout, or production TEE admission.

## P1 Gate Evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Core PQ tests | PASS | `cargo test -p chio-core-types --features pq --quiet` |
| Core PQ clippy | PASS | `cargo clippy -p chio-core-types --features pq -- -D warnings` |
| ML-DSA-65 KAT replay | PASS | `cargo test -p chio-core --test pq_kats --features pq` |
| Hybrid bitflip property | PASS | `cargo test -p chio-core-types --features pq --test hybrid_bitflip` |
| Hybrid canonical roundtrip | PASS | `cargo test -p chio-core --test hybrid_canonical_roundtrip --features pq` |
| Spec and schema prefix check | PASS | `grep -q 'hybrid:' spec/PROTOCOL.md && grep -q 'hybrid' spec/schemas/signature.v1.json` |
| TEE quote scaffold build | PASS | `cargo build -p chio-attest-verify --features tee-quotes --quiet` |
| report_data binding tests | PASS | `cargo test -p chio-attest-verify --features tee-quotes --test expect_report_data` |
| TDX unit scaffold tests | PASS | `cargo test -p chio-attest-verify --features tee-quotes --test tdx_unit` |

## P5 Threat-Model Coverage Handshake (M03.P5.T4)

P5.T4 marks the two M03 threat-register rows covered by tests so the M05
threat-model-as-code CI gate can consume the coverage entries. The
covered-by-tests assignment is recorded in
`spec/security/chio-threat-model.v1.json` under each threat's
`covered_by_tests` array; the rows below summarize the handshake.

### Threat: `pq_signature_downgrade`

Crypto-floor enforcement and the kernel boot path together close the
post-quantum signature downgrade surface. Coverage tests:

- `crates/chio-attest-verify/tests/migration.rs` -- end-to-end
  migration walk through `allow_classical -> allow_hybrid ->
  pq_required` with PQ key roll between stages 2 and 3, asserting the
  v3.18 classical bundle is rejected once `pq_required` is in force.
- `crates/chio-attest-verify/tests/v318_migration.rs` -- byte-equivalence
  baseline plus the `pq_required` rejection of the v3.18 bundle.
- `crates/chio-kernel/tests/pq_key_load_after_self_quote.rs` -- the
  M03.P5.T1 boot gate refusing to materialize the PQ signing key under
  a non-classical floor unless the self-quote binds.
- `crates/chio-kernel/tests/hybrid_receipt_sign.rs` -- the
  `KernelCryptoFloor` dispatch and the hybrid receipt round trip.

### Threat: `tee_quote_forgery`

Three platform quote backends (Intel TDX, AMD SEV-SNP, AWS Nitro NSM)
plus the report-data binding helper close the TEE quote forgery and
quote misbinding surface. Coverage tests:

- `crates/chio-attest-verify/tests/cross_backend_conformance.rs` --
  type-confusion: each backend rejects fixtures meant for the other
  two backends.
- `crates/chio-attest-verify/tests/expect_report_data.rs` --
  `expect_report_data(kernel_pk, receipt_root)` byte-binding shape.
- `crates/chio-attest-verify/tests/tdx_integration.rs` and
  `crates/chio-attest-verify/tests/tdx_unit.rs` -- TDX collateral
  walk and stale-TCB rejection.
- `crates/chio-attest-verify/tests/sev_snp_integration.rs` and
  `crates/chio-attest-verify/tests/sev_snp_unit.rs` -- SEV-SNP VLEK
  and VCEK chains plus mismatched-launch-digest rejection.
- `crates/chio-attest-verify/tests/nitro_unit.rs` and
  `crates/chio-attest-verify/tests/nitro_root_rotation.rs` -- Nitro
  COSE_Sign1 verification and the embedded-root rotation regression.
- `crates/chio-kernel/tests/pq_key_load_after_self_quote.rs::allow_hybrid_loads_pq_only_after_verified_self_quote`
  -- the kernel-side handshake that ties a verified self-quote to the
  PQ key load.

### Handshake Gate

Gate command (also pinned in `tickets/M03/P5.yml#M03.P5.T4`):

```
grep -q '"covered_by_tests"' spec/security/chio-threat-model.v1.json \
  && grep -q 'pq_signature_downgrade' .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md \
  && grep -q 'tee_quote_forgery' .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md
```

The M05 threat-model-as-code consumer picks up the
`covered_by_tests` arrays at CI time; this audit doc is the human-
readable companion that lists the test paths inline.
