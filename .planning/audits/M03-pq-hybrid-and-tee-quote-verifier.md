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
