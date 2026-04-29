# M03: PQ-Hybrid Signing + TEE Quote Verifier

**Wave:** W2  |  **Trust-boundary:** yes  |  **Tickets:** 32  |  **Effort:** 39.50 days

## In one paragraph

M03 lands ML-DSA-65 hybrid signatures (classical + PQ in one envelope) across receipts, capability tokens, and compliance certificates, and consolidates Intel TDX, AMD SEV-SNP, and AWS Nitro NSM quote verification into the existing `chio-attest-verify` crate. The hybrid encoding becomes the substrate that M04 signs revocation roots over and that M10 hardware custody mints capabilities through.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 5 | Pin fips204/dcap-rs/sev/coset; add `pq` cargo feature; seed audit doc and threat-model rows |
| P1 | 6 | `Signature::Hybrid` and `PublicKey::Hybrid` variants + FIPS 204 KAT vectors |
| P2 | 6 | `policy.crypto_floor` enum, hybrid receipt/capability/cert signing, v3.18 migration test |
| P3 | 5 | TDX DCAP backend + `QuoteVerifier` trait + `report_data` binding helper + fixtures |
| P4 | 5 | SEV-SNP and Nitro NSM backends + cross-backend conformance test |
| P5 | 5 | TEE-bound PQ key composition, end-to-end migration suite, key roll, audit close |

## Load-bearing artifacts

- `crates/chio-core-types/src/crypto.rs` Hybrid variants (M03.P1.T1)
- `crates/chio-core/tests/pq_kats.rs` FIPS 204 KAT vectors (M03.P1.T3)
- `policy.crypto_floor` enum in `chio-policy` (M03.P2.T1)
- `crates/chio-attest-verify/src/{tdx,sev_snp,nitro}.rs` + `QuoteVerifier` trait (P3.T1, P4.T1, P4.T3)
- `crates/chio-attest-verify/fixtures/quotes/{tdx,sev_snp,nitro}/` corpora (P3.T4, P4.T2, P4.T4)
- `crates/chio-attest-verify/tests/migration.rs` end-to-end migration (M03.P5.T2)

## Cross-trajectory deps

- trajectory-1 M06 cosign-bundle path - regression-tested under all `crypto_floor` settings (soft_dep on M03.P2.T6)
- trajectory-1 M10 TEE replay - source of pinned TDX fixture quotes (soft_dep on M03.P3.T5)
- trajectory-2 M06 `CanonicalBytes` - hybrid signing input (soft_dep on M03.P5.T3; D16 sequences M06.P1 first)
- trajectory-2 M05 threat model - M03.P0.T4 appends `pq_signature_downgrade` and `tee_quote_forgery` rows; M05's gate marks them covered

## Locked decisions

- D08 PQ primitive: ML-DSA-65 via `fips204` crate (pure-Rust, forbid-unsafe)
- D09 No KEM (Kyber) in trajectory-2 - signatures only
- D10 TEE quote backends: TDX + SEV-SNP + Nitro NSM (Apple SEP, SGX deferred)

## Active freezes

- `m03-attest-verify-pivot` (`crates/chio-attest-verify/src/**`): opens at M03.P1.T1, closes at M03.P3.T5
- `m03-pq-primitives-pivot` (`crates/chio-core/src/signature*.rs`, `crates/chio-core-types/src/canonical*.rs`): opens at M03.P1.T1, closes at M03.P2.T6

## When this milestone is done

- `cargo test -p chio-core --test pq_kats --features pq` green; FIPS 204 KAT vectors locked.
- `Signature::Hybrid` round-trips through canonical JSON byte-identical to fixtures and never alters classical encodings.
- `crypto_floor` rejects invalid combinations at load time (fail-closed).
- Three `QuoteVerifier` implementations green on the pinned fixture corpus; cross-backend conformance test green.
- A v3.18 receipt bundle re-verifies under `allow_classical` byte-identically; a re-signed bundle re-verifies under `pq_required` and rejects the v3.18 bundle.
- `chio-guard-registry` cosign-bundle regression test passes under all three `crypto_floor` settings.
- M05 threat-model coverage gate marks `pq_signature_downgrade` and `tee_quote_forgery` covered.
