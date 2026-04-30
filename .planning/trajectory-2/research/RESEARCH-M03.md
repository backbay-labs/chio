# Research M03: P0 Ready-Pack

Scope: M03 P0 wave-opener for PQ-hybrid signing and TEE quote verifier work.
This research note is implementation guidance only. It does not edit protected
trust-boundary implementation paths and it does not amend milestone narratives,
decisions, freezes, owners, execution board, or style files.

Inputs read:

- `.planning/trajectory-2/03-pq-hybrid-and-tee-quote-verifier.md`
- `.planning/trajectory-2/tickets/M03/P0.yml`
- `.planning/trajectory-2/decisions.yml` decisions D08, D09, D10
- `.planning/trajectory-2/freezes.yml`
- `.planning/trajectory-2/research/M03-P0-implementation-notes.md`
- `Cargo.toml`
- `crates/chio-core-types/Cargo.toml`
- `crates/chio-attest-verify/Cargo.toml`
- `crates/chio-core-types/src/crypto.rs`
- `crates/chio-core-types/src/receipt.rs`
- `crates/chio-acp-proxy/src/compliance.rs`
- `crates/chio-attest-verify/src/lib.rs`
- `crates/chio-attest-verify/src/sigstore.rs`
- `crates/chio-core-types/tests/threat_model_artifacts.rs`
- `spec/security/chio-threat-model.v1.json`
- `spec/SECURITY.md`

## Current Surface Snapshot

- `crates/chio-attest-verify/src/lib.rs`: 131 lines. It exposes
  `AttestVerifier`, `ExpectedIdentity`, `VerifiedAttestation`, and
  `AttestError`. There is no `QuoteVerifier` trait today.
- `crates/chio-attest-verify/src/sigstore.rs`: 626 lines. It is still the
  only production verifier implementation and preserves the Sigstore single
  source of truth.
- `crates/chio-core-types/src/crypto.rs`: 1252 lines. It has Ed25519, P-256,
  P-384, `SigningAlgorithm`, `PublicKey`, `Signature`, and `SigningBackend`.
  There is no hybrid or PQ variant today.
- `crates/chio-core-types/Cargo.toml` has `default = ["std"]` and `fips`.
  There is no `pq` feature today.
- `crates/chio-attest-verify/Cargo.toml` has no feature table today.
- Quote fixture binaries under `crates/chio-attest-verify/**/fixtures/**/*.bin`:
  0.
- `spec/security/chio-threat-model.v1.json` and `spec/SECURITY.md` do not yet
  contain `pq_signature_downgrade` or `tee_quote_forgery`.
- Compliance certificate live type names are `ComplianceCertificateBody` and
  `ComplianceCertificate` in `crates/chio-acp-proxy/src/compliance.rs`.
  M03 prose says `SessionComplianceCertificate`; P0 should use the live names
  in code and avoid renaming during the opener.

## Binding Decisions

- D08: ML-DSA-65 uses the pure-Rust `fips204` crate. Changing to RustCrypto
  `ml-dsa` or any C-binding crate needs an explicit D08 amendment.
- D09: Kyber / ML-KEM is out of scope. P0 must not add KEM dependencies or TLS
  hybrid work.
- D10: Quote verifier backends are Intel TDX DCAP, AMD SEV-SNP VLEK/VCEK, and
  AWS Nitro NSM. Apple SEP and SGX remain out of scope.

Crates.io recheck on 2026-04-30:

- `fips204 = "0.4.6"`
- `ml-dsa = "0.1.0-rc.9"`
- `dcap-rs = "0.1.0"`
- `sev = "7.1.0"`
- `coset = "0.4.2"`

Interpret this as drift evidence, not approval to change decisions. D08 still
binds M03 to `fips204`; P0.T5 should record whether `0.4.6` is the intended
patch pin and whether `ml-dsa` is still too pre-release to amend D08.

## P0 Tickets

### M03.P0.T1 - Pin PQ and TEE Crates

Expected files:

- `Cargo.toml`
- `Cargo.lock`
- Possibly `crates/chio-core-types/Cargo.toml`
- Possibly `crates/chio-attest-verify/Cargo.toml`

Implementation notes:

- Put shared pins in root `[workspace.dependencies]` so later tickets consume
  one resolver surface.
- Keep direct member dependencies optional until P1 or P3 actually uses them.
- `chio-core-types` supports `no_std + alloc`; any PQ dependency there must be
  optional and must not disturb `cargo build -p chio-core-types --no-default-features`.
- `chio-attest-verify` is `std`, but it forbids unsafe code, `unwrap`, and
  `expect`; dependency choices must preserve that trust-boundary posture.
- Serialize P0.T1 because it owns root `Cargo.toml` and `Cargo.lock`.

Gate:

```bash
cargo build -p chio-core-types --quiet && cargo build -p chio-attest-verify --quiet && cargo tree -p chio-attest-verify -d
```

### M03.P0.T2 - Add Default-Off `pq` Features

Expected files:

- `crates/chio-core-types/Cargo.toml`
- `crates/chio-attest-verify/Cargo.toml`

Implementation notes:

- Add `pq = [...]` without adding it to `default`.
- Preserve `default = ["std"]` behavior in `chio-core-types`.
- If `fips204` requires `std`, keep that coupling behind `pq` and record it in
  the audit doc.
- For `chio-attest-verify`, add an explicit feature table even if the first
  version is only `default = []` plus `pq = [...]`.
- Do not expose public hybrid or quote-verifier API in P0 unless a ticket is
  explicitly expanded.

Gate:

```bash
cargo build -p chio-core-types --no-default-features --quiet && cargo build -p chio-core-types --features pq --quiet && cargo build -p chio-attest-verify --features pq --quiet
```

### M03.P0.T3 - Open Audit Doc

Expected file:

- `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md`

Implementation notes:

- Include the literal phrase `starting counts`; the ticket gate greps for it.
- Seed measured counts and commands used to reproduce them.
- Use live counts from the worktree, not stale narrative counts:
  `lib.rs` 131 lines, `sigstore.rs` 626 lines, `crypto.rs` 1252 lines,
  quote fixture binaries 0.
- Record the 2026-04-30 dependency recheck and any unresolved version drift.

Gate:

```bash
test -f .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md && grep -q 'starting counts' .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md
```

### M03.P0.T4 - Add Threat-Model Rows

Expected files:

- `spec/security/chio-threat-model.v1.json`
- `spec/SECURITY.md`

Implementation notes:

- Add exactly two IDs: `pq_signature_downgrade` and `tee_quote_forgery`.
- Preserve the existing threat JSON row shape and Markdown table style.
- Mark controls as planned unless the implementation has actually landed.
- Update `crates/chio-core-types/tests/threat_model_artifacts.rs` if it still
  asserts the old exact six-threat set.
- M05 later consumes these IDs, so spelling is part of the contract.

Gate:

```bash
grep -q 'pq_signature_downgrade' spec/security/chio-threat-model.v1.json && grep -q 'tee_quote_forgery' spec/security/chio-threat-model.v1.json && grep -q 'pq_signature_downgrade' spec/SECURITY.md && grep -q 'tee_quote_forgery' spec/SECURITY.md
```

Recommended extra gate:

```bash
cargo test -p chio-core-types threat_model_artifacts --quiet
```

### M03.P0.T5 - Recheck `fips204` vs RustCrypto `ml-dsa`

Expected file:

- `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md`

Implementation notes:

- Add a line matching the ticket gate, for example:
  `fips204 re-check 2026-04-30: ...`
- If the recommendation changes away from `fips204`, stop and amend D08 first.
- If only the patch pin moves to `0.4.6`, say why that is still consistent
  with D08.
- If `ml-dsa = "0.1.0-rc.9"` remains pre-release, record that as evidence for
  keeping D08 unless a deeper security review says otherwise.

Gate:

```bash
grep -qE 'fips204 (re-check|recheck) [0-9]{4}-[0-9]{2}-[0-9]{2}' .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md
```

Recommended evidence commands:

```bash
cargo search fips204 --limit 5
cargo search ml-dsa --limit 10
cargo search pqcrypto-mldsa --limit 5
cargo search dcap-rs --limit 5
cargo search sev --limit 5
cargo search coset --limit 5
```

## Freeze And Guard Considerations

- M03 freezes start in P1, not P0.
- `m03-attest-verify-pivot` covers `crates/chio-attest-verify/src/**` during
  P1-P3.
- `m03-pq-primitives-pivot` covers `crates/chio-core/src/signature*.rs`,
  `crates/chio-core/tests/pq_kats.rs`, and
  `crates/chio-core-types/src/canonical*.rs` during P1-P2.
- P0 may touch `Cargo.toml`, `Cargo.lock`, crate `Cargo.toml` files, audit
  docs, and security threat-model docs. It should not touch
  `crates/chio-attest-verify/src/**`, `crates/chio-core-types/src/crypto.rs`,
  `crates/chio-core-types/src/capability.rs`, kernel signing paths, TEE
  container code, or frame schemas.
- M05's `m05-adversarial-corpus-pivot` later covers
  `spec/security/chio-threat-model.v1.json` and
  `crates/chio-attest-verify/src/policy.rs`; M03.P0.T4 should coordinate
  exact threat IDs before M05 opens.
- Every M03 PR is a trust-boundary milestone PR and should carry security x2
  review plus `@bb-connor`, even when P0 is dependency and docs only.

## Crate And Dependency Constraints

- Do not add default-on PQ features.
- Do not add KEM dependencies.
- Prefer pure-Rust and unsafe-free dependencies. Any exception needs explicit
  audit-doc rationale and reviewer signoff.
- Keep `chio-core-types` compatible with `no_std + alloc` in default and
  no-default builds.
- Treat `Cargo.lock` churn as dependency resolution only; do not combine it
  with behavior implementation.
- Expect `cargo tree -p chio-attest-verify -d` to surface duplicate x509,
  crypto, or COSE stacks. Review duplicates before merge rather than treating
  them as a mechanical failure.
- The Sigstore path in `chio-attest-verify` must stay unchanged in P0.

## First PR Shape

Recommended first implementation PR: one serialized P0 opener branch,
`wave/W2/m03/p0.t1-pin-pq-and-tee-crates`, with scope limited to:

- root workspace dependency pins
- `Cargo.lock` refresh
- optional dependency entries needed by `chio-core-types` and
  `chio-attest-verify`
- no default feature changes beyond what P0.T1 strictly requires
- no code changes under trust-boundary source paths
- audit note if dependency resolution differs from the trajectory narrative

After that PR merges, split follow-ups by ticket:

- P0.T2: default-off `pq` feature plumbing in the two crate manifests.
- P0.T3: audit doc with starting counts.
- P0.T4: threat-model rows plus artifact-test update if needed.
- P0.T5: dependency ecosystem recheck recorded in the audit doc.

Do not combine P0.T4 with P0.T1 unless lockfile serialization becomes the only
practical path. Keeping threat-model edits separate lowers review risk and lets
M05 consume exact IDs cleanly.

## Gate Bundle Before Review

Run ticket gates exactly, then add:

```bash
cargo fmt --all -- --check
cargo build -p chio-core-types --no-default-features --quiet
cargo build -p chio-core-types --features pq --quiet
cargo build -p chio-attest-verify --features pq --quiet
cargo test -p chio-core-types threat_model_artifacts --quiet
cargo tree -p chio-attest-verify -d
```

If the dependency bump is small enough to afford stricter checks:

```bash
cargo clippy -p chio-core-types --features pq -- -D warnings
cargo clippy -p chio-attest-verify --features pq -- -D warnings
```

## Review Checklist

- No behavior implementation in P0.
- No protected trust-boundary source edits.
- No default-on `pq` feature.
- No Sigstore behavior changes.
- No TEE container or frame schema changes.
- No Kyber, ML-KEM, Apple SEP, SGX, HSM-backed PQ signer, or ZK verifier work.
- Exact threat IDs appear in both machine-readable and human-readable security
  docs.
- Audit doc contains starting counts, date, crate recheck evidence, and
  unresolved decision drift.
