# Milestone 03: PQ-Hybrid Signing + TEE Quote Verifier

## Lens

Cryptography and attestation. One milestone, two cryptographic gaps, both
consolidated in `crates/chio-attest-verify/`. The first gap is signature
algorithm agility: every Chio artifact today (capability token, receipt,
compliance certificate, federation cosign) is signed by exactly one classical
key per envelope. The second gap is TEE attestation depth: trajectory-1 M10
shipped a TEE container and FIPS smoke build but never extended the verifier
crate to consume Intel TDX, AMD SEV-SNP, or AWS Nitro NSM quotes. M03 closes
both with a single coherent surface so M04 (revocation oracle roots), M09
(lineage anchor proofs), and M10 (custody envelopes) all consume one verifier
that understands ML-DSA-65 hybrid signatures and platform attestation quotes.

## Why this is on the trajectory

trajectory-1 left two specific holes that block downstream work:

- M01 locked the canonical-JSON receipt encoding via the vector corpus at
  `crates/chio-core-types/src/_generated/chio_wire_v1.rs` and the supporting
  vectors in `crates/chio-core/tests/`. Every signed artifact in the system
  rides on that encoding. M01 deliberately scoped to one signing algorithm
  per envelope (Ed25519 or one of the FIPS ECDSA curves added by
  `crates/chio-core-types/src/crypto.rs`); there is no `Signature::Hybrid`
  variant. Operators who must accept post-quantum-safe artifacts before
  classical primitives are deprecated have no path.
- M09 shipped `crates/chio-attest-verify/` (Sigstore-only verifier with cosign
  bundle support, current size 131 lines `src/lib.rs` + 626 lines
  `src/sigstore.rs` measured 2026-04-29). M10 shipped `crates/chio-tee/`
  (TEE container, FIPS smoke build, encrypted spool persistence, redaction
  determinism property test) and `crates/chio-tee-frame/` (frame schema lock).
  Neither shipped quote verification: the kernel can run inside a TEE today
  but a remote verifier cannot reconcile a TDX/SEV-SNP/Nitro quote against
  the kernel's signing key and receipt root.

Both gaps survive into trajectory-2 because they were correctly out of scope
for trajectory-1; M03 is the one milestone in W2 whose lens unifies them.
Without this milestone, M04's revocation roots cannot be PQ-signed (deferred
becomes never), M10's custody envelopes have no quote-binding step, and M09's
lineage anchors cannot prove the kernel that produced them ran inside a
known-good TEE.

## Prior-art reckoning

trajectory-1 already shipped, and M03 preserves untouched:

- `crates/chio-attest-verify/src/lib.rs`: the `AttestVerifier` trait, the
  `ExpectedIdentity` and `VerifiedAttestation` shapes, and the
  `AttestError` non-exhaustive enum. M03 does not fork the verifier. It
  adds a sibling `QuoteVerifier` trait next to `AttestVerifier` and the
  feature-gated PQ extensions to existing helpers.
- `crates/chio-attest-verify/src/sigstore.rs`: the `SigstoreVerifier`
  cosign bundle + Rekor inclusion path. M03 adds no Sigstore changes.
- `crates/chio-core-types/src/crypto.rs`: the existing `Signature` enum
  internally tagged `Ed25519 | P256 | P384`, the `SigningBackend` trait,
  and the byte-identity rules ("Ed25519 keys render as bare hex, P-256 as
  `p256:<hex>`, P-384 as `p384:<hex>`"). The hybrid variant added by M03
  follows the same self-describing prefix discipline (`hybrid:<...>`)
  rather than colonizing the existing prefix space.
- `crates/chio-tee/` and `crates/chio-tee-frame/`: the M10 container shape,
  spool, redaction pipeline, and signed NDJSON frame schema. M03 extends
  the kernel signing path that runs inside the container; the container
  itself is unchanged. The frame schema is unchanged. Quote verification
  is a new consumer-side surface, not an in-container modification.
- `spec/SECURITY.md` threat register and
  `spec/security/chio-threat-model.v1.json`. M03 adds rows for
  `pq_signature_downgrade` and `tee_quote_forgery` rather than rewriting
  existing entries; M05's threat-model-as-code consumes the additions.
- M06 cosign bundle gating in `crates/chio-guard-registry/`: PQ migration
  must not break that path. The cosign payload bytes are not signed
  hybrid; the registry verifies them via the existing
  `SigstoreVerifier::verify_bundle` and that path is preserved.

What is changed (deliberately, with migration discipline):

- The `Signature` enum gains a `Hybrid { classical, pq, alg_set }` variant
  with canonical-JSON encoding `hybrid:<classical-hex>:<pq-hex>:<alg-set>`.
  Existing Ed25519 envelopes remain byte-identical. Only artifacts that
  opt in via `crypto_floor` policy switch encoding.
- The kernel acquires a `policy.crypto_floor` enum
  (`allow_classical | allow_hybrid | pq_required`) loaded once at start-up
  and threaded through receipt signing, capability validation, and
  compliance-certificate issuance.
- `crates/chio-attest-verify/` grows a `QuoteVerifier` trait, three backend
  modules (`tdx.rs`, `sev_snp.rs`, `nitro.rs`), and a pinned-fixture
  corpus extending the trajectory-1 M10.P3.T6 fixtures.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses. Update the date and numbers if
you re-run; do not silently let them drift.

- `crates/chio-attest-verify/src/lib.rs`: 131 lines, 1 trait
  (`AttestVerifier`), 0 `QuoteVerifier` implementations.
  (`wc -l crates/chio-attest-verify/src/lib.rs`)
- `crates/chio-attest-verify/src/sigstore.rs`: 626 lines, single struct
  `SigstoreVerifier`, `verify_blob`/`verify_bytes`/`verify_bundle`
  preserved.
- `crates/chio-core-types/src/crypto.rs`: 1090 lines, `Signature` material
  enum has 3 variants (`Ed25519 | P256 | P384`), 0 PQ variants.
  (`grep -c '^enum SignatureMaterial' crates/chio-core-types/src/crypto.rs`
  returns 1; the variant count is from
  `awk '/enum SignatureMaterial/,/^}/' crates/chio-core-types/src/crypto.rs |
  grep -E '^\s+(Ed25519|P256|P384|Hybrid)' | wc -l`.)
- `crates/chio-tee/` source surface: 11 files under `src/`, 0 use of any
  TDX/SEV/Nitro library. (`ls crates/chio-tee/src/`)
- `crates/chio-tee-frame/` source surface: 3 files (`frame.rs`, `lib.rs`,
  `schema.rs`); the frame already carries `tenant_sig` Ed25519 and is not
  modified by this milestone.
- KAT fixtures (`find crates/chio-core/tests -name 'pq_*'`): zero. M03
  adds `crates/chio-core/tests/pq_kats.rs` and the supporting vectors.
- TEE quote fixtures (`find crates/chio-attest-verify -path '*/fixtures/*'
  -name '*.bin'`): zero today. M03 adds
  `crates/chio-attest-verify/fixtures/quotes/{tdx,sev_snp,nitro}/` plus
  the M10 corpus extensions referenced from
  `crates/chio-tee/tests/fixtures/quotes/`.
- Threat model rows touching PQ or TEE quotes
  (`grep -E '"id":\s*"(pq_|tee_quote)' spec/security/chio-threat-model.v1.json`):
  zero today. M03 adds two.

## Workspace dependency state

Pinned in `[workspace.dependencies]` of root `Cargo.toml` today and reused
by M03:

- `ed25519-dalek = "2"` (existing classical signing).
- `aws-lc-rs` (already pulled by `chio-core-types/fips`; reused for
  Nitro NSM COSE_Sign1 verification).
- `serde`, `serde_json` (canonical-JSON encoding of the hybrid variant).
- `thiserror` (error types in `chio-attest-verify`).

Pinned by M03 wave-opener (P0). On the day P0 opens, re-check crates.io for
the then-current latest patch versions before pasting these. Targets at
the time of authoring (2026-04-29):

- `fips204 = "0.4"` -- pure-Rust ML-DSA-65 (FIPS 204) implementation. The
  alternative `pqcrypto-mldsa = "0.1"` wraps PQClean C code; we prefer
  pure-Rust to keep `forbid(unsafe_code)` and to avoid a build-time C
  compiler on TEE container builds. Decision recorded in
  `decisions.yml` under `m03_pq_crate_choice`. Pin rationale: the only
  pure-Rust FIPS-204 implementation with a published 0.x line. If the
  ecosystem moves to `ml-dsa` (RustCrypto), revisit at the start of P1.
- `dcap-rs = "0.1"` (Intel TDX DCAP collateral chain). Pin rationale:
  upstream Intel-maintained verifier surface; reused in the TDX backend.
  Vendored fork lives at `vendor/dcap-rs/` if the upstream version drifts
  before P3 opens.
- `sev = "5"` (the `virtee/sev` AMD SEV-SNP attestation crate). Pin
  rationale: handles VLEK and VCEK chain validation against the AMD KDS
  endpoint shape; we wrap it for offline-fixture verification.
- `coset = "0.3"` (COSE_Sign1 parser used by the Nitro NSM backend). Pin
  rationale: pure-Rust, audited, and already on crates.io with stable
  semver. The Nitro NSM root certificate ships embedded in the crate's
  `fixtures/nitro/aws-nitro-root.pem` blob.
- `proptest = { workspace = true }` (already pinned; M03 reuses for the
  bit-flip property test in P1).

Cargo.lock changes are confined to the P0 wave-opener. Subsequent tickets
add no new direct dependencies; they consume what P0 pins.

## Scope

In:

- `Signature::Hybrid { classical, pq, alg_set }` variant in
  `crates/chio-core-types/src/crypto.rs`. Canonical-JSON encoding
  `hybrid:<classical-hex>:<pq-hex>:<alg_set>`; round-trip identity proven
  against new vectors in `crates/chio-core/tests/pq_kats.rs`.
- ML-DSA-65 (FIPS 204) signing and verifying behind a `pq` cargo feature
  on `chio-core-types` and `chio-attest-verify`. Default builds keep
  classical-only behaviour; the kernel opts in.
- Dual-sign on three artifact classes: capability tokens, receipts, and
  `SessionComplianceCertificate`. Compliance certificate is the
  envelope referenced in `spec/COMPLIANCE-CERTIFICATE.md`.
- `policy.crypto_floor` policy enum
  (`allow_classical | allow_hybrid | pq_required`) loaded at kernel
  start. Kernel-side wiring threads it through receipt signing,
  capability validation, and compliance certificate issuance.
- `QuoteVerifier` trait in `crates/chio-attest-verify/src/lib.rs` next
  to `AttestVerifier`. Backends (one module each):
  Intel TDX DCAP (`tdx.rs`), AMD SEV-SNP VLEK/VCEK (`sev_snp.rs`),
  AWS Nitro NSM COSE_Sign1 (`nitro.rs`).
- `report_data` binding rule: every quote MUST commit to
  `SHA256(kernel_signing_pk_canonical_bytes || receipt_root)` in its
  64-byte `report_data` slot. The 32-byte digest occupies bytes 0..32;
  bytes 32..64 are right-padded with 0x00. Verifiers compare the full
  64-byte slot byte-for-byte and reject mismatches fail-closed.
- TCB freshness check on TDX (collateral validity window) and SEV-SNP
  (current TCB version), with the cutoff documented per backend.
- Pinned fixture corpus: extend
  `crates/chio-attest-verify/fixtures/quotes/{tdx,sev_snp,nitro}/`
  with at least four positive and four negative samples per backend.
- Receipt-path consumer: the `CanonicalBytes` newtype landing in
  trajectory-2 M06 is the byte source the receipt signer consumes
  before producing the hybrid signature. Declared in `soft_deps`
  (cross-trajectory-2 dep).
- Migration test suite: a v3.18 receipt bundle re-verifies under
  `crypto_floor=allow_classical`; the same bundle re-signed via the
  rolled hybrid key re-verifies under `crypto_floor=pq_required`.
- Threat-model rows: `pq_signature_downgrade` and `tee_quote_forgery`
  added to `spec/security/chio-threat-model.v1.json` and
  `spec/SECURITY.md`.

Out (and why):

- Kyber / KEM. Transport is TLS; the Chio wire surface does not
  negotiate session keys. Out of trajectory-2 and not re-litigated.
- Apple SEP. Wildcard-lens proposal; the Apple attestation surface
  does not align with the TDX/SEV-SNP/Nitro server-side picture.
  Deferred to a hardware-custody follow-up.
- `chio-zk-verify`. Explicitly out of trajectory-2 per the open-questions
  resolution in `README.md` (round-2 decision 4).
- Changes to the trajectory-1 M10 TEE container shape. The container
  is unchanged; M03 only adds verifiers that consume quotes produced
  by it.
- Sigstore PQ signing. The Sigstore working-group spec is unstable;
  release artefact signing remains classical Sigstore until upstream
  ships. M03 does not pre-empt that timeline.
- HSM-backed PQ signers. PQ private keys live in software for this
  milestone; HSM rotation is a follow-on once the algorithm baseline
  is stable in production.
- Version-negotiation TLA (Protocol M13) and IETF -01 standards work
  (Protocol M15). Both deferred per round-2 synthesis.
- Kani frontier expansion (Protocol M18). Workspace harness ceiling is
  capped at ~14 per the M04 decision (D11); no new Kani targets land
  in this milestone.

## Phases

### P0: Wave-opener Cargo.lock bump

- M03.P0.T1: Pin PQ + TEE crates (`fips204`, `dcap-rs`, `sev`, `coset`)
  in workspace `Cargo.toml` and refresh `Cargo.lock`.
- M03.P0.T2: Add `pq` cargo feature to `chio-core-types` and
  `chio-attest-verify`; default-off, gates the ML-DSA path.
- M03.P0.T3: Open the audit doc at
  `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md` with the
  starting counts (131 + 626 lines, 0 PQ variants, 0 quote backends).
- M03.P0.T4: Append `pq_signature_downgrade` and `tee_quote_forgery`
  rows to `spec/security/chio-threat-model.v1.json` and the table in
  `spec/SECURITY.md`.
- M03.P0.T5: Re-check `fips204` vs RustCrypto's `ml-dsa` and confirm or
  amend the D08 pin; record the outcome in the audit doc before P1
  opens. Replaces the previous "re-check at the start of P1" comment.

### P1: PQ primitives and KAT vectors

- M03.P1.T1: Add `Signature::Hybrid { classical, pq, alg_set }` and the
  matching `PublicKey::Hybrid` variant in
  `crates/chio-core-types/src/crypto.rs`; preserve byte-identity for
  Ed25519/P256/P384 hex encodings.
- M03.P1.T2: Implement `MlDsa65Backend` behind the `pq` feature; expose
  `HybridBackend { classical: Box<dyn SigningBackend>, pq: MlDsa65Backend }`.
- M03.P1.T3: Land FIPS 204 KAT vectors at
  `crates/chio-core/tests/pq_kats.rs` (sign / verify / NIST KAT
  triples). Vectors source: NIST CAVP FIPS 204 ACVP set (pinned by
  hash in the test file).
- M03.P1.T4: Property test in `crates/chio-core-types/tests/`: flipping
  any bit in either half of a hybrid signature MUST cause verification
  failure; alg_set field tampering MUST fail.
- M03.P1.T5: Hybrid canonical-JSON round-trip vectors added to
  `crates/chio-core/tests/golden/` so the encoding is locked the same
  way the v3.18 receipt encoding is locked.
- M03.P1.T6: Update `spec/PROTOCOL.md` and `spec/schemas/` to document
  the `hybrid:` prefix.

### P2: Hybrid signing in receipts, capability tokens, and compliance certificates

- M03.P2.T1: Wire `policy.crypto_floor` enum into
  `crates/chio-policy/` and the kernel boot path; reject invalid values
  at load time (fail-closed).
- M03.P2.T2: Receipt signer in `chio-kernel` accepts
  `&dyn SigningBackend`; when `crypto_floor=allow_hybrid|pq_required`
  the kernel constructs a `HybridBackend` from the rolled PQ key plus
  the existing classical key.
- M03.P2.T3: Capability token signing path
  (`crates/chio-core-types/src/capability.rs`) accepts hybrid signatures;
  verification path branches on `Signature::algorithm()` and enforces
  `crypto_floor`.
- M03.P2.T4: `SessionComplianceCertificate` issuance path consumes the
  hybrid backend; certificate JSON is canonical-JSON-encoded with the
  new hybrid prefix.
- M03.P2.T5: Migration test fixture: a v3.18 receipt bundle re-verifies
  under `crypto_floor=allow_classical` byte-identically; a re-signed
  bundle re-verifies under `crypto_floor=pq_required` and rejects the
  v3.18 bundle.
- M03.P2.T6: cosign bundle path through `chio-guard-registry` regression
  test: hybrid migration MUST not break the existing M06 P2 cosign-only
  guard verification.

### P3: TDX DCAP backend in `chio-attest-verify`

- M03.P3.T1: Define `QuoteVerifier` trait + shared
  `VerifiedQuote { tee_kind, report_data, tcb_status, signed_at }`
  shape in `crates/chio-attest-verify/src/lib.rs` next to
  `AttestVerifier`.
- M03.P3.T2: TDX backend module
  `crates/chio-attest-verify/src/tdx.rs`: parse the quote envelope,
  walk the collateral chain to the Intel root CA, reject stale TCB
  per the documented `min_tcb_recovery_event_id`.
- M03.P3.T3: `report_data` binding helper in `lib.rs`:
  `expect_report_data(kernel_pk: &PublicKey, receipt_root: &[u8; 32])
  -> [u8; 64]`. TDX backend MUST call it before declaring success.
- M03.P3.T4: Pinned positive/negative TDX fixtures under
  `crates/chio-attest-verify/fixtures/quotes/tdx/`.
- M03.P3.T5: Integration test consuming a fixture quote produced by
  the trajectory-1 M10 container, asserting `report_data` binding
  against the kernel signing key + receipt root.

### P4: SEV-SNP and Nitro NSM backends

- M03.P4.T1: SEV-SNP backend `crates/chio-attest-verify/src/sev_snp.rs`:
  walk VLEK/VCEK chain to the AMD KDS root; verify the launch digest
  vs the expected RTMR / kernel measurement.
- M03.P4.T2: SEV-SNP fixture corpus under
  `crates/chio-attest-verify/fixtures/quotes/sev_snp/` (4 positive,
  4 negative including stale TCB and mismatched launch digest).
- M03.P4.T3: Nitro NSM backend `crates/chio-attest-verify/src/nitro.rs`:
  parse COSE_Sign1, verify against embedded AWS Nitro root certificate
  at `crates/chio-attest-verify/fixtures/nitro/aws-nitro-root.pem`.
- M03.P4.T4: Nitro fixture corpus
  (`fixtures/quotes/nitro/{positive,negative}/*.bin`).
- M03.P4.T5: Cross-backend conformance test: each backend's verifier
  rejects fixtures meant for the other two backends. Catches
  type-confusion bugs that an attacker could exploit by mislabelling
  a quote.

### P5: Cross-cutting (PQ + TEE composition, migration, key roll)

- M03.P5.T1: TEE-bound PQ key composition: extend the kernel boot path
  so the PQ signing key is loaded only after the kernel verifies its
  own quote against `expect_report_data(kernel_classical_pk,
  receipt_root_genesis)`. Fail-closed if the quote does not bind.
- M03.P5.T2: End-to-end migration test suite at
  `crates/chio-attest-verify/tests/migration.rs`: drive a v3.18
  receipt bundle through `allow_classical -> allow_hybrid ->
  pq_required` with a key roll between the second and third stage.
- M03.P5.T3: Receipt path consumes `CanonicalBytes` (trajectory-2
  M06 newtype) for hybrid signing. Per D16, M06.P1 ships before M03.P1
  opens, so this ticket carries a hard `depends_on: M06.P1.T1` edge
  rather than a soft-dep + shim path.
- M03.P5.T4: Threat-model coverage gate (M05 dependency): the two new
  threat IDs MUST be marked covered by M03 fixtures and tests before
  the milestone closes.
- M03.P5.T5: Audit doc final pass at
  `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md` with
  closing counts (Hybrid variant present, KAT vectors present,
  three quote backends green, fixture corpus pinned).

## Cross-milestone interactions

- trajectory-1 M01 (`crates/chio-core/tests/`) canonical-JSON vectors
  lock the receipt encoding. The hybrid variant adds new vectors but
  MUST NOT alter existing ones. Byte-equivalence test in P2.T5 is the
  enforcement.
- trajectory-1 M06 (`crates/chio-guard-registry/`) cosign-bundle
  gating MUST keep working under `allow_hybrid` and `pq_required`.
  Regression test in P2.T6 owns this.
- trajectory-1 M09 (`crates/chio-attest-verify/`) Sigstore path is
  preserved. M03 grows the crate; it does not fork it. The
  `AttestVerifier` trait surface is unchanged.
- trajectory-1 M10 (`crates/chio-tee/`) TEE container produces the
  quote bytes M03 verifies. The container is unchanged; the
  consumer-side verifier is new.
- trajectory-2 M04 (recursive delegation + revocation oracle):
  revocation roots can be PQ-signed only after M03.P2 lands.
  `M04.P3` (whatever signs the sparse-Merkle root) consumes
  M03.P2.T2's `HybridBackend`.
- trajectory-2 M05 (adversarial + threat-model-as-code): the threat
  IDs `pq_signature_downgrade` and `tee_quote_forgery` are the
  artefacts M05's CI gate verifies coverage of.
- trajectory-2 M06 (performance hardening, `CanonicalBytes`): M03.P5.T3
  hard-depends on M06.P1.T1 per D16 (M06.P1 ships first).
- trajectory-2 M10 (hardware custody + policy-bound model cards):
  custody envelopes use `QuoteVerifier::verify` plus
  `expect_report_data` from M03.P3.T3.

## Risks and mitigations

- **PQ algorithm churn.** FIPS 204 is freshly final; pure-Rust
  implementations are young. Mitigation: pin `fips204 = "0.4"` at P0,
  re-check at the open of P1, and treat KAT-vector divergence between
  versions as a release-blocking bug. The KAT file at
  `crates/chio-core/tests/pq_kats.rs` is the regression oracle.
- **Hybrid envelope size.** ML-DSA-65 signatures are ~3.3 KB. Receipts
  carrying hybrid signatures roughly 50x current size. Mitigation:
  `crypto_floor=allow_hybrid` is opt-in; default deployments stay on
  classical until operators flip the floor. M06's `CanonicalBytes`
  zero-copy newtype reduces per-receipt allocation cost.
- **TDX collateral chain freshness.** Intel rotates collateral; a
  verifier with a stale embedded chain rejects valid quotes.
  Mitigation: the TDX backend documents a quarterly collateral re-bake
  job (analog of trajectory-1 M09's Sigstore trust-root re-bake).
- **SEV-SNP VLEK vs VCEK split.** AMD KDS distinguishes VLEK
  (versioned, machine-bound) and VCEK (chip-bound). Mitigation: the
  SEV-SNP backend handles both and the fixture corpus exercises each
  in a positive and negative case.
- **Nitro root rotation.** AWS rotates the Nitro root rarely but it
  has happened. Mitigation: embed the current root, document rotation
  in the audit doc, and ship a `nitro_root_rotation` integration test
  that flips the embedded root and asserts the verifier rejects
  fixtures signed under the previous root unless the chain explicitly
  pins both.
- **Type-confusion across backends.** A hostile prover could mislabel
  a SEV-SNP quote as a TDX quote. Mitigation: every backend asserts
  its own envelope discriminator before doing any cryptographic
  work; the cross-backend conformance test in P4.T5 enforces it.
- **Cosign bundle regression.** PQ migration must not break the
  registry's existing cosign verification path. Mitigation: P2.T6
  is a regression test against an unchanged cosign bundle.
- **`crypto_floor` misconfiguration.** A deployment that flips
  `pq_required` without rolling the PQ key bricks signing.
  Mitigation: invalid values (PQ key not present under `pq_required`)
  fail at policy load, not at first signing call. Tested in P2.T1.

## Success criteria

- `cargo test -p chio-core --test pq_kats --features pq` green; FIPS 204
  KAT vectors locked.
- `cargo test -p chio-core-types --features pq` green; Hybrid variant
  property tests pass.
- `Signature::Hybrid` round-trips through canonical JSON byte-identical
  to the new fixtures and never alters existing classical encodings.
- `crypto_floor` enum present in `chio-policy`; invalid combinations
  reject at load time.
- Three `QuoteVerifier` implementations (TDX, SEV-SNP, Nitro) green
  on the pinned fixture corpus; cross-backend conformance test green.
- `receipt_root_genesis` (consumed by the kernel self-quote in P5.T1) is
  the all-zero 32-byte sentinel `[0u8; 32]` representing the empty
  receipt-tree root at boot; the first signed receipt advances the root.
- A v3.18 receipt bundle re-verifies under `crypto_floor=allow_classical`
  with byte-identical signatures.
- A re-signed bundle re-verifies under `crypto_floor=pq_required`
  with the rolled hybrid key, and the original v3.18 bundle is
  rejected by the same verifier.
- `chio-guard-registry` cosign-bundle path passes the regression
  test under all three `crypto_floor` settings.
- `spec/security/chio-threat-model.v1.json` carries
  `pq_signature_downgrade` and `tee_quote_forgery` rows; M05's
  threat-model coverage gate marks them covered.
- Audit doc at `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md`
  closes with the measured before/after counts.
