# Trajectory 5 - Lane A: Kani Harness Design

This document is the design proposal for sub-lane A3. For each of the
three deferred trust-boundary crates (`chio-attest-verify`, `chio-anchor`,
`chio-weights`), it specifies:

- (a) what invariants to model,
- (b) the harness file path,
- (c) bound parameters,
- (d) CI integration.

**Note on production-entry validation (addressing R2 BLOCKER 3.1)**: this
document lists only `pub fn` symbols verified to exist on disk by
`grep -nE '^pub fn|^pub async fn' crates/<crate>/src/`. Where the
trust-boundary surface is exposed via a trait method (not a free
function), the harness instantiates a concrete production-shipping impl
and the impl crate is named explicitly.

## Reference pattern

The reference pattern is
`crates/chio-kernel-core/src/kani_public_harnesses.rs`. It contains 12
`#[kani::proof]` functions today (verified by grep). Each follows the
shape:

```rust
#[kani::proof]
pub fn public_<invariant_name>() {
    // 1. Build minimal fixture (helpers like grant(), unsigned_capability()).
    // 2. Apply kani::assume() to constrain the input shape.
    // 3. Call the production entry point.
    // 4. Assert the invariant holds via assert!().
}
```

Each `kani_public_harnesses.rs` is a sibling module included from the
crate's `src/lib.rs` and gated by a `#[cfg(kani)]` attribute so production
builds skip it.

## (1) `chio-attest-verify`

### Invariants to model

The `chio-attest-verify` crate exposes its trust-boundary surface
exclusively through two traits, `AttestVerifier` (Sigstore /
bundle-attestation) at `crates/chio-attest-verify/src/lib.rs:263` and
`QuoteVerifier` (TEE-quote backends) at
`crates/chio-attest-verify/src/lib.rs:320`. The free function
`expect_report_data` at `quote.rs:163` is the only `pub fn` exported
outside those traits. Harnesses target the publicly constructible impls.

| # | Invariant | Production entry |
|---|---|---|
| 1 | `expect_report_data` binding determinism: identical `(kernel_pk, receipt_root)` inputs always produce identical 64-byte output; any byte-flip on either input changes the output. | `chio_attest_verify::expect_report_data` (free `pub fn` at `crates/chio-attest-verify/src/quote.rs:163`). |
| 2 | `QuoteVerifier::verify_quote` fail-closed on report-data mismatch: a Nitro quote whose `user_data` slot does not match `expect_report_data(kernel_pk, receipt_root)` is rejected with `AttestError::ReportDataMismatch`. Concrete impl: `NitroVerifier` at `crates/chio-attest-verify/src/nitro.rs:125,199`. | `<NitroVerifier as QuoteVerifier>::verify_quote` (impl at `crates/chio-attest-verify/src/nitro.rs:200`). |
| 3 | `QuoteVerifier::verify_quote` fail-closed on TCB rejection: a SEV-SNP report whose TCB status is not `is_acceptable()` returns `AttestError::QuoteRejected` regardless of signature validity. Concrete impl: `SevSnpVerifier` at `crates/chio-attest-verify/src/sev_snp.rs:169,245`. | `<SevSnpVerifier as QuoteVerifier>::verify_quote` (impl at `crates/chio-attest-verify/src/sev_snp.rs:246`). |
| 4 | TEE-signature dispatch fail-closed on algorithm mismatch: feeding a P-384 signature into the P-256 verification path yields a non-`Ok` result. The crate-private `verify_p256_signature_with_attestation_key` and `verify_p384_signature_with_attestation_key` (`tee_signature.rs:15,36`, `pub(crate)`) are exercised indirectly by harnessing the public `<TdxDcapVerifier as QuoteVerifier>::verify_quote` path with a deliberately mis-tagged quote. Concrete impl: `TdxDcapVerifier` at `crates/chio-attest-verify/src/tdx.rs:94,158`. | `<TdxDcapVerifier as QuoteVerifier>::verify_quote` (impl at `crates/chio-attest-verify/src/tdx.rs:159`). |

### File path

`crates/chio-attest-verify/src/kani_public_harnesses.rs`

### Bound parameters

- Quote payload size: `kani::assume(quote.len() <= 256)`.
- Cert-chain depth: `kani::assume(chain.len() <= 3)` to keep the
  search space tractable. SHA-256 over the full chain is the
  Kani-times-out hot spot; per-harness `#[kani::unwind(8)]`.
- `report_data` slot: full 64 bytes are symbolic; harness asserts
  byte-by-byte equality against the output of `expect_report_data`.
- Per-harness `#[kani::unwind(8)]` matches the existing `chio-kernel-core`
  default. Local wall-clock budget per harness: 30 minutes (see
  Kani harness evidence below).

### CI integration

- The Kani lane lives in `.github/workflows/nightly.yml` (single-crate
  shell loop hardcoded to `cargo kani -p chio-kernel-core`, lines
  62-129) and `.github/workflows/ci.yml` (PR-tier `kani-public-pr` job).
  Kani multi-crate manifest is the workflow rewrite (see Section "CI workflow path"
  below).
- Two consecutive green nightly runs captured to
  `audits/evidence/release work-A3/nightly-runs.md`.

## (2) `chio-anchor`

### Invariants to model

Public verification entries verified by
`grep -nE '^pub fn|^pub async fn' crates/chio-anchor/src/`:

- `verify_anchor_batch` at `batch.rs:208` (the canonical batch verifier;
  internally checks Merkle inclusion proofs and sibling order).
- `verify_anchor_batch_with_witness_policy` at `batch.rs:227`.
- `evaluate_witness_policy` at `witness.rs:312` (the witness-policy
  fail-closed gate).
- `batch_body_hash` at `witness.rs:193`.
- `verify_proof_bundle` at `bundle.rs:46`.

| # | Invariant | Production entry |
|---|---|---|
| 1 | Batch-root inclusion-proof correctness: a leaf with a matching index and matching siblings admits; corrupting any sibling hash denies. Tests `verify_anchor_batch` over a small (depth-3) symbolic Merkle tree. | `chio_anchor::batch::verify_anchor_batch` (`crates/chio-anchor/src/batch.rs:208`). |
| 2 | Mis-ordered sibling rejection: feeding a batch whose siblings are in the wrong order at any level returns `AnchorError::InclusionProofMismatch` (or the equivalent typed reject). | `chio_anchor::batch::verify_anchor_batch` (same entry; the bound covers the sibling-order branch). |
| 3 | `require_public_witness=true` fail-closed: when the witness policy demands a public witness, `evaluate_witness_policy` rejects fail-closed for a config carrying no witness. PROTOCOL.md sections 982-991 (per `02-protocol-realization-engineer.md` line 33). | `chio_anchor::witness::evaluate_witness_policy` (`crates/chio-anchor/src/witness.rs:312`). |
| 4 | `batch_body_hash` determinism: the body hash is a pure function of the batch body; two distinct bodies produce distinct hashes; identical bodies produce identical hashes. This is the binding the witness step depends on. | `chio_anchor::witness::batch_body_hash` (`crates/chio-anchor/src/witness.rs:193`). |

### File path

`crates/chio-anchor/src/kani_public_harnesses.rs`

### Bound parameters

- Tree leaf count: `kani::assume(leaves.len() <= 8)`. (Trees of depth >
  3 are out of harness scope; production trees are checked by
  conformance tests.)
- Witness timestamp range: bounded to a 24-hour window expressed in
  seconds.
- Inclusion-proof length: bounded by `kani::assume(siblings.len() <= 4)`
  matching the depth-3 tree.
- Hash byte length: fixed 32-byte SHA-256.
- Per-harness `#[kani::unwind(4)]` for the sibling-loop (see
  `audits/T0.B-substrate-hardening.md` line 17 budget escalation note).
  Local wall-clock budget per harness: 30 minutes.

### CI integration

- Per `audits/T0.B-substrate-hardening.md` line 17: "Kani harness for
  `chio-anchor` may exceed default Kani budget; document budget
  escalation policy."
- Mitigation: harness uses `#[kani::unwind(4)]` to bound the
  sibling-loop unwinding. Documented in the harness module header.
- Kani multi-crate manifest owns the workflow rewrite (Section "CI workflow path").

### Lane B coordination note (R2 MAJOR Section 8.3)

The Kani harness depends on the shape of `verify_anchor_batch` and
`batch_body_hash` in `crates/chio-anchor/src/`. Lane B owns
`crates/chio-anchor/src/batch.rs` and may revise the signature during
release work-B3. If Lane B changes those signatures, this harness is updated in
the same PR or one wave behind, never more than one wave behind. The
Lane B Wave-end checklist explicitly checks this surface.

## (3) `chio-weights`

### Invariants to model

Public verify-shaped entries verified by
`grep -nE '^pub fn' crates/chio-weights/src/`:

- `verify_model_card_bundle` at `bundle.rs:71` (also re-exported as
  `chio_weights::verify_model_card_bundle` per `lib.rs:43`).
- `verify_model_card_anchor` at `lineage.rs:217`.
- `anchor_model_card` at `lineage.rs:162`.
- `anchor_projection_bytes` at `lineage.rs:120`.
- `weights_hash_of` at `card.rs:274`.

| # | Invariant | Production entry |
|---|---|---|
| 1 | `weights_hash_of` determinism: identical byte buffers produce identical hex strings; any byte-flip in the input produces a different hex string. The card-binding property the bundle verifier ultimately depends on. | `chio_weights::card::weights_hash_of` (`crates/chio-weights/src/card.rs:274`). |
| 2 | `anchor_projection_bytes` is a pure function: given identical `(model_card, anchor_root)` inputs the byte projection is identical; any change in either input changes the byte projection. | `chio_weights::lineage::anchor_projection_bytes` (`crates/chio-weights/src/lineage.rs:120`). |
| 3 | `verify_model_card_anchor` fail-closed: feeding a `(card, anchor_root)` pair whose anchor projection does not match the bundle's recorded anchor returns the lineage-mismatch error variant. | `chio_weights::lineage::verify_model_card_anchor` (`crates/chio-weights/src/lineage.rs:217`). |
| 4 | `verify_model_card_bundle` fail-closed on bundle mismatch: a model-card bundle whose card list disagrees with the manifest is rejected by `verify_model_card_bundle` regardless of signature. The harness instantiates a stub `AttestVerifier` (the only generic parameter) that always admits, so the rejection must come from the bundle-vs-manifest comparison alone. | `chio_weights::bundle::verify_model_card_bundle` (`crates/chio-weights/src/bundle.rs:71`). |

### File path

`crates/chio-weights/src/kani_public_harnesses.rs`

### Bound parameters

- Card body size: `kani::assume(body.len() <= 64)`.
- Lineage chain depth: `kani::assume(chain.len() <= 4)`.
- Bundle card count: `kani::assume(cards.len() <= 4)`.
- Hash byte length: fixed 32-byte SHA-256.
- Per-harness `#[kani::unwind(8)]`. Local wall-clock budget per
  harness: 30 minutes.

### CI integration

- Kani multi-crate manifest owns the workflow rewrite (Section "CI workflow path").
- Two consecutive green runs captured to
  `audits/evidence/release work-A3/nightly-runs.md`.

## CI workflow path (rewritten per R2 BLOCKER 3.3)

The Kani lane is wired through two workflows whose current state
hardcodes `cargo kani -p chio-kernel-core`:

- `.github/workflows/nightly.yml` lines 62-129: a `kani-public-nightly`
  job that runs a Python helper to read
  `formal/rust-verification/kani-public-harnesses.toml` and shell-loops
  `cargo kani -p chio-kernel-core --lib --harness "${harness}"` over the
  resulting list. The TOML schema declares `crate = "chio-kernel-core"`
  at the top level; it is single-crate by construction.
- `.github/workflows/ci.yml` `kani-public-pr` job (referenced from
  `nightly.yml:60`): same shell-loop pattern at PR-tier with
  `lanes.pr` only.

There is **no** matrix today. The earlier draft of this document
sketched a `strategy.matrix.crate` change; that sketch was not
applicable to the actual workflow. Kani multi-crate manifest instead owns the following
concrete rewrite:

### Schema change (Kani multi-crate manifesta)

Extend `formal/rust-verification/kani-public-harnesses.toml` from
single-crate to multi-crate. Two acceptable shapes; pick (B) by default
(less migration churn for `chio-kernel-core` consumers):

(A) **Per-crate manifest files**: split into
`formal/rust-verification/<crate>/kani-public-harnesses.toml` for each
of the four crates, each carrying its own `crate`, `harness_groups`,
`covered_symbols`, and `lanes` blocks.

(B) **Multi-crate manifest schema** (recommended): change the existing
file's top-level from `crate = "chio-kernel-core"` to a `crates =
[...]` array, and shape `lanes.pr.harnesses` and
`lanes.nightly_only.harnesses` as records of
`{ crate = "<name>", harness = "<fn>" }`. The Python helper in
`nightly.yml` is updated to emit `(crate, harness)` pairs.

### Workflow change (Kani multi-crate manifestb)

Concretely, `nightly.yml` lines 102-128 change from:

```bash
mapfile -t HARNESSES < <(python3 - <<'PY'
... print(h)
PY
)
for harness in "${HARNESSES[@]}"; do
  cargo kani -p chio-kernel-core --lib --harness "${harness}" \
    --default-unwind 8 --no-unwinding-checks
done
```

to:

```bash
mapfile -t PAIRS < <(python3 - <<'PY'
... print(f"{crate}|{harness}")
PY
)
for pair in "${PAIRS[@]}"; do
  IFS='|' read -r crate harness <<< "${pair}"
  cargo kani -p "${crate}" --lib --harness "${harness}" \
    --default-unwind 8 --no-unwinding-checks
done
```

The same shape applies to the `ci.yml` `kani-public-pr` job. Kani multi-crate manifestb
captures the diff in the close PR.

### Promotion-of-advisory-to-required (Kani harness evidence, addresses R2 MINOR 10.3)

The new multi-crate Kani lane starts as advisory. After two consecutive
green nightly runs, Kani harness evidence promotes it to required by removing
`continue-on-error` (where present) and adding the job to GitHub
branch-protection required-checks. Without this promotion a regression
in `chio-attest-verify` Kani would not block a PR, contradicting the
synthesis ship-bar 1 banner-vs-reality discipline.

## Kani harness evidence - Kani feasibility spike (addresses R2 MAJOR 3.2)

Before Kani harness evidence / A3.2 / A3.3 start, run each proposed Kani invariant
locally with the proposed bounds:

- Run each `#[kani::proof]` body on a workstation against
  `cargo kani --default-unwind 8 --no-unwinding-checks`.
- Capture per-harness wall-clock, peak memory, and exit status to
  `audits/evidence/Kani harness evidence/local-bound-validation.md`.
- If any harness exceeds 30 minutes locally, escalate (open R-new in
  the Risk Register) before Kani harness evidence starts. SHA-256 verification under
  symbolic input is the canonical Kani-times-out scenario; per-crate
  bound-validation is non-optional.

## Anti-pattern guard

Per Lane A's close bar (PLAN.md and planning docs):

- A harness file that imports `kani::` but contains zero
  `#[kani::proof]` functions fails the close bar.
- A harness whose proofs go through under `kani::assume(false)` (vacuous
  proof) fails the close bar.
- A harness that targets a non-`pub` internal helper instead of a
  production entry point fails the close bar (the public-name prefix
  pattern in `kani_public_harnesses.rs` enforces this convention). For
  trait-method targets, the harness MUST instantiate a publicly
  constructible impl (`NitroVerifier`, `SevSnpVerifier`, `TdxDcapVerifier`)
  rather than a test-local stub.

## Theorem-inventory linkage (corrected per R2 MINOR 3.4)

Kani harness evidence updates the multi-crate
`formal/rust-verification/kani-public-harnesses.toml` (existence
verified) to register the three new harness modules. The earlier draft
referenced `formal/proof-manifest.toml`; that file may exist in
parallel. Kani harness evidence acceptance names both files explicitly: any harness
group added to `kani-public-harnesses.toml` is mirrored in
`formal/proof-manifest.toml` if and only if that file references the
crate; otherwise the kani-public-harnesses entry is the source of
truth.
