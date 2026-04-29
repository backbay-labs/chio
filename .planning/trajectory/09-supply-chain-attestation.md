# Milestone 09: Supply-Chain Attestation (cargo-vet, Sigstore, SBOM, Reproducible Builds)

## Why this milestone

Chio's pitch is comptroller-class trust: a kernel that signs every decision and exports verifiable receipts. A comptroller whose own binary cannot be provenance-checked is one regulators reject. The current state is partial. `Dockerfile.sidecar` already builds with `provenance: mode=max` and `sbom: true` via `docker/build-push-action@v6` (`.github/workflows/sidecar-image.yml`); npm publishes use `--provenance` against an OIDC trusted publisher (`.github/workflows/release-npm.yml`); PyPI publishes use OIDC trusted publishing without stored tokens (`.github/workflows/release-pypi.yml`). But the GitHub Release archives (`release-binaries.yml`) ship only SHA-256 manifests, no signatures, no SBOM, no SLSA provenance. `deny.toml` keeps `multiple-versions = "warn"`, an empty `[advisories.ignore]`, and a single registry allow-entry. There is no `supply-chain/` directory, no `cargo-vet`, no `cargo-auditable` step, no `grype`/`trivy` scan in `release-qualification.yml`, no reproducible-build job, no `cosign` invocation anywhere, and no `docs/install/VERIFY.md`. CI also does not run `cargo deny check` or `cargo audit` on PRs.

The work is cheap to land now and expensive to retrofit after adoption. This milestone closes those gaps so every release artifact (binary, container, npm tarball, PyPI wheel) carries a verifiable Sigstore signature plus a CycloneDX SBOM, every PR is gated on `cargo-deny` plus `cargo-vet`, and an external consumer can reproduce the binary and verify the signature in five commands.

## Round-2 decisions (locked)

- **SLSA tier**: Level 2 only. L3 deferred to v5+ (requires single-tenant builders).
- **Signing mode**: keyless cosign (Fulcio short-lived certs + Rekor + GitHub OIDC). No stored keys, no HSM.
- **Reproducible target**: `x86_64-unknown-linux-gnu` only. macOS / Windows / aarch64 ship signatures and SBOMs but not bit-for-bit reproducibility.
- **Shared verifier crate**: `crates/chio-attest-verify/`. Consumed by M09 (release verification), M06 (WASM guard signing), and M02 (fuzz target for the verifier itself).

## Scope

In scope:

- A merged `cargo-vet` baseline (`supply-chain/audits.toml`, `supply-chain/config.toml`, `supply-chain/imports.lock`) plus a CI gate that denies unaudited new dependencies on every PR.
- A tightened `deny.toml` (verbatim in Phase 1 below): `multiple-versions = "deny"` with an explicit `[bans.skip]` allow-list, `unknown-registry = "deny"` retained, `[advisories]` with `yanked = "deny"` and an audited `ignore` list keyed by RUSTSEC IDs, `[bans.deny]` for known-bad crates, and a license allow-list with explicit `[[licenses.exceptions]]` for the long-tail crates.
- `cargo auditable build` in `release-binaries.yml` so every shipped `chio` binary embeds its dependency graph for `cargo audit bin` post-mortems.
- `syft`-generated CycloneDX SBOMs (1.6 JSON) for each `chio` binary archive, attached to every GitHub Release alongside the existing `.sha256` files.
- `grype` scan inside `release-qualification.yml` that fails on critical CVEs with a documented override path (`--ignore-file .github/grype-ignore.yaml`, change requires CODEOWNERS approval).
- SLSA Level 2 provenance for the binary archives via the official `slsa-framework/slsa-github-generator` GitHub Action. L3 (hardened, isolated build VM) is a v5+ stretch and is documented as out of scope below.
- `cosign` keyless signing (Sigstore via Fulcio + Rekor + GitHub OIDC, no stored keys) on the sidecar image, on every PyPI sdist+wheel, and on every npm tarball, with public-good Rekor entries.
- A reproducible-build job in CI that builds `chio-cli` twice on independent runners and asserts byte-identical output for `x86_64-unknown-linux-gnu`, with documented determinism caveats (other targets out of scope for this milestone).
- A new `crates/chio-attest-verify/` helper that wraps `sigstore-rs`, exposes the trait surface defined in Phase 3 below, and is reused by M06 WASM guard signing and M02 fuzzing.
- A consumer-facing verification recipe under `docs/install/VERIFY.md` that fits in five commands.
- Coordination with M06 (WASM guard signing) so guard-side and release-side Sigstore code paths share the helper crate; coordination with M02 so the verifier ships with a libFuzzer harness from day one.

Out of scope:

- SLSA Level 3 isolated builders. L3 needs a hardened, single-tenant build environment with non-falsifiable provenance; GitHub-hosted runners do not meet the bar. Defer to v5+ once the project owns dedicated build infrastructure.
- Post-quantum signing of releases. Sigstore has a working group but the spec is unstable. Defer.
- HSM-backed release signers. Keyless OIDC is the right default for an open-source project; HSM rotation belongs to the (deferred) hardware-key milestone.
- Bit-for-bit reproducible Docker images. The sidecar image is already attested via buildx SLSA provenance; full image determinism is a separate, harder problem.
- Bit-for-bit reproducibility on macOS, Windows, and aarch64-linux. Linux x86_64 only; the other targets ship signatures and SBOMs but not reproducibility guarantees.
- Air-gapped verification. `cosign verify --offline` is documented but the recipe assumes Rekor is reachable. Offline-only verification is a follow-up.

## Phases

### Phase 1: cargo-vet baseline and deny.toml hardening

**First commit message** (exact): `chore(supply-chain): seed cargo-vet baseline and lock deny.toml`

**Effort**: M, 4 days.

**Tasks** (atomic, in order):

1. Run `cargo vet init`; commit the seeded `supply-chain/{audits,config,imports.lock}.toml` skeleton.
2. Import the four upstream audit feeds (Mozilla, Bytecode Alliance, Google, ZcashFoundation) into `supply-chain/config.toml` (corpus defined below).
3. Run `cargo vet suggest`; for the residual unaudited delta, write per-crate rationale entries into `supply-chain/audits.toml` and commit.
4. Replace the existing `deny.toml` wholesale with the verbatim file in this phase (below).
5. Add the `supply-chain` job to `.github/workflows/ci.yml` running `cargo deny check --all-features advisories bans sources licenses` plus `cargo vet --locked` on every PR.
6. Write `supply-chain/README.md` documenting the `cargo vet certify` ritual contributors run when adding a new dep.
7. Make the new job a required check on `main` via branch-protection.

#### cargo-vet baseline corpus (verbatim entries)

Imported under `[imports]` in `supply-chain/config.toml`. These four feeds are what we converge on; no others are imported at baseline.

```toml
[imports.mozilla]
url = "https://hg.mozilla.org/mozilla-central/raw-file/tip/supply-chain/audits.toml"

[imports.bytecode-alliance]
url = "https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml"

[imports.google]
url = "https://raw.githubusercontent.com/google/supply-chain/main/audits.toml"

[imports.zcash]
url = "https://raw.githubusercontent.com/zcash/rust-ecosystem/main/supply-chain/audits.toml"
```

The `safe-to-deploy` criterion (the bar the project applies for first-party audits in `supply-chain/audits.toml`) is defined inline:

```toml
[criteria.safe-to-deploy]
description = """
This crate may be included in a binary that runs in trusted contexts including
release builds of chio-cli, chio-kernel, and the sidecar container. The audit
must confirm: (1) the crate does not contain known-malicious code, (2) the
crate does not exfiltrate process state or host filesystem contents,
(3) the crate's unsafe code (if any) was reviewed against the documented
invariants, and (4) the crate's build script does not perform network access
or write outside OUT_DIR.
"""
implies = "safe-to-run"
```

Mozilla, Bytecode Alliance, Google, and ZcashFoundation already publish `safe-to-deploy` claims; the import lines above absorb them. Residual unaudited crates land in `audits.toml` with first-party `safe-to-deploy` certifications signed by CODEOWNERS.

#### `deny.toml` (verbatim, replaces the existing file)

```toml
# Workspace-wide cargo-deny configuration.
# Source of truth: .planning/trajectory/09-supply-chain-attestation.md (Phase 1).
# Changes to this file require CODEOWNERS review.

[graph]
all-features = true
no-default-features = false

[output]
feedback-level = "error"

[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
unmaintained = "all"
notice = "warn"
ignore = [
    # Format: "RUSTSEC-YYYY-NNNN", with a CODEOWNERS-reviewed comment naming
    # (a) the affected crate, (b) why we accept the risk, (c) the upstream
    # tracking issue. Empty at baseline; entries land via PR review.
]

[licenses]
unlicensed = "deny"
copyleft = "deny"
allow-osi-fsf-free = "neither"
default = "deny"
confidence-threshold = 0.93
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
    "Unicode-3.0",
    "CC0-1.0",
    "Zlib",
    "MPL-2.0",
]

[[licenses.exceptions]]
# `ring` ships under a bespoke license that is OpenSSL-derived but not
# OSI-approved. It is the de-facto Rust crypto primitive and the rustls
# stack depends on it transitively. Tracked: ring#2746.
name = "ring"
allow = ["OpenSSL", "ISC", "MIT"]

[[licenses.exceptions]]
# `webpki-roots` carries the Mozilla CA bundle under MPL-2.0 within an
# otherwise-permissive crate; pin the exception to the crate to avoid
# widening the workspace allow-list.
name = "webpki-roots"
allow = ["MPL-2.0"]

[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"
workspace-default-features = "allow"
external-default-features = "allow"

[[bans.deny]]
# `time` 0.1 is unmaintained and depends on a soundness-bug-prone localtime
# call. Use `time` >= 0.3 or `chrono` >= 0.4.31.
name = "time"
version = "<0.3"

[[bans.deny]]
# `openssl-sys` is forbidden in favor of rustls; `chio` must not absorb
# OpenSSL transitively. If a dep needs OpenSSL, vendor a rustls fork or
# add a documented [bans.skip] entry with CODEOWNERS sign-off.
name = "openssl-sys"

[[bans.deny]]
# `chrono` 0.4.0..=0.4.30 has a localtime soundness bug. Pin newer.
name = "chrono"
version = "<0.4.31"

[[bans.skip]]
# `windows-sys` ships multiple major versions across the ecosystem and the
# crate graph cannot be flattened without forking ten upstreams. Tracked
# weekly via Renovate; revisit when wasmtime/tokio converge.
name = "windows-sys"

[[bans.skip]]
# `syn` 1.x lingers in proc-macro chains. Force-bump on the next workspace
# audit pass once `darling` and `serde_derive` align on `syn` 2.x.
name = "syn"
version = "1"

[[bans.skip]]
# `bitflags` 1.x is pinned by `clap` and `wasmtime`. Acceptable until both
# converge on 2.x.
name = "bitflags"
version = "1"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = [
    # Every git dep is enumerated here with a comment naming the upstream
    # crate, the reason a registry version cannot be used, and the tracking
    # issue. Empty at baseline; new entries require CODEOWNERS review.
]
```

### Phase 2: SBOM, embedded auditable metadata, and SLSA L2 provenance

**First commit message** (exact): `feat(release): emit cyclonedx sbom and slsa l2 provenance per archive`

**Effort**: M, 3 days.

**Tasks** (atomic, in order):

1. Add `cargo install cargo-auditable --locked` to the `release-binaries.yml` toolchain step; replace `cargo build --release --locked` with `cargo auditable build --release --locked`.
2. Pin `syft` to `anchore/syft@v1.18.1` (matrix step) and emit `chio-${version}-${target}.cdx.json` per archive (CycloneDX 1.6 JSON, schema URL `http://cyclonedx.org/schema/bom-1.6.schema.json`); attach to the GitHub Release as a sibling of the `.tar.gz` and the existing `.sha256`.
3. Pin `grype` to `anchore/scan-action@v6.6.0` inside `release-qualification.yml`; run against the staged binaries plus the sidecar image; fail on `--fail-on critical`, default `--only-fixed`, point at `.github/grype-ignore.yaml` for the override path (CODEOWNERS-reviewed entries).
4. Wire `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0` so each archive ships a `.intoto.jsonl` provenance file. The action emits L2 attestations on GitHub-hosted runners; the file name says "slsa3" but that is a tier-name mismatch in upstream, not a bug. `--certificate-oidc-issuer` is `https://token.actions.githubusercontent.com`. The certificate-identity-regexp pinned by every consumer is `^https://github\\.com/<owner>/chio/\\.github/workflows/release-binaries\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.-]+)?$`.
5. Update `docs/install/PUBLISHING.md` with the SBOM, auditable-metadata, and provenance attachment guarantees and link the schema docs (CycloneDX 1.6 spec, in-toto v1, SLSA v1.0 provenance predicate).

### Phase 3: Sigstore keyless signing for every artifact class plus `chio-attest-verify`

**First commit message** (exact): `feat(attest): land chio-attest-verify and keyless cosign signing`

**Effort**: L, 6 days.

**Tasks** (atomic, in order):

1. Stand up `crates/chio-attest-verify/` as a thin wrapper over `sigstore-rs` in **one** PR that lands the trait, error types, AND the real fail-closed `SigstoreVerifier` implementation together. No `todo!()` / `unimplemented!()` / `panic!()` in any of the three `verify_*` methods. Consumers (M06 P2 in particular) may not merge against this crate until its integration tests are green on `main`. See EXECUTION-BOARD.md "No verifier or trust-boundary stubs" for the workspace policy.
2. Wire `cosign sign --yes ${image_digest}` into `.github/workflows/sidecar-image.yml` after the existing buildx push.
3. Wire `cosign sign-blob --yes` into `release-binaries.yml` for every `.tar.gz`/`.zip`; attach `.sig` and `.crt` to the release.
4. Wire `cosign sign-blob` into `release-pypi.yml` (sdist + wheel) and `release-npm.yml` (tarball), publishing signatures as GitHub Release attachments referenced from `docs/install/VERIFY.md`.
5. Add a M02-owned libFuzzer target `fuzz/fuzz_targets/attest_verify.rs` that consumes the trait below; add the corpus seed `fuzz/corpus/attest_verify/empty.bin` and a regression note in `fuzz/README.md`.
6. Coordinate with M06: open a tracking issue confirming `chio-wasm-guards` migrates from raw `sigstore-rs` to `chio_attest_verify::AttestVerifier` before M06 closes.

#### `chio-attest-verify` trait surface and implementation contract

This is the file shape committed at the first task of Phase 3 (lives at `crates/chio-attest-verify/src/lib.rs`). The trait surface accommodates M09 release-archive verification, M06 WASM guard verification, and M02 fuzzing of the verifier itself.

```rust
//! Single source of truth for Sigstore verification across the chio
//! workspace. M09 (release archives), M06 (WASM guard signing), and M02
//! (fuzz target for the verifier) all consume this crate; no other crate
//! is permitted to call `sigstore-rs` directly.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::time::SystemTime;

/// Identity expectation pinned by every verification call. Both fields are
/// required; verification fails-closed if either is unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    /// Regex anchored against the Fulcio cert SAN. Example:
    /// `^https://github\\.com/owner/chio/\\.github/workflows/release-binaries\\.yml@refs/tags/v.*$`
    pub certificate_identity_regexp: String,
    /// Fulcio cert OIDC issuer. For GitHub-hosted runners this is exactly
    /// `https://token.actions.githubusercontent.com`.
    pub certificate_oidc_issuer: String,
}

/// Result of a successful verification. Carries enough metadata for
/// receipts and audit logs without re-parsing the cert chain.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub subject_digest_sha256: [u8; 32],
    pub certificate_identity: String,
    pub certificate_oidc_issuer: String,
    pub rekor_log_index: u64,
    pub rekor_inclusion_verified: bool,
    pub signed_at: SystemTime,
}

/// Errors are deliberately non-exhaustive so callers cannot pattern-match
/// past a future variant and silently accept. Every variant denies access.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("signature does not verify")]
    SignatureMismatch,
    #[error("certificate identity does not match expected regexp")]
    IdentityMismatch,
    #[error("oidc issuer does not match expected issuer")]
    IssuerMismatch,
    #[error("rekor inclusion proof failed")]
    RekorInclusion,
    #[error("certificate is outside its validity window")]
    CertificateExpired,
    #[error("trust root is missing or stale")]
    TrustRoot,
    #[error("malformed bundle: {0}")]
    Malformed(String),
}

/// The single trait every chio component implements against. Production
/// uses `SigstoreVerifier` (the only impl in this crate); M02's fuzz
/// harness implements a `LoopbackVerifier` that exercises decoder paths
/// without hitting the network.
pub trait AttestVerifier: Send + Sync {
    /// Verify a detached blob signature. Used by M09 for release-archive
    /// verification and by `chio-attest-verify`'s consumer recipe.
    fn verify_blob(
        &self,
        artifact: &Path,
        signature: &Path,
        certificate: &Path,
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError>;

    /// Verify an in-memory blob. Used by M06 when a WASM guard arrives
    /// over a network stream and is not yet on disk.
    fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError>;

    /// Verify a Sigstore bundle (a single self-describing JSON blob that
    /// inlines the cert, signature, and Rekor entry). Used by M06 for
    /// `sigstore-bundle.json` in the OCI cache layout.
    fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError>;
}

/// Production implementation backed by `sigstore-rs` with an embedded TUF
/// trust root. The trust root is refreshed quarterly by a CODEOWNERS-
/// reviewed PR; see `supply-chain/README.md`. The full implementation
/// (constructor + three `verify_*` methods) lands in the same PR as the
/// trait surface; no stubs ship in the merge train. See
/// `.planning/trajectory/EXECUTION-BOARD.md` "No verifier or trust-boundary
/// stubs" for the workspace policy.
pub struct SigstoreVerifier {
    /* private fields in src/sigstore.rs: TUF root handle, OIDC issuer
       allowlist, signature-algorithm allowlist, blob-size cap, async
       client. */
}

// The constructor and trait-impl method bodies live in src/sigstore.rs and
// are NOT shown inline here. The block above is a contract-level signature
// list; the merged crate ships full implementations in the same PR. Each
// method body's required behavior:
//
//   SigstoreVerifier::with_embedded_root()
//     - Loads the embedded TUF root from
//       `crates/chio-attest-verify/sigstore-root/`.
//     - Returns a configured verifier; never panics on a valid embedded
//       root (which is checked at build time by a build.rs assertion).
//
//   verify_blob(artifact, signature, certificate, expected)
//     - Loads artifact bytes, canonicalizes inputs, runs sigstore-rs
//       verification against the TUF root, asserts identity match.
//     - Fail-closed on every error path: I/O error, parse error, signature
//       mismatch, identity mismatch, expired certificate, allowlist miss.
//
//   verify_bytes(artifact, signature, certificate_pem, expected)
//     - Same semantics as verify_blob but operates on in-memory byte
//       slices for streaming guard loads.
//
//   verify_bundle(artifact, bundle_json, expected)
//     - Same semantics; consumes a Sigstore bundle JSON instead of a
//       split signature/certificate pair.
//
// CI workspace-wide forbids `todo!`, `unimplemented!`, and bare `panic!`
// in any file under `crates/chio-attest-verify/src/` (see
// `.planning/trajectory/EXECUTION-BOARD.md` "No verifier or trust-boundary
// stubs"). The reviewer checklist for the M09 P3 PR includes a grep for
// these macros in the diff.
```

Notes for consumers:

- M09 release verification calls `verify_blob` per archive.
- M06 guard loading calls `verify_bundle` against the cached `sigstore-bundle.json` and falls back to `verify_bytes` for streamed loads.
- M02's fuzz harness calls `verify_bytes` with adversarial input pairs and asserts the function never panics.
- The trait is `Send + Sync` so a single verifier can be shared across the kernel's tokio runtime.

### Phase 4: Reproducible build CI and consumer verification recipe

**First commit message** (exact): `feat(ci): land chio-reproducible-build.yml and docs/install/VERIFY.md`

**Effort**: M, 4 days.

**Tasks** (atomic, in order):

1. Land `rust-toolchain.toml` at the workspace root pinning `channel = "1.83.0"` (or whatever the in-tree MSRV is at the time of merge); commit.
2. Add `.github/workflows/chio-reproducible-build.yml` with the two-builder strategy below.
3. Add the `compare` job that fails on hash mismatch and runs `diffoscope` on mismatch.
4. Write `docs/install/VERIFY.md` containing the five-command verification recipe verbatim from below.
5. Cross-link `VERIFY.md` from `README.md` and `docs/install/BINARY_DISTRIBUTION.md`.
6. Add `tests/release/verify_recipe.rs` (integration test) that runs the documented commands against a freshly downloaded release artifact.
7. Promote `chio-reproducible-build.yml` to a required check after 14 consecutive green days on `main`.

#### Reproducible-build comparator (verbatim)

- **Workflow file**: `.github/workflows/chio-reproducible-build.yml`.
- **Builder A**: `runs-on: ubuntu-latest`, fresh runner, no Swatinem cache restore.
- **Builder B**: `runs-on: ubuntu-22.04`, primed Swatinem cache, `--offline` flag on `cargo build`.
- **Common flags**: `cargo build --release --locked --package chio-cli --target x86_64-unknown-linux-gnu`.
- **`SOURCE_DATE_EPOCH`**: derived from `git log -1 --pretty=%ct $GITHUB_SHA` (commit author date), exported into both builders.
- **`RUSTFLAGS`**: `--remap-path-prefix=$GITHUB_WORKSPACE=/build --remap-path-prefix=$CARGO_HOME=/cargo -C codegen-units=1 -C link-arg=-Wl,--build-id=none`.
- **Toolchain**: identical `rust-toolchain.toml`, `RUSTC_BOOTSTRAP=0`.
- **Compare job**: downloads both artifacts, runs `sha256sum -c`, fails on mismatch, then runs `diffoscope --html-dir diffoscope-out builder-a/chio builder-b/chio` and uploads the HTML directory as a workflow artifact for triage.

Determinism caveats (documented inline in both the workflow and `VERIFY.md`):

- `build.rs` scripts that call `chrono::Utc::now()` defeat `SOURCE_DATE_EPOCH`. Replace with `compile_time::env!("SOURCE_DATE_EPOCH")`.
- Without `--remap-path-prefix`, the runner's `/home/runner/work/...` path leaks into panic messages.
- Without `-C codegen-units=1`, multi-CGU symbol order is non-deterministic.
- macOS, Windows, and aarch64-linux are out of scope; reproducibility is asserted only for `x86_64-unknown-linux-gnu`.

#### Consumer verification recipe (verbatim, lands as `docs/install/VERIFY.md`)

The five commands an external consumer runs to verify a release. The recipe is exercised by the `tests/release/verify_recipe.rs` integration test.

```bash
# 1. Download the archive plus its attestations from the GitHub Release.
gh release download v${VERSION} --repo <owner>/chio \
    --pattern "chio-${VERSION}-x86_64-unknown-linux-gnu.tar.gz*" \
    --pattern "chio-${VERSION}-x86_64-unknown-linux-gnu.cdx.json" \
    --pattern "chio-${VERSION}-x86_64-unknown-linux-gnu.intoto.jsonl"

# 2. Verify the cosign signature against the workflow identity.
cosign verify-blob \
    --certificate chio-${VERSION}-x86_64-unknown-linux-gnu.tar.gz.crt \
    --signature   chio-${VERSION}-x86_64-unknown-linux-gnu.tar.gz.sig \
    --certificate-identity-regexp "^https://github\.com/<owner>/chio/\.github/workflows/release-binaries\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    chio-${VERSION}-x86_64-unknown-linux-gnu.tar.gz

# 3. Verify the SLSA L2 provenance.
slsa-verifier verify-artifact \
    --provenance-path chio-${VERSION}-x86_64-unknown-linux-gnu.intoto.jsonl \
    --source-uri github.com/<owner>/chio \
    --source-tag v${VERSION} \
    chio-${VERSION}-x86_64-unknown-linux-gnu.tar.gz

# 4. Verify the SBOM attestation (CycloneDX 1.6 attached via syft attest).
syft attest verify chio-${VERSION}-x86_64-unknown-linux-gnu.cdx.json \
    --certificate-identity-regexp "^https://github\.com/<owner>/chio/\.github/workflows/release-binaries\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# 5. Confirm the SHA-256 against the published manifest.
sha256sum -c chio-${VERSION}-x86_64-unknown-linux-gnu.tar.gz.sha256
```

Five commands, every one fail-closed. Drop the archive on the floor if any step exits non-zero.

## NEW sub-tasks added in Round 2

These were not present in the Round-1 doc; they are M09-scope work items.

- **(NEW) Trust-root re-bake job**: `.github/workflows/sigstore-trust-root-rebake.yml` runs quarterly, refreshes the embedded TUF root inside `chio-attest-verify`, and opens a CODEOWNERS-reviewed PR with the diff. Mitigates root-rotation drift between releases.
- **(NEW) Renovate config for action-pin drift**: `.github/renovate.json` watches `slsa-framework/slsa-github-generator`, `anchore/syft`, `anchore/scan-action`, `sigstore/cosign-installer`, and `slsa-framework/slsa-verifier`; opens weekly grouped PRs so CI pins do not silently drift to `@main`.
- **(NEW) `chio attest verify` CLI subcommand**: a thin `chio-cli` wrapper over `chio_attest_verify::SigstoreVerifier` so consumers who already have `chio` installed can verify the next release without installing `cosign`. Subcommand lives in `crates/chio-cli/src/cmd/attest.rs`; documented as the alternative path in `VERIFY.md`.

## Exit criteria

- `cargo-vet` baseline merged with the four-feed import set; `supply-chain` CI job is required and green on `main`.
- `deny.toml` is the verbatim file in Phase 1; `cargo deny check` is green on `main`.
- Every GitHub Release archive carries: a CycloneDX 1.6 SBOM (syft 1.18.x), a Sigstore signature, a Sigstore certificate, and a SLSA L2 `.intoto.jsonl` provenance file produced by `slsa-github-generator@v2.1.0`.
- The sidecar image, every published npm tarball, and every published PyPI distribution carry a verifiable Sigstore signature in addition to existing provenance.
- `chio-reproducible-build.yml` is required on `main` and stable for at least 14 consecutive days before the milestone closes; mismatches surface a `diffoscope` HTML report.
- `crates/chio-attest-verify/` is published in-tree with the trait surface from Phase 3; M06 imports it and M02 fuzzes it.
- `docs/install/VERIFY.md` walks an external consumer through download, signature, provenance, and SBOM verification in five commands; the recipe is exercised by `tests/release/verify_recipe.rs` against a freshly downloaded release.
- The three NEW sub-tasks (trust-root re-bake job, Renovate config, `chio attest verify` subcommand) are merged.

## Risks and mitigations

- Sigstore Rekor outage breaks releases. Mitigation: `cosign sign --tlog-upload=true` is the default, but the verification recipe documents an offline path (`COSIGN_EXPERIMENTAL=1 cosign verify-blob --offline` plus a cached transparency log); release jobs retry with backoff before failing.
- Sigstore TUF root rotation invalidates cached trust roots. Mitigation: the verification recipe pins `cosign` to a known-good release, and `chio-attest-verify` calls `sigstore-rs` with the embedded TUF root rather than network-fetching at every verification; the NEW quarterly re-bake job updates the embedded root with a CODEOWNERS review.
- `cargo-vet` import churn drowns reviewers. Mitigation: the initial baseline imports four upstream audit feeds (Mozilla, Bytecode Alliance, Google, ZcashFoundation), so the residual surface is small; CODEOWNERS routes vet diffs to a named reviewer pool, and the onboarding cost is paid once at baseline merge.
- `grype` false positives block releases. Mitigation: `.github/grype-ignore.yaml` is the documented override path, every entry requires a CVE ID plus a CODEOWNERS-reviewed comment, and the scan defaults to `--only-fixed` to filter unactionable advisories.
- `cosign` network dependency during release. Mitigation: signing retries on transient Fulcio/Rekor outages; if Sigstore is hard down, the release blocks rather than ships unsigned (fail-closed). Verification consumers who cannot reach Rekor follow the offline recipe.
- SLSA generator version drift. Mitigation: the workflow pins `slsa-framework/slsa-github-generator@v2.1.0` (not `@main`); the NEW Renovate config surfaces upstream releases for review.
- Reproducible-build flakiness from upstream toolchain changes. Mitigation: `rust-toolchain.toml` plus `cargo-auditable` versions are pinned; flakes are tracked as bugs (with the `diffoscope` artifact attached), not silenced by relaxing the equality check.
- Identity-issuer policy drift between guard signing (M06) and release signing. Mitigation: the shared `chio-attest-verify` crate is the single source of truth for the OIDC identity-and-issuer regex; both code paths import it via the `AttestVerifier` trait.

## Cross-doc references

- M01 (schema-and-receipt hardening) governs the SBOM contents: every component identity emitted by `syft` must round-trip through the canonical-JSON identity rules M01 establishes; the SBOM itself is a signed manifest in the same way receipts are.
- M02 (fuzzing and property tests) consumes the `AttestVerifier` trait via `fuzz/fuzz_targets/attest_verify.rs`; the harness asserts no panic on adversarial cert / signature / bundle bytes. Coordinate so the fuzz target lands in the same PR as the trait surface.
- M06 (WASM guard signing) reuses `crates/chio-attest-verify/` introduced in Phase 3; the `verify_bundle` and `verify_bytes` methods are the integration points. Both milestones must agree on the trait surface before either declares its signing path stable; Phase 3 task 6 owns the coordination.
- M07 (release qualification) and M08 (release flows) automatically pick up the new attestation gates; the qualification matrix grows by `cargo deny`, `cargo vet`, `grype`, SLSA verification, and reproducible-build steps.

## Dependencies

- Independent of M01 through M05 for execution, though M01's canonical-JSON identity rules govern SBOM component identity.
- M06 (WASM guard signing) consumes the `chio-attest-verify` helper landed in Phase 3; coordinate the trait surface before either milestone declares its signing path stable.
- M02 (fuzzing) consumes the same helper; the fuzz target lands alongside the trait surface in Phase 3.
- M07 and M08 release flows pick up the new attestation gates as they land; no separate coordination needed beyond the workflow updates in Phases 2 and 3.
