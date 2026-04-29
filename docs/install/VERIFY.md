# Verifying Chio Release Artifacts

This document is the consumer-facing verification recipe for every Chio
release artifact. Every distribution channel attaches Sigstore keyless
signatures (`.sig` + `.pem`) produced by GitHub Actions OIDC; consumers
verify those signatures against the upstream workflow identity.

The signature scheme is identical across channels: a detached
[cosign](https://github.com/sigstore/cosign) signature plus a Fulcio
short-lived certificate. The Rust verification crate
[`crates/chio-attest-verify`](../../crates/chio-attest-verify/README.md)
(milestone M09.P3.T1) consumes the same trust root and identity
contract; CLI consumers can fall back to `cosign verify-blob` directly.

## What you need

Pin tooling versions to a known-good release before verifying a
production artifact:

| Tool | Version | Source |
|---|---|---|
| `cosign` | `v2.4.x` or newer | https://github.com/sigstore/cosign/releases |
| `gh` (optional) | latest | https://github.com/cli/cli/releases |

Or, if you already have Chio installed, the `chio attest verify`
subcommand wraps `chio_attest_verify::SigstoreVerifier` and avoids the
external `cosign` install. See the crate
[README](../../crates/chio-attest-verify/README.md) for the trait
surface (`verify_bundle`, `verify_blob`, `verify_bytes`).

## OIDC identity contract

Every `cosign verify-blob` invocation below pins the same two pieces of
identity:

- `--certificate-oidc-issuer "https://token.actions.githubusercontent.com"`
  asserts that the Fulcio certificate was issued to a GitHub Actions
  workflow run.
- `--certificate-identity-regexp "^https://github\.com/<owner>/chio/\.github/workflows/<workflow>\.yml@refs/tags/<tag-pattern>$"`
  asserts that the workflow run was the release lane producing this
  artifact, against a tag matching the release schema.

These two assertions together prove the artifact was built by the
upstream Chio release workflow on a tag-triggered run, not by some
other workflow or some other repository fork. The
`chio-attest-verify` crate enforces the same regex contract for
in-process verification.

Replace `<owner>` with the GitHub org/user that hosts the release you
are verifying (e.g. `backbay-industries`).

## Verifying a PyPI artifact

PyPI hosts the sdist and wheel; the corresponding `.sig` (cosign
signature) and `.pem` (Fulcio leaf certificate) live on the GitHub
Release attached to the same `py/...` tag.

```bash
export OWNER="<owner>"            # e.g. backbay-industries
export VERSION="<version>"        # e.g. 0.2.0
export PKG="<distribution>"       # e.g. chio-crewai
export PKG_FILE_VERSION="${PKG//-/_}-${VERSION}"

# 1. Download the wheel from PyPI (or sdist via pip download --no-binary :all:)
pip download --no-deps --dest . "${PKG}==${VERSION}"

# 2. Download the matching cosign signature + cert from the GitHub
# Release. The release tag is the meta tag (py/v<VERSION>) for full-fleet
# releases or the slug-specific tag (py/<PKG>-v<VERSION>) for one-off
# bumps. Adjust the tag below to match how the release was cut.
gh release download "py/v${VERSION}" --repo "${OWNER}/chio" \
    --pattern "${PKG_FILE_VERSION}-py3-none-any.whl.sig" \
    --pattern "${PKG_FILE_VERSION}-py3-none-any.whl.pem"

# 3. Verify the wheel signature against the release-pypi.yml workflow
# identity. The regex anchors against either tag shape (meta or
# slug-specific) on a semver-shaped version.
cosign verify-blob \
    --signature   "${PKG_FILE_VERSION}-py3-none-any.whl.sig" \
    --certificate "${PKG_FILE_VERSION}-py3-none-any.whl.pem" \
    --certificate-identity-regexp \
        "^https://github\.com/${OWNER}/chio/\.github/workflows/release-pypi\.yml@refs/tags/py/(${PKG}-)?v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${PKG_FILE_VERSION}-py3-none-any.whl"
```

`cosign verify-blob` exits non-zero if any of the following fail:

- Signature does not match the artifact bytes.
- Fulcio certificate does not chain to the embedded TUF trust root.
- Certificate's SAN does not match the identity regex.
- Issuer in the certificate does not match the OIDC issuer.
- Rekor inclusion proof is absent or invalid (default mode contacts
  the public-good Rekor instance; pass `--insecure-ignore-tlog` only in
  tightly controlled offline scenarios).

To verify the sdist instead of the wheel, swap the `.whl` filename for
`.tar.gz` in steps 1, 2, and 3.

### Multi-package fleet releases

A meta tag (`py/v<VERSION>`) signs every Chio Python distribution at
the same `<VERSION>`. The cosign certificate carries the workflow run
identity, not the package slug, so the same regex above matches every
distribution under that tag.

For a slug-specific tag (`py/<PKG>-v<VERSION>`), narrow the regex
alternation to only the slug shape:

```bash
--certificate-identity-regexp \
    "^https://github\.com/${OWNER}/chio/\.github/workflows/release-pypi\.yml@refs/tags/py/${PKG}-v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$"
```

## Verifying an npm tarball

npm hosts the published tarball under the registry; a copy of the
exact byte-for-byte tarball plus its `.sig` and `.pem` is attached to
the GitHub Release for the `ts/...` tag. Verify against either copy.

```bash
export OWNER="<owner>"            # e.g. backbay-industries
export VERSION="<version>"        # e.g. 0.2.0
export PKG="<slug>"               # e.g. express
# The published distribution name is @chio-protocol/${PKG}; the npm
# tarball naming convention drops the scope and uses a hyphen:
#   @chio-protocol/express -> chio-protocol-express-${VERSION}.tgz
export TARBALL="chio-protocol-${PKG}-${VERSION}.tgz"

# 1. Fetch the tarball + signature + cert from the GitHub Release.
gh release download "ts/v${VERSION}" --repo "${OWNER}/chio" \
    --pattern "${TARBALL}" \
    --pattern "${TARBALL}.sig" \
    --pattern "${TARBALL}.pem"

# 2. Verify against the release-npm.yml workflow identity.
cosign verify-blob \
    --signature   "${TARBALL}.sig" \
    --certificate "${TARBALL}.pem" \
    --certificate-identity-regexp \
        "^https://github\.com/${OWNER}/chio/\.github/workflows/release-npm\.yml@refs/tags/ts/(${PKG}-)?v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${TARBALL}"
```

The same exit-code semantics as the PyPI recipe apply.

### Verifying the npm registry copy

npm publishes provenance attestations via `--provenance`. The cosign
keyless signature is complementary, not redundant: provenance binds
the published version to a workflow identity at the registry layer,
while cosign binds the actual tarball bytes. To verify both, fetch the
tarball directly from the registry (`npm pack @chio-protocol/<slug>`)
and re-run step 2 with the registry copy in place of the GitHub
Release copy. Bytes should match between the two sources; if they do
not, the registry has been tampered with.

## In-process verification (Rust callers)

Rust callers should consume the
[`chio_attest_verify`](../../crates/chio-attest-verify/README.md)
crate rather than shelling out to `cosign`. The crate exposes a single
`AttestVerifier` trait with three methods:

- `verify_bundle` -- strongest assertion, full keyless flow against
  the embedded Fulcio trust root including Rekor log-entry consistency.
- `verify_blob` -- detached `(artifact, signature, leaf-cert)` triple.
- `verify_bytes` -- in-memory variant of `verify_blob`.

The `verify_blob` and `verify_bytes` paths perform certificate-chain
validation against Fulcio, OIDC issuer match, identity SAN regex
match, certificate validity-window check, and signature verification.
They map directly onto the `cosign verify-blob` invocation above with
the same `ExpectedIdentity` (issuer + identity regex).

```rust
use chio_attest_verify::{AttestVerifier, ExpectedIdentity, SigstoreVerifier};

let verifier = SigstoreVerifier::with_embedded_root()?;
let expected = ExpectedIdentity {
    certificate_identity_regexp:
        r"^https://github\.com/backbay-industries/chio/\.github/workflows/release-pypi\.yml@refs/tags/py/(chio-crewai-)?v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$"
            .into(),
    certificate_oidc_issuer:
        "https://token.actions.githubusercontent.com".into(),
};
let claims = verifier.verify_blob(
    artifact_path,
    signature_bytes,
    leaf_cert_bytes,
    &expected,
)?;
```

The crate ships the Sigstore Public Good Instance trust root in tree
under `crates/chio-attest-verify/sigstore-root/` and refreshes it
quarterly via the trust-root re-bake job.

## Failure mode (fail-closed)

Every step above is fail-closed: a non-zero exit from `cosign
verify-blob`, or a returned `AttestError` from `chio_attest_verify`,
means the artifact does not satisfy the keyless attestation contract.
Drop the artifact on the floor and re-fetch from a clean source. Do
not retry verification after manually trimming the signature, the
certificate, or the artifact bytes; any of those mutations make the
verification meaningless.

## Channel inventory (current scope)

| Channel | Workflow | Tag schema | Sig location |
|---|---|---|---|
| PyPI sdist + wheel | `.github/workflows/release-pypi.yml` | `py/v<X.Y.Z>` or `py/<slug>-v<X.Y.Z>` | GitHub Release |
| npm tarball | `.github/workflows/release-npm.yml` | `ts/v<X.Y.Z>` or `ts/<slug>-v<X.Y.Z>` | GitHub Release |

Native release archive (`release-binaries.yml`), sidecar OCI image
(`sidecar-image.yml`), and SLSA L2 provenance (`slsa.yml`)
verification recipes land alongside their respective signing wires
under M09 phase 3 and phase 4 (see
`.planning/trajectory/09-supply-chain-attestation.md`).

## See also

- `crates/chio-attest-verify/README.md` -- trait surface, embedded
  trust root, OIDC issuer regex contract, integration test inventory.
- `docs/install/PUBLISHING.md` -- operator-facing release runbook for
  PyPI and npm, including OIDC trusted publisher setup.
- `.planning/trajectory/09-supply-chain-attestation.md` -- supply
  chain attestation milestone, including the consumer-facing
  five-command recipe for native release archives (verbatim under
  Phase 4).
