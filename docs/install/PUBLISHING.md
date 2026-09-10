# Chio SDK Publishing Runbook

Operator guide for publishing Chio's Python SDKs to PyPI and TypeScript
SDKs to npm. Both release lanes use OIDC Trusted Publishing, meaning
**no long-lived API tokens are stored in GitHub secrets**; all
authentication flows come from GitHub's OIDC identity combined with
pre-configured trust on the registry side.

- Python workflow: [`.github/workflows/release-pypi.yml`](../../.github/workflows/release-pypi.yml)
- TypeScript workflow: [`.github/workflows/release-npm.yml`](../../.github/workflows/release-npm.yml)
- Local smoke-test scripts:
  - [`sdks/python/scripts/package-check.sh`](../../sdks/python/scripts/package-check.sh)
  - [`sdks/typescript/scripts/package-check.sh`](../../sdks/typescript/scripts/package-check.sh)

---

## Tag format

Both workflows trigger on annotated git tags. The tag name encodes
what to publish.

| Tag pattern | Publishes |
|---|---|
| `py/v<MAJOR.MINOR.PATCH>` | Every Python package listed below. All packages must be at the same version. |
| `py/<slug>-v<MAJOR.MINOR.PATCH>` | Just that package (e.g. `py/chio-crewai-v1.2.0`). |
| `ts/v<MAJOR.MINOR.PATCH>` | Every TypeScript package. All packages must be at the same version. |
| `ts/<slug>-v<MAJOR.MINOR.PATCH>` | Just that package (e.g. `ts/express-v1.2.0` -> `@chio-protocol/express`). |

The per-package slug is the **directory name**, not the distribution
name. For example, `@chio-protocol/express` lives in
`sdks/typescript/packages/express`, so its slug is `express`.

**Meta-tag policy**: a `py/v*.*.*` or `ts/v*.*.*` tag publishes every
package, and the matrix CI validates that every package's declared
version matches the tag. If even one is out of step, the workflow
fails before any publish happens. For uneven version trains, use
per-package slug tags.

Tags must be pushed from `main` (or a protected release branch) after
all SDK changes for that version have merged.

### Creating a release tag

```bash
# Single package, single version bump
git tag -a py/chio-crewai-v1.2.0 -m "release chio-crewai 1.2.0"
git push origin py/chio-crewai-v1.2.0

# Full Python SDK fleet (after bumping every pyproject.toml)
git tag -a py/v0.2.0 -m "release Python SDKs 0.2.0"
git push origin py/v0.2.0
```

---

## Package inventory

### Python (PyPI)

Published under the listed distribution name:

| Slug | Distribution | Directory |
|---|---|---|
| `chio-sdk-python` | `chio-sdk-python` | `sdks/python/chio-sdk-python` |
| `chio-adapter-base` | `chio-adapter-base` | `sdks/python/chio-adapter-base` |
| `chio-asgi` | `chio-asgi` | `sdks/python/chio-asgi` |
| `chio-django` | `chio-django` | `sdks/python/chio-django` |
| `chio-fastapi` | `chio-fastapi` | `sdks/python/chio-fastapi` |
| `chio-langchain` | `chio-langchain` | `sdks/python/chio-langchain` |
| `chio-crewai` | `chio-crewai` | `sdks/python/chio-crewai` |
| `chio-autogen` | `chio-autogen` | `sdks/python/chio-autogen` |
| `chio-llamaindex` | `chio-llamaindex` | `sdks/python/chio-llamaindex` |
| `chio-temporal` | `chio-temporal` | `sdks/python/chio-temporal` |
| `chio-prefect` | `chio-prefect` | `sdks/python/chio-prefect` |
| `chio-dagster` | `chio-dagster` | `sdks/python/chio-dagster` |
| `chio-airflow` | `chio-airflow` | `sdks/python/chio-airflow` |
| `chio-ray` | `chio-ray` | `sdks/python/chio-ray` |
| `chio-streaming` | `chio-streaming` | `sdks/python/chio-streaming` |
| `chio-iac` | `chio-iac` | `sdks/python/chio-iac` |
| `chio-observability` | `chio-observability` | `sdks/python/chio-observability` |
| `chio-langgraph` | `chio-langgraph` | `sdks/python/chio-langgraph` |
| `chio-code-agent` | `chio-code-agent` | `sdks/python/chio-code-agent` |
| `chio-hermes` | `chio-hermes` | `sdks/python/chio-hermes` |
| `chio-lambda-python` | `chio-lambda-python` | `sdks/lambda/chio-lambda-python` |

### TypeScript (npm)

| Slug | Distribution | Directory |
|---|---|---|
| `chio-ts` | `@chio-protocol/sdk` | `sdks/typescript/chio-ts` |
| `node-http` | `@chio-protocol/node-http` | `sdks/typescript/packages/node-http` |
| `express` | `@chio-protocol/express` | `sdks/typescript/packages/express` |
| `fastify` | `@chio-protocol/fastify` | `sdks/typescript/packages/fastify` |
| `elysia` | `@chio-protocol/elysia` | `sdks/typescript/packages/elysia` |
| `ai-sdk` | `@chio-protocol/ai-sdk` | `sdks/typescript/packages/ai-sdk` |

`@chio-protocol/conformance` is marked `"private": true` and is
deliberately excluded from publishing.

---

## One-time setup (required before first publish)

### PyPI Trusted Publishing

For **each** Python package, a PyPI project maintainer must configure
a Trusted Publisher:

1. Log in to https://pypi.org as a maintainer of the project (or use
   https://pypi.org/manage/account/publishing/ to pre-register a
   pending publisher for a brand-new distribution).
2. Under **Publishing** -> **Add a new pending publisher**, set:
   - PyPI Project Name: e.g. `chio-crewai`
   - Owner: `backbay-industries`
   - Repository name: `chio`
   - Workflow name: `release-pypi.yml`
   - Environment name: `pypi`
3. Save.

The environment name (`pypi`) is hard-coded in `release-pypi.yml`. Do
not change it without also updating the Trusted Publisher
configuration for every project.

Reference: https://docs.pypi.org/trusted-publishers/

### npm OIDC / provenance

npm provenance requires the workflow to run with
`permissions.id-token: write` (already set in `release-npm.yml`) and
for the npm package to opt in to Trusted Publishing:

1. Log in to https://www.npmjs.com as an org admin of `@chio-protocol`.
2. For each package (`chio-ts`, `node-http`, `express`, `fastify`, `elysia`,
   `ai-sdk`), go to **Settings** -> **Trusted Publishers** -> **Add**
   and register:
   - GitHub org: `backbay-industries`
   - Repository: `chio`
   - Workflow path: `.github/workflows/release-npm.yml`
   - Environment name: `npm`
3. Confirm the org-level 2FA policy is set to "Publishing and
   settings modification" -- provenance publishes bypass interactive
   2FA but still honor the org policy.

After this is done, `npm publish --provenance` from the workflow will
mint an attestation signed by Sigstore and linked to the tag's source
commit. No `NPM_TOKEN` secret is needed; any existing token should be
revoked after the first successful provenance publish.

Reference: https://docs.npmjs.com/generating-provenance-statements

### GitHub environments

Both workflows use deployment environments (`pypi` and `npm`) so that
environment-level protection rules (e.g. required reviewers, branch
restrictions) can gate publishes. Configure under
**Settings** -> **Environments** in the repo:

- `pypi`: restrict to tags matching `py/*`.
- `npm`: restrict to tags matching `ts/*`.
- Optionally add required reviewers for production releases.

---

## Dry-run / test mode

Both workflows expose `workflow_dispatch` with a `dry_run` toggle
(default `true`). A dry run builds the sdist+wheel (Python) or runs
`build` + `lint` + `test` + `npm pack` (TypeScript) and uploads the
artifacts, but skips the `publish` job entirely.

Dry runs are the right way to validate CI after changing the
workflow or adding a new package. Trigger via **Actions** ->
**Release PyPI / Release npm** -> **Run workflow** -> pick branch,
optionally fill `package`, leave `dry_run` checked.

For local iteration, use the `package-check.sh` scripts instead:

```bash
./sdks/python/scripts/package-check.sh
./sdks/typescript/scripts/package-check.sh
```

---

## Release checklist

1. Land all SDK changes for the release on `main`.
2. Bump the version in the package's `pyproject.toml` (or
   `package.json`). For a full-fleet release, bump **every** package.
3. Run the local smoke check:
   - `./sdks/python/scripts/package-check.sh`
   - `./sdks/typescript/scripts/package-check.sh`
4. Open a release PR, get review, merge.
5. From `main`, create and push the release tag (see **Tag format**).
6. Watch the workflow in GitHub Actions. The `build` job should
   succeed for every matrix leg before `publish` starts.
7. Confirm the package is live:
   - `pip install <dist-name>==<version>`
   - `npm view @chio-protocol/<slug>@<version>`

---

## Rollback

### PyPI

PyPI **does not allow re-uploading the same version** after a
release. The correct rollback is to **yank** the broken version and
publish a new patch:

1. On https://pypi.org/manage/project/<dist-name>/releases/, click
   **Options** -> **Yank** on the bad version. Enter a reason
   (shown to users in resolver errors).
2. Fix the bug on `main`, bump the patch version, land the PR.
3. Cut a new tag (e.g. `py/chio-crewai-v1.2.1`) and let the workflow
   publish normally.

Yanked versions remain installable if explicitly pinned, but resolvers
will skip them for `>=` / `~=` specifiers.

### npm

npm allows `npm unpublish` only within 72 hours of first publish and
only if no other package depends on it. The recommended rollback is
to **deprecate**:

```bash
npm deprecate @chio-protocol/<slug>@<version> "Do not use: superseded by <next-version>. See CHANGELOG for details."
```

Then bump the patch version, tag, and let the workflow republish.

For severe security issues within the 72-hour window, unpublishing
is permitted:

```bash
npm unpublish @chio-protocol/<slug>@<version>
```

Coordinate with @chio-protocol org admins before unpublishing; the
name+version combo is burnt for 24 hours.

### Revoking a provenance attestation

Provenance attestations cannot be withdrawn once minted (they live
in the Sigstore transparency log). Deprecation plus a follow-up
release is the correct response.

---

## Candidate archive staging and promotion

SemVer prereleases such as `v0.1.1-rc.1` produce a GitHub draft prerelease.
Stable tags retain the stable-release path. The source CI/security/qualification
checks, auditable build, SBOM validation and cosign signing still run before
release assets are attached. A hyphen in build metadata alone, such as
`v1.2.3+build-42`, does not select prerelease mode.

The SLSA jobs run inside the original tagged release invocation, verify the
provenance before attaching it, and require candidates to remain drafts. They
refuse to reopen an already published candidate. Archive uploads do not
overwrite an existing asset. Never rebuild a tag to replace bytes that have already
been qualified. A changed binary needs a new candidate and fresh acceptance.

GitHub restricts draft release listings to users with push access. Authenticate
`gh` as an authorized maintainer to download the draft. Draft status does not hide
public Actions logs/artifacts or Sigstore transparency records. Do not include
credentials in release artifacts. See [GitHub's release API](https://docs.github.com/en/rest/releases/releases)
and [the pinned generator's workflow contract](https://github.com/slsa-framework/slsa-github-generator/blob/f7dd8c54c2067bafc12ca7a55595d5ee9b75204a/.github/workflows/generator_generic_slsa3.yml).

### Retrieve the hosted candidate

Wait for the exact tag's Release Binaries run, including its provenance jobs,
to finish successfully. Retain its run ID, attempt, source SHA and artifact identities.
The provenance asset must be present before freezing the acceptance inventory.
Use Python 3.11 or newer, a clean checkout at the reviewed release tag and an
empty download directory:

```sh
REPO=backbay-labs/chio
TAG=v0.1.1-rc.1
SOURCE="$(git rev-list -n 1 "$TAG")"
CANDIDATE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/chio-rc-qualification.XXXXXX")"
mkdir "$CANDIDATE_ROOT/assets"
gh release download "$TAG" --repo "$REPO" --dir "$CANDIDATE_ROOT/assets"
python3 scripts/check-release-draft-assets.py record \
  --repository "$REPO" --tag "$TAG" --source-sha "$SOURCE" \
  --directory "$CANDIDATE_ROOT/assets" --manifest "$CANDIDATE_ROOT/asset-identities.json"
```

The identity checker binds every downloaded byte to the current release ID,
asset ID, size and GitHub SHA-256, checks the remote tag's commit, and requires the
five archives with signature/checksum siblings, their SBOM reports, macOS native
materials and the source-named provenance asset. It refuses missing/extra files,
symlinks and changed assets. It does not verify signatures, attest acceptance,
replace the source gates or publish anything.

Before executing a downloaded binary, perform the cosign and SLSA verification
recipes below for its exact archive. Pin the exact certificate identity, for
example `https://github.com/backbay-labs/chio/.github/workflows/release-binaries.yml@refs/tags/v0.1.1-rc.1`,
and the GitHub OIDC issuer. Run `scripts/verify-release-provenance.py verify`
with the intended source SHA, run ID and attempt as shown below. It verifies the
signed source commit, tag, original workflow and immutable upstream builder
identity. Compare the attached SBOM/native reports to the copies
inside the signed archive and run the existing binary inventory/linkage validators.
Retain those verification outputs with the acceptance record.

For Apple Silicon, extract and test `chio-0.1.1-rc.1-aarch64-apple-darwin.tar.gz`
from this download. Record both archive and extracted executable hashes. Run each
required real host and the documented installer against that executable, along
with the selected plugin/SDK archives. A local build or a different hosted rebuild
cannot supply evidence for these bytes. Other platforms require their own stated
qualification; this macOS example supplies none for them.

### Review the signed checksum index

The candidate workflow attaches `v<VERSION>.txt`, `.txt.sig` and `.txt.pem` to the
draft and uploads the same files as Actions artifact `checksum-index-<TAG>`.
GitHub Actions does not create the candidate's review PR: the organization forbids
Actions from creating or approving PRs. No token exception is required. The job
explicitly reports that operator checksum review is pending while SLSA completes
against the unpublished draft.

Verify the signed index with cosign against the same exact release workflow/tag
identity used for archive signatures. In a separate clean branch from canonical
`main`, copy these three downloaded files unchanged into `supply-chain/checksums/`.
Commit them and create the checksum review PR using the trusted operator's existing
GitHub identity. Record the PR number as `CHECKSUM_REVIEW_PR`. Complete the normal
review and required repository checks before merging it. No other files belong in
this PR, and no long-lived token belongs in a workflow or release artifact.

The promotion identity checker requires `--checksum-review-pr`. It rejects an
unmerged PR, a PR against another repository/branch, missing or extra files, and
any index/signature/certificate byte mismatch. Both the merge commit and current
canonical `main` must retain the exact files frozen in the draft inventory. The
operator's PR replaces the prohibited bot action; it does not waive checksum
review or signature verification. Source, security and host gates remain separate.

### Publish the accepted bytes

Promotion is a trusted operator step after every required host gate, operational
procedure, artifact signature, provenance and source/security/release check passes.
Required failures, unavailable cases or skips remain unresolved. Review raw host
records against `asset-identities.json`; this helper intentionally cannot turn an
operator-written boolean into proof of host acceptance.

Re-run `scripts/check-release-source-gates.py` from the clean accepted tag checkout
with `GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_REF_TYPE=tag` and `GITHUB_REF_NAME`
set to the selected repository, source and tag. Retrieve the complete draft again
into a fresh directory and compare it with the inventory used during acceptance:

```sh
mkdir "$CANDIDATE_ROOT/pre-promotion"
gh release download "$TAG" --repo "$REPO" --dir "$CANDIDATE_ROOT/pre-promotion"
python3 scripts/check-release-draft-assets.py check \
  --repository "$REPO" --tag "$TAG" --source-sha "$SOURCE" \
  --directory "$CANDIDATE_ROOT/pre-promotion" --manifest "$CANDIDATE_ROOT/asset-identities.json" \
  --checksum-review-pr "$CHECKSUM_REVIEW_PR"
```

After these checks and the required release review, the operator publishes the
existing release without uploading or rebuilding assets:

```sh
gh release edit "$TAG" --repo "$REPO" --draft=false --prerelease --latest=false --verify-tag
```

This command changes publication state. It does not establish technical acceptance.
Do not run it while acceptance remains incomplete. Do not upload or replace assets
between the final identity check and publication; the trusted release operator owns
that interval. Immediately download the published release into another empty
directory and run the same `check` command with `--published`. Repeat the signature
and public installation checks. Record the release ID, source, URLs and matching
hashes; changing the website's default is a separate deployment procedure.

An interrupted draft upload remains unpublished. Preserve its build artifacts and
investigate the failure before resuming. Asset replacement or a rebuild requires
fresh identity records and affected host qualification. Do not delete an old
acceptance record, reopen a published candidate or use `--clobber` to make an
inconsistent release appear current.

---

## Supply-chain artifacts

Every binary release built by
[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml)
emits two complementary supply-chain artifacts in addition to the
`.tar.gz` / `.zip` archive and its `.sha256` sidecar.

| Artifact | Producer | Where to find it |
|---|---|---|
| Embedded `auditable` dependency graph | `cargo auditable build` (cargo-auditable v0.7.4) | Inside the `chio` binary itself, consumed by Syft's embedded-audit-data cataloger. |
| CycloneDX 1.6 JSON SBOM | `syft` v1.51.1 with [`deploy/sbom/syft.yaml`](../../deploy/sbom/syft.yaml) | Inside the signed archive and as separate release assets: `chio-<target>.cyclonedx.json` and its `chio-<target>.validation.json` report. Also retained as Actions artifact `sbom-<target>` for 90 days. |

Both artifacts are produced per matrix leg, so each of the five
release targets (linux x86_64 / aarch64, macOS x86_64 / aarch64,
windows x86_64) ships its own embedded graph and its own SBOM.

Before packaging or signing,
[`check-release-binary-sbom.py`](../../scripts/check-release-binary-sbom.py)
requires the pinned Syft identity and binds the SBOM to the executable SHA-256.
It checks exact CLI and required kernel package versions against the selected
source, requires Rust package identities from the embedded-audit-data cataloger
to match `Cargo.lock`, and verifies that the required kernel packages are reachable
from the CLI in the dependency graph. Missing or inconsistent inventory fails the
release. The validation report retains both executable and SBOM hashes.

This binary inventory is separate from the source/workspace SBOM and from the
macOS native OpenSSL materials and vulnerability scan. Each answers a different
question; a source scan cannot stand in for the executable inventory, and the
embedded Rust graph does not establish native-library coverage.

Cosign keyless signing of every `release-binaries.yml` archive
ships today; the consumer verification recipe lives below
in [Release-binaries archive signing](#release-binaries-archive-signing).
See `spec/PROTOCOL.md` for the broader attestation contract.

---

## Sidecar image signing

Owned by the release toolchain. The multi-arch sidecar OCI image built by
[`.github/workflows/sidecar-image.yml`](../../.github/workflows/sidecar-image.yml)
is built on native x86_64 and ARM64 GitHub runners. Each native build is
pushed by digest, then an assembly job creates and verifies the two-platform
manifest before keyless signing it with
[Sigstore cosign](https://docs.sigstore.dev/cosign/). The signature is keyed
to the manifest's content-addressed digest, so every tag the metadata-action
emits (`vMAJOR.MINOR.PATCH`, `MAJOR.MINOR`, short SHA, and `latest` on the
default branch) is covered by a single signature on the underlying manifest.
Both native builds use the workspace `docker-release` profile (thin LTO) and
one Cargo job. This keeps the final `chio` link within the standard hosted ARM
runner memory envelope while retaining an optimized container artifact.

### How signing works

1. The workflow builds `linux/amd64` on `ubuntu-24.04` and `linux/arm64` on
   `ubuntu-24.04-arm`, then refuses to sign unless the assembled manifest
   contains both platforms.
2. `sigstore/cosign-installer@v3.7.0` pins cosign at `v2.4.1` on the
   assembly runner.
3. The assembly job runs with `permissions.id-token: write`, which
   lets `cosign sign --yes` exchange a GitHub-issued OIDC token for a
   short-lived Fulcio signing certificate. No long-lived signing key is
   held in repo secrets.
4. `cosign sign --yes ghcr.io/<owner>/chio-sidecar@sha256:<digest>`
   uploads the resulting signature blob and certificate to the
   sigstore cosign signature tag (`sha256-<digest>.sig`) on the same
   ghcr.io repository, and writes a Rekor transparency-log entry that
   binds the signature to the workflow run that produced it.

### Consumer verification

Operators pulling the image can confirm the signature offline against
Sigstore's transparency log:

```bash
# Pin the digest you intend to deploy (recommended in production).
DIGEST=$(docker buildx imagetools inspect \
  ghcr.io/<owner>/chio-sidecar:<tag> --format '{{json .Manifest}}' \
  | jq -r .digest)

cosign verify \
  --certificate-identity-regexp \
    "^https://github\.com/<owner>/chio/\.github/workflows/sidecar-image\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?|heads/[A-Za-z0-9._/-]+)$" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  ghcr.io/<owner>/chio-sidecar@${DIGEST}
```

The `<owner>` placeholder is the lower-cased GitHub repository owner;
the `Normalize image repository` step in the workflow performs the
same lower-casing for the image name itself. Pin a tag rather than
following `:latest` if you need reproducible deploys; the digest is
the canonical reference.

The regex covers the two trigger shapes that push and sign images:

| Trigger             | SAN suffix                               |
|---------------------|------------------------------------------|
| `v*.*.*` tag push   | `@refs/tags/v<MAJOR.MINOR.PATCH[-pre]>`  |
| `main` branch push  | `@refs/heads/main`                       |

Manual `workflow_dispatch` runs are smoke builds only. They do not push
GHCR tags and do not mint cosign signatures.

Operators who require strict release-only verification should narrow
the `--certificate-identity-regexp` to just the `refs/tags/v...` arm
and reject `main`-branch images at deploy time.

### Programmatic verification from chio code

In-tree code MUST go through `chio_attest_verify::AttestVerifier`
rather than calling `sigstore-rs` directly. The trait surface is
documented in [`crates/trust/chio-attest-verify/README.md`](../../crates/trust/chio-attest-verify/README.md)
and exposes `verify_blob`, `verify_bytes`, and
`verify_bundle` with a single canonical `ExpectedIdentity`
(`certificate_identity_regexp`, `certificate_oidc_issuer`). The
sidecar-image workflow's signing identity matches that surface
directly: pass the regex shape above and the
`https://token.actions.githubusercontent.com` issuer.

### Rotation and rebake

Keyless signatures do not need rotation in the long-key sense; each
release mints a fresh ephemeral certificate. The Sigstore TUF trust
root that `chio-attest-verify` ships is refreshed by the quarterly
[`tuf-rebake.yml`](../../.github/workflows/tuf-rebake.yml) job and
landed via a CODEOWNERS-reviewed PR.

---

## Release-binaries archive signing

Owned by the release toolchain. Every per-target archive built by
[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml)
(five legs: linux x86_64 / aarch64, macOS x86_64 / aarch64, windows
x86_64) is keyless-signed with [Sigstore cosign](https://docs.sigstore.dev/cosign/)
immediately after the staging step that materializes the `.tar.gz`
or `.zip`. Two siblings are uploaded alongside each archive on the
GitHub Release:

| Sibling                 | Producer                          | Purpose                                                  |
|-------------------------|-----------------------------------|----------------------------------------------------------|
| `<archive>.sig`         | `cosign sign-blob --output-signature` | Detached signature blob over the archive bytes.       |
| `<archive>.pem`         | `cosign sign-blob --output-certificate` | PEM-encoded short-lived Fulcio certificate (the SAN carries the workflow identity used at verify time). |

The existing `<archive>.sha256` and the combined `SHA256SUMS`
sidecars are unchanged.

### How signing works

1. `sigstore/cosign-installer@v3.7.0` pins cosign at `v2.4.1` on each
   matrix runner. The pin matches the sidecar-image workflow
   ([Sidecar image signing](#sidecar-image-signing)) so consumers
   only need one cosign version on the verifier side.
2. The `build` job runs with `permissions.id-token: write`, which
   lets `cosign sign-blob --yes` exchange a GitHub-issued OIDC token
   for a short-lived Fulcio signing certificate. No long-lived
   signing key is held in repo secrets.
3. After the per-target archive is staged into `dist/`, the workflow
   runs `cosign sign-blob --yes --output-signature <archive>.sig
   --output-certificate <archive>.pem <archive>` and asserts both
   outputs are non-empty before the upload-artifact step. A failed
   signing aborts the matrix leg before any artifact is uploaded.
4. The `release` job copies the `.sig` and `.pem` siblings into
   `release/` alongside the archives and lets
   `softprops/action-gh-release@v2` attach them to the GitHub
   Release with `fail_on_unmatched_files: true`. Missing siblings
   fail the release rather than ship an unsigned archive.

### Consumer verification

The `release-binaries.yml` workflow signs only tag-bound release
builds. Tag pushes already run on `refs/tags/v...`; dispatched
rebuilds must be launched from the matching tag ref and then check out
`refs/tags/<input-tag>` before building. The workflow attaches release
metadata that SLSA consumes. The verification regex below therefore
rejects branch-shaped signing identities by default.

```bash
# Pin the version you intend to install and pick a target triple.
VERSION=0.1.0
TARGET=x86_64-unknown-linux-gnu
ARCHIVE="chio-${VERSION}-${TARGET}.tar.gz"

# Download the archive plus its cosign siblings.
gh release download "v${VERSION}" --repo <owner>/chio \
    --pattern "${ARCHIVE}" \
    --pattern "${ARCHIVE}.sig" \
    --pattern "${ARCHIVE}.pem" \
    --pattern "${ARCHIVE}.sha256"

# Verify the cosign signature against the workflow identity.
cosign verify-blob \
    --certificate "${ARCHIVE}.pem" \
    --signature   "${ARCHIVE}.sig" \
    --certificate-identity-regexp \
        "^https://github\.com/<owner>/chio/\.github/workflows/release-binaries\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$" \
    --certificate-oidc-issuer \
        "https://token.actions.githubusercontent.com" \
    "${ARCHIVE}"

# Confirm the SHA-256 against the published manifest.
shasum -a 256 -c "${ARCHIVE}.sha256"
```

The `<owner>` placeholder is the lower-cased GitHub repository owner
(e.g. `backbay-industries`). Five archive variants ship per release
(one per matrix leg) and each carries its own `.sig` + `.pem`
pair; verifying one platform never implies verifying another.

Archives whose Fulcio SAN is not `refs/tags/v...` are not valid Chio
release archives, even if they are attached to a release name.

### Programmatic verification from chio code

In-tree code MUST go through `chio_attest_verify::AttestVerifier`
rather than calling `sigstore-rs` directly. The trait surface is
documented in [`crates/trust/chio-attest-verify/README.md`](../../crates/trust/chio-attest-verify/README.md)
and exposes `verify_blob`, `verify_bytes`, and
`verify_bundle` with a single canonical `ExpectedIdentity`
(`certificate_identity_regexp`, `certificate_oidc_issuer`). The
release-binaries workflow's signing identity matches that surface
directly: pass the regex shape above and the
`https://token.actions.githubusercontent.com` issuer.

### Rotation and rebake

The same Sigstore TUF trust root that gates sidecar image
verification gates archive verification, refreshed by the quarterly
[`tuf-rebake.yml`](../../.github/workflows/tuf-rebake.yml) job. The
ephemeral cert in each `<archive>.pem` is bound to a single workflow
run via Rekor; there is no long-lived key to rotate.

---

## SLSA L2 provenance

[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml)
calls the local [SLSA workflow](../../.github/workflows/slsa.yml) after the release
matrix succeeds. This nested `workflow_call` retains the original tagged push or
operator dispatch context. A separate `workflow_run` listener would instead
supply its default-branch ref and SHA to the generator, so archive metadata alone
could not establish the signed source identity.

The isolated upstream generator is pinned to commit
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` (reviewed upstream `v2.1.0`). Its supported
`compile-generator: true` mode builds the generator from that revision; the
precompiled download mode requires a tag. See the
[pinned producer contract](https://github.com/slsa-framework/slsa-github-generator/blob/f7dd8c54c2067bafc12ca7a55595d5ee9b75204a/.github/workflows/generator_generic_slsa3.yml).
The lane produces SLSA v0.2 build provenance for the Level 2 release requirement.
It does not claim complete build-material inventory, reproducible builds or
real-host integration acceptance.

### What gets attested

`collect-digests` requires exactly the five platform artifacts from the current
run. Each archive's metadata must match its target, source commit, tag, version,
run ID and attempt. It hashes the actual archives and passes those five named
subjects to the isolated generator. Missing targets, old attempts and relabelled
source metadata fail before signing.

A retry of only the provenance jobs has a new attempt and cannot relabel archives
from an older attempt. If a run fails after candidate assets have been attached,
preserve that failed candidate and its evidence, correct the cause, and build a
fresh reviewed candidate tag. Do not edit metadata or overwrite staged bytes to
make the failed run appear qualified.

The generator emits `chio-<source_sha>.intoto.jsonl` as a Sigstore v0.3 bundle and
retains it as an Actions artifact with `upload-assets: false`. A separate job
verifies each archive against that bundle, then applies the exact authenticated
builder/source/caller policy. Only a passing bundle is attached to the release.
Attachment preserves draft status and never overwrites an existing asset. Raw
verification output and the original bundle are retained on success or refusal.

### Verification

Use Python 3.11 or newer, cosign `v2.4.1`, and the verifier script from the reviewed
release source. Establish the intended tag, commit and Release Binaries run ID
and attempt from the reviewed release and Actions run. Do not derive those
expected values from an unverified statement. For a downloaded archive:

```sh
python3 scripts/verify-release-provenance.py verify \
  --repository "$REPO" --tag "$TAG" --source-sha "$SOURCE" \
  --run-id "$RELEASE_RUN_ID" --run-attempt "$RELEASE_RUN_ATTEMPT" \
  --bundle "$CANDIDATE_ROOT/assets/chio-${SOURCE}.intoto.jsonl" \
  --evidence "$CANDIDATE_ROOT/provenance-verification" \
  "$CANDIDATE_ROOT/assets/chio-${TAG#v}-aarch64-apple-darwin.tar.gz"
```

The evidence directory must be fresh. Additional archive paths verify additional
platforms in the same invocation. `verification.json` lists the archives actually
verified separately from the full authenticated subject list; a consumer's
single-platform check supplies no runtime qualification for the other platforms.

The script first runs the official `cosign verify-blob-attestation` new-bundle
path using the public Sigstore trusted root, certificate chain, SCT and Rekor
verification. It requires the literal SHA-pinned builder certificate identity,
GitHub OIDC issuer, repository, source commit and tag ref, and authenticates the
actual archive bytes. Only then does it enforce the signed SLSA statement's five
subjects, exact builder ID, build type, source/material commit, original
`release-binaries.yml` entry point, event, run ID and attempt. It records the
verified statement and a passing report only after every check succeeds. See the
[pinned cryptographic verifier](https://github.com/sigstore/cosign/blob/v2.4.1/cmd/cosign/cli/verify/verify_bundle.go)
and the [release policy implementation](../../scripts/verify-release-provenance.py).

Stock `slsa-verifier v2.7.1` requires a SemVer-tagged upstream builder identity,
even with an explicit `--builder-id`; it cannot accept this immutable workflow
SHA. The supported recipe above uses cosign's standard bundle verification and an
explicit trusted SHA policy. Do not use testing flags, skip transparency or
certificate checks, switch to a mutable builder tag, or edit signed statements
to make a verification command pass. The restriction is implemented in the
[pinned stock verifier](https://github.com/slsa-framework/slsa-verifier/blob/v2.7.1/verifiers/internal/gha/builder.go).

### Pinning policy

The upstream workflow SHA, authenticated builder ID and cosign version are part
of the reviewed release contract. Upgrades require reviewing the producer and
verifier together, updating their pins and adversarial controls, and obtaining a
new hosted positive against the exact candidate archives. The upstream public
signed fixture confirms bundle-format compatibility; it does not replace that
Chio release test.

---

## Troubleshooting

**`invalid-publisher: invalid audience in JWT`** during PyPI upload
  -> Trusted Publisher config on PyPI does not match the workflow.
  Verify the environment name, workflow filename, owner, and repo
  name match exactly.

**`403 Forbidden` from npm with provenance enabled**
  -> Org-level Trusted Publisher not configured, or the package's
  access level is `restricted`. Run `npm access ls-packages
  @chio-protocol` to verify.

**`build` job passes but `publish` does not start**
  -> The plan job set `dry_run=true`. For `workflow_dispatch`,
  uncheck the **Dry run** input. For tag pushes, `dry_run` is always
  `false`.

**Matrix leg fails with "Meta tag pins version X but package Y is at Z"**
  -> Some package's `pyproject.toml` or `package.json` was not bumped
  in step 2. Bump it, amend the release PR, delete the tag (`git tag
  -d <tag> && git push --delete origin <tag>`), and re-tag.
