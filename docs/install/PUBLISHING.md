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
| `chio-lambda-python` | `chio-lambda-python` | `sdks/lambda/chio-lambda-python` |

### TypeScript (npm)

| Slug | Distribution | Directory |
|---|---|---|
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
2. For each package (`node-http`, `express`, `fastify`, `elysia`,
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

## Supply-chain artifacts

Every binary release built by
[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml)
emits two complementary supply-chain artifacts in addition to the
`.tar.gz` / `.zip` archive and its `.sha256` sidecar.

| Artifact | Producer | Where to find it |
|---|---|---|
| Embedded `auditable` dependency graph | `cargo auditable build` (cargo-auditable v0.7.4, M09.P2.T1) | Inside the `chio` binary itself; read with `cargo audit -f <binary>`. |
| CycloneDX 1.6 JSON SBOM | `syft` v1.18.1 with [`infra/sbom/syft.yaml`](../../infra/sbom/syft.yaml) (M09.P2.T2) | GitHub Actions artifact `sbom-<target>` (90-day retention). One file per matrix leg, named `chio-<target>.cyclonedx.json`. |

Both artifacts are produced per matrix leg, so each of the five
release targets (linux x86_64 / aarch64, macOS x86_64 / aarch64,
windows x86_64) ships its own embedded graph and its own SBOM.

The release job validates the SBOM with
`jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.6"'` before
upload; a missing or malformed SBOM fails the workflow rather than
silently publishing without one.

Cosign keyless signing of every `release-binaries.yml` archive
landed in M09.P3.T3; the consumer verification recipe lives below
in [Release-binaries archive signing](#release-binaries-archive-signing).
See `.planning/trajectory/09-supply-chain-attestation.md` for the
broader attestation roadmap.

---

## Sidecar image signing

Owned by M09 (M09.P3.T2). The multi-arch sidecar OCI image built by
[`.github/workflows/sidecar-image.yml`](../../.github/workflows/sidecar-image.yml)
is keyless-signed with [Sigstore cosign](https://docs.sigstore.dev/cosign/)
immediately after the `docker/build-push-action@v6` push step. The
signature is keyed to the image's content-addressed digest, so every
tag the metadata-action emits (`vMAJOR.MINOR.PATCH`, `MAJOR.MINOR`,
short SHA, `latest` on default branch, optional `workflow_dispatch`
override) is covered by a single signature on the underlying manifest.

### How signing works

1. `sigstore/cosign-installer@v3.7.0` pins cosign at `v2.4.1` on the
   GitHub-hosted runner.
2. The workflow already runs with `permissions.id-token: write`, which
   lets `cosign sign --yes` exchange a GitHub-issued OIDC token for a
   short-lived Fulcio signing certificate. No long-lived signing key is
   held in repo secrets.
3. `cosign sign --yes ghcr.io/<owner>/chio-sidecar@sha256:<digest>`
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
documented in [`crates/chio-attest-verify/README.md`](../../crates/chio-attest-verify/README.md)
(landed in M09.P3.T1) and exposes `verify_blob`, `verify_bytes`, and
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

Owned by M09 (M09.P3.T3). Every per-target archive built by
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
documented in [`crates/chio-attest-verify/README.md`](../../crates/chio-attest-verify/README.md)
(landed in M09.P3.T1) and exposes `verify_blob`, `verify_bytes`, and
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

[`.github/workflows/slsa.yml`](../../.github/workflows/slsa.yml)
(M09.P2.T3) wires the upstream
[`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator)
reusable workflow at the pinned tag `v2.1.0` to produce a signed
[SLSA](https://slsa.dev) Level 2 provenance attestation for every
release built by `release-binaries.yml`.

### Trigger model

The provenance lane runs as a `workflow_run` listener on a successful
`Release Binaries` invocation rather than as an inline job. This keeps
the release matrix lean and confines the elevated permissions
(`id-token: write` and `contents: write`, required by the upstream
generator) to a single, auditable workflow file. A failed release
build short-circuits the listener via
`if: github.event.workflow_run.conclusion == 'success'`, so the
generator never runs against a half-built release.

### What gets attested

`collect-digests` downloads the per-target `chio-<target>` artifacts
that `release-binaries.yml` uploaded, validates the embedded
`release-metadata.json` across every matrix leg, computes one SHA-256
digest per archive (`*.tar.gz` and `*.zip`), and emits the digests as a
base64-encoded subjects list. The metadata pins the release tag,
`refs/tags/<tag>` source ref, and checked-out source commit, including
operator-dispatched rebuilds. The reusable
`generator_generic_slsa3.yml` job consumes that list and emits an
in-toto attestation named
`chio-<head_sha>.intoto.jsonl`. With `upload-assets: true` the
attestation is uploaded to the GitHub Release that the build job
already created, so the provenance ships next to the binaries it
covers.

### Verification

A consumer with `slsa-verifier` installed can verify any release
archive against its provenance:

```bash
slsa-verifier verify-artifact \
  --provenance-path chio-<head_sha>.intoto.jsonl \
  --source-uri github.com/<owner>/chio \
  --source-tag <release-tag> \
  chio-<version>-<target>.tar.gz
```

The verifier confirms the artifact digest is listed in the signed
attestation, that the attestation was produced by the pinned
`slsa-github-generator` workflow, and that the source repo and tag
match the build's claimed origin.

### Pinning policy

`slsa.yml` pins
`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`.
Bumping to a newer tag is intentionally a manual change because the
upstream workflow's identity is part of the verification chain;
unpinning to `@main` or to a commit SHA outside an audited tag would
weaken the L2 guarantees.

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
