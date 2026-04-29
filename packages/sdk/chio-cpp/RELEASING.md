# Chio C++ SDK Family Release Checklist

The Chio C++ surface ships as four sibling packages under `packages/sdk/`:

| SDK              | CMake target                       | Conan ref            | vcpkg name        |
|------------------|------------------------------------|----------------------|-------------------|
| `chio-cpp`       | `ChioCpp::chio_cpp`                | `chio-cpp/0.1.0`     | `chio-cpp`        |
| `chio-cpp-kernel`| `ChioCppKernel::chio_cpp_kernel`   | `chio-cpp-kernel/0.1.0` | `chio-cpp-kernel` |
| `chio-guard-cpp` | `ChioGuardCpp::chio_guard_cpp`     | `chio-guard-cpp/0.1.0`  | `chio-guard-cpp`  |
| `chio-drogon`    | `ChioDrogon::chio_drogon`          | `chio-drogon/0.1.0`  | `chio-drogon`     |

Each SDK is independently versionable but shares the C ABI invariant boundary
defined by `crates/chio-bindings-ffi` (used by `chio-cpp`) and
`crates/chio-cpp-kernel-ffi` (used by `chio-cpp-kernel`). The stable package
boundary for every SDK is native C++17 over a C ABI invariant layer; do not
expose Rust structs, CXX bridge types, session handles, callback handles, or
async runtime state as public API.

## Per-SDK release gates

Run the gate for an SDK from the repository root:

```bash
./scripts/check-chio-cpp-release.sh
./scripts/check-chio-cpp-kernel-release.sh
./scripts/check-chio-guard-cpp-release.sh
./scripts/check-chio-drogon-release.sh
```

All four are thin wrappers around `scripts/check-sdk-release.sh`. Each gate
covers, in order:

- Per-SDK CMake configure, build, CTest, and install smoke against the
  generated `find_package(... CONFIG REQUIRED)` config.
- Conan recipe smoke (`conan create .`) when `conan` is available. Set
  `CHIO_CPP_REQUIRE_PACKAGERS=1` (auto-set on CI) to fail closed if `conan` is
  missing.
- vcpkg manifest smoke (`vcpkg install --x-manifest-root=... --dry-run`) when
  `vcpkg` is on PATH or `VCPKG_ROOT` points at a `vcpkg` binary. Without
  vcpkg, the manifest is parsed and the `name` field is verified.

## Dependency ordering

`chio-drogon` depends on `chio-cpp` at the package-manager level. The Conan
gate for `chio-drogon` first runs `conan create` on `chio-cpp` to seed the
local Conan cache before creating the `chio-drogon` package. The vcpkg dry-run
relies on the eventual private overlay registry resolving `chio-cpp` to the
sibling port; it is a no-op until that registry is wired up.

`chio-cpp-kernel` does not depend on `chio-cpp`. The published Conan port
ships the `chio-cpp-kernel-ffi` Rust crate sources alongside the C++ tree and
builds them with `cargo build -p chio-cpp-kernel-ffi` during package build.
The vcpkg port is FFI-off; FFI builds remain a from-source CMake configure
that sets `CHIO_CPP_KERNEL_ENABLE_FFI=ON` with explicit
`CHIO_CPP_KERNEL_FFI_*` paths.

`chio-guard-cpp` is header-only, has no compiled artifact, and has no third
party runtime dependencies. The published port omits the optional
`wit-bindgen` and WASI component build paths; those remain available via the
from-source CMake options.

## Private registry endpoints

### Conan: Sonatype Nexus 3 OSS on the platform-dev OKE cluster

Remote URL: `https://nexus.dev.backbay.io/repository/chio-conan/`

Add the remote and authenticate as the publisher service account (token lives
in OCI Vault at `chio-registry/chio-publisher`, property `token`):

```bash
conan remote add chio-private https://nexus.dev.backbay.io/repository/chio-conan/
conan remote login chio-private chio-publisher --password-stdin <<< "${CHIO_NEXUS_PUBLISHER_TOKEN}"
```

Tag-driven publishes are wired through `.github/workflows/release-cpp.yml` and
do not require operator action. Manual publishes (e.g. one-off republish):

```bash
conan upload chio-cpp/0.1.0 -r=chio-private --confirm
conan upload chio-cpp-kernel/0.1.0 -r=chio-private --confirm
conan upload chio-guard-cpp/0.1.0 -r=chio-private --confirm
conan upload chio-drogon/0.1.0 -r=chio-private --confirm
```

### vcpkg: overlay registry plus OCI Object Storage binary cache

The four SDKs are exposed to vcpkg consumers through a separate private git
repo, `backbay-labs/chio-vcpkg-registry`, which holds one `ports/<sdk>/` tree
per SDK and a `versions/` index. Port file sources live in this repo under
`tools/vcpkg-overlay/`; the release CI mirrors them to the registry repo on
tag push.

Consumers point vcpkg at both upstream and the chio overlay through a
`vcpkg-configuration.json` checked into their project root:

```json
{
  "default-registry": {
    "kind": "git",
    "repository": "https://github.com/microsoft/vcpkg",
    "baseline": "<vcpkg-baseline-sha>"
  },
  "registries": [
    {
      "kind": "git",
      "repository": "https://github.com/backbay-labs/chio-vcpkg-registry",
      "baseline": "<chio-overlay-sha>",
      "packages": ["chio-cpp", "chio-cpp-kernel", "chio-guard-cpp", "chio-drogon"]
    }
  ]
}
```

The binary cache lives in OCI Object Storage; consumers point vcpkg at it via
the `x-aws` provider against the OCI S3-compatible endpoint:

```bash
export VCPKG_BINARY_SOURCES="clear;x-aws,s3://chio-vcpkg-cache/cache,readwrite"
export AWS_ENDPOINT_URL_S3="https://<namespace>.compat.objectstorage.us-ashburn-1.oraclecloud.com"
export AWS_DEFAULT_REGION="us-ashburn-1"
export AWS_ACCESS_KEY_ID="<from terraform output: chio_vcpkg_cache_access_key_id>"
export AWS_SECRET_ACCESS_KEY="<from terraform output: chio_vcpkg_cache_secret_access_key>"
```

The full endpoint string and bucket name come from the platform terraform
outputs `chio_vcpkg_cache_endpoint` and `chio_vcpkg_cache_vcpkg_binary_sources`
in `infra/terraform/envs/dev/us-ashburn-1/platform-dev/cluster/`.

### Operator one-time setup

Before the first release the platform team must:

- Seed `chio-registry/nexus-admin` (property `admin-password`) and
  `chio-registry/chio-publisher` (property `token`) in OCI Vault. The
  `nexus-bootstrap-job` consumes both via ExternalSecrets.
- Provision the `backbay-labs/chio-vcpkg-registry` private GitHub repo and
  add the deploy key whose private half is stored as the GitHub Actions
  secret `CHIO_VCPKG_REGISTRY_DEPLOY_KEY` on this repo.
- Confirm the platform-dev cluster has merged the GitOps PR that ships
  `infra/gitops/apps/platform/nexus.yaml` and friends.
