# Executable SBOM gate

The real optimized CLI built without cargo-auditable produced a successful
Syft 1.18.1 scan with CycloneDX 1.6 metadata and zero inventory components.
The prior release workflow accepted its format/version fields. The repaired
gate refuses the exact same SBOM because its dependency inventory is empty.
The binary SHA256, original scanner output and both gate results are retained
in [manifest.json](manifest.json), with lossless raw payloads and checksums.

The release workflow now validates every platform before SBOM upload, staging
and signing. It compares the scanned executable SHA256 to the actual file;
requires the pinned Syft version and embedded-audit cataloger; checks the CLI
version and nonoptional core, guards, kernel and runtime package identities
against their source manifests; checks Rust package identities against the
selected lock; and rejects broken dependency references or critical packages
that are disconnected from the CLI. Failed retries remove stale reports.
The validated SBOM and report are placed inside each archive before the
existing archive signature and provenance steps, and attached to the release
as readable files. Their availability no longer depends only on expiring
Actions artifacts. Consumers can compare the separate files to those inside
the verified signed archive; the report binds SBOM and executable SHA256 values.

This is a binary inventory gate. A source-tree SBOM cannot substitute. The
[pinned Syft Rust parser](https://github.com/anchore/syft/blob/v1.18.1/syft/pkg/cataloger/rust/parse_audit_binary.go)
returns no packages when embedded audit data is absent and deliberately omits
build-only dependencies. Therefore the gate does not demand every package in
the workspace lockfile or use an arbitrary minimum package count. The
[pinned package properties](https://github.com/anchore/syft/blob/v1.18.1/syft/pkg/package.go)
and [CycloneDX conversion](https://github.com/anchore/syft/blob/v1.18.1/syft/format/common/cyclonedxhelpers/to_format_model.go)
control the cataloger and dependency-reference checks. The gate does not
independently extract the entire embedded graph to prove inventory equality.
It also does not establish native OpenSSL inventory: pinned native source,
build identity, dependency scanning and macOS linkage qualification remain
separate requirements. Rust lockfile compatibility cannot establish those.

Twelve mutation-control tests pass, including real CLI invocation with
synthetic files, source-scan substitution, changed binary, wrong version,
missing critical packages, invalid graph references, and stale report refusal.
Actionlint, existing release-assurance checks and release-input checks pass.
These are validator tests, not six-host integration acceptance.

The [actual cargo-auditable diagnostic positive](../auditable-binary-sbom/README.md)
now passes with Syft 1.51.1. The original 1.18.1 reader rejected the real
little-endian Mach-O format before examining its embedded inventory. The
follow-up records both the old refusal and qualified new scanner result.
The diagnostic binary retains Homebrew dynamic linkage; final portable
artifact and real-host qualification remain separate requirements.

Confidence: high in the reproduced empty-inventory refusal and the linked
actual scanner compatibility result. No six-host acceptance is claimed here.
