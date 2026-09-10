# Source inventory comparison and authenticated archive rescans

Two actual Syft 1.51.1 source scans now produce the same 10,771-component
inventory after removing only the generated `serialNumber` and
`metadata.timestamp` fields. Both original raw JSON documents are retained,
and the comparison report binds their individual SHA256 values and the
normalized document hash. Package identities, JSON value types, hashes,
graphs, list order and all other metadata must match. A changed component
cannot be normalized out of the comparison.

The initial actual pair had 8,618 and 8,619 components. The differing
`concat-map@0.0.1` entry comes from the example Bun lockfile. Syft's
[pinned Bun parser](https://github.com/anchore/syft/blob/v1.51.1/syft/pkg/cataloger/javascript/parse_bun_lock.go)
classifies development-only dependencies with a graph keyed by package name,
so the two `brace-expansion` versions can overwrite each other in map iteration
order. The supported `javascript.include-dev-dependencies: true` setting
preserves all parsed entries and expands the source inventory. No lockfile
or package is excluded. The old unequal pair is refused by the final comparison
gate. The same actual auditable diagnostic binary also passes the unchanged
Rust inventory requirements with the updated configuration.

The SBOM workflow retains its verifier checkout and creates a detached release
source worktree. It checks a pushed or completed-build tag against the event's
commit before use. Archive rescanning additionally checks the actual selected
source HEAD and clean inputs, then requires all five expected platform archives.
Cosign verification pins the exact release-binaries workflow, tag, repository,
source commit and GitHub OIDC issuer before an archive parser runs. Signature
or certificate failure stops processing. Verification uses the standard
transparency and certificate checks without bypass flags.

The extractor validates member paths, duplicate names and regular-file types,
then streams only the expected executable into a fresh private location.
It never extracts the whole archive. Syft scans that executable and the existing
binary validator checks its hash, exact source-compatible CLI and kernel
identities, cataloger provenance and dependency graph. Successful reports bind
archive, signature, certificate, executable, SBOM and selected-source identities.
SLSA, native-library qualification and real-host acceptance remain separate gates.

Failures retain raw source scans, comparison/scanner/verifier logs and available
signing material. A signature refusal also retains the exact refused archive
bytes. The always-run evidence artifact is not an acceptance signal; a failed
step prevents SBOM signing and there is no passing aggregate rescan record.

Thirteen control methods pass with zero skips, including refusal before parsing
on a signature failure, mismatched or dirty source, dangerous archive members,
changed verified bytes, JSON type coercion, lost inventory and stale comparison
reports. The binary validator's thirteen methods, actionlint, existing release
assurance and release-input checks also pass. These are helper and workflow
controls, not real cryptographic verification fixtures.

The public v0.1.0 release currently has no archive signature/certificate assets.
An actual authenticated five-archive positive remains required against the new
hosted signed candidate; it has not been replaced with a synthetic claim.
[manifest.json](manifest.json) records this open requirement, raw evidence hashes,
working-source identity and executed results. No host acceptance closes here.

Confidence: high in the actual source comparison and diagnostic binary results.
The new hosted archive rescan remains unexecuted until its signed inputs exist.
