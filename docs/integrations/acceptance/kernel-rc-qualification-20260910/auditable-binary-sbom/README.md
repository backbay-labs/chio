# Actual auditable binary inventory

The real cargo-auditable diagnostic CLI from source
`0599e9fa3ee337719986f6fd88466f75ba0290dd` passes the binary inventory gate
with checksum-pinned Syft 1.51.1: 742 Rust packages, 743 total components,
and 570 dependency entries. The exact CLI version and four required kernel
package identities are present and connected to the CLI. The validation report
binds the inventory to executable SHA256
`ca9b669d333a5f592d13d032b37941c06d933b6bf522372c885d77ec1d32b093`.
This is an actual executable scan, not a source lockfile substitution.

Syft 1.18.1 selected the Rust binary cataloger but reported `unknown file format`
for this executable and emitted no components. Its
[pinned reader](https://github.com/microsoft/go-rustaudit/blob/4b17361d90a5/rustaudit.go)
recognizes only the other Mach-O byte order. The actual binary starts with
`cf fa ed fe` and has a 13,294-byte `__DATA/.dep-v0` section. The
[upstream Syft reader update](https://github.com/anchore/syft/pull/3689)
first shipped in Syft 1.21.0. The qualified 1.51.1 release retains that fix.
The gate's identity, hash and graph requirements are unchanged; only the
expected scanner version changes. Both the old refusal and actual new
positive are retained losslessly in [manifest.json](manifest.json).

The same new scanner was also run against the previously frozen real binary
built without cargo-auditable. Its output is refused: it cannot supply the
required embedded Rust inventory. Thirteen validator test methods pass with
zero skips. The new scanner download and upstream checksum list are recorded;
all compressed raw records include original and stored SHA256 identities.

This source 0599 diagnostic binary still links Homebrew OpenSSL. It cannot
establish portable final delivery. The final static binary must pass the same
inventory gate and independent native linkage and real-host tests on its own
hash. Other release target platforms and hosted archive provenance remain
required. These scanner results do not close any host's I01-I08 acceptance.

Confidence: high in the reproduced old reader failure and actual new scanner
compatibility for this diagnostic aarch64 Mach-O binary.
