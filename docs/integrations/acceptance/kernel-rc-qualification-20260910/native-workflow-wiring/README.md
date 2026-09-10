# Native release workflow wiring

The macOS matrix now builds checksum-pinned static OpenSSL with the reviewed
preparation script, imports its target-specific build environment before Cargo,
and requires the real loader/linkage gate before inventory generation, archive
staging or signing. The native manifest, linkage report and actual OpenSSL
license text are included inside each signed archive and attached as readable
release files. The other release targets retain their own build paths.

[The command record](manifest.json) identifies the actual preparation/linkage
implementation and unchanged raw unit output: 13 binary-inventory/wiring tests
and seven portability tests pass with zero skips. Actionlint and existing
release-assurance checks pass. These verify code/wiring; they do not substitute
for the static native build, independent native vulnerability scan, actual
portable CLI linkage/startup or the final artifact's six-host acceptance.

The native manifest remains source/build identity evidence. It is not labeled
as scanner output or a Cargo-vet audit. Native OpenSSL scan results remain
unresolved and must be recorded separately before final release qualification.
