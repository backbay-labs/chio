# Kernel release readiness, 2026-09-09

Status: **not release-qualified**. This record is independent of the per-host I01-I08 records. It does not accept any host, certify a public release, or replace the full workspace and hosted release gates. Confidence is high in the executed results and artifact identities; the cause of the intermittent TypeScript test failure remains unknown.

## Exact identities and scope

- Tested runtime source: `d8c5f53705173e614a853bad6c0a85acfdf1212b`.
- Retained native debug binary: `/tmp/chio-tool-error-ack-candidate-20260909/chio-33dd1dea21a4`.
- Rechecked SHA256: `33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`.
- Metadata/test-organization repair: `abfd3b56111e2838ae648a4a82c5059eda16e210`, cherry-picked into root as `d802701ab582c5bfaccd007311377a053cda765a`.
- SDK release-driver repair: `10d347df9d6b717af8e22a79202dd1723c680c8b`, cherry-picked into root as `aed14bf728f463f82bbb68babd4004d29491b0f6`.
- Root assembled publication: `aed14bf728f463f82bbb68babd4004d29491b0f6`, incorporating the repairs by cherry-pick. The original runtime d8 is an ancestor. Origin PR 1156 and its SHA-identical Chio topic ref were reported live by the root worker; required CI run 34434603153 had started, with no success inferred. The root worker owns subsequent hosted status.
- No production kernel source, selected runtime artifact, or dependency lockfile change was adopted in this lane. The metadata commit moves existing tests, adds the SQLite file-identity crate to the review slice, and refreshes the existing governed-intent schema digest and manifest self-digest. It does not change schema content or increase file-size caps.

The audit used its own worktrees and temporary package consumers. It made no remote mutation, published no package, and did not touch any existing runtime owner. Environment and exact command/timestamp/exit records are retained under raw/. Native Node is 26.7.0; the hosted workflow specifies Node 22, so native results do not assert that hosted environment passed.

## Executed results

| Gate | Observed result |
| --- | --- |
| Full `qualify-release.sh`, exact original runtime source | Failed review-slice classification for the new SQLite file-identity crate before reaching full builds/tests. |
| Initial independent mandatory checks | 25 of 28 commands passed. Failures: cargo-deny advisories, Rust file hygiene, schema registry. Review-slice failure was recorded separately by the full script. |
| Repaired review slices, file hygiene, schema registry and formatting | Passed. Existing limits remain intact. |
| Core-types and MCP-edge complete library suites | 402 and 112 tests passed; zero failed/ignored. The moved governed-intent and nonce-identity tests ran. |
| Full qualifier on clean metadata-only source | Reached Lean/mathlib compilation; gracefully interrupted with status 130 after excessive shared-machine load. The run is incomplete. Cached proofs and logs are retained. |
| Policy analyzer on immutable selected binary | Passed. |
| Go SDK release driver | Passed test/vet/build/install and independent consumer build. |
| Python SDK release driver | Passed ordinary and generated SDK wheel/sdist validation and consumer installation smokes. |
| Original TypeScript release driver | Returned zero after a Bash 3.2 empty-array nounset error, before the first consumer installation. This is a demonstrated false success and is rejected. |
| Repaired release-driver behavioral regression | Passed positive packed dependency-closure consumers, preserves consumer failure status 37, rejects nounset failure; the same regression rejects the old driver. |
| Full repaired TypeScript driver | Correctly returned 1 on a node-http verifier error-classification assertion. This full lane remains unresolved. |
| Focused node-http diagnosis after owned Lean interruption | The exact failing case passed five runs; all 73 package tests then passed with the same Vitest 3.2.6/Vite 7.3.5. The disposable copy added only an assertion diagnostic message. No repository runtime source was changed. The original failure remains retained and its cause is not attributed to resource pressure or timeout without proof. |
| Final selected lockfile | cargo-vet and duplicate inventory pass; cargo-deny remains blocked by yanked der 0.8.0. |

The release-driver fix checks completion before allowing exit status zero because Bash 3.2 can report zero to an EXIT trap after nounset. It also avoids expanding an empty dependency array on that shell. No required package or verification step was removed.

## Dependency blocker and selected-runtime boundary

The workspace selects yanked `der 0.8.0` through the optional Iroh / Ed25519 3 / PKCS8 0.11 / SPKI 0.8 graph. The upstream changelog identifies a minimal-version CI reason for that yank; the gate failure is not represented as a RustSec CVE.

The minimal `0.8.1` candidate cleared the yank check but failed cargo-vet for the new unaudited version. Full published-source review identified its nested trailing-data regression, confirmed by upstream fix PR 2401. Compatible non-yanked `0.8.2` fixes that regression, but its new `SetOfRef` still suppresses typed element errors. A compiled probe of the checksum-verified published 0.8.2 source demonstrates that SET OF containing NULL is accepted as `SetOfRef<u8>`, reports len 1, iterates zero items, and re-encodes as an empty set; a valid INTEGER control round-trips correctly.

No `SetOfRef` use was found in Chio or the inspected parent crates, and no Chio authentication bypass was demonstrated. The optional Iroh peer-key parser does use DER, so the dependency cannot be dismissed from the full workspace gate. Neither candidate received a generic safe-to-deploy certification, waiver, or vendor patch. The 0.8.1 proposal is retained as an explicitly unaccepted patch; Cargo.lock was restored byte-for-byte.

Complete default CLI normal/build dependency graphs before and after the proposed lock update are byte-identical on all five release targets. They omit Iroh and der 0.8; the CLI manifest makes Iroh default-off, and the release build workflow enables no extra feature. This supports the unchanged selected-runtime dependency boundary. It does not pass the full workspace release gate or constitute a new binary build.

See [supplier review](raw/der-review/REVIEW.md), [executed probe](raw/der-review/EXECUTED-PROBE.md), and [graph comparisons](raw/dependency-impact/results.json). Published archive checksums, metadata, complete deltas and source manifests are retained. Downloaded upstream archives/source and disposable build outputs remain under `/tmp/chio-kernel-release-audit-20260909/der-review`; they are not represented as accepted repository dependencies.

## Hosted handoff and mirror identity

The read-only hosted snapshot in raw/hosted predates the root worker's subsequent source-ref publication. At the snapshot time, exact d8 source was absent from both remotes and had zero hosted candidate runs; Chio Actions was disabled. These are timestamped observations, not claims about repository state after later publication. The root worker owns updated PR/ref/check status.

Run `.github/workflows/release-qualification.yml` on the exact assembled candidate in its supported Ubuntu environment. Preserve the pinned Aeneas/Charon release, Creusot revision, Kani version, Lean toolchain, Java/Apalache, Node 22/Bun 1.3.3, Python 3.12, Go 1.23, PostgreSQL 16.6 roles, portable/WASM/Android tools, real Linux sandbox probe, all workspace lint/build/test gates, repeated conformance, coverage threshold, and exact-source signed artifact-manifest verification. Native targeted successes do not substitute for this lane. The local interrupted Lean run does not establish proof success or failure; the checked-in authenticated Aeneas artifacts are Linux executables.

Required hosted CI contexts on Arc are build/lint/test, MSRV build/test, cargo-vet, and cargo-deny. Preserve any applicable security-contract evidence and trusted configuration. New release identity, five-platform release builds, checksums, signatures, SBOMs, successful provenance, and public installation verification remain required. The current workspace version still says 0.1.0; the debug candidate must not be confused with the original public CLI.

Preserve SHA-identical Git objects when copying Arc source refs to Chio. The historical v0.1.0 tag objects are identical and the 11 Chio asset API digests match Arc, but repository-bound check runs and attestations do not transfer to another repository merely by copying bytes. The release-binaries publication job only depends on its build matrix; it does not require successful full qualification/security first, and SLSA follows afterward. An upload is therefore insufficient release acceptance.

## Evidence and reproduction

Raw commands, timestamps, results, logs, rejected candidate patch, supplier diffs, hosted API snapshot and diagnostic-only test change are retained under raw/. SHA256SUMS.json covers this record's files. The normal source repairs are separate commits; this evidence commit changes no runtime behavior. Required gates not executed to completion remain unresolved, including the full repaired TypeScript lane and full exact-candidate Linux qualification. No evidence from another host or an older public release is promoted into acceptance here.

## Raw evidence storage

Selected terminal logs and nested patches are retained as lossless `.gz` files.
Use `gzip -dc FILE.gz` to read their original bytes. The
[encoding map](../raw-evidence-encoding-20260910/manifest.json) records original
Git blobs and both compressed/decompressed hashes; current checksums refer to
stored files. Historical paths inside raw metadata map to those original bytes.
The unchanged repository whitespace gate applies to all authored text.
