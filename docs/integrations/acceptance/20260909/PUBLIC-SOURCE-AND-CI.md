# Public source and hosted CI checkpoint

Status: **source review and qualification in progress; 0/6 hosts accepted**.
This checkpoint records source publication, source CI and released-test-process
cleanup. It promotes no archive, npm package, release tag or public kernel.
Confidence is high in the captured identities and command results; pending or
failed hosted checks remain unresolved.

## Current static-candidate source snapshot, 2026-09-10

The [current source checkpoint](../static-public-source-ci-20260910/README.md)
supersedes the earlier head/check table below. All seven standalone plugin,
bridge and harness draft PRs have successful source checks on their recorded
latest heads, including native OpenClaw `ec4267779ff180b2a58cfc5d2f86c36197a99fb9`.
Actual workflow checkout identities and source-tree comparisons are retained
separately from topic heads and frozen runtime archives.

The snapshot's Linux jobs each skip one platform-specific Claude/Cursor test.
Those skip outcomes remain unchanged. Later local macOS records execute the
exact applicable tests: [Claude supervisor](https://github.com/backbay-labs/chio-claude-code-plugin/blob/c84da4a446c57b287777124b916110f8ba15f13e/acceptance/2026-09-10/supervisor-platform-qualification/README.md)
passes one test with zero skips; [Cursor process boundary](https://github.com/backbay-labs/chio-cursor-plugin/blob/2549e53255160273d890ed6992eb8ab98a2cb6c9/evidence/final/macos-boundary-20260910/README.md)
passes three with zero skips. Both records bind tested module bytes to the selected
archives. They are component observations, not another real-host matrix or proof
of Cursor's unresolved server boundary. Their evidence-only commits postdate the
source snapshot and require their own reported hosted status.

Canonical [Chio draft PR 2](https://github.com/backbay-labs/chio/pull/2) remains at
`bafa02b06de93553cecb6f60b340f3dd8fd9b401` while its hosted workspace/MSRV checks
complete. At the captured checkpoint, 87 checks succeeded, 11 were skipped by
their workflow conditions and two remained in progress. Those skipped contexts
are not promoted to required-test passes. Later local source/evidence commits
are not yet qualified by this older source run. Chio Actions is enabled; the
earlier disabled-Actions statement below is historical.

The final consolidated source still requires its own applicable checks, followed
by the exact canonical-main release qualifier, release artifact/provenance checks
and compatible public delivery. No green plugin source check accepts a host or
transfers an older kernel result to another binary.

## Historical source checkpoint below

## Draft PRs and exact check snapshot

Initial GitHub API snapshots were captured on 2026-09-10 at 04:01:04 UTC;
follow-up snapshots at 04:07:25-30 UTC retain harness success and the newly opened
bridge PR. All seven PRs were draft and open. These are five standalone host
plugins plus the shared bridge and test harness, not accepted host integrations.
Hermes source is in the ARC PR.
The [raw snapshots](raw/publication-and-ci) retain exact timestamps, workflow names,
check URLs, status and conclusion; subsequent remote changes require a new snapshot.

| Component | Source PR | Exact head | Captured source check |
|---|---|---|---|
| Claude Code | [draft PR 1](https://github.com/backbay-labs/chio-claude-code-plugin/pull/1) | `34c7d7b1976d7bc672988c1b3ed7b26073133e79` | [source-package: SUCCESS](https://github.com/backbay-labs/chio-claude-code-plugin/actions/runs/34434143983/job/102735624251) |
| Codex | [draft PR 1](https://github.com/backbay-labs/chio-codex-plugin/pull/1) | `9e1afda3940292c314820553f48f366286bba52d` | [test: SUCCESS](https://github.com/backbay-labs/chio-codex-plugin/actions/runs/34434164364/job/102735684503) |
| Cursor | [draft PR 1](https://github.com/backbay-labs/chio-cursor-plugin/pull/1) | `1dbb2b57ab333b8528ab0481fc4cae1e45810098` | [test: SUCCESS](https://github.com/backbay-labs/chio-cursor-plugin/actions/runs/34434175295/job/102735716963) |
| OpenClaw | [draft PR 1](https://github.com/backbay-labs/chio-open-claw-plugin/pull/1) | `647c4fef2b775be84c554ecc03403e2418fb0879` | [test: SUCCESS](https://github.com/backbay-labs/chio-open-claw-plugin/actions/runs/34434447182/job/102736507159) |
| Pi | [draft PR 1](https://github.com/backbay-labs/chio-pi-plugin/pull/1) | `b24b14e9c4d69261ab39eb9507db45bc07cba96f` | [test: SUCCESS](https://github.com/backbay-labs/chio-pi-plugin/actions/runs/34435298347/job/102738991841) |
| Shared test harness | [draft PR 1](https://github.com/backbay-labs/chio-test-harness/pull/1) | `98a0f5e33d63ded80cf36434c448b7ec45c3b413` | [self-test: SUCCESS](https://github.com/backbay-labs/chio-test-harness/actions/runs/34435362383/job/102739187548) |
| Shared bridge | [draft PR 1](https://github.com/backbay-labs/chio-bridge/pull/1) | `e3a9ab685f901c4fa54f31551ff7484a47e673d4` | [test: SUCCESS](https://github.com/backbay-labs/chio-bridge/actions/runs/34435801997/job/102740489703) |

The checks above exercise their repository source/package contracts. They do not
rerun the retained real-host I01-I08 matrices, confer Cursor enforcement, or
qualify the unchanged kernel and plugin archives for public release.

## Actual tested source trees

These pull-request workflows check out `github.sha`, which is a synthetic merge,
not the topic head. The completed job logs record the actual checkout below.
GitHub Git-object reads confirm each tested repository tree equals its topic
head tree. The exact merge object is retained separately; commit identities are
not treated as interchangeable merely because their trees match.

| Component | Actual successful job checkout | Tree equal to recorded head |
|---|---|---|
| Claude Code | `47493b0777ca7ae19d7be4df943073f4f4a437a5` | `2dd446355c9d86176f01bb255684bc8ed9944e85` |
| Codex | `bc158a970c6cc188df2dfa922ba25723780fcb59` | `ae49887a0763accfb833bd4762a1f8a6d17f433b` |
| Cursor | `8818160c1ca52d036dd3172a07c5fa843f17f124` | `fbcff80350c3e7cd5f0741100c3b52339d265f48` |
| OpenClaw | `127ea1ef93a45c9b480b192aada57219729312f4` | `45fffa4caec7f74a4e3c1c1090b80065bd1b6d1a` |
| Pi | `74fd0e9689a37e93248e373ef133070ce1159c65` | `ac54d3c51cdfada1bb7cafe7817ff5f5095f6930` |
| Shared test harness | `51c0284d9724d658e4ffb793cba6b40e2ffe2398` | `5a0601c5cda1442eb909a3c4dde6e440c5fc8eb1` |

Each `*-source-tree-binding.json` and losslessly compressed `*-source-check.log.gz`
under [raw/publication-and-ci](raw/publication-and-ci) binds the evidence to the
run and exact checked-out source. The harness also checked out kernel
`d8c5f53705173e614a853bad6c0a85acfdf1212b` from ARC in a separate step; this is
not the harness repository tree and not a full kernel release qualification.
The bridge subsequently passed 144 component and 16 real-kernel API tests. Its actual job checkout `75d598ef43ed685480fb65961cbf63f3816b36b1` has tree `f0b0de932029b576c811604587a9d9a5a63eb7ea`, equal to the recorded head. The later bridge-success records retain this completed result; the initial pending snapshot remains historical.

## Pi hosted failure, isolated fix and passing rerun

[Run 34434474791](https://github.com/backbay-labs/chio-pi-plugin/actions/runs/34434474791)
failed at `82aa3dd9b8126941c7fa3ea800bcb26a2cb1684c`: four scripted stock-host
contract tests reached Pi's pre-stream auth check without a provider credential
and reported `No API key found for openai`. This was a fixture dependency on
ambient auth, not evidence that a live host/kernel workflow passed or failed.
The [original failed log](raw/publication-and-ci/pi-first-hosted-ci-failure.log.gz)
is retained with a lossless gzip envelope and original-byte SHA256.

Test-only commit `b24b14e9c4d69261ab39eb9507db45bc07cba96f` gives ModelRuntime's
AuthStorage a mode-0600 dummy auth file inside the isolated fixture profile.
Fetch and socket-connect guards reject and count any network attempt, including
errors swallowed upstream. The [exact patch](raw/publication-and-ci/pi-fixture-auth-fix.patch.gz)
changes only `test/host-contract.test.mjs`. Typecheck and all 23 tests passed with
zero skips using an empty home/profile and an allowlisted environment containing
no provider auth variables. [Local result](raw/publication-and-ci/pi-isolated-local-result.json)
and compressed stdout/stderr remain separate from hosted evidence.

[Run 34435298347](https://github.com/backbay-labs/chio-pi-plugin/actions/runs/34435298347)
then passed all 23 tests using synthetic merge `74fd0e9689a37e93248e373ef133070ce1159c65`,
whose tree equals the exact fixed head. Its
[run metadata](raw/publication-and-ci/pi-fixed-success-run.json) and
[complete log](raw/publication-and-ci/pi-fixed-hosted-ci-success.log.gz) are retained.
Pi's frozen runtime source `2ccc027b42b837f3df2889863273df2c1e2d5669` and archive
`ec6095390b9eae233540b73aee0ad2fef6977c36122dd30aa2779329b1897aa1`
are unchanged. New source CI is not a repack or a new real-host acceptance claim.

## Root publication, mirrors and independent release gates

The [publication commands](raw/publication-and-ci/source-publication.json) pushed
SHA-identical source `aed14bf728f463f82bbb68babd4004d29491b0f6` to the ARC and Chio
topic refs and opened [ARC draft PR 1156](https://github.com/bb-connor/arc/pull/1156).
The [LFS mirror record](raw/publication-and-ci/lfs-mirror-verification.json) verifies
the same two Swift static-library objects in both repositories by SHA256 and size.
It retains no credentials or signed download URLs. Git/LFS byte identity does not
transfer repository-bound checks or attestations.

The [ARC check snapshot](raw/publication-and-ci/root-pr.json) at 04:01 UTC contains
failed `cargo-audit and osv-scanner` and `Cognition market PostgreSQL isolation`
checks, as well as unfinished required and other checks. Root workers own their
failure diagnosis and subsequent status. The separate full
[release-qualification run 34435441587](https://github.com/bb-connor/arc/actions/runs/34435441587)
was created by workflow dispatch at 03:59:57 UTC against exact `aed14bf728f`;
its [initial record](raw/publication-and-ci/root-release-run-start.json) says queued.
No success is inferred. Chio Actions remains disabled at this checkpoint.

The [kernel release-readiness report](../kernel-release-readiness-20260909/README.md)
records the full local qualifier's incomplete run, repaired metadata/driver
checks, unresolved full TypeScript lane and yanked `der 0.8.0` workspace gate.
Neither proposed DER dependency update was accepted as a safe release repair.
These release failures are separate from the five hosts' immutable kernel
`33dd1dea21a4` observations. All applicable release/security gates remain required.

## Released owner shutdown and retention

The byte-exact [shutdown record](raw/publication-and-ci/storage-owner-shutdown.json)
has SHA256 `ba54f23277ea582ecf5a95669d6da0f12cc44eb579850c89da82254e8c928718`.
It identifies 15 live kernels stopped by `serve-filesystem.py stop` on ports
58512-58526 and three already-stopped rejected Claude setup owners. Every live
PID matched its exact configured command, binary hash, database paths and owned
listener before signaling. No other process was signaled.

Logical contents of all four SQLite databases per owner matched before/after;
configuration/journal hashes matched and all 36 resource/audit volumes remained.
Unknown fences and private state were retained. Healthy listeners 58492, 58493,
58494, 58503, 58618 and 58396 kept their original PIDs. Released ports were empty
and no shutdown failed. No credentials, private profiles, databases or volumes
were copied into this acceptance directory. The shutdown record was compared
against 36 known operator credential values with no matches.

[Retention identities](raw/publication-and-ci/retention-identities.json) bind the
original source records and losslessly compressed logs to their retained bytes.
The acceptance checksums cover these records. This cleanup makes no new claim
about prevention, recovery acceptance, or public delivery.

## Candidate checksum and credential exclusions

[Bundle verification](raw/publication-and-ci/bundle-verification.json) checks all
48 selected entries plus the manifest checksum. Only README/status/review metadata
changed; all executable, image and package identities remain selected as before.
The exact root evidence exclusion scan found zero matches for 810 designated
credential values from 1,474 private sources, which are read only in memory and
never copied into evidence. The [additional bundle scan](raw/publication-and-ci/bundle-credential-exclusion.json)
also checks top-level gzip and ZIP payloads and new compressed evidence. Its
explicit scope retains the limitation that nested compressed Docker payloads are
compared as their stored bytes. These checks do not claim detection of every
possible secret format or supply-chain safety.
