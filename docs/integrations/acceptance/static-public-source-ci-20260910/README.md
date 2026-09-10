# Public source CI checkpoint for the static candidate program

This record establishes public draft source availability and the exact source
checked by completed hosted jobs. It does not accept an agent host, promote the
local static bundle, publish a release, or close I01/I08 public installation.
Confidence is high in the captured API identities, raw logs and tree comparisons.
All six integrations remain mandatory under document 19.

The initial 08:11 UTC checkpoint is preserved byte-for-byte under
`raw/initial/`. The later PR snapshots below were captured from
`2026-09-10T08:14:10.804145+00:00` through
`2026-09-10T08:14:11.415064+00:00`. All eight PRs were open drafts. The
OpenClaw head advanced from the initial `647c4fef` snapshot to `ec426777`;
its new completed result is recorded separately, without rewriting the earlier
snapshot. Later remote changes require a new record.

| Component | Source PR | Exact captured head | Captured check rollup |
|---|---|---|---|
| Claude Code | [draft PR 1](https://github.com/backbay-labs/chio-claude-code-plugin/pull/1) | `00a0ad130cf13fbe434ab08616fe2f2483187c77` | 1 success |
| Codex | [draft PR 1](https://github.com/backbay-labs/chio-codex-plugin/pull/1) | `97a1d98414004a04f41f607cfbe74663e381499a` | 1 success |
| Cursor | [draft PR 1](https://github.com/backbay-labs/chio-cursor-plugin/pull/1) | `16c213afec93d63aeea7112681084f4336f3766a` | 1 success |
| OpenClaw | [draft PR 1](https://github.com/backbay-labs/chio-open-claw-plugin/pull/1) | `ec4267779ff180b2a58cfc5d2f86c36197a99fb9` | 1 success |
| Pi | [draft PR 1](https://github.com/backbay-labs/chio-pi-plugin/pull/1) | `cee55d79bf159e51fa7f70b986a8d8f5979a4f3f` | 1 success |
| Shared harness | [draft PR 1](https://github.com/backbay-labs/chio-test-harness/pull/1) | `6d49d48c478967e518c052c628e59a7183ff9814` | 2 success |
| Shared bridge | [draft PR 1](https://github.com/backbay-labs/chio-bridge/pull/1) | `e3a9ab685f901c4fa54f31551ff7484a47e673d4` | 1 success |
| Chio kernel and Hermes source | [draft PR 2](https://github.com/backbay-labs/chio/pull/2) | `bafa02b06de93553cecb6f60b340f3dd8fd9b401` | 2 in progress, 11 skipped, 87 success |

The Chio PR remains at source `bafa02b06de93553cecb6f60b340f3dd8fd9b401`.
Its `Build, lint, test` and `MSRV build and test` jobs are still in progress in
this snapshot. Eleven skipped jobs remain explicitly listed in `summary.json`
and the raw API response. Neither running nor skipped jobs are treated as
successful checks. This PR does not contain the program's later local evidence
commits merely because they exist in an owning worktree. No claim here says the
final program source head or complete root CI has passed.

## Actual successful checkout identities

The seven standalone repositories have eight completed successful jobs. Their
workflow runs name the exact recorded topic heads, while the job logs identify
actual synthetic merge checkouts. GitHub Git-object responses prove each first
job checkout's complete tree equals its topic head's tree and the topic head is
a merge parent. Commit identities remain distinct. Both harness jobs are bound
separately. The full responses, exact log line contexts and every additional
checkout are retained in `raw/current/` and `summary.json`.

| Component and job | Captured result | Actual job checkout | Tree equal to recorded topic head |
|---|---|---|---|
| Claude Code / source-package | [SUCCESS](https://github.com/backbay-labs/chio-claude-code-plugin/actions/runs/34450420952/job/102784660550) | `102ff834b9309b4e9254b270bdb00e15b97452ce` | `30c659f1c3f4a9adbe5e3a47602e4564401672a4` |
| Codex / test | [SUCCESS](https://github.com/backbay-labs/chio-codex-plugin/actions/runs/34452257763/job/102790439048) | `850d69c99811834a4aff7d157ea9b26b7344b04d` | `9539eeb3aec7516542838bf4245c7fb4ec3f94b8` |
| Cursor / test | [SUCCESS](https://github.com/backbay-labs/chio-cursor-plugin/actions/runs/34447190158/job/102774457676) | `b3ab622bdeb22b1524053e56856f9837767886fa` | `14b90b8e9e7257f39f21ee635eef9da43fae2aee` |
| OpenClaw / test | [SUCCESS](https://github.com/backbay-labs/chio-open-claw-plugin/actions/runs/34453867292/job/102795584401) | `15718f8d9f98aa980e60b353d54b4e3e65ff525a` | `f984e3820e603281091a73e86c0f8c2853df6c7a` |
| Pi / test | [SUCCESS](https://github.com/backbay-labs/chio-pi-plugin/actions/runs/34450646300/job/102785368297) | `679f469ad9afdcc97503bd34b484911cc5db3cc0` | `4ba17d707bbb6c6e768f28d742133529e293bd9d` |
| Shared harness / delivery-integrity | [SUCCESS](https://github.com/backbay-labs/chio-test-harness/actions/runs/34451459259/job/102787919614) | `bff82981dee2edacd62c36a10d17c134791a6861` | `43886f00eadc653564478e6f4685fe9f1e7ff65d` |
| Shared harness / self-test | [SUCCESS](https://github.com/backbay-labs/chio-test-harness/actions/runs/34451459259/job/102787919303) | `bff82981dee2edacd62c36a10d17c134791a6861` | `43886f00eadc653564478e6f4685fe9f1e7ff65d` |
| Shared bridge / test | [SUCCESS](https://github.com/backbay-labs/chio-bridge/actions/runs/34435801997/job/102740489703) | `75d598ef43ed685480fb65961cbf63f3816b36b1` | `f0b0de932029b576c811604587a9d9a5a63eb7ea` |

Claude's source suite records 32 passed and one skipped test: `trusted host
supervisor stops its process group when the parent lifeline closes`. Cursor's
source suite records 32 passed and one skipped test: `actual macOS process
boundary blocks operator reads, aliases, links, writes and unrelated network`.
These skipped checks provide no execution evidence here. Codex records 32
passed, OpenClaw 25, and Pi 23. The harness delivery-integrity job records 13
passing integrity tests. Its separate self-test job also succeeds, but explicitly
checks out historical kernel source `d8c5f53705173e614a853bad6c0a85acfdf1212b`.

The bridge records 144 component tests and 16 real-kernel API tests. That job
checks out the same historical `d8c5f537` kernel and separate harness source
`05945ccf4f652a22801c9ab35cabf99456ef76c9`. These API and self-test results are
not evidence for the frozen static binary `c03a8a711dbbd15d...`, kernel source
`bafa02b0`, or any final real-host acceptance matrix. Successful source packaging
or clean consumer checks also do not establish that the locally selected frozen
archive was executed by CI or publicly released. Per-host exact-artifact records
remain authoritative for those independent claims.

The Codex and bridge log bytes were reused from existing exact-job captures;
source and compressed hashes identify those retained inputs. Remaining completed
job logs were retrieved read-only from their precise GitHub job IDs. OpenClaw's
existing anonymous HTTP-200 repository, PR, commit and evidence-source checks
are retained under `raw/openclaw-public/`; its exact merge/head tree binding was
also independently rechecked here. No native host, kernel, CI rerun, merge,
package publication or release operation was performed for this record.

## Evidence and unresolved delivery

`raw-files.json` binds every retained source byte stream to its lossless compressed
copy. `SHA256SUMS` covers this record. Credential exclusion scans compare both
plain files and decompressed raw files against known provider, npm, operator and
delegated credentials without exporting secret values. Raw completed logs retain
all skips and outcomes; initial snapshots and later observations stay separate.

No selected kernel/plugin/SDK package or bundle identity was modified. The actual
hosted release build, required source/release gates, public artifact downloads,
provenance verification and per-host cold installation/lifecycle tests must
still establish usable public delivery. Cursor's supported enforcement contract
and every host's acceptance status are separate program records, not conclusions
that can be inferred from these green source checks.
