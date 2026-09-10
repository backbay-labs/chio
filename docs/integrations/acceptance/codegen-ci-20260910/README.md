# PR 1156 codegen job triage

Confidence: high for the observed failure and local qualification. Hosted CI
has not been rerun by this worker; no remote changes were made.

## Exact failure and minimal repair

Run `34434603167`, job `102736959361`, tested commit
`aed14bf728f463f82bbb68babd4004d29491b0f6`. The job failed at
`Assert Chio-owned schemas stay v1-only before release`. Rust toolchain setup,
all code-generation lanes and generated-tree checks were skipped.

The only scanner finding was line 129 of the frozen Claude launcher snapshot
under `20260909/raw/subscription-relay-audit/sources/claude/scripts/`.
Its local launch-record format tag is audit data, not an active Chio wire or SDK
schema. That audit snapshot was added by this PR. The scanner is byte-identical
at base `f5566d9a765c21cb36652a99c79de64968a656bf`, the failed head and the repair.
No generated-code defect was demonstrated by the hosted failure.

Repair `1bbc7996b` stores that exact source in deterministic gzip with its
original logical path, original Git blob, decoded length/SHA-256 and compressed
length/SHA-256 recorded beside it. Decompression was compared byte-for-byte to
the original Git object. Original source identities remain unchanged. The v1
scanner, CI workflow, runtime source, dependency manifests and lockfiles were
not changed by this repair. No new scanner exemption was added.

## Local qualification

`make codegen-check` first passed on the failed head plus the snapshot repair.
`make spec-drift` then passed at `47c7b2007effe193170e557f167f86abde2a7553`, which
combines the failed head, snapshot repair and Codex worker's `a6b99d23f`
lossless whitespace-evidence repair (local cherry-pick `47c7b2007e`).

The combined run includes the unchanged version scan, Rust/Python/TypeScript/Go
codegen checks, four editor snippet sources and the local drift script. The
additional explicit CI path check includes generated federation and conformance
files and the generated state-machine reference: no tracked or untracked drift.
Cargo.lock and the TypeScript codegen package lock remain unchanged.

These observations ran on macOS arm64 with Rust 1.94.1, Node 25.5.0 and Go
1.26.2. The hosted workflow uses Ubuntu with Node 20 and Go 1.22. Local success
does not replace a hosted rerun on the final integrated commit. Full tool
versions, exact commands, head identity and timings are retained in JSON.

`npm ci` succeeded but reported a separate high-severity js-yaml advisory,
GHSA-2883-xcg3-v3hh. A subsequent read-only `npm audit --json` exited 1 and
confirmed that advisory; its exact output is retained. The dependency repair
was handed to the worker who owns JavaScript manifests and locks. It is not
silently counted as a passing security gate.

## Retained raw evidence

The exact hosted job log and API job/run metadata are losslessly encoded,
as are both local generation logs and the separate dependency audit. Use
`gzip -dc FILE.gz` to inspect them. `raw-encoding.json` binds decoded and stored
bytes; `SHA256SUMS` binds every retained file. No source or log was normalized
to remove the original failure, and no product or host acceptance is claimed.
