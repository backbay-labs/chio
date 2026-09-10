# Static release candidate: complete shared kernel qualification

The complete audited-resource rerun passed all eleven shared kernel cases,
with zero failures or skips. The real kernel binary was unchanged during the
run. This establishes the bounded shared contract for the exact combination
below. It accepts no agent host and does not establish publication, installation,
or completion of the six-host integration program.

Confidence is high in these recorded results and artifact identities. Complete
I01-I08 acceptance remains a separate requirement for each mandatory host.

## Exact tested combination

| Input | Identity |
|---|---|
| Kernel source | `bafa02b06de93553cecb6f60b340f3dd8fd9b401` |
| Kernel binary SHA-256 | `c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e` |
| Reported CLI version | `chio-cli 0.1.1-rc.1` |
| Resource image | `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0` |
| Resource audit wrapper SHA-256 | `23c83a3568a5d42af9a99e8bc837d4f17ef5b5bb18efeec4af502b5f7779c2ef` |
| Qualification runner SHA-256 | `7576929ba3f28e2115216803898e5304d7dfce274805d7e745d8d376f471d92b` |
| Response barrier SHA-256 | `a690f141d14fb3b9a18a8541e89bb5eabf76a18f71e504ad16cd2878bec398b6` |
| Environment | macOS 26.4, build 25E246; Docker client 28.3.3 |
| Rerun started | `2026-09-10T07:18:50.562706+00:00` |

The runner verified the actual image entrypoint and audit-wrapper bytes before
starting the kernel. It created isolated state, credentials, ports, and resource
volumes for each case. The manifest and raw observations retain their exact
policy and resource identities. The response barrier holds a real resource
reply at the designated cutpoint; it does not fabricate a resource result.

## All eleven cases

| Case | Rerun status | Independently recorded resource dispatches |
|---|---|---:|
| `authority-replay` | Passed | 2 |
| `capability-expiration` | Passed | 1 |
| `unknown-after-dispatch` | Passed | 1 |
| `cancellation-after-dispatch` | Passed | 1 |
| `approval-artifact-rejection` | Passed | 1 |
| `approval-workflow` | Passed | 1 |
| `bounded-approval-workflow` | Passed | 1 |
| `approved-grant-budget` | Passed | 2 |
| `approved-unknown-after-dispatch` | Passed | 1 |
| `grant-budget` | Passed | 3 |
| `parallel-grant-budget` | Passed | 2 |

These counts are observations, not a replacement for each case's assertions.
The archived runner and raw evidence retain exact requests, outcomes, file
observations, restart cutpoints, and independent sentinels. The case meanings
and known limits are specified in the
[shared qualification instructions](../../../../integrations/required-agents/qualification/README.md).

The budget case deliberately issues fresh authority through the trusted
operator after exhausting the original grant. Its third dispatch demonstrates
that a new session receives a new quota. The session admission credential must
remain outside the untrusted host. Unknown-outcome cases deliberately observe
an original committed effect before interruption and require subsequent replay
to preserve the unknown outcome without dispatching the operation again.

## Original failed run remains failed

The original run began at `2026-09-10T07:00:50.583322+00:00` with the same
kernel binary. A mutable local resource tag selected the old unaudited image
`sha256:0106edcb15a1c0d12d914ea0504f0e63ec85f5e6fdd3825b4d7a0d1367af3991`.
All eleven resource dispatch logs were empty. The bounded approval and approved
budget cases failed their exact dispatch assertions and made the aggregate run
fail. The earlier driver incorrectly left their manifest statuses as `passed`
alongside `cleanupError`; those original bytes are preserved, not corrected.

The other nine cases retain their bounded file and response observations, but
do not qualify the intended audited-image combination. Their original statuses
were not transferred to the successful rerun. Every case ran again through the
real kernel with the repaired observer-selection/reporting driver. The
[preceding investigation](../static-approval-dispatch-20260910/README.md) retains
the image comparison, original-volume reinspection, intermediate initialization
timeout, two-case reproductions, and the narrow runner repair.

## Reproduce and verify

With the exact binary and resource image available, run all cases serially by
omitting `--cases`:

```sh
python3 integrations/required-agents/qualification/shared_kernel.py \
  --binary /absolute/path/to/chio-c03a8a711dbb \
  --source-revision bafa02b06de93553cecb6f60b340f3dd8fd9b401 \
  --image sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0 \
  --output /tmp/chio-static-shared-qualification-UNIQUE
```

`raw/original-unaudited-failure/` contains all 54 public files from the original
eleven-case run. `raw/qualified-audited-rerun/` contains all 55 public files from
the successful eleven-case run. The exact drivers, policies, kernel logs, raw
MCP/HTTP evidence, resource dispatch logs, held replies, and empty release
markers are exported losslessly. Each case's private database directory and
signer seeds remain private and were not exported.

`files.json` binds each gzip export to its original bytes, SHA-256, length, and
local source path. `runs.json` summarizes the manifests and dispatch logs while
preserving the distinction between original source statuses and failed cases.
`normalizedAggregateExitCode` applies the archived driver's failure conditions
to its complete manifest; it is not a new process execution.
`SHA256SUMS` covers the committed record. The validation record includes exact
export verification, credential exclusion, and the unchanged release-copy gate.

This evidence-export task did not run Docker or the kernel again.
