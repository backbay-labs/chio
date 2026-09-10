# Static kernel approval dispatch investigation

The two original shared qualification cases failed independent dispatch
observation because their selected filesystem image omitted the resource audit
wrapper. This investigation did not demonstrate a kernel dispatch regression.
Confidence in this cause is high: image entrypoints, original retained volumes,
and fresh real-kernel reproductions agree.

This is shared kernel evidence only. It accepts no agent host and does not
replace the complete qualification of the selected release artifacts.

## Original failure

The original run used kernel source
`bafa02b06de93553cecb6f60b340f3dd8fd9b401`, binary SHA-256
`c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`,
reporting `chio-cli 0.1.1-rc.1` on macOS 26.4, Docker 28.3.3.

Its mutable default image tag selected
`sha256:0106edcb15a1c0d12d914ea0504f0e63ec85f5e6fdd3825b4d7a0d1367af3991`.
That image directly starts the official filesystem server. It does not start
`/opt/resource/audit-tool-server.mjs`.

| Case | Expected dispatches | Original observed dispatches |
|---|---|---|
| `bounded-approval-workflow` | One `write_file` for `/workspace/valid.txt` | Empty |
| `approved-grant-budget` | `write_file`, then `read_text_file`, for `/workspace/budgeted-approved.txt` | Empty |

Both cases failed despite their earlier request/effect assertions passing.
The original driver returned aggregate exit 1, but incorrectly retained
`status: passed` alongside `cleanupError` for each failed case. Those original
bytes remain unchanged in this record and must not be consumed as passes.

All eleven original cases selected that unaudited image. The other nine retain
their bounded file and response observations, but lack resource dispatch audit
records. Their statuses cannot qualify the intended audited-image combination.
The entire original suite is retained as a failed run.

Read-only reinspection of the original retained volumes found empty audit
directories. The bounded case contained only `valid.txt` with its independent
post-execution sentinel. The budget case contained only the expected approved
file. Original volumes and private state were preserved. Absence of the audit
record leaves the original dispatch-count claims unresolved.

## Repair and independent reproductions

The runner now checks the image entrypoint and exact audit-wrapper source hash
before creating resource volumes or starting a kernel. It records the observer
identity and retains the source alongside its driver. Actual selection of the
unaudited image now fails at this preflight, before creating a run output.

Any independent-observer or cleanup error sets the case status to `failed`.
The observer assertion is unchanged; failures include actual and expected
dispatches. Raw evidence is written after failure and names remaining owned
volumes for reconciliation. Five component reporting/negative-control tests
passed with zero skips. They are not host acceptance evidence.

Fresh reproductions explicitly selected the audited image
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
Its audit wrapper hash is
`23c83a3568a5d42af9a99e8bc837d4f17ef5b5bb18efeec4af502b5f7779c2ef`,
matching the selected source. The frozen static kernel was unchanged.

The first reproduction with the original driver passed the budget case. Its
bounded case failed before initialization returned: the existing 20-second
HTTP timeout elapsed with no dispatch. That failed attempt and its private
state were retained. A separate image full-inspect command also timed out;
the underlying cause of that transient initialization timeout is unknown.
Neither timeout was relaxed or reclassified.

The final repaired-driver reproduction ran both cases in fresh isolated volumes
with the same timeouts. Both passed, aggregate exit 0, zero skips. The observed
dispatches exactly matched the table's expected column, and the binary hash
was unchanged during execution. Its driver SHA-256 is
`7576929ba3f28e2115216803898e5304d7dfce274805d7e745d8d376f471d92b`.

Reproduce from this source with the qualified image present locally:

```sh
python3 integrations/required-agents/qualification/shared_kernel.py \
  --binary /absolute/path/to/chio-c03a8a711dbb \
  --source-revision bafa02b06de93553cecb6f60b340f3dd8fd9b401 \
  --image sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0 \
  --cases bounded-approval-workflow,approved-grant-budget \
  --output /tmp/chio-static-approval-reproduction-UNIQUE
```

The complete shared suite still requires a new run with the audited image.
No kernel source change or binary rebuild was needed for this runner repair.
Every host still requires its own applicable acceptance gates.

## Record format

`files.json` binds every lossless gzip export to its original SHA-256, byte
count, and local source path. `SHA256SUMS` verifies the committed record.
The original manifest, the two failed-case raw records, read-only resource
reinspection, intermediate failure, final reproduction, actual image refusal,
and component test output are retained. Private database directories, signer
seeds, and operator/provider credentials are excluded. The exclusion report
compares both compressed and decompressed exports against known credentials.
