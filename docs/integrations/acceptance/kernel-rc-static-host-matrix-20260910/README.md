# Static kernel candidate: five real-host matrices, 2026-09-10

**Five bounded matrices passed; no host is accepted by this record.** Claude
Code, Codex, Pi, Hermes and OpenClaw each completed 37 driver commands using the
same static kernel candidate. That is **185 commands: 15 setup commands, five
useful workflows and 165 matrix commands**, not 185 distinct acceptance tests.
Cursor remains mandatory and unresolved. Complete I01-I08 acceptance and public
delivery remain open. Confidence in the retained observations is high.

## Exact candidate and useful work

The selected binary reports `chio-cli 0.1.1-rc.1`, kernel source
`bafa02b06de93553cecb6f60b340f3dd8fd9b401`, SHA-256
`c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`.
The matrix's test-driver checkout was
`1a79792a956e863c17b9c244c0154c8dbd9a73eb`; the evidence-export worktree began
at `9e3f7c35f95b5afafc56f7f1ba62cb8432755293`. These are distinct source
identities, not alternative build revisions for the binary.

| Host | Selected integration artifact | Useful workflow | Matrix commands |
|---|---|---|---|
| Claude Code | `@chio/claude-code-plugin` 0.3.1-rc.1, archive `1258385647d228ebeed32662091ed721aeda3b60450cabae480ca0d4292fbe0a` | Passed: four dispatches and confirmed deliveries | 33 passed |
| Codex | `@chio/codex-plugin` 0.3.0, archive `ac4f14ee4073abdc0c9ff2b4771e99adf7a871d084a9b488513f5d28eae56874` | Passed: four dispatches and confirmed deliveries | 33 passed |
| Pi | `@chio/pi-plugin` 0.1.0, archive `ec6095390b9eae233540b73aee0ad2fef6977c36122dd30aa2779329b1897aa1` | Passed: four dispatches and confirmed deliveries | 33 passed |
| Hermes | `chio-hermes` 0.1.2, wheel `625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818` | Passed: four dispatches and confirmed deliveries | 33 passed |
| OpenClaw | `@chio/openclaw-kernel` 0.1.0, archive `a79dbffa8356a608f22db847e100d1989cb7ff322ab1315144774decb2b13ab4` | Passed: four dispatches and confirmed deliveries | 33 passed |

Each useful workflow wrote a disposable remote file, edited its content, read
that file, then listed the resource directory. Before/after filesystem and
resource-dispatch observations are retained alongside actual native tool calls,
model-relay records and delivery acknowledgements. The three setup commands per
host start its resource owner, prepare the scoped session and seed the approved
fixture. Setup is not a model workflow.

The hosts used separate owner directories, profiles and resource/audit volumes.
The protected filesystem image was
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
OpenClaw's native host image was
`sha256:7f925d68ced724f4a6314ab76dc117e9000515ba62149ee971a11c510be6637f`.
This is native agent execution, not acceptance of the legacy hosted chat gateway.

Claude was 2.1.267, binary
`a681f3008f0050029aeebcab3af51bb6a55ddeb625a3af3141a4416d43cd2558`,
using `claude-sonnet-5` and native Claude login. Codex was 0.153.4, binary
`b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3`,
using `gpt-5.5` and its native ChatGPT cache. Pi's retained installation record
selects public peer `@earendil-works/pi-coding-agent@0.85.1`. Pi, Hermes and
OpenClaw used `gpt-5.5` through the native Codex subscription transport.

Hermes' public source was `175054c14b54404663d8614a178280cffe6062eb`, tree
`b485d3e994bda896e30ba7e3216aadb641b1d8e3`. Its newly prepared host environment
used Python 3.11.3, binary
`c220ae7b6c2b9da2a4e498c09cdbc64b03b43db96dbbf9f64d26bfbbd698e2bd`.
The retained host-install identity also records the earlier failed no-config
installation attempt; this is not silently converted into a passing attempt.
The batch verifies the host interpreter hash, source HEAD and clean tracked
source state at startup. Other installation measurements in that copied record
are not independently repeated by the batch.

Claude's useful-run identity records macOS 26.4 arm64, Node 25.5.0, bridge 0.3.0
and SDK 0.1.1-rc.1. Per-run launch records provide the measured host commands,
configuration hashes and launcher/gateway identities. An omitted field is not
inferred from another host's record.

## Matrix scope and remaining acceptance

Each 33-command matrix contains 24 base suites, six original-session resume
fences and three signed-owner recovery suites. The base suites cover seven
forbidden filesystem requests and alternate path/tool forms; approvals;
revocation and in-flight capability/credential revocation; kernel kill,
malformed response, timeout and absence; expired session credentials; wrong
principal/session/resource; scope escalation; foreign-receipt, wrong-signer
and request-ID substitution; and concurrent owners. All commands exited zero
at the test-driver level and all five matrix summaries record zero skips.
Expected denied host calls can themselves exit nonzero, as retained in raw data.

The native host makes actual tool attempts where the case requires them.
Invalid startup authority is explicitly refused by the real launcher before
host initialization in the applicable cases. These startup refusals are not
relabeled as model-generated tool calls. Claude's declared-tool negative
controls ask the real provider for that tool choice; their records distinguish
that request from fabricated assistant output or modified tool arguments.

In-flight fault cases retain any already admitted effect and uncertain result;
subsequent original-session fences and signed-owner recovery test the recorded
outcome. A stopped kernel cannot undo an earlier committed effect. Fault
injection and operator recovery execute in the trusted test parent. Native
host output alone is not the resource observer.

This matrix contributes to I02-I07 but does not close those gates in full.
Native confinement, all unsupported consequential paths, plugin omission and
failure, actual capability expiry and aggregate budgets, cancellation and host
lifecycle/restart, storage/signing cutpoints, and installation/upgrade/removal
remain separate required host evidence. The lifecycle and storage workers'
results are not incorporated or declared passed here. Existing archive consumers
were reused after startup byte checks; this batch does not claim a fresh public
installation for each host. I01 and I08 still require usable published artifacts
and supported procedures. Cursor still needs an established server-enforced
restriction for consequential remote actions before its matrix can proceed.

The [shared kernel record](../kernel-rc-static-shared-20260910/README.md) is
separate direct kernel evidence. Its results do not substitute for any host.
Earlier failures against other binaries or Claude archives remain in their
original records. No selected-candidate manifest, host acceptance decision,
publication status, independent-adoption claim or research-novelty claim changes
through this export.

## What is actually pinned

The aggregate driver snapshot is SHA-256
`29e578a06d9e5f26685a453c5c0eb32e4df12c0588069034ba946011e36f2d12`.
For 180 Python commands, the driver copies the entry script immediately before
execution, hashes it, and checks the same entry file after the command returns.
All 180 stored copies match their command records, across eight distinct entry
script hashes. The five Docker fixture commands have their full arguments and
resource-image digest recorded, but no entry-script snapshot. The aggregate
driver itself is copied once; there is no recorded aggregate before/after check.

The shared entry script loads five sibling helpers for declared tool choice,
dispatch holding, kernel interruption, revocation and evidence substitution.
Those helpers are not snapshotted per command. `source-review` preserves their
bytes from the matrix's recorded Git revision and the later comparison with the
working files: all five match, and no commit changed those paths through the
record base. This is source corroboration after the run, not a retroactive
attestation of every runtime dependency or every byte throughout execution.

At batch startup, the aggregate driver checks the kernel digest and all regular
files from the four selected npm host archives against their installed bytes.
The export's separate post-run comparison matches those archives again:
Claude 1,227 files, Codex 2,337, Pi 1,090 and OpenClaw 1,075. It also matches
Hermes' 18 adapter files, the Hermes bridge archive, the operator recovery bridge
archive and the selected kernel. Supplementary post-run comparisons do not
imply startup assertions absent from the driver. The Hermes wheel comparison
covers package code files, not every installed distribution or interpreter
transitive dependency. Exact comparison results and limitations are in
`source-review/post-run-provenance.json.gz`.

## Shutdown, resource drain and export

`completed-owner-stops` preserves the five completed matrix-owner shutdown
records. Each uses the shipped identity-checking helper and binds the host's
summary hash, resource volume and audit volume; state is retained. These are
post-run owner shutdowns, not independent lifecycle acceptance tests.

`completed-resource-drain` preserves the earlier bounded cleanup of 22 proven
completed or explicitly superseded older owners and their 22 exact containers.
Their pre-stop reported container memory totaled 643.39 MiB. All 44 named
resource/audit volumes and recorded persistent database/journal files remained.
Six leftover resource containers required an exact-ID stop after their owner
was stopped. Current static/final owners and unrelated containers were excluded.
Two ambiguous older owners remained untouched. These historical records do not
claim the same containers are still running now or quantify net VM memory after
other concurrent work.

The four complete input trees contain 2,894 regular files. Two validation logs
are added, for 2,896 losslessly compressed raw files. `source-inputs.json` binds
each input tree; `files.json` binds every original path, byte count, original
SHA-256 and compressed SHA-256. `SHA256SUMS` covers the entire exported record.
Raw failed-attempt descriptions, denied calls and historical model output remain
byte-exact; they are observations, not authored product claims.

Private databases, raw operator journals, signer seeds, provider credentials,
package archives and kernel binaries are not included. Sanitized state
projections, public signatures, public identities and request-bound delivery
acknowledgements remain intact. The credential scan compares decompressed raw
files and authored metadata with known private credential values.

Run `python3 verify.py` from this directory for an offline check of all hashes,
command counts, entry snapshots, shutdown-summary bindings and the preserved
resource-drain checksums. This verifier launches no host or Docker container and
makes no acceptance decision. The unchanged product-copy gate and its negative
controls are recorded under `validation`.
