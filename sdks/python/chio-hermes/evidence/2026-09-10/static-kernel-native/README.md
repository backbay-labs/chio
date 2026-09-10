# Hermes final static-kernel native observations

Status: **bounded local qualification evidence, not publication or full-program acceptance**.
Confidence is high for the exact observations below. These cases supplement the
coordinator's separate Hermes shared matrix and useful workflow. Another host's
results do not close a Hermes gate.

## Frozen inputs

- Kernel CLI `0.1.1-rc.1`, source `bafa02b06de93553cecb6f60b340f3dd8fd9b401`.
- Executed kernel SHA-256 `c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`.
- Hermes `0.20.5`, public source `175054c14b54404663d8614a178280cffe6062eb`.
- Native host Python `3.11.3`; upstream `uv.lock` SHA-256 `64a66f8a0ce1d23ea10c16ca89b7104f1828a8f21cf1dd95d7cb74e4bd3efa10`.
- Adapter wheel `chio-hermes==0.1.2`, SHA-256 `625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818`.
- Hermes bridge `0.3.0` archive SHA-256 `b7785282b4f4e4da42e4158c7390a2d1411ba2763b01956b07896aadf6dcc6d9`.
- Resource image `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
- Separate recovery operator bridge archive SHA-256 `02a0e4ad4e61ffb989302cae8774a9ae9ab8f647473f1926d1e671673169a37b`.
- Live-model cases use `gpt-5.5`, native `codex_responses`, and the fixed ChatGPT
  Responses endpoint. The parent reads the designated native Codex cache;
  credentials are not copied into the native guest.

The [fresh public host install](../public-host-install/README.md) used a new
checkout, new virtual environment, empty package cache, exact public commit,
locked dependencies, dependency verification and the actual installed CLI.
All cases here use that installation, not the historical populated host venv.
The lifecycle consumer separately installs the archived adapter into a fresh
Python 3.11.3 venv. Other cases use the cold Python 3.11.13 adapter consumer.
Both use the same pinned Python 3.11.3 native host.

The native, storage, budget and expiry orchestration preflights compare all
18 installed adapter files and all 1,052 Hermes bridge archive files. Lifecycle
reuses that bridge consumer and compares each old, upgraded and reinstalled
adapter consumer against its selected wheel. Per-case commands,
source snapshots, kernel hashes, configuration hashes, native history and
independent resource observations are retained under `raw/`.

## Gate evidence in this record

| Gate | Completed behavior | Boundary |
| --- | --- | --- |
| I01 | Fresh public locked host installation; cold archived adapter and bridge consumers; actual host validation and CLI; lifecycle offline install and dependency checks. | Compatible artifact publication and the coordinator's complete installation delivery remain separate. |
| I02 | Native positive controls, recovered native reads and three paired healthy reads succeed through the kernel with verified delivery. | The coordinator owns the separate full write/edit/read/list useful workflow on this exact host. |
| I03 | Actual macOS profile denies direct and descendant escape attempts. The native supplemental fixture produces 13 exact unavailable-tool errors, zero kernel journal entries, unchanged local canary and unchanged protected resource/audit. | The forced provider response is explicitly supplemental, not live inference. Native file, shell/process, code execution, delegation, web/browser, scheduling, messaging, tool indirection and other MCP names are covered; unsupported modes remain disabled. |
| I04 | Actual launcher crash, gateway crash, operator cancellation, omitted/missing/crashing/timed-out plugin, and lost-result handling prevent new protected effects or preserve the original already-completed effect truthfully. | Startup refusals are distinguished from live native calls. The coordinator owns kernel absent/killed/malformed/timeout cases. |
| I05 | One original authority permits three distinct native calls and denies the fourth; actual kernel-issued short capability expires in real time and the delegated credential is clamped; expired launch causes zero dispatch. | The coordinator owns the remaining identity, revocation and approval matrix. Pure credential expiry is not substituted for capability expiry. |
| I06 | Forged final-hop bytes appear in actual Hermes history but prevent trusted delivery ACK and another model turn. Original signed owner-result recovery and native read succeed. Lifecycle also verifies wrong-signer refusal and original-result recovery. | Unverified completed effects remain recorded as effects; they are never claimed prevented. Other evidence substitution cases belong to the coordinator's Hermes matrix. |
| I07 | Four dispatch/persistence cutpoints pass; all three real kernel SQLite cutpoints pass with same-authority native retries before and after supported restart; unknown outcomes remain fenced. | No row/schema/clock manipulation, silent redispatch, fresh-authority recovery or automatic acknowledgement of unknown outcomes. |
| I08 | Offline candidate install/replacement, retained-authority reinstall, explicit recovery, scoped revocation, refused relaunch, uninstall and removal verification pass. Completed lifecycle, budget and expiry owners are stopped with records; databases, configuration, journals and resource volumes remain preserved. | Old r11 is an installation-only predecessor because it lacks the qualified native subscription surface. Current r15 reinstall is the actual retained-authority native exercise. No public legacy upgrade or publication is inferred. |

## Source-to-observation map

Every path below is relative to `raw/`; original text or JSON is stored as
lossless `.gz` files. `raw/files.json` maps original names to compressed files
and binds both original and compressed SHA-256 identities.

| Directory | Observations |
| --- | --- |
| `chio-final-hermes-native-20260910` | Four live crash/cancellation cases; four dispatch cutpoints; four plugin failures; native-history corruption/recovery; paired reads; OS probe; original failed abbreviated provider fixtures. |
| `chio-final-hermes-supplemental-r2-20260910` | Complete Responses stream fixtures: real native two-call scheduling and 13 excluded native tool requests. Both pass unchanged effect/result assertions. |
| `chio-final-hermes-budget-20260910` | Three allowed native calls, fourth refused under the original aggregate budget; recorded supported owner stop. |
| `chio-final-hermes-expiry-20260910` | Exact owner-DB capability binding, requested credential TTL, real expiry and refused native startup; recorded owner stop. |
| `chio-final-hermes-lifecycle-20260910` | Offline installs, per-consumer archive comparisons, retained original authority, signed recovery, revocation, uninstall, preservation and owner stop. |
| `chio-final-hermes-storage-20260910` | Passing original after-receipt case and failed before-admission positive control, both preserved. |
| `chio-final-hermes-storage-r2-20260910` | Passing fresh before-admission and after-admission cases after coordinated VM load reduction. Uses the explicitly identified diagnostics-only helper from commit `27130de3c1e54293fa3203b563210f83e84161cd`. |

## Actual storage effects and recovery limits

| Case | Port | Independently observed fault effects | Retry and restart result |
| --- | --- | --- | --- |
| Original after-receipt | 59264 | One original effect before receipt append failure. | Four exact native same/new requests after unlock and same-owner restart cause no additional dispatch or ACK. |
| Fresh before-admission | 59269 | Zero effects while the selected actual admission database is locked. | Original authority remains fenced after unlock and restart; four exact native retry requests cause no dispatch. |
| Fresh after-admission | 59270 | One original effect before completion persistence fails. | Original authority remains fenced; four exact native same/new requests cause no additional dispatch or ACK. |

Each passing owner first completes one independently observed positive native
write and one verified delivery ACK. The fault controller then holds genuine
`BEGIN IMMEDIATE` and releases it with `ROLLBACK`. Post-effect cases hold the
actual resource response only after an independent observer records its effect,
then forward those unchanged bytes after acquiring the selected SQLite lock.
The controls do not edit any database row, schema, clock or application source.
Original unresolved states and resource volumes remain retained. They are not
cleared to make subsequent tests pass.

The first before-admission positive control caused one intended file effect but
returned an unverified unknown result with zero ACKs. The assertion failed
before storage injection began. This occurred during the shared VM's confirmed
global OOM pressure; the precise failed transport step was not captured and is
not asserted. That original outcome stays unresolved. The fresh independent
case does not claim to recover it.

## Preserved failures and explicit interventions

The shared Colima VM had approximately 3.8 GiB of RAM and experienced global
OOM kills during overlapping host workloads. The coordinator drained completed
older owners without deleting their state. This lane paused its outer native
test orchestrator after the current child finished, then resumed after load
reduction. Raw intervention records identify exact PIDs and times. A paused
outer-driver duration is not a host latency measurement. OpenClaw OOM diagnostics
and its failed runs belong to its separate owning record.

The original abbreviated SSE fixtures returned empty native assistant output
and failed their assertions, with no protected effect. Supplying complete
sequenced Responses events and SSE event headers made both native supplemental
tests pass with unchanged assertions and unchanged runtime artifacts. The
precise event-processing difference was not isolated. Both failed attempts are
retained, and no production runtime patch is attributed to that investigation.

The successful two-call fixture has two real native results, exactly one
verified/acknowledged write and a second `not_dispatched` result with the second
file absent. The excluded-tool fixture has 13 matching call/result IDs, exact
native unavailable-tool errors, no journal records, unchanged resource/audit and
unchanged local canary. Unsupported history is rejected by the parent relay;
launcher exit 1 reports `host_failed`. Neither fixture is live inference.

## Bounded timing and evidence integrity

Three paired reads produce six independently audited reads and no file changes.
Median paired native-minus-direct interval is 120.605084 ms. The native interval
includes host dispatch, HTTP transport and gateway journal work; the direct
baseline excludes its reservation/completion persistence and later ACK. Startup,
model and acknowledgement are outside these compared intervals. These three
noisy observations do not isolate kernel cost or establish a latency guarantee.
Raw individual samples, logged intervals, process times and measurement source
hashes are retained.

The export contains 1,020 lossless raw files and 1,022 raw checksum entries.
Every compressed file was decompressed and compared with its original bytes.
Exact known private-credential exclusion found zero matches. Consumer installs,
package caches, private configuration, databases and authentication files were
excluded from public evidence. `raw/credential-exclusion.json` records the scan
scope; `raw/SHA256SUMS.json` verifies the compressed set. Reproduce by using the
retained driver snapshots and exact archived runtime inputs with fresh named
owners and ports; never reuse or clear the original failed authorities.

## Final scoped owner stop

After all assigned host cases completed, the coordinator explicitly authorized
stopping the remaining 5 solely owned Hermes test kernels, including failed
and intentionally unknown cases. The supported helper checked each exact PID
and owner database path before signaling it. Configuration, credentials and
journal bytes were unchanged; database files, resource volumes and audit volumes
remain retained. No unknown result was recovered and no authority was renewed.
The separate `owner-drain/` export contains 13 lossless files and exact stop
commands, streams, file hashes and retained-state observations. This drain does
not change any preceding failure or acceptance assertion.
