# Required six-host integration execution record

Status: **in progress, zero of six integrations accepted**. Confidence is high
in the recorded observations and unresolved failures. No source commit, unit
test total, locally installed package or historical host run closes I01-I08.

The authoritative requirement is planning commit
`d1d99f881ed2547367e45d1715f3c41c8c21589d`, document
`docs/strategy/chio-direction/19-priority-agent-integrations.md`, SHA256
`716c066323889ce54f0dfe6988dfbc7fa76b0c27c8afc7c8d0287f686b786099`.
That planning checkout has a different Git common directory from the main
kernel checkout. Its untracked document 13 was preserved. The initial paths,
revisions, dirty files, environment and document hashes are in
[source-baseline.json](raw/source-baseline.json). All six remain mandatory;
three accepted systems would only be an intermediate milestone.

## Current host records

Paths in this table are relative to `/Users/connor/Medica/backbay/standalone`.
Each plugin worktree is `.worktrees/required-agent-integrations-20260909` unless
another path is shown. Exact source and package dependency snapshots are in
[source-checkpoint-preack.json](raw/source-checkpoint-preack.json). These are
local candidate identities, not a published version combination.

| Host | Pinned runtime | Recorded implementation and observations | Remaining acceptance work |
|---|---|---|---|
| Claude Code | 2.1.267 for current received-result cases; earlier 2.1.266 retained separately | Restricted parent HTTP transport and full native-result verification; actual host/kernel useful work, budget, denial, native-tool and response-loss cases with local Messages fixture | Isolated Anthropic credential; authenticated provider cases, remaining authority/fault/lifecycle matrix and publication |
| Codex | 0.153.4 | Current archive: useful work, denials, budget, approvals, revocation, 14 authority/fault cases, evidence substitution, cancellation, crash and signed owner-result recovery through actual OpenAI/kernel sessions | Remaining plugin omission/failure, parallel-call and lifecycle cases; release qualification and publication |
| Cursor | GUI 3.19.13; CLI 2026.09.08-6caf4ff | Parent-owned HTTP gateway, scoped guest route and private journal; packaged real CLI discovery plus exact retained default-deny OS profile probes | Isolated authentication and bounded hosted AgentService protocol; protected prompt mode refuses. No useful model-driven workflow or full gate accepted |
| Hermes | 0.20.5; upstream `175054c14b54404663d8614a178280cffe6062eb` | Current r10 wheel: useful work, denials, approvals, budget, 14 authority/fault cases, evidence substitution, cancellation, gateway crash and signed owner-result recovery through actual OpenAI/kernel sessions | Remaining plugin omission/failure, parallel-call, launcher SIGKILL and lifecycle cases; four legacy opt-in skips unresolved; publication |
| Pi Agent | `@earendil-works/pi-coding-agent@0.85.1`; upstream `d981de1229ef899957bbe968bc8dcda02a21f477` | Current archive: stock AgentSession with one Chio tool; actual provider/kernel workflow, denials, approvals, budget, 14 authority/fault cases, evidence substitution, cancellation, crash and signed owner-result recovery | Remaining plugin omission/failure, parallel-call and lifecycle cases; publication |
| OpenClaw | 2026.5.20 (`e510042`) | Current supervised archive/image: actual provider/kernel workflow, denials, approvals, budget, 14 authority/fault cases, evidence substitution, cancellation, crash and signed owner-result recovery; current-image process/descendant probes | Remaining plugin omission/failure, parallel-call, early creation crash and lifecycle cases; publication |

All eight gates are open for the program. Individual passed cases in host records
are bounded to their recorded source, artifact and configuration. Counts from
different builds cannot be combined into a final passing host matrix. No result
from one host substitutes for another host's missing case.

## Retained delivery failures and repairs

The bridge could acknowledge a completed result before the host received its
HTTP response. A dropped-response regression caused a replacement request to
execute. This is an I07 failure in the prior packaged HTTP candidates. The
repair retains the fence until an actual host returns the exact delivery proof.
Codex and Claude launchers consume host tool-result history. The earlier Pi guest proof
round trip was replaced by parent acknowledgement of native history. The later host records below qualify bounded repairs; full acceptance
is still open. The first repaired artifact had a malformed MCP capability
announcement and failed Codex and Claude initialization with zero dispatches.
Both failures are retained; no older passing host result closes this gap.

The corrected bridge artifact `b7785282b4f4` passed 11 actual kernel/resource
response-loss and recovery checks. Current cold-installed Codex, Pi and Claude
packages each independently exercised loss of the complete HTTP result before
the real host received it. Each original write occurred once, restart/resume
remained fenced, and explicit operator recovery permitted a subsequent useful
read without repeating the write. Codex and Pi used actual OpenAI providers;
Claude used its actual host with a local Messages fixture. The ordinary current
host cuts also passed: Codex five cases, Pi three cases, and Claude four cases.
These bounded observations do not close the complete I01-I08 matrix. See each
host's new `host-delivery` evidence directory. Hermes is being moved to the same
launcher-owned transport; OpenClaw and Cursor remain independently mandatory.


## Demonstrated shared repairs

- The shipped CLI reports `0.1.0` and has SHA256
  `c8d7ee8dc4ffdbed4a864b5984f931164a2b320e1a3d914adcb61d0636c354c3`.
  It lacks the required modern runtime surfaces. The new source retains that
  version label, so candidates are selected by source and binary hashes.
- SDK `0.1.1-rc.1` verifies the current content-addressed receipt with trusted
  signer and request/result bindings. Its package passed 108 tests and a clean
  consumer installation. The bridge returns distinct authorization, execution,
  evidence and unknown states. Old self-signer or local-policy checks are not
  accepted as kernel execution evidence.
- The MCP edge now exposes signed execution evidence and the actual resource
  owner before dispatch. An actual Codex test demonstrated that checking a
  wrong expected resource only after execution was too late. The repair must
  pass a final real-host rerun.
- A macOS SQLite identity defect prevented kernel startup. The existing local
  `fstat` repair was copied into this isolated worktree without altering the
  original dirty files and passed the targeted tests and lint.
- Native policy supports a single aggregate invocation limit. A demonstrated
  explicit-grant bypass of confirmation constraints is repaired. Exact bound
  approvals include caller/session, capability, request, tool and canonical
  arguments; pending/rejected approval does not dispatch the action. See the
  [approval record](../shared-approval-qualification-20260909/REPORT.md), including
  the failed predecessor candidate.
- Operator-issued credentials restrict the guest to one retained session and
  four tools. They cannot initialize new authority or reach admin APIs. The
  owner persists pending execution fences and exact completed-response replay.
  [Credential qualification](../../session-credentials/QUALIFICATION-20260909.md)
  records the first 24 actual kernel/resource cases. The
  [delivery acknowledgement candidate](../../session-credentials/DELIVERY-ACK-20260909.md)
  passed 34 actual kernel/resource cases, including complete response loss,
  erased guest journals, rotation, restart, forged acknowledgements and exact
  replay recovery. New request IDs remain fenced until verified completion has
  been durably retained and acknowledged.
- Receipt reconciliation repeatedly verified entire checkpoint histories while
  starting a session. A verified SQLite batch read replaces that repeated work
  without bypassing corruption checks. Combined library tests passed: control
  plane 764, kernel 1,104, remote MCP 53, MCP edge 112, schema 2. Startup timing
  [qualification](session-startup/README.md) remains separate from those functional tests.
- The isolated filesystem image now independently records forwarded requests
  and rejects imported symbolic links, hardlinks and special files before
  starting the official server. Five actual container cases passed. Audit write
  failure prevented the resource write; independent alias reads proved the
  negative controls were effective. See [resource observations](raw/resource-audit-run2/results.json).

## Candidate identities and limitations

The current kernel includes the terminal tool-error acknowledgement repair at
`d8c5f53705173e614a853bad6c0a85acfdf1212b`, binary SHA256
`33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`.
It passed 38 actual kernel/resource cases and 55 remote library tests. The
predecessor mishandled a known filesystem error discovered by a clean-installed
Codex run. All earlier host passes remain bounded to their recorded artifacts.

The preceding acknowledgement kernel was built from
`8501b0058dfcbccd858ae2cdeda82948fb1e9a08`, equivalent to root code `31c28d05c3`.
Its SHA256 is
`0e683f6f7cc8f21816b10641e3c18fba2dd1445fbcd28752cd3260d8ac5edb5a`.
The bridge source `c77861d` produces the self-contained candidate tarball SHA256
`c22c8dd094e39249484b3f4631d9ee6728db76bfd9e6f1f767c22538ab18a0ff`.
It passed 116 component tests and an empty-cache offline consumer installation.
The launcher-owned HTTP transport keeps kernel credentials and durable journals
outside the guest process. Closing or killing the launcher closes the transport.
Shared real-kernel ordinary and approval cases are recorded in the bridge repo;
every host must still qualify that contract independently.

The historical combined pre-acknowledgement kernel was built from
`25d5717a5bcfd228391dbeee61d8d57f3c5e6177`, equivalent to the kernel crate contents
at root commit `f516b0d1e1`, and copied before any later build. Its SHA256 is
`d0b87623cb3dd227f79cd3178b32bb04e35b48ddcb9dab63c6598d79b8e13b66`.
The audited filesystem image identity is
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
Neither artifact is a published accepted release. Earlier evidence naming
`e7539855906b...` or exploratory kernels remains historical. The oldest running
kernel's binary hash was not captured before the shared build path changed;
[its observations](raw/shared-exploratory-observations.json) explicitly retain
that missing provenance instead of assigning a later hash.

The resource runbook's initial restart test returned the recorded completed
write without overwriting an independent operator sentinel. Its subsequent new
read failed before dispatch. That is partial replay evidence and an unresolved
readiness failure, not a passing recovery gate. Raw stdout, stderr and the
independent observation are in [runbook-initial](raw/runbook-initial/observations.json).

## Delivery and next acceptance cut

The [resource-owner runbook](../../../../integrations/required-agents/README.md)
uses explicit kernel/image identities, isolated operator state, independent
resource and audit volumes, and retained databases. Host packages are built and
installed through cold consumer directories with self-contained Chio
dependencies; public upstream host dependencies stay explicitly pinned. Final
packages must be rebuilt after the acknowledgement/approval bridge contract is
settled, then installed and exercised through each real host.

The bridge implements explicit approval proposals/resume, durable delivery
acknowledgement and operator lock recovery. Outstanding work is real-host
qualification of those behaviors, final process boundaries and every remaining
host-specific I01-I08 case. Cursor authentication and its bounded
hosted execution contract, and Claude's isolated model credential, are external
inputs under investigation. Required checks that cannot run remain unresolved.
Publication must preserve the existing release and security gates. No public
release, independent adoption or research novelty is claimed by this record.

## Native HTTP host qualification and received-result repair

All six remain mandatory and unaccepted (0/6). Hermes source `65671a01c`,
qualified by `cbb5d5e0a`, completed useful write/edit/read/list through the real
Hermes/OpenAI host, plus forbidden read/write and final-response-loss recovery.
The cold-installed wheel has four useful deliveries, zero forbidden dispatches,
and same-authority restart fencing until the operator reads and acknowledges
the exact retained outcome. Python and descendant process probes observed the
selected TCP positive controls and denied home/other-profile data, filesystem
aliases, hardlinks, shell execution, Unix sockets and unrelated TCP access.
The initial framework-bootstrap probe failure is retained separately.

The native OpenClaw launcher now keeps kernel credentials and journals outside
the agent. Its cold-installed archive builds a pinned host image without a
private sibling or host filesystem share. Source `8928eba` and the owning
repository's `native/evidence/2026-09-09/http-host-delivery` record useful work,
forbidden read/write, response-loss recovery and substituted output through the
actual OpenClaw/OpenAI host, with independent resource observations. Native
container process boundaries and the remaining gates still need qualification.

Final-hop result substitution exposed a concrete evidence defect in Pi and
OpenClaw: both older guests accepted forged result text under an authentic
unchanged decision receipt, reported completion and acknowledged delivery.
Bridge `b8cef33` adds received-result verification, retaining the existing MCP
protocol. Its artifact SHA256 is
`eb4392bf298595d52d92610ea82c6e64d6f534718fe575bc5ea9a583c5810a4b`;
119 component tests passed without skips. Repaired Pi and OpenClaw guests now
verify the result hash and expected host operation before acknowledgement.
Both real hosts reject the same substitution, return unresolved, retain the
original resource read, and leave delivery unacknowledged. Each host's 18-test
component suite and its own real-host observations are retained separately.

Pi artifact SHA256:
`6c994035ef3d3b51f6f4db3859cead726afe9e5dc710642b782be9beeb466bbb`.
OpenClaw artifact SHA256:
`96f67ee343d14f7ba40d2ff6986fc3b79887ee53179a6399156249cee8ac5c79`.
OpenClaw image:
`sha256:38ab384535544261d851394a9d6ef59d9c6de5b7367652464f977f7a8bc890a6`.
All use kernel `33dd1dea21a4`; these are qualified subsets, not published
accepted releases. Full authority/approval/budget/revocation, kernel and plugin
faults, later crash cutpoints, cancellation and lifecycle gates remain open.
Cursor's isolated authentication and bounded hosted execution contract and
Claude's isolated provider credential remain external inputs. No synthetic
fixture or another host's result closes those missing real-host cases.

The subsequent acknowledgement-confirmation-loss cutpoint failed in both Pi
`6c994035ef3d...` and OpenClaw `96f67ee343d...`. After receiving the signed result,
the guest sent its proof, but the HTTP acknowledgement response was lost. Both
reported uncertainty and, after restart with the same authority, dispatched a
replacement write. Each independent resource audit records two writes and the
replacement content. The owning repositories retain `ack-confirmation-loss`
evidence. Their preceding bounded passes do not resolve this I07 failure.

The repair under qualification moves acknowledgement into the trusted model
relay, after the native host echoes the full verified result in conversation
history. Bridge source `0d31365` exposes exact received-outcome acknowledgement;
its archive is `7d9e34f7408a316e35125982a23faaecfd2f31f4da6b50ca8eab287c2c918f67`.
The 119-test existing suite and expanded six-case HTTP suite passed. Pi and
OpenClaw package rebuilds and real-host reruns are required before claiming the
specific failure resolved. No host is accepted.

The native-history candidates now pass the specific predecessor ACK-response
fault with actual Pi and OpenClaw: each completed one original write, the
resource observer recorded one dispatch, and the parent journal confirmed the
result from native history. No guest acknowledgement response exists for the
injector to drop. Both candidates also passed their own five actual-host cases
(useful work, forbidden read/write, result loss/recovery and result substitution).
Pi archive: `380c7ab33de2dd5ccdfd5b3ff5b8ad079e87800d32d4282398ceefe2f7b712d3`.
OpenClaw archive: `f93ea8480937bf85fe07910a0260a24baaefc0089a4e3c213a311cb21efff0e1`.
Exact images, commands and observations are in each owning repository's
`evidence/2026-09-09/native-history-ack` record (under `native/` for OpenClaw).
Later host/plugin crash cutpoints and the full required matrix remain open.

## Current authority and received-result checkpoint

All six remain mandatory and zero are accepted. Exact artifacts and raw
observations are committed in each owning repository. The current source
checkpoints are Codex `cb2433d`, Claude `5a7d69a`, Pi `93f4567`, OpenClaw
`b3fb4fd`, and Hermes approval repair `c29b9d3c3`.

Codex, Hermes, Pi and OpenClaw each executed seven approval stages through the
actual native host and OpenAI provider: pending, missing decision, changed
arguments, approved resume, completed replay, pending rejection and rejected
resume. Only approved resume caused an effect. Exact native calls, arguments,
return identities and all additional model attempts are retained. Independent
resource observers saw one approved write, no substituted/rejected write and
no replay dispatch. Hermes initially omitted chio_resume from native MCP
filtering; its r7 resume observations lacked a native call and are failed
coverage. The r8 repair exposes this gateway control tool without widening the
four-tool session credential.

Aggregate budgets were exercised separately through each of those four hosts:
write/edit/read completed, the fourth list call received a signed invocation
budget denial, and the resource audit contains exactly three new dispatches.
Claude also passed this budget case through the actual executable and kernel,
with a local Messages fixture. No authenticated Anthropic result is claimed.

Final-hop result substitution exposed additional failures in Codex and Claude:
the old launchers acknowledged authentic delivery proofs carrying substituted
result bytes. Codex reported the forged content; Claude forwarded it in native
history to the local model fixture. Both repairs verify the complete received
outcome before acknowledgement and another model turn. Their new cold-installed
candidates reject the substituted result with zero acknowledgements. Codex also
passed useful work, forbidden reads/writes, response loss with fenced restart
and explicit recovery, approvals and the three-call aggregate budget. Claude
passed useful work plus forbidden/native probes, result loss and the budget
case using the local fixture. Previous failed evidence remains committed.

| Host | Current local candidate SHA256 | Evidence directory in owning repository |
|---|---|---|
| Codex | `860811efcdebea7a4c9fe4db7b9a4c9eb764b55c0fadd4dc6e9429447e7813b6` | `acceptance/2026-09-09/received-result` |
| Claude | `8a7f9a21615271ec12ff641ff90ff3e6fec8229caf0d4cde5b0eda9b138c1e82` | `acceptance/2026-09-09/host-supervision` |
| Pi | `b6f38bfb2c129e00d6e8c5c74b5b92ec4d527d26a81683316683abc690afac2c` | `evidence/2026-09-09/authority` |
| OpenClaw | `ba6b80e71598ec8f01205ef7d443f71fdb2df78fe4b3cad576d9107518f3b6c5` | `native/evidence/2026-09-09/host-supervision` |
| Hermes r8 | `ae93ce01524b78a824a7a150dfa0367952c98b33c77ef270fce759415098aba2` | `sdks/python/chio-hermes/evidence/2026-09-09/authority` |

These five candidates use kernel `33dd1dea21a4`. The TypeScript candidates use
bridge `7d9e34f7408a`; Hermes r8 uses `b7785282b4f4` with its private complete
outcome verifier. Hermes budget evidence in the authority directory uses r7,
as its artifact record explicitly states. No results across different builds
are silently combined into an accepted matrix.

OpenClaw's actual container boundary probe passed in the running host and a
Node descendant: isolated state writes worked, protected resource/operator
files, Docker socket, control and plugin writes, root writes and direct host
TCP were denied. The trusted relay's TCP positive control succeeded with zero
guest connections observed. Host image for the r2 archive is
`sha256:98404ca86440e10066733abc421e8af82a40571f46d244c0dec14ea99d5a6d08`.
The earlier probe image and exact evidence remain separately recorded in
`native/evidence/2026-09-09/container-boundary`.

Full remaining identity/scope/revocation, fault/cancellation/crash cutpoints,
and supported upgrade/recovery/removal qualification remain open. The public
installer still delivers the incompatible historical CLI. None of these
archives is a published accepted release. Cursor still requires isolated
host authentication and a bounded hosted protocol; Claude requires isolated
Anthropic provider access. Those external inputs do not waive other hosts'
remaining tests or the six-of-six completion requirement.

## Retained candidates, revocation and current Cursor boundary

The four provider-backed hosts each performed a useful write, then an exact
native write attempt after capability revocation received a verified kernel
denial without a new dispatch. After session-credential revocation, each
launcher refused before starting the native host. The latter is explicitly a
preflight case, not fabricated native execution. First harness failures are
retained: it had incorrectly required a tool result when the launcher refused.
In-flight revocation is still a separate unresolved case.

Hermes source `9dc475c60` repairs the native-history cache to bind the complete
outcome instead of proof alone. Its component regression failed before the fix;
235 tests pass after it, with four retained opt-in skips. Cold-installed r9
wheel SHA256 `8b600edd80fdbfa91ca976c264d53ad145b79c49b9ac37c376f6685cfb90c929`
passed its own actual host/provider useful, denial, response-loss/recovery,
approval, budget and revocation cases. It supersedes r8 for current qualification.

Cursor source `3a69f4e` moves the bridge, kernel credential and journal into the
parent and removes the direct kernel TCP route from the guest. Archive SHA256
`d4b9f71aa73300396d28957e6e75111682274ee617056e23ace88527ae38cc4f` installed offline
with an empty cache. The actual pinned CLI discovered four tools. Exact retained
OS-profile probes in a process and descendant denied operator/journal access,
control writes and direct kernel TCP while allowing isolated state and the
parent route; the independent positive listener recorded two connections.
Build, typecheck and 32 tests pass. No authenticated model work is claimed.

Current candidates, the selected kernel, dependency wheelhouse, and exact
filesystem/OpenClaw Docker images are retained outside temporary directories at
`/Users/connor/.local/share/chio-required-candidates/20260909`. Its manifest and
SHA256SUMS identify every selected input. This is local qualification delivery,
not six accepted integrations or a public release. See CANDIDATE-DELIVERY.md.

The retained bundle passed all 44 file checksums. Both saved image archives
loaded successfully. From the relocated bundle, an offline-installed bridge
prepared fresh authority and an offline-installed Codex candidate performed
write/edit/read/list through the copied kernel. After a same-artifact owner
restart, the original authority completed a native read of the retained file
with exactly one new read dispatch and no repeated write. Raw observations are
in `raw/local-delivery`. This verifies a local installation/restart subset,
not cross-version upgrade or six-host release acceptance.

Identity correction: current Claude received-result raw summaries consistently
record host 2.1.267, SHA256
`a681f3008f0050029aeebcab3af51bb6a55ddeb625a3af3141a4416d43cd2558`.
Its artifact summary initially retained the old 2.1.266 inventory label. The
summary is corrected from raw observations; earlier 2.1.266 cases stay separately
bound to their own builds and are not promoted to current-version acceptance.


## Launcher death, live revocation and kernel-failure qualification

Status remains **0/6 accepted**. Confidence is high in the bounded observations
below; complete host acceptance remains unresolved.

Claude's earlier launcher-death probe left its actual native process running
until the test deadline. Source `717cdb0` adds a separate trusted process lifeline;
source `d09f330` retains the exact generated gateway bundles used in the archive.
The new candidate stops the isolated host when its parent dies, preserves the
original resource fence and allows an explicit recovery read without replaying
the write. Its own cold-installed workflow, budget, substituted-result and
response-loss cases pass. Native identity is Claude 2.1.267, not 2.1.266. These
runs use a local Messages fixture; isolated Anthropic qualification is still
blocked. The failed predecessor remains in the host supervision record.

OpenClaw source `3915efa` adds a private Docker lifeline watchdog. The prior real
crash left agent and relay containers running and needed operator cleanup. The
new candidate's forced launcher crash automatically removes only its recorded
containers and network, preserves state/control volumes and retains the
unacknowledged resource fence. Independent inspection confirms container absence.
A failed Docker inventory query yields unresolved cleanup, never false absence.
Nineteen component tests pass with no skips. The current archive ran its own
real native host/OpenAI useful workflow, denials, response loss/recovery, result
substitution, seven approval stages, aggregate budget and revocation cases.
Its image is `sha256:1586b295831a811e4ba890fe466e9397bc44eeff9b77fa41ae740cc845eb4c2d`.
Earlier creation cutpoints and full lifecycle coverage remain open.

Each of Codex, Pi, Hermes r9 and this OpenClaw candidate now has an additional
14-case record in its `kernel-faults` directory, separately classified:

- Two native sessions revoke actual capability or session credentials between
  a successful first write and the second native call. No second write occurs.
  Capability revocation is a verified denial. Credential loss stays unverified
  and unknown because no trusted terminal result was obtained.
- Three native sessions exercise an actual isolated kernel SIGKILL, an injected
  malformed transport response, or a withheld response until timeout. Exactly
  the first authorized write is observed; the second outcome stays unknown.
- Three later native sessions retain each original configuration and journal.
  Replacement writes remain fenced and original unknown records are unchanged.
- Six startup cases refuse an absent kernel, genuinely expired credential,
  incorrect principal/session/resource, or unauthorized fifth tool. These are
  launcher refusals before native startup, not native tool-call denials.

There are 32 native runs and 24 explicit preflight refusals across these four
hosts, with no skips. This is a case count, not a count of accepted gates.
Hermes's first expired-credential run was unrecognized by the harness; the exact
local validation error was checked in source, added to the preflight classifier,
and rerun. Both records remain. Per-host archive identities and evidence paths
are in `raw/live-fault-authority-records.json`; reproducible test procedures are
in `scripts/acceptance/README.md`. Remaining plugin omission/failure, cancellation,
parallelism, authority/evidence variants and lifecycle cases must still be
resolved separately for each host.

The durable bundle now selects the supervised Claude and OpenClaw candidates.
All 44 active file hashes verify. The previous selections are preserved under
`superseded/pre-host-supervision`. The new OpenClaw image loads from its saved
archive; both packages install offline with empty caches. Using the relocated
OpenClaw installation, saved image and copied bundle kernel, the actual host
completed write/edit/read/list with four independent dispatch observations.
Raw local delivery evidence is in `raw/local-delivery-supervision`. Public
publication and six-host acceptance remain open.


## Operator cancellation and the current Hermes wheel

Actual operator SIGTERM after a committed write, before host result delivery,
passed on the unchanged Codex, Pi and OpenClaw candidates. Each reported unknown
or unresolved, retained the original fence and completed an explicit recovery
read without another write. The exact cutpoint appears in each host's
`operator-cancellation` record; the reused driver retains its older
`host-response-loss` scenario label. It is not an additional ordinary loss test.

Hermes r9 failed that test: its Python launcher exited on SIGTERM without a
terminal report after one committed write. Source `d0062596d` handles cancellation,
forwards it to the isolated native process group, stops remaining descendants
and writes the truthful terminal outcome. The current r10 wheel SHA256 is
`660d3bb2be90a1096eef0daed2701ba3c1b461a8a0e5e43a79f011f165423215`.
It independently passed cancellation/recovery, useful work, denials, response
loss/recovery, private gateway crash, budget and approvals, plus the complete
14-case authority/kernel-fault subset described above. Source and evidence are
committed as `d0062596d` and `425092599`. Its component suite passes 236 tests;
four legacy opt-in skips remain explicitly unresolved. Prior r9 results are
historical, not substitutes for these r10 executions.

The durable bundle now selects r10 and retains r9 under `superseded/hermes-r9`.
It includes Hermes's exact qualified bridge archive `b7785282b4f4`, installed
under a separate `hermes-bridge` prefix. Other hosts continue using their pinned
bridge builds. All 45 selected bundle checksums pass. The wheel and bridge
installed offline with no cache; pip check passed. From those relocated files,
the actual Hermes/OpenAI host completed write/edit/read/list through the copied
kernel, with four independent dispatch observations. Raw evidence is in
`raw/local-delivery-hermes-r10`. This closes another installation subset, not
public release or full upgrade/removal acceptance. All six remain unaccepted.


## Native evidence substitution and current container qualification

The current Codex, Pi, Hermes r10 and OpenClaw candidates each passed three
additional native evidence-negative sessions and three original-authority
fenced restarts. Each initial session performs two legitimate kernel writes.
The transport then substitutes either the first call's intact valid signed
receipt into the second response, an altered signing key, or a mismatched
request ID. Every second result is rejected as unverified unknown. Its delivery
is not acknowledged. The later replacement write remains fenced and the
original unknown record remains unchanged. The independent observer records
the two original authorized writes, then zero new restart effects. These are
I06/I07 subsets, not a claim of preventing an already authorized original effect.
Per-host archive identities and committed raw records are in
`raw/native-evidence-binding-records.json`.

OpenClaw's delivered current image `1586b295831a` also passed a fresh boundary
probe while its actual native host performed kernel reads. Independent processes
and a Node descendant each passed ten confinement checks. Operator files,
protected resource mounts, Docker socket, control/plugin/root writes and direct
host TCP were inaccessible; isolated state remained writable. A trusted-relay
positive connection succeeded and zero guest connections reached the observer.
This rerun is bound to the current image, rather than borrowing the earlier
`98404ca86440` image's boundary result. Record:
`native/evidence/2026-09-09/container-boundary-current`.


## Signed owner-result recovery without redispatch

Bridge source `52f80517af3fce948a3cbc9c9bb485fcdac7dd04` adds an operator-only
importer for completed signed owner records absent from a host's verified cache.
It verifies the retained original caller, session, capability, resource, request,
trusted signer, result and delivery proof. It preserves the original unknown
outcome and does not dispatch, acknowledge or release the fence. A separate
explicit export/read/acknowledgement step is still required. The standalone
owner exporter reads SQLite in read-only mode. No kernel or wire change was
needed. The bridge suite passes 131 tests with zero skips.

Each current Codex, Pi, Hermes r10 and OpenClaw candidate independently passed
an actual native two-write evidence-substitution session, followed by signed
owner recovery and one successful native read. Each rejected a forged owner
signature with unchanged journal and effects. Export, import and explicit
acknowledgement produced zero resource dispatches; the original write was never
repeated. Four missing-owner-completion negatives refuse export and preserve the
original unknown records. Exact per-host evidence commits and artifact hashes
are in `raw/signed-owner-recovery-records.json`. These are I06/I07 subsets.

The separate operator bridge archive SHA256 is
`02a0e4ad4e61ffb989302cae8774a9ae9ab8f647473f1926d1e671673169a37b`.
It and the standalone exporter are included in the local candidate bundle;
host runtime archives remain unchanged. The documented procedure requires the
original private authority and never creates a replacement session for recovery.

Claude's current official gateway documentation explicitly states that routing
Claude Code to non-Claude models is unsupported. The available OpenAI credential
therefore does not supply a supported substitute for the missing isolated
Claude-provider credential. Source checked 2026-09-09:
<https://code.claude.com/docs/en/llm-gateway>. Cursor authentication and its hosted
execution boundary remain separate blockers. All six remain unaccepted.

All 47 selected bundle file hashes verify. The operator archive installed offline
with an empty npm cache. The relocated bundle exporter, operator bridge, Codex
package and copied kernel passed a fresh native fault/recovery run: two original
authorized writes, zero operator dispatches, one recovery read and no repeated
write. Evidence is in `raw/local-delivery-owner-recovery`. This qualifies the
local documented recovery path, not public release or full lifecycle acceptance.
