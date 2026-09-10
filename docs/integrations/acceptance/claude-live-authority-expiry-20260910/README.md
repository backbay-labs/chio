# Claude live capability-bound authority expiry

This is one passing native Claude expiry case for I05. It does not close Claude's
entire I01-I08 matrix, qualify another host, or transfer to another artifact hash.
The archive is the frozen local 0.3.1-rc.1 candidate. No credential was fabricated,
rewritten or made artificially expired, and the runtime transport deadline was
not increased.

## Exact candidates

- Kernel CLI 0.1.1-rc.1, source `bafa02b06de93553cecb6f60b340f3dd8fd9b401`,
  SHA256 `c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`.
- Claude plugin archive 0.3.1-rc.1, source `16624ede65015be091e91b7c29213425d5e2517e`,
  SHA256 `1258385647d228ebeed32662091ed721aeda3b60450cabae480ca0d4292fbe0a`.
  All 1,227 regular installed files matched this archive before execution.
- Native Claude Code 2.1.267,
  SHA256 `a681f3008f0050029aeebcab3af51bb6a55ddeb625a3af3141a4416d43cd2558`,
  model `claude-sonnet-5`, existing native Max authentication via the trusted
  parent Messages relay.
- Filesystem resource image
  `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
- Fixture source `7df0bd46d841e20f1e767e5ff79d9fdfb5937dc6`.
  macOS 26.4 arm64, Node v25.5.0, Python 3.14.4, Docker 28.3.3.
  Docker guest had 2 CPUs and 4,095,369,216 bytes of memory; this case ran serially.

## Observed behavior

The real owner issued a signed 20-second capability. The gateway requested a
900-second delegated credential; the real kernel clamped its expiration to the
capability's expiration. The fixture independently read the owner SQLite
capability and bound its ID, subject, signature and lifetime to the prepared
session credential. The original private configuration retained the same hash.

Claude successfully wrote the requested content, with a verified signed terminal
receipt and delivery ACK. Its second native call targeted the same exact path
with replacement content. The fixture held that actual second HTTP request while
its authority was still valid, then released its original body, normalized
headers, method and AbortSignal to the original kernel endpoint after expiry.
The unchanged 30-second SDK deadline did not abort.

| Observation | Actual value |
| --- | --- |
| Held while valid | 1789026354509 ms since epoch |
| Capability and credential expiry | 1789026365000 ms since epoch |
| Released to kernel | 1789026366003 ms since epoch |
| Kernel response | 1789026366018 ms since epoch |
| Hold duration | 11,494 ms |
| Kernel HTTP status | 401 |
| Native tool calls | 2 |
| Positive resource dispatches | 1 |
| Expired request dispatches | 0 |
| Qualification exit / timeout | 0 / false |
| Total qualification wall time | 21.071661667 seconds |

The kernel returned `WWW-Authenticate: Bearer` and the exact plain response body
`invalid, expired, or revoked session credential`. This is capability-bound HTTP
authority expiry. HTTP authentication rejects the expired delegated credential
before kernel capability evaluation; this case does not claim a signed
`CapabilityExpired` admission receipt. The bridge truthfully returned
`unknown` with `unverified` evidence for the unadmitted request, and native Claude
received that same request-bound result with its tool error flag set. It did not
ACK or retry the unknown request.

Independent read-only mounts observed the original successful content and exactly
one resource dispatch. The replacement content never appeared. The first success
also contained a masked filename in sanitized output; Claude retained the exact
path from its original known arguments for the subsequent authorized request.

## Reproduction and controls

The retained `native/start-command.json.gz`, `native/policy.yaml.gz` and
`native/qualification-inputs.json.gz` contain exact commands, candidate paths and
selected hashes. Create a new owner directory, unused TCP port and new dedicated
resource and audit volumes. Never reuse or reset these retained stores. After
starting the real owner with the short-lived policy, run the committed driver:

```sh
python3 scripts/acceptance/host-approvals.py --suite in-flight-expiry \
  --host claude --operator-state /absolute/fresh/owner \
  --package-dir /absolute/verified/installed/@chio/claude-code-plugin \
  --output /absolute/fresh/output
```

The same driver has explicit native result readers for Codex, Pi, Hermes and
OpenClaw, but each host requires its own real execution and evidence. A missed
live authority window, a hold over 21 seconds, an aborted original signal, a
changed request/header/identity, a non-401 response, missing native returned
outcome, or a resource dispatch fails the case. Do not increase a product timeout
to accommodate a test setup. The signed capability and delegated credential must
actually exist before the real host starts; short TTL must still leave enough
startup time for both real native tool calls.

Seven bounded fixture controls passed, with zero skips. They verify preserving a
real mocked response (including an unexpected allow), rejecting a wrong caller,
wrong actual MCP session or mutated header, refusing a missed live window, and
preserving cancellation without forwarding a cancelled request. These controls
are synthetic and are not native acceptance evidence. An initial five-control
development invocation failed the cancellation control because its one-second
wall-clock setup expired before the Node process reached the first mocked call.
The unit-test-only clock was made deterministic, then the controls passed. That
initial tool output was not saved as a raw file and is not reconstructed here.
The real native fixture continues to use actual wall-clock time.

Full local discovery ran 33 controls and retained one existing readiness test
error. Its Python 3.14 framework launcher re-executes a different native binary,
so the production exact process-identity check correctly rejects the test's
incorrect expected executable and argv. This checkout and record preserve that
failure. The parent workstream owns the separate fixture repair; no passing
33-control result is claimed here.

## Retained state and evidence

The completed owner at port 59227 was stopped through the identity-checked
helper. Protected file hashes, every SQLite table's logical row digest, and the
independent file/dispatch observation stayed unchanged. Both volumes remain. The
immediate cleanup observer saw the resource container still exiting and retained
its failed cleanup record. A later separate read-only observation confirmed no
owner process or labeled container remained. No further signal, recovery,
reconciliation, ACK, journal clearing or store reset was performed.

`manifest.json` binds every compressed raw member to its original path, length
and original and compressed SHA256. `SHA256SUMS` binds the delivered record.
Private operator/gateway configurations, raw private databases, signing keys,
authentication stores and installed dependency trees are not exported; selected
public identities, exact configuration hashes and complete installed-file hashes
are retained. Exact-value credential scanning covers every exported plain or
decompressed member against designated operator, delegated session, provider and
npm credentials. No required native case was skipped in this bounded run.
