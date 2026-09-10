# Shared kernel qualification

This runner exercises the real `chio mcp serve-http` process and the pinned
Docker filesystem resource used by the required six-agent program. It is
shared-contract evidence. It does not qualify any agent host or establish
I01/I08 installation and release acceptance.

Prerequisites are Python 3, Docker, the qualified Chio binary, and the
`chio-required-agent-filesystem:20260909` image built from the adjacent
`filesystem/` delivery inputs. The run records the binary SHA-256, declared
source revision, image identity, operating environment, policy, complete MCP
responses and independent resource observations.

```sh
python3 shared_kernel.py \
  --binary /absolute/path/to/qualified/chio \
  --source-revision FULL_SOURCE_COMMIT \
  --image sha256:FULL_QUALIFIED_RESOURCE_IMAGE_ID \
  --output /tmp/chio-shared-qualification-UNIQUE
```

Pin the qualified resource image explicitly. A mutable local tag can select an
older server without the independent dispatch observer. Before starting any
kernel or creating resource volumes, the runner requires the audit wrapper as
the image entrypoint and verifies its bytes against the adjacent delivery
source. This identity check does not replace the actual dispatch observations.

Use `--cases grant-budget,parallel-grant-budget` to rerun specific cases.
The output directory must not already exist. Each case creates its own port,
random Docker volume, agent token, distinct administrator token and database
directory. The agent token is never printed. Private database state is stored
under a directory with mode 0700 and must not be committed or shipped as public
evidence. The runner cleans only the Docker resources it created. It does not
modify agent profiles or stop other kernel processes.
Unknown case names are errors. Assertion or cleanup failure, or replacement
of the tested binary during the run, makes the runner exit nonzero. The exact
driver and barrier source are retained beside each run's manifest.
An independent-observer or cleanup failure also sets that case's manifest
status to `failed`, even when its earlier request assertions passed. Failure
records name the retained disposable volumes for operator reconciliation.

Cases:

- `authority-replay`: useful write; changed-request replay rejection; forbidden
  file and alternate-tool scope denial; administrator-token separation; wrong
  bearer and session rejection; same-session duplicate suppression; restart
  with unchanged authority and original receipt replay; durable revocation;
  explicit fresh operator-issued authority restores useful work.
- `capability-expiration`: a useful write before expiration and no file effect
  for a new request after expiration.
- `unknown-after-dispatch`: the actual resource commits a file; a stdio proxy
  holds its real reply before the kernel sees it; the kernel is killed and
  restarted; retry with the same session and request does not redispatch.
- `cancellation-after-dispatch`: the same independently observed cutpoint is
  cancelled through MCP, then restarted and retried without redispatch.
- `approval-artifact-rejection`: a useful unrestricted read, denied write
  without required approval intent, and rejection of a malformed approval
  token, with no resulting files. Real pending/rejected/approved operator
  workflows remain unresolved by this case.
- `approval-workflow`: durable operator pending/reject/approve, wrong admin
  credential rejection, exact arguments, immutable decisions, expiration,
  record integrity, revoked capability, useful approved execution, and signed
  outcome replay after restart. See [APPROVALS.md](APPROVALS.md).
- `approved-unknown-after-dispatch`: a legitimately approved resource effect
  occurs before the kernel receives its result; restart and retry with the
  original approved request preserve the effect's unknown outcome and the
  independent sentinel.
- `bounded-approval-workflow`: the complete operator workflow using the native
  `approval-policy.yaml` with a single 64-invocation grant, including direct
  missing-approval prevention. Every listed tool requires approval in this mode.
- `approved-grant-budget`: approved write and read share one two-invocation
  wildcard grant; restart and a new approved token cannot authorize a third
  effect after the quota is exhausted.
- `grant-budget`: one wildcard grant's two-invocation quota spans different
  tools, remains exhausted after restart, and explicitly demonstrates that
  fresh session issuance grants a new quota.
- `parallel-grant-budget`: four concurrent writes share a two-invocation
  grant; exactly two resource files may appear and restart does not replenish
  that grant.

The observer runs separately from the kernel and reads the Docker volume. For
retry tests it replaces the first result with an independent sentinel; any
redispatch would overwrite that sentinel and fail the case. The response
barrier is test instrumentation outside the kernel. It forwards real JSON-RPC
to the filesystem server and retains the server's actual result; it does not
invent resource success or a kernel verdict.

## Interpreting outcomes

`passed` means the bounded assertions named above passed. All I01-I08 cases
must still run independently through every required host. These cases do not
prove signed receipt verification by an installed host plugin, operating
system isolation of a host, kernel-process tamper prevention, approvals through
an actual agent host, or publication of compatible artifacts.

The selected CLI creates a new capability for each newly admitted session.
`max_invocations` is keyed by capability ID and grant index. Multiple explicit
grants have separate quotas. A single wildcard grant shares a quota across its
tools, with an explicit tool allowlist controlling availability. The session
admission credential must stay outside the untrusted host, and the trusted
gateway must retain the operator-approved session. Giving the host that bearer
credential lets it obtain fresh quota by initializing another session.

A retry denied because the original operation is retained as
`OutcomeUnknownAfterDispatch` does not mean the original effect was denied.
The runner deliberately observes an effect before triggering that condition.
Current retry receipts encode the retained state in the signed denial reason;
they do not carry structured admission-state metadata. Consumers must preserve
the original unknown outcome. An unsigned duplicate rejection also does not
establish no original effect. Successful replay after restart returns the
original signed receipt and preserves the observer's sentinel.
