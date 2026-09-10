# Required-host qualification tools

These scripts are operator test drivers. They are not production host plugins
and must only target dedicated test owners and disposable host profiles.
Credentials remain in the private owner directory. Never use the legacy
normal-home smoke cleanup scripts.

`host-approvals.py --help` lists the supported host, suite and path inputs.
Use a cold-installed candidate directory and a live disposable resource owner:

```sh
python3 scripts/acceptance/host-approvals.py \
  --host codex --suite kernel-killed \
  --operator-state /absolute/private/test-owner \
  --package-dir /absolute/install/node_modules/@chio/codex-plugin \
  --model-auth-file /absolute/private/codex-auth.json \
  --output /absolute/new/evidence
```

The driver launches the real host with an isolated profile. It requires the
intended native tool attempt and returned result, independently observes the
resource volume and dispatch audit, and retains every observed native attempt.
Kernel death targets the exact recorded test PID only after checking its binary
and database path. The owner restarts with the same databases after observation.
Malformed and timed-out responses are injected at the trusted gateway transport;
they are not synthetic tool calls or evidence of unmodified kernel behavior.

`--model-auth-file` selects the parent-only native ChatGPT subscription cache
for Codex, Pi, Hermes and OpenClaw. Each adapter maps it to its pinned native
provider contract; it is never a guest-readable API-key file. Claude uses
`--model-auth claude-login` through its trusted native-login helper and the fixed
Anthropic endpoint. No test driver copies credentials into evidence. Missing
native authentication is a failed run, not permission to invent model output.

Claude forbidden-write and approval-resume cases additionally use
`force-declared-tool.mjs`. It requests the actual provider's documented
[declared-tool selection](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools)
for a tool already present in the native request. It does not modify tool
arguments or fabricate assistant output. Its per-case log identifies the
selection; the native tool call and independent effect observations still
determine whether the case passes. Ordinary model refusals without a tool
attempt remain failed test coverage.

`in-flight-capability` and `in-flight-credential` revoke actual authority between
the first completed native write and the next native request. The private
injector never forwards administrative credentials to a guest or logs them.
`kernel-killed`, `kernel-malformed` and `kernel-timeout` retain unknown outcomes.
Verify their original fence using the configuration recorded in identity.json:

```sh
python3 scripts/acceptance/host-approvals.py \
  --host codex --suite resume-fence \
  --existing-config /absolute/original/private/gateway.json \
  --operator-state /absolute/private/test-owner \
  --package-dir /absolute/install/node_modules/@chio/codex-plugin \
  --output /absolute/new/resume-evidence
```

This mode does not prepare replacement authority or clear a journal. It requires
the original unknown record to stay unchanged and no new resource dispatch.

`kernel-absent`, `expired-credential`, `wrong-principal`, `wrong-session`,
`wrong-resource`, and `scope-escalation` exercise launcher preflight refusal.
These cases must not be labeled native host tool denials. The credential expiry case waits
for a genuinely issued five-second credential to expire; the other binding
cases keep the real credential while altering the claimed binding or scope.

`expired-capability` is separate. Pass `--existing-config` and
`--capability-expiry-binding` from the short-lived capability preparation. The
driver checks the actual retained owner capability, verifies that the delegated
credential was clamped to its expiry, waits for real-clock expiration, and
requires startup refusal with zero new resource dispatches. It does not claim a
live delegated credential can outlast its capability.

`forbidden-edit`, `secret-dry-run`, `secret-list`, `secret-path-alias`, and
`forbidden-write-alias` cover alternate paths through the four supported tools.
Each requires the exact native arguments, verified kernel denial and unchanged
independent resource observations. Claude's declared-tool selection helper also
applies to these cases when the model would otherwise refuse without a call.

`approvals` needs the separate owner policy requiring confirmation for all four
tools. `revocation` checks native capability denial followed by revoked-credential
startup refusal. Concurrent tests must use different owners or their independent
dispatch counts will be contaminated. Required cases that fail or cannot run
remain unresolved. Passing these subsets does not close I01-I08.


`cancel-host-response.mjs` is used by each host's response-loss driver with
`CHIO_CANCEL_HOST_KIND=self` (or `hermes` for its private Node gateway). The
fault record identifies an actual SIGTERM to the isolated trusted launcher
after a committed effect but before host delivery. Preserve the driver's raw
case label and record the cancellation cutpoint explicitly.

`evidence-foreign-receipt`, `evidence-wrong-signer`, and `evidence-request-id`
perform two legitimate native writes. The second kernel response is altered
before the bridge verifies it. The foreign-receipt case reuses the intact
signed receipt from the first actual successful native call. Independent
observation must see two authorized effects, an unknown second result and no
second acknowledgement. Follow each with `resume-fence` using its original
configuration. These cases test evidence rejection, not pre-effect denial of
the two authorized writes. They do not resolve unknown outcomes automatically.


`recover-owner-result` requires `--existing-config` from an original native
unknown or pending operation and `--operator-bridge` pointing to the separately installed
signed-owner recovery candidate. It exports the owner's retained signed row,
requires forged-signature rejection without journal changes, imports the valid
completion while preserving its fence, reads the exact exported result, and
acknowledges it explicitly. The actual host then performs one read with no
repeated write. `--owner-exporter` selects the delivered standalone exporter for
relocated installation testing. Missing owner completions remain unresolved.
This suite never prepares replacement authority or retries the original write.
For a pending journal record whose completion write failed, the imported record
retains `previousState: pending` and `previousOutcome: null`; it must not invent
an earlier unknown outcome. Missing operator code is a setup failure, not proof
of forged-signature rejection.


`concurrent-owners` pauses the first actual native call before kernel transport,
then attempts a second launcher using the same configuration. The second must
refuse startup with no resource effect or journal-lock change. After release,
the original call and a subsequent native read must succeed. This covers
exclusive ownership across concurrent launchers, not every sibling-call schedule.

`aggregate-budget` uses the separate three-invocation owner. Four native sessions
retain the same issued grant and original kernel session while requesting write,
edit, read, and list. Exactly three dispatches succeed; the fourth native call
must be a verified denial with no fourth resource dispatch. This test does not
replenish the grant between sessions or rely on a model continuing a four-step
workflow unprompted.
