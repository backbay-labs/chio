# Required agent integration resource profile

This is a qualification candidate for the six mandatory integrations in
[document 19](https://github.com/backbay-labs/chio/blob/codex/required-agent-integrations-20260909/docs/strategy/chio-direction/19-priority-agent-integrations.md). No host is
accepted merely by installing this profile. See the per-host acceptance records.

The resource owner runs the official MCP filesystem server in a container with
only its designated workspace volume. The kernel owns the container's stdio.
The resource entrypoint rejects symbolic links, hardlinked files and special
files before starting the server. Stop all owners before importing a workspace;
the operator must not mutate the volume concurrently with an agent session.
The four exposed tools cannot create filesystem aliases. An operator-only audit
volume records and fsyncs every forwarded tool request before the filesystem
server sees it. An audit failure stops forwarding. This independently observes
reads without disclosing their contents in the audit log.
The agent receives four tools through a pinned Chio gateway: `read_text_file`,
`write_file`, `edit_file`, and `list_directory`. It receives neither the resource
mount nor the Docker socket. A host-specific launcher must disable or confine
all other consequential paths. Running a normal agent with an advisory hook
does not establish that boundary.

The selected policy uses one grant, shared across tool names, with 64 invocations,
a one-hour capability TTL and no delegation. The gateway exposes only the four
selected tools even though the upstream resource server implements more. Creating
a fresh kernel session issues fresh authority and a fresh counter. The bearer
that can initialize sessions therefore belongs only to the operator. Preparation
exchanges it for a separate credential restricted to one retained session and
four tools. The guest credential cannot initialize sessions, issue authority,
reach admin APIs or select another session. Budgets are per issued grant, not a
global account budget. Credential rotation preserves the same grant and fence.

## Select the qualified RC artifacts

Use the checksummed kernel and resource image selected by the companion delivery
manifest. The candidate CLI version is `0.1.1-rc.1`. The historical public CLI
`0.1.0` and the older debug candidate with the same version label are not this
combination. Neither version text nor an arbitrary rebuild is a release identity.

Run `python3 verify.py verify-bundle --bundle . --images` from the assembled
bundle before creating installs or runtime state. This verifies the complete
local artifact inventory, image blobs and pinned image identity. The separate
release signature and provenance procedures establish publisher/source trust;
checksums alone do not. Real-host acceptance and public delivery remain pending
until their exact selected-artifact records are complete.

The local static auditable candidate was built from source
`bafa02b06de93553cecb6f60b340f3dd8fd9b401`, reports `chio-cli 0.1.1-rc.1`,
and has binary SHA256
`c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`.
This is a local qualification artifact. A later hosted release build can have
a different hash and requires its own artifact qualification. Source metadata
or a version label cannot promote this local binary into a signed public release.

The filesystem Dockerfile pins its base image and public npm lockfile. The
bundle ships its saved OCI image, so installation does not need a private image
registry, a sibling SDK checkout, or an unrecorded image rebuild. Load and use
its exact `imageId` from `manifest.json`.

Copy the selected executable to an immutable artifact path before starting it.
Pass its independently recorded SHA256 and the immutable Docker image identity:

```sh
python3 resource-owner/serve-filesystem.py start \
  --state-dir /absolute/private/chio-owner-example \
  --kernel /absolute/artifacts/chio \
  --kernel-sha256 REPLACE_WITH_RECORDED_SHA256 \
  --image sha256:REPLACE_WITH_IMAGE_ID \
  --volume chio-required-example \
  --port 58483
```

Create the operator parent directory with mode 0700 first. Every supported host
sandbox must deny this directory, historical operator state in `/tmp`, and all
other host profiles. A mode-0600 file alone does not isolate same-user processes.
The launcher refuses an existing resource or audit volume or state directory. It creates private
operator credentials, snapshots and hashes the policy, and starts a durable kernel owner.
Use `--policy /absolute/selected-policy.yaml` for a separately qualified policy,
such as the explicit-confirmation qualification policy. Restart rejects changes
to that snapshot.
A listening process alone is not readiness. `prepare-session.py` waits up to
60 seconds for the existing operator's trusted signer before creating a new
session directory or making a network request. It checks private owner state,
the recorded executable SHA256, actual live process and exact session database
command, and a protected regular signer file. Use `--readiness-timeout-seconds`
only for an explicitly selected bounded deadline (maximum 300 seconds). A timeout,
changed identity or dead process fails closed and preserves the owner without
retrying preparation. Authenticated MCP preparation must then also succeed.
Preserve failed startup databases and logs for diagnosis.

## Prepare a host

Install the checksummed `@chio/bridge` candidate tarball using its packaged
instructions. The tarball includes the compatible unpublished SDK candidate;
the supported candidate path must pass an independent consumer installation.

Create a mode-0600 operator request containing these fields:

```json
{
  "endpoint": "http://127.0.0.1:58483",
  "bearerToken": "OPERATOR_AGENT_TOKEN",
  "adminToken": "DISTINCT_OPERATOR_ADMIN_TOKEN",
  "credentialTtlSeconds": 3600,
  "trustedSigners": ["PUBLIC_KEY_FROM_TRUSTED_KERNEL_STATE"],
  "serverId": "fs",
  "sessionId": "OPERATOR_SELECTED_HOST_SESSION_UUID",
  "journalDir": "/absolute/private/host-journal",
  "allowedTools": ["read_text_file", "write_file", "edit_file", "list_directory"]
}
```

Use the public key from `sessions.sqlite.admission.kernel.pub` in trusted operator
state, not a key supplied by an unverified receipt. `endpoint` is the base origin;
the SDK appends `/mcp`. Never append `/mcp` twice. The operator token is in the
private `operator.json`; never copy that file into public evidence.

```sh
chio-prepare-gateway /absolute/private/request.json /absolute/private/gateway.json
```

Preparation establishes and pins the actual caller, capability, resource owner
and retained kernel session. It authenticates the delegated credential's scope
against that session and stores only the delegated bearer in the private gateway config.
It performs no protected tool action. The restricted launcher loads this file
outside the guest sandbox and starts the packaged `startGatewayHttp` transport
in its own process. The guest receives only an ephemeral loopback transport token,
with no direct kernel egress or access to the gateway config or journal. Closing
or killing the launcher removes this resource route. The delegated context must
advertise delivery acknowledgement version 1. Do not enable other MCP servers, native shell, custom tools,
delegation, background jobs or administrative commands in this mode.

## Observe and recover

Observe effects independently using an operator-only read-only container mount:

```sh
docker run --rm --network none --read-only \
  --mount type=volume,src=chio-required-example,dst=/observe,readonly \
  --entrypoint node sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0 \
  -e 'const fs=require("fs"); console.log(fs.readFileSync("/observe/example.txt","utf8"))'
```

The gateway persists an operation fence before dispatch. Unknown outcomes and
denials retain that fence. A denial can reject a retry of an action that already
took effect; it does not prove the original action had no effect. Do not remove
journals, change request identities, clear locks, or create replacement sessions
to retry an uncertain action. Reconcile the resource and the durable kernel
ledger first. Automatic unknown-outcome resolution is not supplied by this
candidate. The bridge offers `chio-gateway-operator status CONFIG` and
`chio-gateway-operator recover-lock CONFIG`. Recovery requires the recorded
process to be dead on the same machine, protects against concurrent recovery,
and preserves every operation record. It does not clear an unknown outcome. The companion bundle README instructions describe signed owner-result import and explicit delivery acknowledgement when the owner retained a verified completion.

The kernel keeps completed-but-unacknowledged calls fenced. The bridge verifies
and durably records the exact response before acknowledging it. An exact replay
returns the retained response without dispatching it again. Credential rotation
and restart preserve the owner fence. A fresh host transport uses a new RPC
namespace while retaining the same kernel authority and operation journal.

Retained MCP sessions expire after 15 minutes of inactivity by default, which
can precede a delegated credential's expiry. Preparation is not a lease extending
that idle limit. An expired session refuses new effects and is terminal; do not
automatically initialize a replacement to retry uncertain work. Reconcile the
prior session before the operator authorizes an independent new session.

```sh
python3 resource-owner/serve-filesystem.py stop --state-dir /absolute/private/chio-owner-example
python3 resource-owner/serve-filesystem.py restart --state-dir /absolute/private/chio-owner-example
```

Restart preserves the database, policy snapshot, signing identity and resource
volume. It refuses a changed binary hash. An upgrade needs a new qualified
artifact, a retained-state backup and host-specific upgrade tests. Do not replace
the executable or policy of a running owner. Removal starts by stopping the host
and kernel and revoking authority. Retain evidence and unresolved operation
state. Explicitly remove only the designated test container/volume after the
operator has resolved outstanding outcomes; the launcher never deletes them.

Read the independent dispatch log through a separate read-only observer mount of
`chio-required-example-audit`, at `/observe/dispatch.jsonl`. Compare counts for
the exact tool and path before and after each forbidden-read case. Include an
allowed-read control that produces an observation. The dispatch log is neither
a kernel receipt nor proof that a dispatched action completed; retain both the
kernel evidence and the independent resource observation.

Published release qualification, real pending/rejected/approved transaction
workflows, complete host recovery and all applicable I01-I08 cases remain gates.
