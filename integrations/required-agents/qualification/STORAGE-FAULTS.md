# Actual kernel storage failures

`storage_fault.py` creates single-use, disposable resource owners. It exercises
the selected kernel and real Docker resource, without modifying kernel code,
database rows, database schemas, or clocks. These shared prerequisites do not
establish acceptance for any agent host. Each host runs its own supported launcher
and retains its own result, journal, owner state, and independent observations.

## Create an isolated case

Supply the explicitly selected artifacts and a fresh port/name:

```sh
python3 storage_fault.py create --name HOST-CASE --port PORT \
  --kernel /absolute/chio --kernel-sha256 RECORDED_SHA256 \
  --image sha256:RECORDED_RESOURCE_IMAGE \
  --policy /absolute/filesystem-policy.yaml \
  --owner-launcher /absolute/serve-filesystem.py \
  --bridge /absolute/installed/node_modules/@chio/bridge
```

Use a lowercase case name. The default private owner parent is
`~/.local/share/chio-required-operators/kernel-storage-fault-20260909`; the default
evidence parent is `/tmp/chio-kernel-storage-fault-20260909`. Override these parents
explicitly for a new qualification run. Existing case directories and resource
volumes are refused. The helper records artifact and helper identities, prepares
a scoped session credential, and prints the private gateway path.

The only transport alteration is the existing `stdio_response_barrier.py`, which
holds the genuine resource response for `/workspace/uncertain.txt`. The kernel,
resource implementation, and policy are unchanged. This barrier runs at the
trusted test owner and is absent from ordinary delivery configurations.

## Before admission

Start this in a separate process and wait for `fault-locked.json`:

```sh
python3 storage_fault.py fault --name HOST-CASE \
  --cutpoint before-admission --hold-seconds 600
```

Then invoke the real host with the prepared gateway and request one write to
`/workspace/before-fault.txt`. The helper holds `BEGIN IMMEDIATE` on the actual
`sessions.sqlite.admission`. Reads remain available, while admission writes fail
after SQLite's busy bound. Record the response and independently establish zero
new resource dispatches and no file. A caller can conservatively report unknown
even when the independent observer establishes that this attempt had no effect.

## After a real effect

Start the controller first, then invoke the real host to write
`/workspace/uncertain.txt`:

```sh
python3 storage_fault.py fault --name HOST-CASE \
  --cutpoint after-receipt --wait-seconds 600 --hold-seconds 600
```

The controller waits for the real resource response. It independently reads the
file and resource dispatch audit, acquires a write transaction on the actual
`receipts.sqlite`, then releases the genuine response. Receipt append failure
therefore occurs after an observed resource effect. The required result is a
truthful unresolved caller outcome, no delivery acknowledgement, and no automatic
redispatch. It cannot establish prevention of the original write.

`--cutpoint after-admission` instead holds the durable admission/outcome database
at the same post-effect cutpoint. This distinguishes a missing durable outcome
from failure to append a receipt after the outcome was already stored.

## Release, inspect, and recover

```sh
python3 storage_fault.py unlock --name HOST-CASE
python3 storage_fault.py snapshot --name HOST-CASE --filename after-unlock.json
```

Unlock performs `ROLLBACK` on the test connection. It changes no rows or schema.
The bounded timeout also releases this connection if the operator does not
unlock. Snapshots read the resource and audit in a separate read-only container,
and read relevant SQLite state without modification. Binary SQLite values are
represented as hexadecimal bytes. Snapshot files refuse overwrite.

Retry the exact request and attempt a fresh request through the same host/session.
Preserve any unknown journal and signed owner fence. Restart using the supported
owner launcher, retaining all databases, credentials, and volumes, then repeat
the same checks. No extra dispatch is permitted. Do not generate a replacement
session, acknowledge an unknown outcome, or delete evidence to obtain progress.

Positive controls must be separate or fully delivered and acknowledged before
arming a fault. Otherwise an existing pending-call fence can intercept the test
before the selected storage failure occurs.

## Selected software signer boundary

The qualified binary source is `d8c5f53705173e614a853bad6c0a85acfdf1212b`.
Source inspection found the following ordinary hosted MCP path:

- `remote_mcp/session_core/factory.rs:176-183` passes the durable in-memory key to
  `build_kernel` and configures the receipt store.
- `chio-control-plane/src/lib.rs:369-399` constructs `KernelConfig` with that key.
- `chio-kernel/src/kernel/responses/allow_responses.rs:58-114` constructs receipt
  content from tool output, signs, and then persists the allow receipt.
- `responses/receipt_persistence.rs:77-81,174-190` selects the configured key and
  calls `sign_receipt_with_handle` using `Ed25519Backend`.
- `chio-core-types/src/crypto.rs:194-199` returns `Signature` directly;
  `Ed25519Backend::sign_bytes` at `997-999` is `Ok(self.keypair.sign(message))`.

This selected primitive has no external signer, network dependency, key-file
reread, timeout, or recoverable signing-error branch. The optional signing queue
is a separate API and is not invoked by ordinary hosted MCP tool evaluation.
Deleting an already loaded seed would not demonstrate an unavailable signer.
Kernel termination is an interruption case, not a cryptographic signing outage.

Receipt coupling, preimage hash/key matching, semantic validation,
serialization/canonicalization, and persistence can still fail. Their rejection
branches are respectively in `receipt_persistence.rs:3-12,153`,
`chio-kernel-core/src/receipts.rs:74-102,136-145`,
`chio-core-types/src/receipt/body.rs:161-176,247-250,302-307`, and
`chio-core-types/src/crypto.rs:927-933`. A source branch does not prove that a
selected real host can trigger it. The storage cases above exercise actual
runtime failures. They do not claim a synthetic failure of the infallible
software Ed25519 primitive.
