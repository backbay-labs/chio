# Real kernel storage fault handoff

Helper: `/Users/connor/Medica/backbay/standalone/arc/.worktrees/mcp-execution-evidence-20260909/integrations/required-agents/qualification/storage_fault.py`. Each case creates a new single-use owner with isolated DBs and Docker volumes. No existing owner is modified. Port coordination: operator cases58506-58509; Pi58512-58513. Root coordinates other host ports.

## Create

Replace CASE and PORT (fresh lowercase name, distinct port).

```sh
python3 /Users/connor/Medica/backbay/standalone/arc/.worktrees/mcp-execution-evidence-20260909/integrations/required-agents/qualification/storage_fault.py create \
  --name CASE --port PORT \
  --kernel /tmp/chio-tool-error-ack-candidate-20260909/chio-33dd1dea21a4 \
  --kernel-sha256 33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25 \
  --image sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0 \
  --policy /Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/integrations/required-agents/filesystem-policy.yaml \
  --owner-launcher /Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/integrations/required-agents/serve-filesystem.py \
  --bridge /Users/connor/.local/share/chio-required-candidates/20260909/install/operator-bridge/node_modules/@chio/bridge
```

Outputs private gateway path under `~/.local/share/chio-required-operators/kernel-storage-fault-20260909/CASE/gateway.json` and public `/tmp/chio-kernel-storage-fault-20260909/CASE/manifest.json`. The kernel/resource are the frozen candidates. The explicit test-only stdio barrier holds the actual resource response for exactly `/workspace/uncertain.txt`; every other tool call is forwarded normally. Preparation runs no tools/call.

## Before admission

Start a separate persistent process:

```sh
python3 HELPER fault --name CASE --cutpoint before-admission --hold-seconds 600
```

Wait for case output `fault-locked.json` (verify cutpoint and timestamp), then start native host using the prepared gateway. Ask it for exactly one write `/workspace/before-fault.txt`. This path does not use the resource barrier. The fault process holds `BEGIN IMMEDIATE` on actual `sessions.sqlite.admission`; it performs no data/schema mutation. Retain native response. Snapshot before release; expected no dispatch/effect.

## After effect, receipt store

Start in a separate persistent process:

```sh
python3 HELPER fault --name CASE --cutpoint after-receipt --wait-seconds 600 --hold-seconds 600
```

Start native host with the prepared gateway and request exactly one write `/workspace/uncertain.txt`. The helper waits for the actual resource reply, independently observes the file and audited write, then holds `BEGIN IMMEDIATE` on actual `receipts.sqlite`, writes `fault-locked.json` and releases the genuine reply. Kernel receipt append times out after 5000ms. Expected host outcome unknown, one effect, no delivery ACK. Do not wait for fault-locked before starting the native host in this case; effect must come first.

`after-admission` is now qualified. It locks `sessions.sqlite.admission` after the same independent effect observation, then releases the genuine resource response. Use `--cutpoint after-admission --wait-seconds 600 --hold-seconds 600`. Actual kernel response: `durable admission failed: admission operation store is unavailable: database is locked`; no receipt/delivery acknowledgement, caller unknown. Owner snapshot before restart retains `dispatch_committed` and no tool outcome. After ordinary same-owner restart, admission becomes `outcome_unknown_after_dispatch`. The signed delegated call and latch remain `fenced`. Identical and new-action attempts stay fenced without additional dispatch.

Final host port assignment: Pi58512/58513/58526, Claude58514/58515/58516, Codex58517/58518/58519, Hermes58520/58521/58522, OpenClaw58523/58524/58525 (receipt/before-admission/after-admission).

## Release, inspect, retry

```sh
python3 HELPER unlock --name CASE
python3 HELPER snapshot --name CASE --filename after-unlock.json
```

`unlock` ends the lock with ROLLBACK, no row mutation. The fault subprocess exits and writes `fault-released.json`. Preserve owner state, signed fences, and resource volumes. Run same-action replay and a new requested action through native host if your harness supports it. No extra dispatch is permitted after an unknown result. `snapshot` independently reads resource volume/audit and read-only actual admission/session tables; binary SQLite values are hex encoded. Choose new snapshot filenames, because it refuses overwrite.

Do not silently recreate the session/config after failure. Do not reset a pending journal or delete the volume. No automatic ACK is issued by this helper. Positive controls should be separate or fully delivered/ACKed by the real host before fault arming.

## Same-authority restart and recovery boundary

After unlock and a snapshot, use the supported owner restart on exactly the same state:

```sh
python3 /Users/connor/Medica/backbay/standalone/arc/.worktrees/required-agent-integrations-20260909/integrations/required-agents/serve-filesystem.py restart --state-dir /Users/connor/.local/share/chio-required-operators/kernel-storage-fault-20260909/CASE
```

Re-run the real native host with the same gateway config, retained bridge journal, delegated credential and original session. Identical retry must remain retained/unknown; altered action must not cross the fence. The snapshots distinguish independently established effects from what the caller can know. Postreceipt can have a completed durable kernel outcome despite caller unknown; post-admission has no durable outcome and becomes outcome_unknown_after_dispatch. Neither may silently redispatch.

These tests establish safe refusal and retained evidence across faults/restart. They do not claim an automatic administrative reconciliation endpoint or that unresolved work can continue after resetting state. A new authority/session is new work and is prohibited as recovery in these cases. Never clear the journal/fence or ACK an unknown result. All owner volumes stay preserved.
