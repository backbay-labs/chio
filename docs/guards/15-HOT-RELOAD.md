# WASM Guard Hot Reload

Hot reload publishes a replacement guard only after the canary harness accepts
the frozen 32-fixture corpus. The publish step is an atomic epoch swap, so
in-flight evaluations keep their original module snapshot while new calls use
the new epoch.

## Rollback Watchdog

Each accepted reload can attach a post-swap watchdog. The default M06 policy
rolls back after 5 consecutive error-class verdicts within 60 seconds. Error
classes include traps, fuel exhaustion, serialization failures, and other
fail-closed backend errors.

When the threshold trips, the watchdog restores the prior loaded module,
emits `chio.guard.reload.rolled_back`, and writes an incident directory:

```text
${XDG_STATE_HOME}/chio/incidents/<utc-iso8601>-<guard_id>-<reload_seq>/
  incident.json
  last_5_eval_traces.ndjson
```

`last_5_eval_traces.ndjson` contains redacted trace summaries only. Tool
arguments and request payloads must not be persisted in incident files.

## Digest Blocklist

The local digest blocklist lives at:

```text
${XDG_STATE_HOME}/chio/guards/blocklist.json
```

`Engine::reload` denies a replacement module whose `sha256:<digest>` is present
in the blocklist and returns `E_GUARD_DIGEST_BLOCKLISTED`. `chio guard pull`
performs the same check against the pinned OCI manifest digest before network
fetch or cache write.

Operators can remove an entry with:

```bash
chio guard blocklist remove sha256:<digest>
```
