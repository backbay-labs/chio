# Chiodos Pheromone Relay Operations Runbook

This runbook covers the signed HTTP/JSON pheromone relay as a local service. It does not create dynamic trust, peer crawling, lease or governance decisions, settlement, hidden predicates, or a new transport protocol.

## Deployment Boundary

Production relays use verifier-owned peer-directory bundles. The bundle issuer must be configured outside the peer directory, and the relay must reject unsigned, stale, rollback, unknown issuer, duplicate peer, duplicate endpoint, and unsafe endpoint inputs.

Profiles:

- `local-dev` permits loopback HTTP for fixture and operator rehearsal.
- `production` requires HTTPS endpoints, no credentials, no query string, no fragment, bounded batch sizes, bounded catch-up sizes, and explicit peer-directory issuer trust.

Recommended deployment:

1. Terminate TLS at a reverse proxy owned by the same operator boundary as the relay.
2. Pin the relay upstream path to `/v1/chiodos/pheromone`.
3. Disable redirects on egress.
4. Keep Chio relay request signatures mandatory even when TLS is present.
5. Rotate peer-directory bundles by increasing version and preserving the previous version hash.

## Operator Commands

```bash
chio chiodos pheromone relay lint \
  --peer-directory peer-directory-bundle.json \
  --profile production \
  --trusted-issuers trusted-peer-directory-issuers.json \
  --report relay-lint.json

chio chiodos pheromone relay serve \
  --listen 127.0.0.1:8080 \
  --store relay.sqlite3 \
  --peer-directory peer-directory-bundle.json \
  --transit-policy transit-policy.json \
  --proof-package buyer-auditor-proof-package.json \
  --trust-bundle verifier-trust-bundle.json \
  --context verification-context.json \
  --report-dir reports

chio chiodos pheromone relay tick \
  --store relay.sqlite3 \
  --peer-directory peer-directory-bundle.json \
  --now-unix-ms 1766000000500 \
  --max-batches 32 \
  --signing-key relay-signing-key.json \
  --report relay-tick.json
```

Signing keys are local operator inputs. Do not place private signing seeds in peer-directory bundles, public profiles, or proof packages.

## Health And Readiness

The service exposes local artifact endpoints:

- `GET /v1/chiodos/pheromone/health`
- `GET /v1/chiodos/pheromone/ready`

The health report includes queue depth, oldest pending age, retry count, dead-letter count, inbox count, cursor count, stale lease count, and peer-directory version when the directory came from a signed bundle.

Readiness should fail closed when the store is unreachable, stale leases remain unrecovered, or outbox pressure exceeds the bounded local threshold.

## Recovery Procedures

### Stuck Outbox

1. Run `relay status` and inspect pending, retry, and dead-letter counts.
2. Run `relay tick` with the correct sender signing key.
3. If attempts keep increasing with transport failures, confirm the peer directory endpoint and reverse-proxy route.
4. If stale leases are present, restart the relay and run one tick. Expired leases are recovered into retry state.

### Dead-Letter Triage

1. Group dead letters by last error code.
2. For `endpoint_denied`, lint the current peer-directory bundle against the active profile.
3. For `sender_mismatch`, confirm the local signing-key `kernelId` matches the outbox sender.
4. For receiver rejections, inspect the receiver report and rerun the runtime gate with the same proof package, trust bundle, and context.
5. Requeue only after the root cause is fixed and the replacement batch hashes are understood.

### Stale Directory

1. Reject the stale bundle and keep the current accepted bundle active.
2. Ask the directory issuer for a higher version with a valid issued and expiry window.
3. Confirm the previous version hash chains to the last accepted bundle.
4. Run production lint before replacing operator inputs.

### Replay Storm

1. Treat repeated relay nonce failures as an authentication or retry-loop incident.
2. Confirm whether duplicates are exact idempotent delivery or nonce replay conflict.
3. Block the offending peer at the reverse proxy only after preserving the signed request and report evidence.
4. Rotate the peer directory if a key is suspected compromised.

### Database Lock Contention

1. Confirm the relay process count. A single store should have one writer boundary.
2. Check filesystem latency and available disk space.
3. Stop duplicate local relay workers.
4. Restart the relay and verify the health report.

### Catch-Up Overload

1. Confirm requested frame and byte limits.
2. Check treaty subscription and requester identity.
3. Lower the peer catch-up bounds in the next signed peer-directory bundle if pressure is sustained.
4. Do not advance cursors for poison frames or unauthorized catch-up attempts.

### Safe Requeue

1. Requeue only accepted local deposits.
2. Preserve the signed deposit body.
3. Append only relay-owned transit metadata.
4. Use a fresh relay nonce for new outbound delivery.
5. Record the operator reason and old outbox id in the incident record.
