# Chiodos Pheromone Relay Operations Runbook

This runbook covers the signed HTTP/JSON pheromone relay as a local service. It does not create dynamic trust, peer crawling, lease or governance decisions, settlement, hidden predicates, or a new transport protocol.

## Deployment Boundary

Production relays use verifier-owned peer-directory state. The state stores a last-known-good active signed bundle plus rejected candidates. The bundle issuer must be configured outside the peer directory, and the relay must reject unsigned, stale, rollback, unknown issuer, duplicate peer, duplicate endpoint, removed peer, and unsafe endpoint inputs.

Profiles:

- `local-dev` permits loopback HTTP for fixture and operator rehearsal.
- `production` requires HTTPS endpoints, no credentials, no query string, no fragment, bounded batch sizes, bounded catch-up sizes, and explicit peer-directory issuer trust.

Recommended deployment:

1. Generate the relay observability report, relay alert report, relay trend report, relay handoff report, delivery import report, acknowledgement report, and drift report before inspecting raw store rows.
2. Terminate TLS at a reverse proxy owned by the same operator boundary as the relay.
3. Pin the relay upstream path to `/v1/chiodos/pheromone`.
4. Disable redirects on egress.
5. Keep Chio relay request signatures mandatory even when TLS is present.
6. Rotate peer-directory bundles through `relay directory promote`, increasing version and preserving the previous version hash.
7. Keep removed peers quarantined in active state until a future active directory explicitly reintroduces them under an operator-reviewed version.

## Operator Commands

```bash
chio chiodos pheromone relay lint \
  --peer-directory-state peer-directory-state.json \
  --profile production \
  --trusted-issuers trusted-peer-directory-issuers.json \
  --report relay-lint.json

chio chiodos pheromone relay directory promote \
  --state peer-directory-state.json \
  --candidate peer-directory-candidate.json \
  --trusted-issuers trusted-peer-directory-issuers.json \
  --profile production \
  --now-unix-ms <now-unix-ms> \
  --report peer-directory-rotation-report.json

chio chiodos pheromone relay serve \
  --listen 127.0.0.1:8080 \
  --store relay.sqlite3 \
  --peer-directory-state peer-directory-state.json \
  --profile production \
  --trusted-issuers trusted-peer-directory-issuers.json \
  --transit-policy transit-policy.json \
  --proof-package buyer-auditor-proof-package.json \
  --trust-bundle verifier-trust-bundle.json \
  --context verification-context.json \
  --report-dir reports \
  --operator-token-env CHIO_RELAY_OPERATOR_TOKEN

chio chiodos pheromone relay observe \
  --store relay.sqlite3 \
  --peer-directory-state peer-directory-state.json \
  --profile production \
  --trusted-issuers trusted-peer-directory-issuers.json \
  --report-dir reports \
  --limit 25 \
  --report relay-observability-report.json

chio chiodos pheromone relay metrics \
  --store relay.sqlite3 \
  --format prometheus \
  --output relay-metrics.prom

chio chiodos pheromone relay tick \
  --store relay.sqlite3 \
  --peer-directory-state peer-directory-state.json \
  --profile production \
  --trusted-issuers trusted-peer-directory-issuers.json \
  --max-batches 32 \
  --signing-key relay-signing-key.json \
  --report relay-tick.json \
  --report-dir reports

chio chiodos pheromone relay alert evaluate \
  --observability-report relay-observability-report.json \
  --event-dir reports \
  --routing-profile relay-alert-routing-profile.json \
  --suppression-state relay-alert-suppression-state.json \
  --now-unix-ms <now-unix-ms> \
  --report relay-alert-report.json

chio chiodos pheromone relay trend \
  --reports-dir reports \
  --event-dir reports \
  --routing-profile relay-alert-routing-profile.json \
  --since-unix-ms <since-unix-ms> \
  --until-unix-ms <until-unix-ms> \
  --report relay-trend-report.json

chio chiodos pheromone relay alert handoff \
  --alert-report relay-alert-report.json \
  --trend-report relay-trend-report.json \
  --routing-profile relay-alert-routing-profile.json \
  --handoff-profile relay-alert-handoff-profile.json \
  --now-unix-ms <now-unix-ms> \
  --report relay-alert-handoff-report.json

chio chiodos pheromone relay alert delivery import \
  --handoff-report relay-alert-handoff-report.json \
  --delivery-profile relay-alert-delivery-profile.json \
  --evidence-dir downstream-delivery-evidence \
  --now-unix-ms <now-unix-ms> \
  --report relay-alert-delivery-report.json

chio chiodos pheromone relay alert delivery acknowledge \
  --handoff-report relay-alert-handoff-report.json \
  --delivery-report relay-alert-delivery-report.json \
  --delivery-profile relay-alert-delivery-profile.json \
  --now-unix-ms <now-unix-ms> \
  --report relay-alert-acknowledgement-report.json

chio chiodos pheromone relay alert delivery drift \
  --handoff-reports-dir reports \
  --delivery-reports-dir reports \
  --delivery-profile relay-alert-delivery-profile.json \
  --since-unix-ms <since-unix-ms> \
  --until-unix-ms <until-unix-ms> \
  --report relay-alert-handoff-drift-report.json

chio chiodos pheromone relay supervisor lint \
  --profile relay-supervisor-profile.json \
  --report relay-drill-report.json
```

Signing keys are local operator inputs. Do not place private signing seeds in peer-directory bundles, public profiles, or proof packages.

## Health And Readiness

The service exposes local artifact endpoints:

- `GET /v1/chiodos/pheromone/health`
- `GET /v1/chiodos/pheromone/ready`
- `GET /v1/chiodos/pheromone/observability`
- `GET /v1/chiodos/pheromone/metrics`

The health report includes queue depth, oldest pending age, retry count, dead-letter count, inbox count, cursor count, stale lease count, and peer-directory version from the verified active state.

Readiness should fail closed when the store is unreachable, stale leases remain unrecovered, or outbox pressure exceeds the bounded local threshold.

Production observability and metrics endpoints require `Authorization: Bearer <token>` sourced from `--operator-token-env`. Health and readiness remain lightweight probes.

## Observability Workflow

1. Run `relay observe` and read `relay-observability-report.v1`.
2. Run `relay alert evaluate` and read `relay-alert-report.v1`.
3. Run `relay trend` and read `relay-trend-report.v1` to check whether the condition is isolated or growing.
4. Run `relay alert handoff` and read `relay-alert-handoff-report.v1` to confirm downstream route coverage, dedupe keys, severity mapping, escalation mapping, and runbook references.
5. Run `relay alert delivery import` and read `relay-alert-delivery-report.v1` to confirm downstream systems produced bounded delivery, rejection, duplicate, delayed, or unknown evidence.
6. Run `relay alert delivery acknowledge` and read `relay-alert-acknowledgement-report.v1`.
7. Run `relay alert delivery drift` and read `relay-alert-handoff-drift-report.v1`.
8. Use bounded event reports in `--report-dir` to inspect recent batch receive, catch-up, outbound delivery, and request rejection evidence.
9. Use raw SQLite inspection only after alert, trend, handoff, delivery, acknowledgement, drift, observability, and bounded event reports have narrowed the incident.
10. Export `relay metrics --format prometheus` for downstream Alertmanager routing. Labels are bounded to status, reason, notification route, service, severity, and downstream route aliases.
11. Use the receipt dashboard relay cards as a view over the canonical reports. Missing relay reports render as `unknown` and do not block receipt workflows.

Chio produces alert handoff and delivery evidence only. Downstream Alertmanager, PagerDuty, OpsGenie, Slack, email, webhook, and SIEM systems perform live notification delivery from their own credentialed configuration.

## Recovery Procedures

### Stuck Outbox

1. Read `relay-alert-report.v1` and confirm whether `retries_pending` or `dead_letters_present` is firing.
2. Read `relay-trend-report.v1` for retry and dead-letter trend direction.
3. Run `relay observe` and inspect pending, retry, dead-letter, and recommendation codes.
4. Run `relay tick` with the correct sender signing key.
5. If attempts keep increasing with transport failures, confirm the peer directory endpoint and reverse-proxy route.
6. If stale leases are present, restart the relay and run one tick. Expired leases are recovered into retry state.

### Dead-Letter Triage

1. Read `relay-alert-report.v1` and follow the linked runbook reference for the firing `dead_letters_present` alert.
2. Read `relay-trend-report.v1` to separate a one-off dead letter from sustained pressure.
3. Read `relay-observability-report.v1` and group dead letters by recent bounded failure code.
4. For `endpoint_denied`, lint the current peer-directory state against the active profile.
5. For `sender_mismatch`, confirm the local signing-key `kernelId` matches the outbox sender.
6. For receiver rejections, inspect the receiver report and rerun the runtime gate with the same proof package, trust bundle, and context.
7. Requeue only after the root cause is fixed and the replacement batch hashes are understood.

### Directory Rotation

1. Inspect the current state with `relay directory inspect`.
2. Promote only candidates whose previous version hash chains to the active bundle.
3. Reject stale, rollback, unsafe endpoint, duplicate peer, and unknown issuer candidates with `relay directory reject`.
4. Confirm the last-known-good active state still verifies after a rejected candidate and after restart.
5. Run production lint before using the active state for serve, tick, or catch-up.

### Removed Peer Quarantine

1. Confirm removed peer ids in the active state.
2. Deny new inbound batches, outbound delivery, and catch-up for quarantined peers.
3. Preserve old rejected and removal reports for audit.
4. Reintroduce a peer only through a higher signed candidate with explicit operator review.

### Stale Directory

1. Reject the stale bundle and keep the current accepted state active.
2. Ask the directory issuer for a higher version with a valid issued and expiry window.
3. Confirm the previous version hash chains to the last accepted bundle.
4. Run production lint before replacing operator inputs.

### Replay Storm

1. Treat repeated relay nonce failures in the observability report as an authentication or retry-loop incident.
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
