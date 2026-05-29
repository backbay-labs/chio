# Healthcare Pilot Tenant Onboarding

This runbook records the P0 onboarding shape for the single healthcare
design-partner deployment. It does not bind the partner identity in repo docs.

## Preconditions

1. Contract memo recorded in the audit doc.
2. BAA-ready posture confirmed.
3. No PHI-bearing production traffic before Business Associate Agreement chain
   sign-off.
4. Tenant is single-tenant for the current pre-release v1 posture.
5. Chio mediation edge runs in sidecar mode.
6. Existing API surface remains owned by the design-partner ops team.
7. Chio team owns the P0/P1 PagerDuty routing key.
8. Design-partner ops receives the production routing key at cutover.

## Bounded Profile

The onboarding imports the BOUNDED_OPERATIONAL_PROFILE from
`docs/release/OPERATIONS_RUNBOOK.md`.

- Trust-control truth is local or leader-local single-writer.
- Hosted auth is single-node or dedicated per session.
- Monetary budgets are single-node atomic on one SQLite store.
- Receipts are signed local audit evidence with checkpoint export.
- No public transparency-log semantics are claimed.
- No consensus-backed HA is claimed.
- No multi-tenant isolation claim is made in this pilot.

## Runtime Services

`chio trust serve` starts first:

```bash
chio trust serve \
  --listen 127.0.0.1:8710 \
  --service-token "$CHIO_TRUST_SERVICE_TOKEN" \
  --receipt-db /var/lib/chio/healthcare-pilot/receipts.sqlite \
  --revocation-db /var/lib/chio/healthcare-pilot/revocations.sqlite \
  --authority-db /var/lib/chio/healthcare-pilot/authority.sqlite \
  --budget-db /var/lib/chio/healthcare-pilot/budgets.sqlite
```

`chio mcp serve-http` starts after trust-control readiness:

```bash
chio mcp serve-http \
  --policy /etc/chio/healthcare-pilot/policy.yaml \
  --server-id healthcare-pilot-sidecar \
  --listen 127.0.0.1:8720 \
  --auth-jwt-public-key /etc/chio/healthcare-pilot/jwks.pem \
  -- chio-openapi-mcp-bridge --spec /etc/chio/healthcare-pilot/openapi.json
```

## Onboarding Steps

1. Create the tenant data directory under `/var/lib/chio/healthcare-pilot`.
2. Install the policy file from the design-partner change request.
3. Install the partner JWKS or static auth token.
4. Start `chio trust serve` and verify health.
5. Start `chio mcp serve-http` and verify health.
6. Run `chio doctor` against the sidecar endpoint.
7. Send a synthetic allow decision and verify receipt persistence.
8. Send a synthetic deny decision and verify PagerDuty suppression.
9. Verify receipt checkpoint export.
10. Verify OCSF JSON export to the staging SOC sink.
11. Verify CEF preview output once P3 lands the emitter.
12. Record the onboarding rehearsal in the audit doc.

## PagerDuty

Use service `chio-healthcare-pilot-prod`.

- P0 incidents page primary on-call within 5 minutes.
- P1 incidents page primary on-call within 15 minutes.
- P2 incidents enter the ticket queue.
- PHI-bearing alert text is forbidden.
- Heartbeat alert cadence is weekly until P1 changes it.

## Cutover Rules

Cutover requires the contract memo, BAA chain sign-off, PagerDuty routing key,
topology acceptance, and zero-PHI shadow traffic rehearsal. If any item is
missing, the deployment remains in shadow mode.
