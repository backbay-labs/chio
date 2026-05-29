# Healthcare Pilot Topology

This runbook pins the deployment topology for the healthcare
design-partner pilot. It intentionally omits the partner identity and records
only the trust-boundary shape that downstream work consumes.

## Deployment Shape

The pilot is a single-tenant deployment. One healthcare design-partner tenant
routes zero-PHI shadow traffic through a Chio mediation sidecar before any
tool call reaches the wrapped MCP server.

```text
design-partner app
  -> Chio sidecar mediation edge
  -> wrapped MCP HTTP server
  -> design-partner API surface
```

The sidecar is the trust-boundary crossing point. It validates the caller,
evaluates policy and guards, sends every allow or deny decision to the receipt
log, and exports audit events to the design-partner SOC pipeline.

## Process Inventory

| Process | Owner | Network scope | Notes |
|---------|-------|---------------|-------|
| design-partner app | design-partner ops | tenant private network | Calls only the Chio sidecar endpoint. |
| Chio sidecar mediation edge | Chio ops during P0/P1, design-partner ops at cutover | localhost or tenant private network | Runs `chio mcp serve-http` with policy, auth, and wrapped server command. |
| trust-control service | Chio ops during P0/P1 | localhost only by default | Runs `chio trust serve` with receipt, revocation, authority, and budget stores. |
| wrapped MCP server | design-partner ops | localhost only by default | Existing partner API bridge, no direct agent access. |
| SOC forwarder | design-partner SOC | egress to SOC collector | Receives OCSF JSON in P0 and CEF preview after P3. |
| PagerDuty integration | Chio ops during P0/P1 | egress to PagerDuty Events API | Service name is `chio-healthcare-pilot-prod`. |

## Trust Boundaries

- Agent-to-sidecar traffic is authenticated before policy evaluation.
- Sidecar-to-trust-control traffic stays tenant local.
- Sidecar-to-wrapped-MCP traffic stays local to the tenant deployment.
- Receipt export is append-only audit evidence, not a policy input.
- SOC export failures never allow a tool call that policy or guards denied.
- PagerDuty alerting failures remain incident telemetry failures, not access
  grants.

## Required Runtime Flags

`chio trust serve` runs before the sidecar:

```bash
chio trust serve \
  --listen 127.0.0.1:8710 \
  --service-token "$CHIO_TRUST_SERVICE_TOKEN" \
  --receipt-db /var/lib/chio/healthcare-pilot/receipts.sqlite \
  --revocation-db /var/lib/chio/healthcare-pilot/revocations.sqlite \
  --authority-db /var/lib/chio/healthcare-pilot/authority.sqlite \
  --budget-db /var/lib/chio/healthcare-pilot/budgets.sqlite
```

`chio mcp serve-http` runs as the sidecar:

```bash
chio mcp serve-http \
  --policy /etc/chio/healthcare-pilot/policy.yaml \
  --server-id healthcare-pilot-sidecar \
  --listen 127.0.0.1:8720 \
  --auth-jwt-public-key /etc/chio/healthcare-pilot/jwks.pem \
  -- chio-openapi-mcp-bridge --spec /etc/chio/healthcare-pilot/openapi.json
```

## Failure Rules

The topology is fail-closed.

- If trust-control readiness fails, the sidecar does not serve traffic.
- If policy loading fails, the sidecar does not serve traffic.
- If authentication fails, the request is denied before tool dispatch.
- If guard evaluation fails, the request is denied and a receipt is attempted.
- If receipt persistence fails, the request is denied.
- If the wrapped MCP server is unavailable, the request fails without bypass.
- If the SOC or PagerDuty path is unavailable, access decisions still follow
  policy, guards, and receipt persistence.

## Cutover Acceptance

Production cutover requires these checks:

1. Contract memo and BAA chain sign-off recorded in the pilot audit doc.
2. Sidecar and trust-control health checks pass in tenant staging.
3. Synthetic allow and deny receipts persist locally.
4. SOC export accepts a synthetic audit row.
5. PagerDuty service `chio-healthcare-pilot-prod` receives a test event.
6. Design-partner ops accepts the single-tenant topology and support rotation.

Until all six are recorded, the pilot remains in zero-PHI shadow mode.
