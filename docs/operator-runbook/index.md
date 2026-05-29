# Healthcare Pilot Operator Runbook

This directory is the tenant-shaped operator runbook for the healthcare
design-partner pilot. It layers deployment-specific operating rules on top of
the generic bounded release runbook at `docs/release/OPERATIONS_RUNBOOK.md`.

The pilot is a single-tenant deployment. It remains in zero-PHI shadow mode
until the contract memo, BAA chain, topology acceptance, PagerDuty routing key,
and cutover rehearsal are recorded in the pilot audit doc.

## Required Reading

Read these pages before operating the pilot:

1. `bounded-profile.md` - release boundary and unsupported claims.
2. `topology.md` - sidecar, wrapped MCP edge, trust-control, SOC, and alerting
   placement.
3. `onboarding.md` - first tenant setup and rehearsal procedure.
4. `slo.md` - availability, latency, receipt-write, and export objectives.
5. `incidents.md` - P0/P1/P2 classification and MTTR targets.
6. `pagerduty.md` - service, routing key, severity override, and alert payload
   rules.
7. `rotations.md` - weekly primary and secondary on-call rotation.

Later pilot phases add:

- `quota.md` for sustained-load sizing.
- `phi-policy.md` for request, response, receipt, and alert redaction.

## Operating Boundary

The operator must keep these constraints true:

- One healthcare design-partner tenant.
- One Chio sidecar mediation edge in front of the wrapped MCP server.
- One tenant-local trust-control service.
- One local receipt store with checkpoint export.
- One configured SOC export path.
- One PagerDuty service named `chio-healthcare-pilot-prod`.

Do not widen the pilot to multi-tenant, multi-region, public transparency-log,
or consensus HA claims. Those claims are outside the pilot scope.

## Runtime Surfaces

The runbook assumes these commands:

```bash
chio trust serve
chio mcp serve-http
chio doctor
```

The generic runtime input list remains in
`docs/release/OPERATIONS_RUNBOOK.md` lines 28-78. This directory records the
tenant-specific values, escalation contracts, and acceptance checks.

## Change Control

Every production change requires:

1. A design-partner change request or Chio incident ticket.
2. Confirmation that the deployment remains single-tenant.
3. Confirmation that PHI is not placed in PagerDuty summary fields.
4. A synthetic allow receipt and deny receipt after rollout.
5. SOC export and PagerDuty heartbeat verification when alerting config
   changes.

If any check fails, roll back the deployment change and keep the pilot in
shadow mode.

## Evidence Links

Internal self-assessment artifacts are maintained under `compliance/hitrust/`
(see `compliance/hitrust/control-mapping.csv` for the per-control mapping).

- P0 opened audit hard counts and the topology baseline.
- P1 hardens this runbook and wires PagerDuty.
- P2 records capacity and onboarding rehearsal evidence.
- P3 records schema negotiation and PHI policy evidence.
- P4 records weekly incident reviews.
- P5 records operator sign-off and freeze closure.
