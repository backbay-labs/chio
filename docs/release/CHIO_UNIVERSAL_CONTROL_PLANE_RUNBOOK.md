# Chio Universal Control-Plane Runbook

## Purpose

This runbook defines the operator-facing review path for Chio's stronger
internal technical-control claim: Chio is a cryptographically signed,
fail-closed, intent-aware governance control plane on the qualified
authoritative protocol surfaces. This is an internal milestone claim, not a
Chio-owned protocol version.

This runbook is not the market-position proof. It documents the technical
runtime, trust boundaries, and failure handling that back the stronger control-
plane claim.

## Qualified Surface

The current control-plane claim covers the authoritative paths across:

- HTTP/API enforcement via `chio-api-protect` and `chio-tower`
- MCP runtime execution
- A2A authoritative send/stream/get/cancel mediation
- ACP-Client authoritative invoke/stream/resume/cancel mediation

Compatibility-only helpers and deferred OpenAI adapter surfaces are out of
scope for this claim.

## Trust Boundaries

The qualified topology has three material trust layers:

1. Source protocol surface
   - HTTP, MCP, A2A, or ACP-Client originates a governed request
2. Chio control plane
   - route planning
   - capability / policy enforcement
   - kernel-backed authorization
   - receipt signing and lineage
3. Target execution surface
   - `native`
   - `mcp`
   - any additional registered target executor that is explicitly qualified

Route selection is explicit or registry-derived, signed, and surfaced on the
qualified authoritative receipts.

## Route Planning Behavior

Control-plane route planning must support all three outcomes:

- `select`: choose the preferred route when intent, policy, and availability
  permit it
- `attenuate`: fall back to a narrower allowed route when the preferred route
  is unavailable or disallowed
- `deny`: fail closed when no claim-eligible route remains

Signed route-selection evidence is required on the authoritative receipts for
every outcome.

## Lifecycle Contract

The claim-eligible surfaces share one runtime lifecycle contract:

- blocking entrypoint
- deferred stream entrypoint
- follow-up resume/get entrypoint
- cancel entrypoint
- explicit streaming and partial-output delivery semantics

When a protocol surface uses deferred-task semantics instead of native push
streaming, that is documented as an adapted but still claim-eligible lifecycle.

## Failure Handling

Operators should expect the following fail-closed behaviors:

- unavailable or unsupported target route -> signed deny or signed attenuation
- missing or invalid capability -> signed deny
- incompatible lifecycle method on a compatibility surface -> explicit
  non-claim-eligible compatibility response
- target execution failure after authorization -> receipt-bearing incomplete or
  terminal failure state with preserved lineage

## Qualification Commands

Run both gates for the strongest technical claim:

```bash
./scripts/qualify-cross-protocol-runtime.sh
./scripts/qualify-universal-control-plane.sh
```

The first gate proves the bounded runtime substrate and multi-language surface.
The second gate proves the stronger route-planning, multi-hop, lifecycle, and
operator-boundary control-plane delta.

## Artifact Review Checklist

Review these files in the universal-control-plane artifact bundle:

- `qualification-report.md`
- `CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json`
- `CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md`
- `logs/universal-fabric.log`
- `logs/kernel-authority.log`
- `logs/control-plane-authority.log`
- `logs/planning-truth.log`

Confirm:

- the route-planning and multi-hop tests passed
- the shared HTTP authority path passed
- the planning ledger agrees on milestone and phase state
- the claim surfaces agree that the technical control-plane thesis is
  qualified while the broader market thesis is not
