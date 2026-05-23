# Chio Protocol Specification

This directory holds the normative Chio protocol specification. The canonical
version banner lives at the top of `PROTOCOL.md`; Chio is unreleased and the
current Chio-owned protocol surface is v1 only. All other documents in this
directory are either normative companions to `PROTOCOL.md` or supporting
machine-readable artifacts.

## Reading order

Pick the sequence that matches why you are here:

- **Implementer (building a Chio kernel, edge, or bridge)**: start with
  `PROTOCOL.md` for the overall surface, then read `WIRE_PROTOCOL.md` and
  `GUARDS.md` for the mandatory runtime contract, then `HTTP-SUBSTRATE.md` if
  you intercept HTTP traffic, then `METERING.md` and `WORKFLOW.md` for
  extended semantics, and finally `CONFIGURATION.md` for operator surface.
- **Auditor (verifying receipts, guards, and compliance)**: start with
  `SECURITY.md` for the threat model, then `GUARDS.md` for the fail-closed
  pipeline invariants, then `COMPLIANCE-CERTIFICATE.md` for the session-level
  proof artifact, then walk `errors/`, `security/`, and `schemas/` for the
  referenced machine artifacts.
- **SDK or bridge author**: start with `WIRE_PROTOCOL.md` for frame and
  lifecycle shapes, then `HTTP-SUBSTRATE.md` and `OPENAPI-INTEGRATION.md` for
  HTTP surfaces, then `BRIDGES.md` for the extension contract that external
  protocol edges must uphold.

## Top-level documents

- `PROTOCOL.md`: repository-wide Chio profile and the canonical version banner
  for this directory.
- `WIRE_PROTOCOL.md`: shipped wire protocol narrow enough for an independent
  implementation, covering the four cooperating surfaces.
- `GUARDS.md`: normative guard taxonomy, fail-closed pipeline invariants,
  advisory signals, WASM custom guards, and the session journal contract.
- `HTTP-SUBSTRATE.md`: normative sidecar HTTP evaluation protocol, typed
  request and receipt models, and receipt mapping rules.
- `METERING.md`: normative cost dimensions, budget enforcement, billing
  export, and operator query surface for per-receipt cost attribution.
- `OPENAPI-INTEGRATION.md`: normative OpenAPI-to-manifest pipeline, the
  `x-chio-*` extension vocabulary, and the `chio api protect` proxy contract.
- `SECURITY.md`: normative threat model and minimum transport-security
  posture for the Chio agent-kernel-tool trust boundary.
- `WORKFLOW.md`: normative skill and workflow authority system, including
  SkillGrant, SkillManifest, WorkflowReceipt, and WorkflowAuthority.
- `BRIDGES.md`: normative companion to `PROTOCOL.md` covering each bridge and
  edge crate, its invocation flow, fidelity assessment, and receipt mapping.
- `COMPLIANCE-CERTIFICATE.md`: normative Session Compliance Certificate
  format, signing algorithm, error semantics, and verification modes.
- `CONFIGURATION.md`: normative `chio.yaml` configuration file format and
  parser requirements.

## Subdirectories

- `errors/`: machine-readable Chio error registry (`chio-error-registry.v1.json`)
  enumerating normative error codes and taxonomy.
- `ietf/`: IETF draft artifacts, currently `draft-chio-protocol-00.md`, for
  external standardization tracks.
- `schemas/`: JSON schema trees for the native wire protocol (`chio-wire/v1`)
  and the HTTP substrate (`chio-http/v1`).
- `security/`: structured threat-model artifacts such as
  `chio-threat-model.v1.json` that pair with `SECURITY.md`.
- `versions/`: version-negotiation artifacts such as
  `chio-protocol-negotiation.v1.json`; see Versioning below.

## Versioning

The canonical version banner lives in the header of `PROTOCOL.md`. Individual
normative companion documents carry their own `Version` stamp that is
independently maintained. The machine-readable negotiation artifact lives in
`versions/chio-protocol-negotiation.v1.json` and is the authoritative source
for which protocol version an implementation may advertise during session
initialization. Until first public release, Chio-owned schema and API surfaces
remain v1 or unversioned, and pre-release semantic changes are folded into the
current v1 shape.
