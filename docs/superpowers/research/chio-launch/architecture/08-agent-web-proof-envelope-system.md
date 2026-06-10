# Agent Web Proof Envelope And Standards Alignment

Status: architecture outline
Primary source: `../agent-drafts/08-external-standards-proof-envelope.md`
Confidence: high for taxonomy and envelope direction, moderate for evolving external standard details.

## Position

There is no single external standard called the Agent Web Proof Envelope that Chio can simply implement. Chio should define its own detached proof envelope that references external protocol objects by digest and signature. The envelope should make Chio proof portable without pretending external protocols natively enforce Chio authority.

## Naming Rules

Bare `ACP` is banned.

Use:

- `ACP-Client` for Agent Client Protocol.
- `ACP-Commerce` for Agentic Commerce Protocol.
- `AGNTCY-ACP` only for historical Agent Connect Protocol references.

Do not use:

- `ACP bridge`
- `ACP-compatible`
- `ACP support`
- `agent commerce protocol` without naming which external source and date.

## Core Artifact

`chio.agent-web-proof-envelope.v1` contains:

- `envelope_id`
- `transaction_passport_ref`
- `source_protocol`
- `source_protocol_version`
- `external_subject`
- `external_subject_digest`
- `external_subject_signature_ref`
- `projection_manifest_ref`
- `chio_claim_refs`
- `receipt_refs`
- `disclosure_capsule_refs`
- `settlement_refs`
- `risk_refs`
- `limitations`
- `signature`

The envelope is detached. It does not mutate the external protocol object unless a protocol-specific extension explicitly supports that.

## Projection Manifest

`chio.agent-web.external-projection-manifest.v1` defines how a Chio artifact maps to an external object.

Fields:

- `projection_id`
- `source_protocol`
- `source_version`
- `external_fields_used`
- `external_fields_not_used`
- `sidecar_fields`
- `digest_algorithm`
- `signature_algorithm`
- `claim_mapping`
- `unsupported_claims`
- `copy_limitations`

## Protocol Alignment

### MCP

Chio can bind tool calls, tool names, arguments digests, server identity, auth context, and receipt refs. Chio should not claim MCP itself enforces Chio policy unless a Chio edge mediated the call.

### A2A

Chio can bind task ids, message parts, state transitions, and delegated execution refs. Chio should distinguish A2A task lifecycle proof from Chio capability authority proof.

### ACP-Client

Chio can bind permission requests, file/terminal/tool-call flows, and sidecar refs. Chio should separate signed Chio receipts from unsigned or host-native audit entries.

### ACP-Commerce

Chio can bind delegated-payment token constraints, checkout/order/payment hashes, and receipt refs. Chio should treat ACP-Commerce as payment and checkout evidence, not Chio authority.

### AG-UI

Chio can bind user interaction events, tool invocation events, and UI-side proof refs. UI event evidence should be advisory unless bound to signed receipts.

### OpenAPI

Chio can bind operation id, request/response digest, egress policy, and route-plan receipt. Chio should not claim the upstream API attests Chio authority.

### AP2

Chio can bind mandate refs, intent constraints, payment authorization context, and order context. AP2 evidence should be subordinate to commerce order context.

### x402

Chio can bind payment challenge, verify, settle transcript, resource, amount, payee, and settlement state. x402 is payment evidence, not a full transaction passport.

### VC, BBS, And SD-JWT

Chio can use VC, BBS, and SD-JWT style credentials and disclosures as evidence formats. Chio should not claim all passport claims are W3C VC claims unless actually encoded and verified that way.

### Sigstore, SLSA, in-toto, And DSSE

Chio can bind build provenance, supply-chain attestations, and signed statements to tool servers and release artifacts. These prove software supply-chain facts, not runtime authority by themselves.

## Interop Verifier Report

`chio.agent-web.interop-verifier-report.v1` answers:

- did the external object digest match;
- did the Chio receipt refs verify;
- did the projection manifest support the claimed fields;
- which claims were unsupported by the external protocol;
- which claims were only sidecar Chio proof;
- which copy limitations apply.

## Copy Guardrails

Allowed:

- "Chio attaches verifiable proof to MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE workflows."
- "Chio projects its Transaction Passport into external protocol contexts."

Disallowed:

- "Chio is the universal agent protocol."
- "All agent protocols verify Chio authority."
- "ACP support" without qualifier.
- "Every external protocol natively carries Chio proof."

## Negative Cases

- external subject digest mismatch;
- projection manifest for wrong protocol version;
- bare `ACP` in public docs;
- unsupported claim not marked as unsupported;
- sidecar proof presented as native protocol enforcement;
- external signature missing but required by manifest.
