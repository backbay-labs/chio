# Schema Coverage

This file describes the JSON Schema set under `spec/schemas/` as it exists
today. It is a coverage map of the shipped schema families, not a planning
document. Update the tables below when a schema is added, removed, or renamed.

## Source-of-truth pointers

- Agent guide: `AGENTS.md`.
- Normative wire spec: `spec/PROTOCOL.md` and `spec/WIRE_PROTOCOL.md`.
- Wire schema subtree notes: `spec/schemas/chio-wire/v1/README.md` and the
  per-subtree `README.md` files under it (`capability/`, `jsonrpc/`,
  `provenance/`, `receipt/`, `trust-control/`).
- Verifier-facing artifact registry: `spec/schemas/registry.json`. Load-time
  and verify-time code rejects signed artifacts whose schema string is not
  listed there.
- Content digests: `spec/schemas/MANIFEST.sha256` records a SHA-256 over each
  schema file (and over `VERSION`).
- Schema-set version: `spec/schemas/VERSION`.

The schema files are hand-typed and are the source of truth for the wire and
HTTP contracts. The hand-maintained Rust protocol types live in
`crates/core/chio-core-types`; when a Rust type and its schema disagree, fix one so
they match again before shipping. The schema-derived Rust snapshot lives under
`crates/core/chio-core-types/src/_generated/` as regenerate-only code with the
canonical `chio_spec_codegen::GENERATED_HEADER`; it is not exported from
`chio-core-types::lib` yet.

## Wire schemas: `chio-wire/v1/`

The native Chio message families defined in `spec/WIRE_PROTOCOL.md`. Fifty-one
schema files across eleven subtrees.

### agent (5)

| File                                                 | Lines |
|------------------------------------------------------|-------|
| `agent/active-response-governed-intent.schema.json`  |    51 |
| `agent/governed-transaction-intent.schema.json`      |    48 |
| `agent/heartbeat.schema.json`                        |    12 |
| `agent/list_capabilities.schema.json`                |    12 |
| `agent/tool_call_request.schema.json`                |    50 |

### kernel (6)

| File                                           | Lines |
|------------------------------------------------|-------|
| `kernel/capability_list.schema.json`           |    15 |
| `kernel/capability_revoked.schema.json`        |    16 |
| `kernel/combined-capture-metadata.schema.json` |    42 |
| `kernel/heartbeat.schema.json`                 |    12 |
| `kernel/tool_call_chunk.schema.json`           |    21 |
| `kernel/tool_call_response.schema.json`        |   185 |

### result (5)

| File                                 | Lines |
|--------------------------------------|-------|
| `result/cancelled.schema.json`       |    20 |
| `result/err.schema.json`             |   103 |
| `result/incomplete.schema.json`      |    20 |
| `result/ok.schema.json`              |    13 |
| `result/stream_complete.schema.json` |    16 |

### error (6)

| File                                  | Lines |
|---------------------------------------|-------|
| `error/capability_denied.schema.json` |    16 |
| `error/capability_expired.schema.json`|    12 |
| `error/capability_revoked.schema.json`|    12 |
| `error/internal_error.schema.json`    |    16 |
| `error/policy_denied.schema.json`     |    27 |
| `error/tool_server_error.schema.json` |    16 |

### capability (11)

Capability tokens, grants, revocation envelopes, and the capability list
projection. See `capability/README.md`.

| File                                                   | Lines |
|--------------------------------------------------------|-------|
| `capability/aggregate-budget-root.schema.json`         |    47 |
| `capability/aggregate-invocation-budget.schema.json`   |    27 |
| `capability/capabilities.schema.json`                  |    28 |
| `capability/cumulative-approval-root.schema.json`      |    64 |
| `capability/governed-approval-token.schema.json`       |    41 |
| `capability/grant.schema.json`                         |   140 |
| `capability/revocation.schema.json`                    |    20 |
| `capability/supplemental-authorization.schema.json`    |    17 |
| `capability/threshold-approval-proposal.schema.json`   |    48 |
| `capability/token.schema.json`                         |   604 |
| `capability/verified-approval-set.schema.json`         |    44 |

### receipt (4)

Signed receipts produced after tool calls complete, plus lineage and
inclusion-proof shapes. See `receipt/README.md`.

| File                                           | Lines |
|------------------------------------------------|-------|
| `receipt/admission-metadata.schema.json`       |   153 |
| `receipt/inclusion-proof.schema.json`          |    30 |
| `receipt/lineage_statement.schema.json`        |    97 |
| `receipt/record.schema.json`                   |   448 |

### jsonrpc (3)

JSON-RPC framing used by the hosted MCP HTTP edge. See `jsonrpc/README.md`.

| File                              | Lines |
|-----------------------------------|-------|
| `jsonrpc/notification.schema.json`|    34 |
| `jsonrpc/request.schema.json`     |    46 |
| `jsonrpc/response.schema.json`    |    67 |

### trust-control (5)

Trust-control plane messages: lease, heartbeat, terminate, attestation, and budget snapshot anchor provenance.
See `trust-control/README.md`.

| File                                  | Lines |
|---------------------------------------|-------|
| `trust-control/attestation.schema.json` |  88 |
| `trust-control/budget-snapshot-anchor-provenance.schema.json` |  62 |
| `trust-control/heartbeat.schema.json` |    41 |
| `trust-control/lease.schema.json`     |    64 |
| `trust-control/terminate.schema.json` |    52 |

### provenance (4)

Provenance and attestation records emitted by the kernel. See
`provenance/README.md`.

| File                                       | Lines |
|--------------------------------------------|-------|
| `provenance/attestation-bundle.schema.json`|   125 |
| `provenance/context.schema.json`           |    41 |
| `provenance/stamp.schema.json`             |    42 |
| `provenance/verdict-link.schema.json`      |   100 |

### federation (2)

Bilateral signature-slice envelopes for cross-kernel cosignature.

| File                                              | Lines |
|---------------------------------------------------|-------|
| `federation/bilateral-signature-slice.schema.json`|   231 |
| `federation/bilateral-signature-slice-envelope.schema.json` | 41 |

### anchor (1)

| File                       | Lines |
|----------------------------|-------|
| `anchor/batch.schema.json` |   188 |

## HTTP schemas: `chio-http/v1/`

The hosted HTTP substrate edge (request envelopes, caller identity, evaluation
verdicts, receipts, streaming frames, and session lifecycle). Ten schema files.

| File                                          | Lines |
|-----------------------------------------------|-------|
| `chio-http/v1/caller-identity.schema.json`    |   117 |
| `chio-http/v1/chio-http-request.schema.json`  |    73 |
| `chio-http/v1/error-envelope.schema.json`     |    46 |
| `chio-http/v1/evaluate-request.schema.json`   |     6 |
| `chio-http/v1/evaluate-response.schema.json`  |    40 |
| `chio-http/v1/http-receipt.schema.json`       |   164 |
| `chio-http/v1/session-init.schema.json`       |    66 |
| `chio-http/v1/session-resume.schema.json`     |   103 |
| `chio-http/v1/stream-frame.schema.json`       |   100 |
| `chio-http/v1/verdict.schema.json`            |    65 |

## Supporting schema families

These families cover higher-layer artifacts. File counts are summarized here;
the per-file schemas live in their respective subtrees.

| Family                  | Files | Covers |
|-------------------------|-------|--------|
| `chio-attest/v1/`       |   10  | Buyer-attestation packets, proof packages, selective-disclosure proofs, and verifier reports. |
| `chio-comptroller/v1/`  |    1  | `surface-report.schema.json`: unified spend/exposure contract; the signed `ComptrollerSurfaceReport` projection used by the flagship proof demo. |
| `chio-federation/v1/`   |   22  | Treaty scopes, capability leases, issuance bundles, governance receipts, peer pins, and revocation publication artifacts. |
| `chio-frost/v1/`        |    4  | Signed rosters, rollback-independent epoch and authorization-slot checkpoints, and threshold authorizations. |
| `chio-pheromone/v1/`    |   85  | Pheromone deposits, gossip and catchup envelopes, relay configuration, relay-alert and relay-assurance reports, and observation-cost telemetry. |
| `chio-runtime/v1/`      |   36  | Admission profiles and reports, orchestration plans and run reports, evidence manifests, proof parity and regeneration reports, and trust-floor state. |
| `chio-replay-report/`   |    1  | `chio-replay-report/v1.schema.json`: the stable JSON report shape emitted by `chio replay --json`. |

## Top-level schemas

Loose schema files at the root of `spec/schemas/`.

| File                          | Lines | Covers |
|-------------------------------|-------|--------|
| `signature.v1.json`           |    26 | Algorithm-aware public-key and signature string encodings for signed artifacts. |
| `model-card.v1.json`          |    68 | Signed declaration binding a model's loaded weights to an allowed capability set, banned tools, and training-data class. |
| `receipt-provenance-v1.json`  |    29 | Receipt-provenance record shape. |
| `chio-tee-frame-v1.json`      |   151 | Capture frame emitted by the chio-tee shadow runner per kernel evaluation. |
| `registry.json`               |  1533 | Verifier-facing registry of signed artifact schema IDs and their schema files. |

## Conformance and vector coverage

Two corpora exercise the schemas above and must stay schema-covered.

Conformance scenarios under `tests/conformance/`:

| Subtree                                         | Files |
|-------------------------------------------------|-------|
| `scenarios/mcp_core/`                           |   5   |
| `scenarios/auth/`                               |   5   |
| `scenarios/tasks/`                              |   2   |
| `scenarios/nested_callbacks/`                   |   4   |
| `scenarios/notifications/`                      |   2   |
| `scenarios/chio-extensions/`                    |   1   |
| `native/scenarios/`                             |   6   |

The native scenarios cover capability validation, delegation attenuation, DPoP
verification, governed-transaction enforcement, receipt integrity, and
revocation propagation.

Cross-language binding vectors under `tests/bindings/vectors/` (one `v1.json`
per domain): `canonical`, `capability`, `eval`, `hashing`, `manifest`,
`receipt`, and `signing`. SDKs in other languages round-trip these vectors
through their generated bindings.
