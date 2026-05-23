# ADR-0010: Current V1 Receipt-Kind And Trace Semantics

- Status: Accepted
- Decision owner: protocol strategy
- Related plan items: PR 652 current v1 receipt-kind decision packet, boundary taxonomy, async receipt durability

## Context

PR 652 research needs a receipt model that can represent mediated Chio
decisions without making provider-reported or advisory observations look like
Chio-mediated `Allow` receipts. This prevents receipt washing: an activity that
Chio only observed must never be replayed, exported, or shown as if the kernel
authorized it before effect.

Chio is not released, so the model is still mutable. The receipt-kind and trace
semantics are folded into the current v1 receipt shape rather than introduced as
a new public schema generation.

## Decision

The current v1 receipt uses one signed receipt envelope with a required
`receipt_kind` field:

- `mediated_decision`: Chio was in the decision path before effect. This kind
  may carry `decision = Allow | Deny | Cancelled | Incomplete`.
- `trace_observation`: Chio records provider-reported or externally observed
  activity. This kind must not carry a `decision` field.
- `advisory_evaluation`: Chio records discovery, scoring, or recommendation
  data that did not grant or deny a capability. This kind must not carry a
  `decision` field.

`Decision::Trace` is rejected. Trace and advisory records are receipt kinds, not
new allow-like decisions. If a trace or advisory record needs status, it uses a
non-authorizing `observation_outcome` field such as `reported`, `failed`, or
`redacted`, never `Allow`, `Deny`, `Cancelled`, or `Incomplete`.

There is no receipt schema limit field or legacy compatibility path before
release. All Chio-owned runtime and SDK surfaces expose the current v1 shape
only. A peer that cannot validate the current receipt-kind semantics must fail
closed.

Current v1 core fields:

- `receipt_kind`
- `actor_chain: Vec<ActorRef>`, using the typed `ActorRef` model from the
  receipt design track.
- `tool_origin`, orthogonal to redaction.
- `trust_level`, using the existing trust vocabulary.
- `redaction_mode`, signed separately from `tool_origin`.
- `policy_hash`, using the existing receipt field. Implementations may use a
  lowercase digest or an operator-pinned symbolic policy id.

Extension hash handling is not part of the current signed v1 receipt body.
Security-affecting extension bundles remain blocked until an accepted extension
binding design lands in code and tests.
There is no current v1 `extensions_hash` field, extension signing contract, or
`must_understand` registry. Future extension work must define those semantics in
a separate accepted ADR before implementation.

The async durability ADR defines `signed_but_not_durable` state. Current v1
only names that state; it does not allow trace or advisory records to stand in
for missing mediated receipts.

## Rationale

A separate `receipt_kind` preserves one audit envelope while making receipt
washing machine-detectable. Using `Decision::Trace` would overload the most
security-sensitive field in the receipt and make older UI, SIEM, and verifier
code too likely to treat trace as a decision.

Removing pre-release schema negotiation avoids spending effort on compatibility
for shapes that never shipped. Verifiers that cannot reason about trace-only and
advisory-only records fail closed rather than receiving allow-shaped fallback
records.

Deferring extension signing keeps the current v1 receipt core narrow and
prevents unimplemented extension semantics from looking like signed protocol
authority.

## Consequences

### Positive

- Mediated `Allow` remains a narrow, replayable security claim.
- Trace-only and advisory-only observations can be exported without borrowing
  mediated receipt language.
- Verifiers fail closed instead of accepting misleading allow-shaped traces.
- Extension-bearing security changes remain blocked until their binding is
  explicit and testable.

### Negative

- Security-affecting extension bundles cannot be treated as current protocol
  authority until a later accepted design lands.
- Existing receipt UI must learn `receipt_kind` before showing current receipts.
- Pre-release dev data may need destructive migration or regeneration.

## Required Follow-up

- Add schema tests for mediated, trace, and advisory current v1 receipts.
- Add verifier tests that reject trace/advisory records carrying decisions.
- Add a separate extension-binding ADR before adding `must_understand`,
  extension signing, or extension hash tests.
- Add UI and SIEM wording tests that forbid showing trace or advisory records as
  `Allow`.
- Update adapter ticket templates to require `receipt_kind`,
  `boundary_class`, durability state, verifier behavior, and UI/SIEM wording.
