# in-toto attestation WG issue draft

**Status**: Draft. Not yet filed.
**Intended target**: <https://github.com/in-toto/attestation/issues>
**Owner**: file under your own GitHub identity.
**Date**: 2026-05-04

This file is a ready-to-paste GitHub issue body packaging
[`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`](../../spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md)
for upstream engagement. Adjust the framing once we have a stable
public link to the spec (today it lives in this private repo). Strip
this preamble before posting.

---

## Suggested title

```
Proposal: bilateral-cosign-invocation predicate type for runtime agent invocation receipts
```

## Suggested labels

`predicate`, `discussion`, `runtime`, `ai-ml`

## Suggested assignees / cc

- @adityasaky (in-toto attestation framework maintainer)
- @TomHennen (SLSA spec lead)
- /cc OpenSSF AI/ML Security WG, CoSAI Workstream 4

---

## Body

### Summary

We have a runtime-attestation use case that does not fit any current
in-toto predicate cleanly, and we would like the WG's read on whether
to land a new predicate type, extend `runtime-trace`, or treat it as
out-of-scope.

The use case is **cross-vendor agent action attestation**: when
Vendor A's agent invokes Vendor B's tool on a buyer's behalf, both
vendors' kernels independently evaluate the request, sign the same
canonical body, and produce a **jointly-authored** attestation. The
buyer's auditor verifies every cross-vendor action without trusting
either vendor unilaterally. This is structurally distinct from
single-party DSSE entries on Rekor (no notion of joint intent),
`runtime-trace` (no cross-org bilateral semantics), and
`slsa-provenance` (build-shaped, not invocation-shaped).

### Proposal at a glance

Predicate type URI:

```
https://in-toto.io/attestation/bilateral-cosign-invocation/v1
```

Subject: the canonical-JSON SHA-256 of the underlying invocation event
(in our project this is a `ChioReceipt`, but the predicate is
agnostic to the receipt format).

DSSE envelope: two signatures over the same Statement payload, one
per kernel. The mechanically-checkable contract that distinguishes
joint commit from accidental dual-signing is a **named-set keyid
binding**: both kernel passport key fingerprints MUST appear in the
predicate body, and both signatures MUST verify against those exact
keyids. Either signature alone is insufficient.

Predicate body (highlights; full schema in the linked spec):

- `invocation_id`
- `tool_server_a` and `tool_server_b` (passport key fingerprints)
- `tool_name`, `tool_args_hash`
- `capability_lease_ref` (per-action attenuated authorisation scope)
- `policy_evaluation_summary` (each side's local policy verdict)
- `governance_receipt_ref` (optional; required for destructive actions)
- `consistency_model` (`crdt-commutative` / `totally-ordered` / `quorum-required`)
- `cross_org_visibility`, `co_sign`
- `timestamp_unix_ms`

Verification (17-step pseudocode in the linked spec; key invariants):

- Both DSSE signatures MUST verify against the declared keyids.
- Both kernel passports MUST be currently valid at the verifier's
  pinned revocation epoch.
- The `policy_evaluation_summary` MUST agree on the verdict.
- The `capability_lease_ref` MUST resolve to a non-expired lease.

Composition with workflow receipts: N bilateral-cosign-invocation
predicates compose into a single workflow predicate (a separate type;
not in this proposal).

Composition with Rekor: the DSSE envelope can be additionally
anchored in Rekor v2 for transparency-log evidence. This is a free
property and does not change the verification contract.

### Why a new predicate, and not an extension to `runtime-trace`

`runtime-trace` per the current spec captures process / network /
file-system events inside a single build step and explicitly disclaims
cross-organisational signing semantics. The bilateral-cosign-invocation
predicate is structurally different:

- The signing surface is multi-party by design (DSSE PAE over two
  signatures with named-set keyid binding), not a transport-level
  artefact.
- The predicate carries authorisation scope (`capability_lease_ref`)
  that has no analogue in `runtime-trace`.
- The verifier's accept/reject decision depends on cross-party
  agreement (`policy_evaluation_summary`), not on a single-party
  trace.

We are open to making it a sibling under `runtime-trace`'s namespace
if the WG prefers, but the verification contract is different enough
that we expect a sibling type rather than a field extension is the
right shape.

### Open questions for the WG

1. Does the WG want to absorb a multi-signer predicate type, or
   prefer a sibling DSSE envelope variant that carries multi-signer
   semantics outside the predicate body?
2. Is there appetite for a workflow-receipt predicate that composes
   N of these into a single attestation, or should that live in a
   separate spec (e.g., chiodos-side)?
3. Should the `capability_lease_ref` shape be standardised (in-toto
   defines a capability format) or left implementation-defined and
   carried by reference only?
4. How should the predicate interact with Rekor v2 entries? Should
   the WG bless a specific anchoring profile?
5. Does the project want a worked example using a non-Chio runtime
   to demonstrate the predicate is portable?

### Engagement intent

Our intent in opening this issue is to either (a) land
bilateral-cosign-invocation semantics in the in-toto vocabulary, or
(b) confirm in writing that this is structurally out of scope for
in-toto, so we can document the gap honestly in our own protocol.

The full draft spec (Status: Draft v0.1) including the complete JSON
Schema, verification pseudocode, comparison table against
`runtime-trace` / `slsa-provenance` / single-party DSSE on Rekor,
and engagement plan is at `<insert public URL when published>`. Happy
to mirror the spec into a fresh repo or as an ITE if that is the
preferred contribution path; let us know what works for the WG.

Thank you for reading.

---

## Engagement steps after filing

1. Post the issue body above. Link to the spec from a public mirror
   if this repo is not yet public.
2. Cross-post a short note to the OpenSSF AI/ML Security WG mailing
   list with a link to the issue.
3. Cross-post to the CoSAI Workstream 4 channel with a link to the
   issue.
4. If the WG indicates appetite, draft an ITE following the
   contribution process documented at
   <https://github.com/in-toto/ITE/blob/master/CONTRIBUTING.md> (verify
   path before posting).
5. Track responses in this file; update the CHIODOS_CONCEPT
   "next moves" section to reflect WG feedback.
