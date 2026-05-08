# Bilateral Cosigned Invocation Flow - DSSE Adapter

This document maps the spec wire format
(`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`) onto the federation
types and specifies how Lane C consumes Lane B's B4 DSSE-conformant
signing primitive.

**Wave 3 rework (review finding 1):** the original Wave 1 plan proposed
a Lane-C-side "Option A" two-signature adapter that bolted a DSSE
PAE signature alongside the existing `CoSigningBody` signature. The
review (`reviews/R4-lane-c-feasibility.md` Finding 1)
rejected that design as structural-framing-without-wiring and
escalated the DSSE-conformant signing primitive to Lane B as
sub-lane B4 (`lane-b-wiring/dsse-bilateral-signing.md`, tickets
`bilateral DSSE signing item-B4.6` plus `bilateral DSSE signing item` Evidence Gate close).
After B4 lands:

- The kernel hot path emits the spec §6 DSSE envelope by default
  for cross-org bilateral cosign dispatch.
- The legacy `CoSigningBody`-scoped Ed25519 signing surface is
  retained only as a fixture-only signer used by B4's negative
  conformance test (proves the production verifier rejects the
  legacy preimage).
- Lane C consumes the B4-produced envelope, drives the demo
  orchestration that constructs the §5 predicate body from kernel
  state, and walks the §7 partial local verifier subset.

The remainder of this document specifies (a) the spec §6 wire
shape, (b) the §5 predicate body fields the demo populates,
(c) Lane C's helper for predicate construction, and (d) the §7
verifier algorithm with the architecture cut for cross-crate
calls.

## What exists today

From `crates/chio-federation/src/bilateral.rs`:

```text
CoSigningBody (line 41):
  schema: String                                = "chio.federation-bilateral-cosigning.v1"
  receipt_canonical_json: String                = canonical JSON of ChioReceipt body
  org_a_kernel_id: String                       = did:chio identifier
  org_b_kernel_id: String                       = did:chio identifier

DualSignedReceipt (line 93):
  schema: String                                = "chio.federation-dual-signed-receipt.v1"
  body: ChioReceipt
  org_a_kernel_id, org_b_kernel_id: String
  org_a_signature, org_b_signature: Signature   (Ed25519 over canonical_bytes(CoSigningBody))

CoSigningRequest (line 132): wire-level RPC body sent B->A.
CoSigningResponse (line 162): wire-level RPC reply A->B.

Verification (line 108 verify):
  - Reconstruct CoSigningBody from receipt + kernel IDs
  - Verify both Ed25519 signatures over its canonical bytes
  - Both must verify (fail-closed)
```

## What the spec section 6 requires

```text
DSSE envelope:
  payloadType: "application/vnd.in-toto+json"
  payload: Base64(canonical-JSON Statement)
  signatures: [
    { keyid: sha256_hex(server_a_passport_pubkey), sig: ed25519_pae }
    { keyid: sha256_hex(server_b_passport_pubkey), sig: ed25519_pae }
  ]

Statement (in-toto v1):
  _type: "https://in-toto.io/Statement/v1"
  subject: [{ name: "...", digest: { sha256: <hex> } }]
  predicateType: "chio.bilateral-cosign-invocation.v1"   <-- chio-namespaced fallback
  predicate: <spec §5 schema>

PAE (RFC 8785 + DSSEv1):
  "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(statement_bytes) SP statement_bytes
```

## Mapping (where the bytes come from)

| Spec field | Source today | Gap |
|---|---|---|
| `payloadType` | constant | none |
| `payload` (decoded -> Statement) | NEW: serialised in adapter | adapter |
| `Statement._type` | constant | none |
| `Statement.subject[0].digest.sha256` | SHA-256 over canonical JSON of `ChioReceipt` body. The receipt body IS what `CoSigningBody.receipt_canonical_json` is the string form of. | adapter must compute the digest |
| `Statement.predicateType` | constant `"chio.bilateral-cosign-invocation.v1"` | none |
| `Statement.predicate` | NEW struct `BilateralCoSignInvocationPredicate` populated from kernel state | adapter |
| `signatures[0].keyid` | SHA-256 of Org A passport public key (hex). Org A's public key comes from `FederationPeer.passport_public_key`; the kernel's own pubkey is on the `Keypair`. | adapter must derive `keyid` |
| `signatures[0].sig` | Ed25519 over the PAE bytes. **Different message bytes** than today's `CoSigningBody.canonical_bytes()`. | adapter signs the PAE; not the existing body |
| `signatures[1].keyid` / `sig` | same, for Org B | adapter |

## Single signing surface: DSSE PAE produced by Lane B B4

review (review finding 1) rejected the original "Option A:
two co-existing signatures" design. The reasoning, in brief: the
existing `CoSigningBody`-scoped signature is not in any sense the
spec section 6 PAE-over-Statement signature; shipping both alongside
each other would let release work tag a "spec-§6 conformant" release whose
primary federation artifact (`DualSignedReceipt`) is signed under a
non-§6 preimage. That is the structural-framing-without-wiring
anti-pattern (`templates/EVIDENCE-GATE.md` §2.4) verbatim.

**The resolution is structural, not adapter-level.** Lane B's
fourth primitive sub-lane B4 (`lane-b-wiring/dsse-bilateral-signing.md`,
tickets `bilateral DSSE signing item-B4.6` plus `bilateral DSSE signing item` Evidence Gate close)
replaces the `DualSignedReceipt`
signing surface so the production cross-org dispatch path emits
DSSE-conformant Ed25519-over-PAE signatures by default. After B4
lands:

- The kernel-side bilateral cosigning hot path emits DSSE PAE
  signatures (one preimage, spec-§6 conformant).
- The legacy `CoSigningBody::canonical_bytes()` signing surface is
  retained only as a private helper used by Lane B's negative
  conformance fixture (a fixture-only signer that proves a legacy
  signature is REJECTED by the production verifier).
- Lane C's adapter is a thin wrapper that consumes the B4-produced
  envelope and walks the spec section 7 partial local verifier subset; it does
  not introduce its own parallel signing surface.

Lane C therefore depends on `bilateral DSSE signing item` (the gating B4 negative
conformance fixture, analogous to the B1.6/B2.5/B3.5 gating pattern)
for the production signing hot path; the C2 sub-lane simplifies from
"build an Option-A adapter that bolts a second signature on" to
"consume B4 envelopes and run the §7 verifier".

If Lane B reports during W2/W3 that B4 cannot fit the release work budget,
the fallback (review finding 1 option 2) is to ship Lane C with explicit
bounded-claim language disclaiming spec-§6 conformance for the
legacy `DualSignedReceipt` and asserting §6 conformance only of a
Lane-C-side DSSE adapter. This fallback is documented in
`release-bar.md` "Fallback bounded-claim text (if B4 slips)" but is
NOT the primary plan.

## The adapter module

After B4 lands, `crates/chio-federation/src/bilateral_dsse.rs`
(introduced by B4) is where the production envelope shape lives.
Lane C extends this module with:

- A small Lane-C-side helper `build_envelope_from_kernel_state` that
  constructs the §5 predicate body from kernel A and kernel B state
  during the demo's orchestration (the kernel exposes this state via
  trait objects so the federation crate does not need a kernel
  dependency; see Finding 8 below).
- The full §7 partial local verifier subset (`verify_envelope`), invoked by the
  demo and by `chio receipt explain` for bilateral chains.

```rust
// crates/chio-federation/src/bilateral_dsse.rs (extended by Lane C;
// the envelope and signing types themselves live here as of Lane B B4)

use crate::bilateral::{CoSigningBody, BilateralCoSigningError, DualSignedReceipt};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

pub const BILATERAL_COSIGN_INVOCATION_SCHEMA: &str =
    "chio.bilateral-cosign-invocation.v1";

pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// In-toto Statement carrying the bilateral cosign invocation predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BilateralCoSignInvocationStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,            // "https://in-toto.io/Statement/v1"
    pub subject: Vec<StatementSubject>,
    pub predicate_type: String,            // "chio.bilateral-cosign-invocation.v1"
    pub predicate: BilateralCoSignInvocationPredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementSubject {
    pub name: Option<String>,
    pub digest: Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub sha256: String,                    // hex
}

/// Predicate body matching spec §5 schema verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BilateralCoSignInvocationPredicate {
    pub invocation_id: String,
    pub tool_server_a: KernelIdentity,
    pub tool_server_b: KernelIdentity,
    pub tool_name: String,
    pub tool_args_hash: HashRef,
    pub capability_lease_ref: CapabilityLeaseRef,
    pub policy_evaluation_summary: PolicyEvaluationSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_receipt_ref: Option<GovernanceReceiptRef>,
    pub consistency_model: ConsistencyModel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency_anchor: Option<ConsistencyAnchor>,
    pub cross_org_visibility: CrossOrgVisibility,
    pub co_sign: CoSignMode,
    pub timestamp_unix_ms: u64,
}

/// DSSE envelope carrying the Statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,              // DSSE_PAYLOAD_TYPE
    pub payload: String,                   // Base64 of canonical-JSON Statement
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,                     // sha256 hex of passport pubkey
    pub sig: String,                       // Base64
}

pub fn dsse_pae(payload_type: &str, statement_bytes: &[u8]) -> Vec<u8> {
    // "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    let mut out = Vec::with_capacity(
        "DSSEv1".len() + 1 + 16 + 1 + payload_type.len() + 1 + 16 + 1 + statement_bytes.len()
    );
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(statement_bytes.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(statement_bytes);
    out
}

// As of Lane B B4, envelope construction happens inside the kernel
// hot path during cross-org bilateral dispatch. The two kernels each
// sign the PAE with their own passport keypair (the bilateral
// signing protocol is described under "Two-keypair signing protocol"
// below). Lane C's role is to drive the demo orchestrator so that
// envelopes are emitted, captured into fixtures, and verified.
//
// This module exposes a Lane-C-side helper for demo orchestration
// (constructing the predicate body from out-of-band kernel state):

pub fn predicate_from_kernel_state(
    kernel_a_view: &impl BilateralKernelView,
    kernel_b_view: &impl BilateralKernelView,
    invocation: &CrossOrgInvocationContext,
) -> Result<BilateralCoSignInvocationPredicate, BilateralCoSignError> {
    // Populate every spec §5 field from the trait views. No kernel
    // crate dependency: the trait re-exports are the seam.
    Ok(BilateralCoSignInvocationPredicate { ... })
}

/// Spec §7 verification algorithm.
pub fn verify_envelope(
    envelope: &DsseEnvelope,
    pinned_epoch: u64,
    peer_pin_set: &PeerPinSet,
) -> Result<VerifiedBilateralCoSignInvocation, BilateralCoSignError> {
    // Steps 1-17 from spec §7. Each step returns its named error code
    // on failure. See bilateral_dsse_negative.rs for the negative
    // fixtures matching each error code.
}
```

## Verification algorithm gap analysis

Spec section 7 defines verification obligations; here is what each requires from
existing crates:

| Step | What it needs | Have it? |
|---|---|---|
| 1 | DSSE parse | Lane B B4 (envelope types live in `bilateral_dsse.rs`) |
| 2 | Base64 decode payload | Lane B B4 |
| 3 | in-toto Statement schema parse | Lane B B4 |
| 4 | predicateType in {chio fallback, in-toto canonical} | Lane B B4 |
| 5 | predicate body validates against spec §5 schema | Lane B B4 (schema bundled as `&str`) |
| 6 | parse predicate | Lane B B4 |
| 7 | subject digest equals canonical-JSON SHA-256 of resolved receipt body | Lane C verifier; receipt resolution via the existing `ReceiptStore` trait (`chio-kernel::receipt_store::ReceiptStore`); depends on `release work-B2.x` so the receipt body is actually v2 when negotiated v2 |
| 8 | both kernel_ids in `peer_pin_set` and fingerprints match | Lane C verifier; pin set comes from `FederationPeer` table |
| 9 | both passports non-revoked at pinned_epoch | uses `crates/chio-revocation` (existing) |
| 10 | recompute PAE | Lane B B4 (PAE function reused) |
| 11 | server_a Ed25519 over PAE | Lane B B4 |
| 12 | server_b Ed25519 over PAE | Lane B B4 |
| 13 | verdicts agree; joint_disposition consistent | Lane C verifier |
| 14 | capability lease resolves; not expired | Lane C verifier via `CapabilityVerifier` trait whose impl in `chio-kernel` calls `verify_capability_full` (depends on `release work-B1.x`) |
| 15 | governance_receipt_ref present iff receipt-backed | Lane C verifier; ladder lookup |
| 16 | consistency_anchor reconcilable | uses `chio-anchor`; depends on `release work-B3.x` so async path is the only reachable one when public-witness required |
| 17 | return | Lane C verifier |

## Wire format precisely

### Canonicalisation rules

- Statement body: RFC 8785 JCS over the in-toto Statement struct.
- Predicate body: RFC 8785 JCS, then `payload = base64url(canonical
  JSON statement)` per DSSE.
- Base64: standard `base64url` per RFC 4648 section 5; no padding for
  payload, no padding for signature bytes either - **all DSSE Base64
  in this adapter is RFC 4648 std-alphabet without padding**, matching
  what existing chio-federation tests use for `Signature`
  serialisation.

### Predicate field encoding

Matches spec section 5 schema verbatim. `serde(rename_all =
"camelCase")` aligns with the spec's JSON Schema property names
(`tool_server_a`, `tool_args_hash`, `capability_lease_ref`,
`policy_evaluation_summary`, `governance_receipt_ref`,
`consistency_model`, `consistency_anchor`, `cross_org_visibility`,
`co_sign`, `timestamp_unix_ms`). `additionalProperties: false`
enforced via `deny_unknown_fields`.

### Signature surface (recap)

The DSSE envelope's signatures are Ed25519 over PAE bytes of the
canonical-JSON Statement payload. After Lane B B4 lands this is the
ONLY production signing surface for cross-org bilateral cosign on
the kernel hot path. The legacy `CoSigningBody`-scoped Ed25519
preimage is retained as a fixture-only signer used by Lane B's
negative conformance test (`b4_legacy_cosigning_body_signature_rejected.rs`)
to prove the production verifier rejects legacy-shaped signatures.

`DualSignedReceipt::verify` is rewired by B4 to call into the DSSE
envelope path. Existing test fixtures that hand-construct legacy
`DualSignedReceipt` bodies are migrated by B4; any remaining
references in this lane's docs to "two co-existing signatures" are
errata that pre-date the B4 promotion.

## Two-keypair signing protocol

The DSSE envelope carries two signatures (one per kernel). Each
kernel only holds its own passport keypair. The bilateral signing
protocol therefore runs in two steps:

1. Kernel A canonicalizes the Statement, computes the PAE, signs
   the PAE with its own keypair, and forwards `{statement_bytes,
   sig_a, keyid_a}` to Kernel B as part of the existing
   `CoSigningRequest` exchange (`crates/chio-federation/src/bilateral.rs`
   wire-level RPC body, generalised by B4 so the request carries
   the Statement bytes rather than only the legacy `CoSigningBody`).
2. Kernel B re-derives the PAE from the same Statement bytes
   (rejecting if the bytes do not canonicalize to themselves),
   signs with its own keypair, and assembles the final two-signature
   envelope returned to Kernel A in the `CoSigningResponse`.

This pattern matches the existing `CoSigningRequest` /
`CoSigningResponse` cadence; B4 generalises the wire body but keeps
the round-trip count.

## Required Lane B invariants

Step 14 `capability.lease_expired_or_unknown` is only reliable if
Lane B's `verify_capability_full` is the only hot-path verifier; if
`verify_capability_full_without_budget_admit` is still reachable, a
lease in the predicate could be stale at the kernel boundary even
though the predicate's `expires_at_unix_ms` validates here. In other
words: the spec's verifier checks the lease against pinned_epoch.now,
but the kernel that minted the receipt could have admitted the call
under the legacy verifier and the demo's adversarial fixture wouldn't
catch that. Lane B `release work-B1.x` (single-entry verifier) closes that
hole. Lane B `release work-B2.x` closes the receipt-v2 downgrade hole that
otherwise breaks step 7 (subject digest). Lane B `bilateral DSSE signing item` closes
the signing-surface hole that otherwise leaves §6 unenforced.

## Architecture cut for cross-crate calls

Spec §7 steps 7 (subject digest equals canonical-JSON SHA-256 of the
resolved receipt body) and 14 (capability lease resolves) require
the verifier to reach into kernel-resident state. Three options:

A. New crate `chio-cosign-verifier` that depends on both
   `chio-kernel-core` and `chio-federation` and hosts the §7
   verifier. Lane C ships this crate.
B. The §7 verifier lives in `chio-federation` (alongside the B4
   envelope module) but takes trait objects for `ReceiptStore` and
   `CapabilityVerifier` so it does not pull in `chio-kernel`
   directly. Lane C ships the trait definitions; the demo wires
   `chio-kernel`'s implementations.
C. The §7 verifier lives in `chio-kernel`, which already depends on
   `chio-federation`. Grows `chio-kernel` surface; works against
   synthesis line 366-367 ("we do not refactor kernel/mod.rs beyond
   Lane B's `ToolServerConnection` work").

**Decision: option B.** Cleanest. `ReceiptStore` is already a trait
in `chio-kernel::receipt_store::ReceiptStore`
(`crates/chio-kernel/src/lib.rs:396-397` re-exports it). Lane C
adds a `CapabilityVerifier` trait in `chio-federation` whose
implementation in `chio-kernel` calls `verify_capability_full`
(B1's single-entry verifier). The §7 verifier in `chio-federation`
takes both as trait objects. No new crate is required; no kernel
hot-path mutation beyond B1/B2/B3/B4 is required.

## What is NOT in the adapter (deferred)

- `n_of_m` co-sign mode (spec section 6 lines 313-317). Demo runs
  `bilateral_required` only; the adapter struct supports the enum
  variant but emission is gated.
- in-toto canonical predicateType. Spec section 3 mandates the
  chio-namespaced fallback until WG acceptance; we ship that.
- Rekor uploads (spec section 9). Demo does not write to Rekor;
  bounded-claim discipline.
- Workflow receipt composition (spec section 8). Demo emits the
  bilateral envelope per refund step, not a workflow-level wrapper.
  The composition rule is documented; the demo's single-step
  scenario is a degenerate case.
