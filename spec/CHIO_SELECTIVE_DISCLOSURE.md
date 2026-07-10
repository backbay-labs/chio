# Chio Selective Disclosure Over Chio Receipts

**Status:** v1 wire format with a real-BBS implementation slice.

This specification describes the v1 wire format and verification
contract for **selective-disclosure proofs over chio receipts and
workflow receipts**. The repository now includes
`chio-selective-disclosure` with an opt-in `bbs` feature that signs
receipt, workflow, and step projections and verifies reveal-set BBS
proof packages. Compatibility federation placeholder proof packages are not a
conformance surface and any schema ending in `.stub` is rejected by the
v1 proof schema and verifier. Hidden range predicates, VC Data
Integrity interop, and zkVM proofs are still deferred.

The v1 contract defines privacy and selective-disclosure support over signed
canonical-JSON receipts. Signed receipts remain authoritative; a secondary
commitment is added for efficient proof generation.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY
are to be interpreted as described in RFC 2119. Canonical JSON
serialisation follows RFC 8785 (JCS): UTF-8, sorted object keys, no
insignificant whitespace, exact-form numbers.

---

## 1. Motivation

The three motivating use cases are structurally identical: a cybersec peer
proves a detection meets a confidence threshold
without revealing the indicator; a finance counterparty proves a
settlement falls within an amount cap without disclosing amount or
counterparty; a compliance verifier proves KYC tier sits at or above
a floor without revealing tier or evidence. All reduce to one
primitive: **a verifier wants a predicate over a signed chio receipt
body without learning the body.**

The 3-vendor cross-vendor fixture exercises the same primitive at the workflow
layer: a buyer auditor
verifies "the refund step transferred no more than $250 to a customer
at KYC tier 2 or higher" without learning customer, exact amount, or
upstream prompts. The implemented v1 slice proves reveal-set BBS
disclosure. Hidden comparisons such as "amount <= $250 while the amount
is hidden" remain G6 follow-up work. Gaps G3 and G9 are now handled by
the workflow verifier through optional `StepRecord` fields, while the
BBS step projection remains limited to stable step summary fields.

---

## 2. Scope

### 2.1 Implemented slice

- BBS secondary commitments over a single
  [`ChioReceipt`](../crates/core/chio-core-types/src/receipt/body.rs) body.
- BBS secondary commitments over a
  [`WorkflowReceipt`](../crates/platform/chio-workflow/src/receipt.rs) body and
  its inner `StepRecord` list.
- A canonical envelope schema (`chio.selective-disclosure-proof.v1`)
  for reveal-set proofs.
- An opt-in implementation crate:
  [`chio-selective-disclosure`](../crates/trust/chio-selective-disclosure/src/lib.rs).

### 2.2 Target scope still open

- A frozen predicate language: three primitives (`eq`, `cmp`,
  `member`), `AND`-only composition, hard ceiling of eight clauses.
- Predicate verification for hidden comparisons or membership.

### 2.3 Out of scope (future-projection gated)

- The future zkVM lane (Risc0 / SP1 + Groth16 wrap) for chained-receipt
  proofs, predicates over the Ed25519 signature itself, predicates
  over fields hashed into a single BBS message (5.6), and
  non-arithmetic boolean composition (`OR`, negation, nested
  quantifiers). Section 13 enumerates the deferred surfaces.
- SD-JWT VC bridging for EUDI Wallet interop: the EUDI ARF does not
  approve BLS12-381, so a separate SD-JWT VC mapping is required for
  EUDI-facing verifiers. Flagged in section 14.
- `OR` and negation in the predicate language; deferred so v1 stays
  expressible by BBS+ + AnonCreds-v2 range proofs alone.

---

## 3. Cryptosuite Pinning

This specification pins the BBS+ surface to:

- **Cryptosuite:** `bbs-2023` (W3C *Data Integrity BBS Cryptosuites
  v1.0*, Candidate Recommendation Draft). Implementations MUST track
  W3C CR exit and bind to the eventual recommendation hash.
- **Signature:** IRTF CFRG BBS+ per `draft-irtf-cfrg-bbs-signatures-10`
  over BLS12-381 (`bls12-381-sha-256` default; `bls12-381-shake-256`
  MAY be negotiated).
- **`cmp` range proofs:** Hyperledger AnonCreds v2 `RangeStatement`
  (Bulletproofs-style commitments + range proofs) over the same
  BLS12-381 commitments the BBS+ projection produces.
- **`member` Merkle inclusion:** SHA-256 binary Merkle tree, RFC 9162
  leaf encoding (`0x00 || leaf`) and node encoding
  (`0x01 || left || right`). Roots are signed by an external signer
  whose public key is part of the proof's public inputs.

Ed25519 over RFC 8785 JCS remains the **authoritative** signature on
every chio receipt and workflow receipt. The BBS+ signature is a
**secondary commitment**: verifiers uninterested in selective
disclosure ignore it and rely on Ed25519 exactly as today. Verifiers
that do care MUST first verify Ed25519, then verify the BBS+
commitment was produced over the canonical projection of the same
body (section 9). Two signatures bind one body.

v1 pins narrowly: implementations MUST NOT ship BBS#, threshold-BBS,
or other variants. Future revisions MAY add them under new schema ids
once IRTF and W3C documents stabilise.

---

## 4. Cross-Spec Consistency

- [CHIO_PHEROMONE.md](./CHIO_PHEROMONE.md) section 11 reserves a
  future BBS+ projection over the pheromone deposit body; when it lands,
  its ordering rule MUST follow the same canonical-ordering principle
  (5.1) used here.
- [CHIO_LADDER.md](./CHIO_LADDER.md) section 9 lists "BBS+
  projection of the manifest body" as open; once specified, the
  manifest projection inherits this spec's predicate language and
  envelope schema by reference.
- [CHIO_BILATERAL_COSIGN_INVOCATION.md](./CHIO_BILATERAL_COSIGN_INVOCATION.md):
  a disclosure proof MAY bind to a bilateral-cosign invocation by
  referencing the invocation's `subject.digest.sha256` in the
  envelope's `subject_receipt_sha256` field. The disclosure proof
  attests properties of the receipt body that the bilateral envelope
  signs over; it does not replace it.

---

## 5. ChioReceipt Projection

### 5.1 Canonical message ordering

Each disclosable top-level field of `ChioReceiptBody` projects to one
BBS message (one BLS12-381 scalar). Ordering is **alphabetical by
serde field name**, frozen by `bbs_projection_version` (5.3). The
`bbs_projection_version` field itself is a projection selector, not a
projected message; it is bound by `ChioReceiptIdInput` and by the BBS
header's `projection_version`.
Alphabetical wins over schema-declared because (a) inserting a field
forces a new projection version rather than silently shifting
indices, (b) it is mechanically reproducible from the struct with no
sidecar manifest, and (c) RFC 8785 already mandates alphabetical key
ordering for canonical JSON, so projection and JCS walk the same
fields in the same sequence.

### 5.2 Field-by-field projection table

`chio.bbs-projection.receipt.v1` maps `ChioReceiptBody` to messages
in alphabetical-by-serde-field-name order. Encoding shorthand: `S` =
UTF-8 bytes hashed to scalar; `H` = SHA-256 over canonical JSON of a
structured sub-body, mapped to scalar (wholesale-only per 5.6); `Hx`
= hex-decoded 32-byte SHA-256 mapped to scalar; `U64` = u64
little-endian; `Opt<S>` = `S` with `None` projected as `"\u{0000}"`.

| Index | Field | Encoding | Notes |
|---|---|---|---|
| 0  | `action`        | H        | wholesale-only |
| 1  | `capability_id` | S        | disclosable |
| 2  | `content_hash`  | Hx       | disclosable |
| 3  | `decision`      | H        | wholesale-only |
| 4  | `evidence`      | H        | wholesale-only |
| 5  | `id`            | S        | disclosable |
| 6  | `kernel_key`    | H        | disclosable |
| 7  | `metadata`      | H (`None` -> `"null"`) | wholesale-only |
| 8  | `policy_hash`   | Hx       | disclosable |
| 9  | `tenant_id`     | Opt<S>   | disclosable |
| 10 | `timestamp`     | U64      | `cmp`-able |
| 11 | `tool_name`     | S        | disclosable |
| 12 | `tool_server`   | S        | disclosable |
| 13 | `trust_level`   | S (`as_str()`) | disclosable |

Hash-to-scalar is `BBS.hash_to_scalar` from
`draft-irtf-cfrg-bbs-signatures-10` section 4.4. Default ciphersuite
`bls12-381-sha-256`; `bls12-381-shake-256` MAY be negotiated out of
band.

### 5.3 Schema versioning

`ChioReceiptBody` gains an optional `bbs_projection_version: Option<String>`
declaring which projection produced the BBS+ commitment. v1
implementations MUST emit `"chio.bbs-projection.receipt.v1"` when a
`bbs_signature` is present and MUST omit it otherwise. Older receipts
that lack the field deserialize unchanged. Unknown versions fail
closed (`disclosure.unknown_projection_version`).

### 5.4 New optional `bbs_signature` field

`ChioReceipt` gains an optional
`bbs_signature: Option<BbsReceiptSignature>` carrying:

- `schema = "chio.receipt.bbs_signature.v1"`
- `projection_version`
- `algorithm = "bbs"`
- `ciphersuite`
- `issuer_fingerprint`
- `issuer_public_key_hex`
- `message_count`
- `signature_hex`

The Ed25519 authoritative signature MUST cover this field through the
canonical `ChioReceiptSigningBody` wrapper. `ChioReceiptIdInput`
includes `bbs_projection_version` but not the BBS signature bytes, so
producers can compute the final receipt id, project that final body,
produce the BBS signature, then bind the BBS material into the
authoritative Ed25519 signature without a circular id dependency.
Verifiers that ignore selective disclosure MUST still re-canonicalize
and re-verify Ed25519 with the field included when present, preserving
the two-commitment binding.

### 5.5 Per-kernel BBS keypair

Each kernel maintains a **separate** BBS+ keypair from its Ed25519
federation identity. BLS12-381 and Ed25519 are not interchangeable
and their security analyses do not compose. The BBS+ public key MUST
be advertised in the kernel's `chio-credentials` passport under a new
`bbs_public_key` field (sibling work; v1 treats as a forward
reference). Issuer fingerprints that do not resolve to a non-revoked
passport at pinned_epoch fail closed
(`disclosure.bbs_issuer_unknown_or_revoked`).

### 5.6 Nested-field disclosure constraint

Wholesale-only rows (0, 3, 4, 7 of the 5.2 table) carry a single BBS
message. They MAY be revealed wholesale (producer discloses the
nested JSON body, verifier re-hashes) or kept hidden, but v1
clauses cannot reach inside. Predicates over individual
`GuardEvidence` elements MUST defer to the future zkVM lane. This is a
deliberate v1 simplification: the nested-field count is small,
wholesale disclosure covers most asks, and the future zkVM lane handles
the residual.

---

## 6. WorkflowReceipt Projection

### 6.1 Workflow-level messages

`chio.bbs-projection.workflow.v1` maps `WorkflowReceiptBody`
alphabetically (encoding shorthand from 5.2):

| Index | Field | Enc. | Notes |
|---|---|---|---|
| 0  | `agent_id`       | S      | disclosable |
| 1  | `capability_id`  | S      | disclosable |
| 2  | `completed_at`   | U64    | `cmp`-able |
| 3  | `duration_ms`    | U64    | `cmp`-able |
| 4  | `id`             | S      | disclosable |
| 5  | `kernel_key`     | H      | disclosable |
| 6  | `outcome`        | H      | wholesale-only |
| 7  | `schema`         | S      | disclosable |
| 8  | `session_id`     | Opt<S> | disclosable |
| 9  | `skill_id`       | S      | disclosable |
| 10 | `skill_version`  | S      | disclosable |
| 11 | `started_at`     | U64    | `cmp`-able |
| 12 | `total_cost`     | H      | wholesale-only at workflow level (per-step `cost` is in 6.2) |

The `steps` field is **not** projected here; each `StepRecord`
contributes its own message list per 6.2.

### 6.2 StepRecord projection

`chio.bbs-projection.step.v1` (encoding shorthand from 5.2; `B` = u8
padded to scalar):

| Idx | Field | Enc. |
|---|---|---|
| 0 | `step_index` | U64 |
| 1 | `server_id` | S |
| 2 | `tool_name` | S |
| 3 | `allowed` | B |
| 4 | `tool_receipt_id` | Opt<S> |
| 5 | `outcome` | S (`success`/`denied`/`failed`/`skipped`) |
| 6 | `duration_ms` | U64 |
| 7 | `cost` | H |
| 8 | `output_hash` | Opt<S> |

Chio workflow receipts include optional `StepRecord` fields for bilateral
DSSE linkage, governance receipt id, parent receipt hash, consistency anchor,
and destructive-step status. Those fields are verified by the offline Chio
package verifier. They are not part of `chio.bbs-projection.step.v1`; adding
them to the BBS projection would require a future projection profile.

| Idx | Field (future-projection gated) | Enc. |
|---|---|---|
| 9  | `bilateral_dsse_sha256` | Hx |
| 10 | `governance_receipt_id` | Opt<S> |
| 11 | `parent_receipt_sha256` | Hx |
| 12 | `consistency_anchor` | S (CHIO_LADDER 4.2 enum) |
| 13 | `destructive` | B |

Until then, `step.v1` stops at index 8 and verifiers MUST reject
proofs referencing indices 9-13. Disclosure proofs carry their own
projection version; verifiers fall back fail-closed on unknown
versions.

### 6.3 Composition

The workflow-level BBS+ signature commits to a **list-of-lists**: the
ordered concatenation of (a) workflow-level messages, then (b)
per-step messages in `step_index` order. Step count N is bound via a
standard BBS+ header value (hash of the serialized count). Proofs MAY
reveal subsets of workflow-level messages by index, per-step messages
by `(step_index, message_index)`, or assert predicates over hidden
messages.

### 6.4 Worked example: 3-vendor buyer auditor

The auditor verifies "the refund step transferred no more than $250
to a customer at KYC tier 2 or higher" without learning customer,
exact amount, or upstream prompts. The producer:

- `subject_receipt_sha256`: SHA-256 of canonical-JSON
  `WorkflowReceiptBody`.
- Discloses workflow-level messages 7 (`schema`), 9 (`skill_id`),
  10 (`skill_version`).
- For refund `step_index = 4`, discloses step messages 0, 2, 5.
- Wholesale-discloses step 4 message 7 (`cost`); a parallel BBS
  message commits `cost.amount_minor` (7.2) and the `cmp` clause runs
  against it.
- A separate child receipt's projection contributes a `kyc_tier`
  message; `cmp(kyc_tier, >=, 2)` runs against that commitment.

Clauses:
`[cmp(refund_amount_minor, <=, 25000, scale=2), cmp(kyc_tier, >=, 2, scale=0)]`.
The auditor verifies per section 9 and learns nothing beyond the two
predicate outcomes plus the disclosed step fields.

---

## 7. Predicate Language v1 (frozen)

### 7.1 Primitives

**`eq(field, const)`**: field equals a public constant. Disclosed ->
direct comparison; withheld -> producer attaches an equality
commitment in the BBS+ PoK binding the hidden message to the constant
via the projection hash-to-scalar.

**`cmp(field, op, const)`** with `op` in `< | <= | > | >=`. BBS+ has
no native inequality. Implementations MUST use AnonCreds v2
`RangeStatement` (Bulletproofs-style commitment + range proof) over
the BBS commitment to prove the message lies on the appropriate side
of the constant. Const MUST be a non-negative integer or fixed-point
decimal with public `scale: u8`; negatives rejected
(`disclosure.range_negative_constant`).

**`member(field, merkle_root)`**: field is in a public set committed
by `merkle_root`. Root MUST be signed by an external signer (CCIP
allowlist, OFAC sanctions list, indicator hash set, etc.); the
signer's Ed25519 public key is in the proof's public inputs. The
envelope's `merkle_proofs[]` carries the inclusion path; verifiers
check it against the signed root plus an equality commitment binding
the hidden BBS message to the leaf.

### 7.2 Fixed-point and amount conventions

Monetary amounts MUST project as `amount_minor` (smallest currency
unit; USD cents, JPY yen) with explicit `scale` (USD `2`, JPY `0`).
Scale MUST be public and declared inline; mismatches rejected at
construction (`disclosure.scale_mismatch`).

### 7.3 Composition

**AND only**, hard ceiling of **eight clauses per proof**. v1
forbids `OR`, negation, nested quantifiers, and predicates over
wholesale-only field hashes (5.2, 6.1, 6.2); all flow to the future
zkVM lane. The ceiling is a deliberate cost cap; section 1 use cases
do not motivate more than four. Producers fail at construction,
verifiers reject (`disclosure.predicate_clause_count_exceeded`).

### 7.4 No predicates over nested-field hashes

A clause naming a wholesale-only field MUST be rejected at
construction with `disclosure.unknown_predicate_field`. Wholesale
disclosure plus a parallel projection clause (6.4) is the v1 path;
native predicates over nested sub-fields are future zkVM lane.

---

## 8. Disclosure Envelope Schema

The envelope schema id is `chio.selective-disclosure-proof.v1`. JSON
Schema (Draft 2020-12):

All objects below have `"type": "object", "additionalProperties": false`
(elided for brevity); `HEX64` is shorthand for
`{"type":"string","pattern":"^[0-9a-f]{64}$"}`; `IDX` is
`{"type":"integer","minimum":0}`; `CIDX` is
`{"type":"integer","minimum":0,"maximum":7}`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "chio.selective-disclosure-proof.v1",
  "required": ["schema_id", "subject_receipt_sha256", "projection_version",
    "predicate_clauses", "disclosed_messages", "withheld_messages",
    "bbs_proof_bytes", "issuer_bbs_public_key_fingerprint"],
  "properties": {
    "schema_id": { "const": "chio.selective-disclosure-proof.v1" },
    "subject_receipt_sha256": HEX64,
    "subject_receipt_kind": { "enum": ["chio_receipt", "workflow_receipt"] },
    "projection_version": { "enum": [
      "chio.bbs-projection.receipt.v1", "chio.bbs-projection.workflow.v1",
      "chio.bbs-projection.step.v1",    "chio.bbs-projection.step.v1.1" ] },
    "predicate_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
    "predicate_clauses": { "type":"array","minItems":0,"maxItems":8,
                           "items":{"$ref":"#/$defs/clause"} },
    "disclosed_messages": { "type":"array","items":{"$ref":"#/$defs/disclosed"} },
    "withheld_messages":  { "type":"array","items":{"$ref":"#/$defs/withheld"} },
    "range_proofs":       { "type":"array","items":{"$ref":"#/$defs/rangeProof"} },
    "merkle_proofs":      { "type":"array","items":{"$ref":"#/$defs/merkleProof"} },
    "bbs_proof_bytes": { "type": "string" },
    "issuer_bbs_public_key_fingerprint": HEX64,
    "verifier_image_hash": HEX64
  },
  "$defs": {
    "clause": {
      "required": ["kind", "field"],
      "properties": {
        "kind": { "enum": ["eq", "cmp", "member"] },
        "field": { "type": "string" },
        "op": { "enum": ["<", "<=", ">", ">="] },
        "const_value": {},
        "scale": { "type": "integer", "minimum": 0, "maximum": 18 },
        "merkle_root": HEX64, "merkle_root_signer_pk": HEX64,
        "merkle_root_signature": { "type": "string" },
        "step_index": IDX
      },
      "allOf": [
        { "if": {"properties":{"kind":{"const":"cmp"}}},
          "then": {"required":["op","const_value","scale"]} },
        { "if": {"properties":{"kind":{"const":"member"}}},
          "then": {"required":["merkle_root","merkle_root_signer_pk","merkle_root_signature"]} }
      ]
    },
    "disclosed": { "required":["index","value"],
                   "properties":{"index":IDX,"step_index":IDX,"value":{}} },
    "withheld":  { "required":["index"],
                   "properties":{"index":IDX,"step_index":IDX} },
    "rangeProof": { "required":["clause_idx","bytes"],
                    "properties":{"clause_idx":CIDX,"bytes":{"type":"string"}} },
    "merkleProof": {
      "required": ["clause_idx", "path"],
      "properties": {
        "clause_idx": CIDX,
        "path": { "type":"array", "items":{
          "required":["sibling","side"],
          "properties":{"sibling":HEX64,"side":{"enum":["left","right"]}} } },
        "leaf_commitment_proof": { "type": "string" }
      }
    }
  }
}
```

Envelopes are canonical-JSON-encoded per RFC 8785 before storage and
gossip.

---

## 9. Verification Algorithm

A conforming verifier MUST execute these steps in order. Any failure
aborts with the corresponding code from section 12.

```text
verify(envelope, pinned_receipt, pinned_epoch, peer_pin_set):
  1.  validate envelope against section 8 schema -> envelope_invalid
  2.  verify pinned Ed25519+JCS signature; require
      sha256_hex(canonical_json(body)) == envelope.subject_receipt_sha256
                                              -> subject_receipt_mismatch
  3.  for ChioReceipt subjects, require pinned.bbs_signature present and
      body.bbs_projection_version == envelope.projection_version
                                              -> unknown_projection_version
      for WorkflowReceipt subjects, require envelope.projection_version
      is a workflow projection version and rely on the proof header's
      subject hash binding until workflow-embedded BBS material lands
  4.  resolve issuer_bbs_public_key_fingerprint to non-revoked passport
      at pinned_epoch; verify fingerprint    -> bbs_issuer_unknown_or_revoked
  5.  recompute projection (section 5/6) -> message vector M
                                              -> projection_recompute_failed
  6.  for ChioReceipt subjects, verify pinned.bbs_signature against M
      and issuer key
                                              -> bbs_signature_invalid
      for WorkflowReceipt subjects, continue with proof verification
      against the trusted issuer key and recomputed workflow projection
  7.  verify envelope.bbs_proof_bytes as BBS+ PoK over the
      disclosed/withheld split, binding disclosed values to indices
                                              -> bbs_proof_invalid
  8.  require predicate_clauses.len() <= 8    -> predicate_clause_count_exceeded
  9.  for each clause c at index i in predicate_clauses:
        a. require c.field resolves to a known index AND the index is
           not wholesale-only (or wholesale-disclosed with a parallel
           projection message per 6.4)        -> unknown_predicate_field
        b. eq disclosed: compare value         -> eq_clause_mismatch
           eq withheld:  verify BBS equality commitment
                                              -> eq_commitment_invalid
        c. cmp: require range_proofs[i].clause_idx == i; verify range
                proof on commitment of c.field, c.op, c.const_value,
                c.scale                       -> range_proof_invalid
        d. member: require merkle_proofs[i].clause_idx == i;
                   verify Ed25519(c.merkle_root_signature) under
                   c.merkle_root_signer_pk    -> merkle_root_signature_invalid
                   verify inclusion path      -> merkle_proof_invalid
                   verify leaf_commitment_proof binds hidden BBS msg
                                              -> merkle_leaf_commitment_invalid
 10.  all clauses MUST verify (AND fails closed)
                                              -> predicate_and_failed
 11.  return Ok(VerifiedDisclosure { ... })
```

`pinned_receipt` (step 2) is the verifier's locally-held authoritative
receipt, fetched via its own audit-store lookup keyed on
`subject_receipt_sha256`. Verifiers that cannot resolve a pinned
receipt MUST fail closed (`disclosure.subject_receipt_unresolved`);
v1 does not specify a proof-carrying-receipt mode.

---

## 10. Implementation Crate Placement

The implemented slice lives in
[`chio-selective-disclosure`](../crates/trust/chio-selective-disclosure/src/lib.rs).
It is outside the default build and enabled with the crate's `bbs`
feature. Federation does not ship a parallel selective-disclosure
proof path; BBS projection, signing, proof derivation, and verification
are owned by `chio-selective-disclosure`.

The implementation uses `affinidi-bbs = 0.1.0`, pinned because
`affinidi-bbs = 0.1.1` requires Rust 1.94 while this workspace is pinned
to Rust 1.93. It keeps the baseline chio build BLS12-381-free unless
the `bbs` feature is selected.

Dependencies: `chio-core-types` (receipt body, canonical JSON,
signature primitives); `chio-workflow` (workflow receipt body, step
record); and the external BBS implementation. Range predicates still
need a future range-proof dependency.

Public surface:

```rust
pub struct SelectiveDisclosureProof {
    pub schema_id: String,
    pub predicate_id: Option<String>,
    pub public_inputs: PublicInputs,
    pub proof_bytes: Vec<u8>,
}

pub struct PublicInputs {
    pub subject_receipt_sha256: [u8; 32],
    pub projection_version: String,
    pub disclosed_messages: Vec<DisclosedMessage>,
    pub merkle_root_signers: Vec<Ed25519PublicKey>,
    pub issuer_bbs_public_key_fingerprint: [u8; 32],
}

pub fn verify(
    proof: &SelectiveDisclosureProof,
    pinned_receipt: &PinnedReceipt,
    pinned_epoch: AnchorEpoch,
    peer_pin_set: &PeerPinSet,
) -> Result<VerifiedDisclosure, DisclosureError>;
```

`verify` fail-closes mirroring
[chio-attest-verify](../crates/trust/chio-attest-verify/src/lib.rs): every
error path returns a stable `DisclosureError` whose `code()` yields
one of section 12's canonical strings.

---

## 11. Future Test Corpus Expectations

A future complete implementation must ship, at minimum, fixtures under
its own `tests/fixtures/` directory:

1. `chio-receipt-roundtrip.json`: ChioReceipt signed Ed25519+JCS and
   BBS+ over v1; proof reveals `tool_server`, `tool_name`, `decision`;
   verifies per section 9.
2. `workflow-receipt-three-steps-disclose-one.json`: discloses only
   step 1's `(step_index, server_id, tool_name, outcome)`; steps 0
   and 2 hidden.
3. `predicate-eq-fixture.json`: `eq(tool_name, "refund")` over a
   withheld field; equality commitment verifies.
4. `predicate-cmp-fixture.json`: `cmp(timestamp, <=, 1234567890)`;
   range proof verifies.
5. `predicate-member-fixture.json`:
   `member(content_hash, <signed root>)`; inclusion + signed root
   verify.
6. `predicate-and-all-three.json`: composed `eq` + `cmp` + `member`.
7. `3vendor-buyer-auditor.json`: full section 6.4 worked example.
8. `negative-tampered-disclosure.json` -> `bbs_proof_invalid`.
9. `negative-revoked-issuer.json` -> `bbs_issuer_unknown_or_revoked`.
10. `negative-invalid-range-proof.json` -> `range_proof_invalid`.
11. `negative-merkle-wrong-signer.json` -> `merkle_root_signature_invalid`.
12. `negative-nine-clauses.json`: rejected at construction with
    `predicate_clause_count_exceeded`.

CI MUST regenerate each fixture and diff against checked-in canonical
JSON to guard against silent format drift, mirroring
[CHIO_PHEROMONE.md](./CHIO_PHEROMONE.md) section 12.

---

## 12. Failure Modes

All rejections are fail-closed; verifiers return an error and surface
no predicate result. Error codes (all prefixed `disclosure.`) are
stable strings:

| Code | Cause |
|---|---|
| `envelope_invalid` | Envelope JSON fails section 8 schema. |
| `subject_receipt_mismatch` | `subject_receipt_sha256` mismatches the verifier's pinned receipt. |
| `subject_receipt_unresolved` | No pinned receipt resolves for `subject_receipt_sha256`. |
| `unknown_projection_version` | Version not enumerated, or disagrees with the receipt's `bbs_projection_version`. |
| `bbs_issuer_unknown_or_revoked` | Issuer fingerprint does not resolve to a non-revoked passport at pinned_epoch. |
| `projection_recompute_failed` | Recomputing the BBS message vector raised an error. |
| `bbs_signature_invalid` | Receipt's `bbs_signature` fails to verify against recomputed messages. |
| `bbs_proof_invalid` | Envelope's BBS+ PoK fails on the disclosed/withheld split. |
| `unknown_predicate_field` | Clause names a missing or wholesale-only field. |
| `unknown_predicate_clause` | Clause `kind` not in `{eq, cmp, member}`. |
| `eq_clause_mismatch` | Disclosed value not equal to `eq` constant. |
| `eq_commitment_invalid` | Hidden equality commitment does not bind. |
| `range_proof_invalid` | `cmp` range proof fails. |
| `range_negative_constant` | `cmp` clause supplies a negative constant. |
| `scale_mismatch` | `cmp` `scale` disagrees with projection convention. |
| `merkle_root_signature_invalid` | Ed25519 signature over Merkle root fails under declared signer. |
| `merkle_proof_invalid` | Merkle inclusion path does not chain to signed root. |
| `merkle_leaf_commitment_invalid` | Leaf-commitment proof does not bind hidden BBS message to leaf. |
| `predicate_clause_count_exceeded` | More than eight clauses. |
| `predicate_and_failed` | Catch-all when no per-clause code is more specific. |

Error envelopes follow `chio.error.v1`; see `spec/errors/README.md`.

---

## 13. Future zkVM Lane (deferred)

The future zkVM lane uses a zkVM (Risc0 or SP1) plus Groth16 wrap for
expressivity BBS+ cannot reach. Use cases:

- **Chained-receipt proofs.** Properties over N receipts ("every
  receipt in this child chain shares the same parent capability lease
  and falls within a 5-minute window"). BBS+ commits to one body;
  chained proofs require a chain-walking circuit.
- **Predicates over the Ed25519 signature itself.** "Signed by a key
  in this set" without revealing which. v1 reveals the kernel key.
- **Non-arithmetic boolean logic.** `OR`, negation, nested
  quantifiers, anything past v1's AND-of-eight.
- **Predicates over wholesale-only fields.** Future zkVM circuits crack
  nested bodies (`evidence`, `metadata`, `outcome`) and prove
  sub-field predicates without disclosing them.

v1 reserves the optional `verifier_image_hash` envelope field so a
future zkVM proof can ride the same envelope, with the image binding as
a public input. Proof-bytes wire format is **not** specified here.

---

## 14. Open Questions for v1 Review

1. **Canonical ordering rule.** This spec picks alphabetical (5.1);
   [CHIO_PHEROMONE.md](./CHIO_PHEROMONE.md) section 11 has not
   committed. Review SHOULD confirm alphabetical for both or flag the
   divergence.
2. **Per-kernel BBS keypair separate from Ed25519 signing key.** 5.5
   mandates separate keypairs (BLS12-381 vs Ed25519). Confirm the
   `chio-credentials` passport extension to advertise `bbs_public_key`
   alongside `kernel_key` is the right shape.
3. **SD-JWT VC bridging for EUDI.** EUDI does not approve BLS12-381;
   a separate SD-JWT VC mapping is required. Out of scope; flagged
   for the future zkVM lane.
4. **`predicate_id` registry: cross-org or local?** Inline clauses
   work without one. A cross-org registry would let buyers reference
   predicates by name (`chio.refund_cap_v1`) but introduces a bootstrap
   problem. v1 leaves the field optional; review SHOULD confirm
   whether to draft a cross-org registry post-v1 or rely on local
   ladder-manifest declarations indefinitely.
