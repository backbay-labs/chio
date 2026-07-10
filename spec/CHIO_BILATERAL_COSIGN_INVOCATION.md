# Chio Bilateral Co-Signed Invocation: An in-toto Predicate Proposal

**Status:** v1 (Chio-owned pre-release spec carrying an in-toto WG proposal) | **Date:** 2026-05-04
**Intended audience:** in-toto Attestation WG; OpenSSF AI/ML Security
WG; CoSAI Workstream 4. **Editors:** chio maintainers.

This document specifies the shipped Chio-owned predicate type
`chio.bilateral-cosign-invocation.v1` for **bilateral co-signed runtime
invocations** between two distinct organisational kernels, and carries
the matching in-toto WG proposal that mirrors it. The intent is either
to land chio's bilateral-co-signed invocation semantics in the
in-toto vocabulary or to confirm in writing the structural gap that
motivates the chio-namespaced predicate.

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to
be interpreted as described in RFC 2119. Canonical JSON serialisation
follows RFC 8785 (JCS). DSSE follows the Secure Systems Lab spec
(`secure-systems-lab/dsse`, envelope and PAE).

---

## 1. Status

- **Version:** v1 (Chio-owned pre-release spec carrying an in-toto WG
  proposal); **Date:** 2026-05-04.
- **Intended audience:** in-toto Attestation WG (primary), OpenSSF AI/ML
  Security WG (secondary), CoSAI Workstream 4 (secondary).
- **Disposition:** Chio ships the Chio-owned predicate type
  `chio.bilateral-cosign-invocation.v1` (section 3) today and proposes
  the matching in-toto canonical URI for adoption by the in-toto WG.
  Implementations switch to the in-toto vocabulary once (or if) it is
  accepted.
- **Engagement contacts named:** Aditya Sirish A Yelgundhalli (in-toto),
  Tom Hennen (SLSA). See section 12.

---

## 2. Motivation

Current in-toto predicates are **artifact-centric**. The SLSA Provenance
predicate (`https://slsa.dev/provenance/v1`) is build-provenance-shaped:
who built which artifact under what configuration. The Runtime Trace
predicate (`https://in-toto.io/attestation/runtime-trace/v0.1`) extends
in-toto into runtime by capturing process, network, and file events
under a single monitor, but its scope is the **builder's own runtime
observability** of a build. Sigstore Rekor anchors single-party DSSE
entries against Fulcio-issued identities and gives a public
transparency log; multi-signature DSSE envelopes are mechanically
permitted (`secure-systems-lab/dsse` protocol allows `(t,n)` thresholds)
but no predicate vocabulary in-toto ships today says "this DSSE envelope
verifies if and only if these two specific organisational identities
both signed the same Statement, each having independently evaluated
their local policy on the underlying invocation."

That is the gap chio addresses. It is not a transparency-log gap and
it is not a build-provenance gap. It is the gap between two parties
**signing the same canonical body** (a statistical accident) and two
parties **independently committing to the same canonical action under
their separate policies** (a verifiable, mechanically-checkable joint
intent). The existing chio primitive is
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs).
The composition unit is the workflow receipt
([../crates/platform/chio-workflow/src/lib.rs](../crates/platform/chio-workflow/src/lib.rs)),
and capability scoping rides on agent passports
([../crates/trust/chio-credentials/src/lib.rs](../crates/trust/chio-credentials/src/lib.rs)).
The cross-vendor agent action attestation use case needs all three properties
at once: bilateral intent, per-action capability scoping, and workflow-receipt
composition.

---

## 3. Predicate Type URI

This proposal reserves two URIs:

- **Proposed in-toto canonical:**
  `https://in-toto.io/attestation/bilateral-cosign-invocation/v1`
- **Chio-namespaced fallback (in use today):**
  `chio.bilateral-cosign-invocation.v1`

Implementations SHOULD emit the canonical URI once the in-toto WG
accepts it. Until then, implementations MUST emit the chio-namespaced
fallback so verifiers do not collide with an unaccepted reservation.
Verifiers MUST treat the two as semantically equivalent within a single
deployment but MUST NOT silently rewrite one into the other (the
predicate type is part of the signed Statement and rewriting would
break signature verification).

Implementation status: `crates/trust/chio-federation` emits and verifies the
chio-namespaced fallback strict predicate type,
`chio.bilateral-cosign-invocation.v1`, for Chio proof packages. The
older `chio.bilateral-signature-slice.v1` profile remains available as a
compatibility artifact for local receipt binding, but strict Chio
verification rejects it as conformance evidence.

Chio offline package verification is verifier-owned. The proof package
MUST NOT define its own peer pins, accepted ladder refs, action-class
policy, workflow-intersection acceptance hash, revocation checkpoint, BBS
issuer trust, authority lifecycle, or disclosure policy. Those values are
supplied by `chio.federation.verifier-trust-bundle.v1` plus the required
`chio.federation.verification-context.v1`. A verifier MUST reject packages
whose embedded hints disagree with the trust bundle or whose BBS proof
nonce is not bound to the verifier context.

---

## 4. Subject Definition

The in-toto Statement v1 envelope binds a predicate to one or more
ResourceDescriptor subjects. For bilateral co-signed invocations, the
subject is the **content-addressable invocation event itself**, not an
on-disk artifact.

Recommendation: the subject's `digest` MUST be the SHA-256 of the
canonical-JSON (RFC 8785) serialisation of the underlying
`chio_core_types::ChioReceipt` body. The `name` SHOULD be the receipt's
internal identifier (UUID or hash-derived string). Concretely:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "chio-receipt:<receipt_id>",
      "digest": {
        "sha256": "<hex SHA-256 of canonical-JSON ChioReceipt body>"
      }
    }
  ],
  "predicateType": "https://in-toto.io/attestation/bilateral-cosign-invocation/v1",
  "predicate": { ... }
}
```

Rationale: anchoring to the receipt body's content hash makes the
predicate refer to a precise invocation event independent of where the
receipt is stored. A verifier resolving the receipt out of a kernel's
audit log can re-hash the body and confirm subject membership without
needing to dereference any external pointer. This mirrors the chio
internal pattern in
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs)
where both kernels sign over the canonical bytes of `CoSigningBody`.

---

## 5. Predicate Body Schema

The predicate is a JSON object with the following JSON Schema (Draft
2020-12). Implementations MUST validate the predicate against this
schema before signature verification.

This schema is the strict CHIO target, not the currently emitted
`chio.bilateral-signature-slice.v1` compatibility profile. A signature
slice MUST NOT be described as conforming to this section unless its
predicate validates against the schema below.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://in-toto.io/attestation/bilateral-cosign-invocation/v1",
  "title": "Chio Bilateral Co-Signed Invocation",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "invocation_id",
    "tool_server_a",
    "tool_server_b",
    "tool_name",
    "tool_args_hash",
    "capability_lease_ref",
    "policy_evaluation_summary",
    "consistency_model",
    "cross_org_visibility",
    "co_sign",
    "timestamp_unix_ms"
  ],
  "properties": {
    "invocation_id": {
      "type": "string",
      "description": "UUIDv4 or canonical-JSON SHA-256 of the underlying invocation event. MUST be globally unique within the federation graph.",
      "pattern": "^[A-Za-z0-9._:-]{1,128}$"
    },
    "tool_server_a": { "$ref": "#/$defs/kernelIdentity" },
    "tool_server_b": { "$ref": "#/$defs/kernelIdentity" },
    "tool_name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256,
      "description": "Logical tool identifier as known to both kernels. Inclusion here ensures the joint commit is bound to a specific named tool surface."
    },
    "tool_args_hash": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "value"],
      "properties": {
        "alg": { "type": "string", "enum": ["sha256"] },
        "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
      },
      "description": "SHA-256 over the canonical-JSON of the tool arguments. The arguments themselves are off-chain; only the hash binds to the predicate."
    },
    "capability_lease_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["lease_id", "issuer", "expires_at_unix_ms"],
      "properties": {
        "lease_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
        "issuer": { "type": "string", "description": "did:chio of the kernel that minted the lease." },
        "expires_at_unix_ms": { "type": "integer", "minimum": 0 },
        "scope_digest": {
          "type": "object",
          "additionalProperties": false,
          "required": ["alg", "value"],
          "properties": {
            "alg": { "type": "string", "enum": ["sha256"] },
            "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
          }
        }
      },
      "description": "Reference to the chio capability under which the action ran. Verifier MUST resolve and confirm non-expiry at the pinned epoch."
    },
    "policy_evaluation_summary": {
      "type": "object",
      "additionalProperties": false,
      "required": ["server_a_verdict", "server_b_verdict"],
      "properties": {
        "server_a_verdict": { "$ref": "#/$defs/policyVerdict" },
        "server_b_verdict": { "$ref": "#/$defs/policyVerdict" },
        "joint_disposition": {
          "type": "string",
          "enum": ["allow", "deny"],
          "description": "Derived joint outcome. MUST equal `allow` only when both kernel verdicts are `allow`."
        }
      }
    },
    "governance_receipt_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["receipt_id", "kernel_id", "digest"],
      "properties": {
        "receipt_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
        "kernel_id": { "type": "string" },
        "digest": {
          "type": "object",
          "additionalProperties": false,
          "required": ["alg", "value"],
          "properties": {
            "alg": { "type": "string", "enum": ["sha256"] },
            "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
          }
        }
      },
      "description": "REQUIRED iff the action class is declared `receipt-backed` in the chio governance ladder manifest (see CHIO_LADDER.md section 3.3). Otherwise OPTIONAL."
    },
    "consistency_model": {
      "type": "string",
      "enum": ["crdt-commutative", "totally-ordered", "quorum-required"],
      "description": "Mirrors CHIO_LADDER.md section 4. The chosen model MUST match the action class declaration in both kernels' ladder manifests."
    },
    "consistency_anchor": {
      "type": "string",
      "enum": ["chio-anchor", "hash-chain", "frost-quorum"],
      "description": "REQUIRED for `totally-ordered` and `quorum-required` consistency models."
    },
    "cross_org_visibility": {
      "type": "string",
      "enum": ["private", "treaty_only", "federated", "public"],
      "description": "Mirrors the ladder. Drives downstream gossip and BBS+ disclosure decisions."
    },
    "co_sign": {
      "type": "string",
      "enum": ["bilateral_required", "bilateral_if_cross_org", "n_of_m"],
      "description": "Restricted to co-sign modes that produce a multi-signature DSSE envelope. `none` MUST NOT appear in this predicate."
    },
    "timestamp_unix_ms": {
      "type": "integer",
      "minimum": 0,
      "description": "Tool-server B's wall-clock timestamp at the moment the joint body was canonicalised."
    }
  },
  "allOf": [
    {
      "if": { "properties": { "consistency_model": { "const": "totally-ordered" } } },
      "then": { "required": ["consistency_anchor"] }
    },
    {
      "if": { "properties": { "consistency_model": { "const": "quorum-required" } } },
      "then": { "required": ["consistency_anchor"] }
    }
  ],
  "$defs": {
    "kernelIdentity": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kernel_id", "passport_key_fingerprint", "alg"],
      "properties": {
        "kernel_id": {
          "type": "string",
          "description": "did:chio identifier of the participating kernel."
        },
        "passport_key_fingerprint": {
          "type": "string",
          "pattern": "^[0-9a-f]{64}$",
          "description": "SHA-256 of the kernel's passport public key, hex-encoded."
        },
        "alg": {
          "type": "string",
          "enum": ["ed25519", "hybrid:ed25519:mldsa65"]
        }
      }
    },
    "policyVerdict": {
      "type": "object",
      "additionalProperties": false,
      "required": ["verdict", "policy_id", "policy_version"],
      "properties": {
        "verdict": { "type": "string", "enum": ["allow", "deny"] },
        "policy_id": { "type": "string" },
        "policy_version": { "type": "string" },
        "rationale_code": { "type": "string", "maxLength": 64 }
      }
    }
  }
}
```

A predicate that fails this schema MUST be rejected before any
signature verification is attempted.

---

## 6. DSSE Envelope Shape

This predicate uses the standard DSSE envelope
(`secure-systems-lab/dsse`) with **exactly two signatures** for the
default `bilateral_required` and `bilateral_if_cross_org` co-sign modes.
For the `n_of_m` mode the envelope carries `n` signatures (where `n` is
the FROST quorum size) but the verification contract still requires
that **every signature in the envelope verify**; threshold rejection
falls back to the chio governance ladder, not to DSSE's `(t,n)`
permissive default.

The serialised envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<Base64(canonical-JSON Statement)>",
  "signatures": [
    {
      "keyid": "<sha256 of tool_server_a passport public key, hex>",
      "sig": "<Base64(Ed25519 signature over PAE)>"
    },
    {
      "keyid": "<sha256 of tool_server_b passport public key, hex>",
      "sig": "<Base64(Ed25519 signature over PAE)>"
    }
  ]
}
```

Signing uses the standard DSSE Pre-Authentication Encoding:

```
PAE("application/vnd.in-toto+json", canonical-JSON Statement bytes)
  = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
```

Both kernels sign the same PAE bytes. The `keyid` for each signature
MUST equal the SHA-256 of the corresponding kernel's passport public
key (hex-encoded), and MUST equal the `passport_key_fingerprint` of
that kernel as declared in the predicate's `tool_server_a` or
`tool_server_b` field. This binding is what distinguishes a
bilateral-cosign-invocation envelope from "two independent signers
happen to sign the same Statement": the predicate body itself names
which two keys MUST appear in the envelope, and the envelope is
invalid if they are absent or out of order.

The verification contract is therefore stricter than DSSE's default
threshold semantics: it is a **named, ordered set of signers** rather
than "any t-of-n succeed."

---

## 7. Verification Algorithm

A conforming verifier MUST execute the following steps in order. Any
step that returns failure aborts verification with a code from section
7.1.

```text
verify_bilateral_cosign_invocation(envelope, pinned_epoch, peer_pin_set):
  1. parse envelope as DSSE                        -> dsse.malformed
  2. Base64-decode envelope.payload                -> statement_bytes
  3. parse and validate Statement against in-toto v1 schema
     (_type, subject[].digest, predicateType, predicate present)
                                                   -> statement.{malformed,schema_invalid}
  4. require predicateType in {
       "https://in-toto.io/attestation/bilateral-cosign-invocation/v1",
       "chio.bilateral-cosign-invocation.v1"
     }                                             -> predicate.type_unrecognised
  5. validate predicate against the JSON Schema in section 5
                                                   -> predicate.schema_invalid
  6. let pred = statement.predicate
  7. require subject[0].digest.sha256 equals
       sha256_hex(canonical_json(resolve_receipt(pred.invocation_id)))
     (verifier MUST resolve the receipt body from a trusted chio
     audit store and re-hash; no resolution => fail-closed)
                                                   -> subject.digest_mismatch
  8. require both kernel_ids in peer_pin_set with passport keys whose
     fingerprints match pred.tool_server_*.passport_key_fingerprint
                                                   -> peer.unpinned_or_keyid_mismatch
  9. require both passports are non-revoked at pinned_epoch against
     the chio-revocation-oracle epoch root        -> peer.revoked_at_epoch
 10. compute pae = "DSSEv1" SP LEN(payloadType) SP payloadType
                          SP LEN(statement_bytes) SP statement_bytes
 11. require exactly one signature with keyid == server_a fingerprint
     verifies under A's passport key against pae  -> signature.server_a_invalid
 12. require exactly one signature with keyid == server_b fingerprint
     verifies under B's passport key against pae  -> signature.server_b_invalid
 13. require server_a_verdict.verdict == server_b_verdict.verdict and
     (if present) joint_disposition equals that common verdict
                                                   -> policy.verdict_disagreement
 14. resolve pred.capability_lease_ref.lease_id; require lease exists,
     issuer matches, and expires_at_unix_ms > pinned_epoch.now
                                                   -> capability.lease_expired_or_unknown
 15. if the local ladder intersection declares the class receipt-backed:
       require pred.governance_receipt_ref present and resolves
                                                   -> governance.receipt_required_missing
 16. if consistency_model == "totally-ordered": require consistency_anchor
       in {"chio-anchor","hash-chain"} and reconcilable with verifier view
                                                   -> consistency.anchor_unverified
     if consistency_model == "quorum-required": require envelope contains
       the declared quorum's signatures (FROST aggregate or n-of-m)
                                                   -> consistency.quorum_underpopulated
 17. return Ok(VerifiedBilateralCoSignInvocation { ... })
```

### 7.1 Error Codes

The following codes MUST be surfaced verbatim. Each maps to a
`GenericGovernanceCaseKind::Dispute` finding in
[../crates/trust/chio-governance/src/lib.rs](../crates/trust/chio-governance/src/lib.rs).

| Code | Meaning |
| --- | --- |
| `dsse.malformed` | Envelope JSON is not parseable. |
| `statement.malformed` | Statement payload is not parseable JSON. |
| `statement.schema_invalid` | Statement does not satisfy in-toto v1 schema. |
| `predicate.type_unrecognised` | predicateType is neither the proposed in-toto URI nor the chio-namespaced fallback. |
| `predicate.schema_invalid` | Predicate body fails section 5 schema. |
| `subject.digest_mismatch` | Subject SHA-256 does not match the resolved receipt body's canonical JSON. |
| `peer.unpinned_or_keyid_mismatch` | Either kernel identity is not pinned in the verifier's peer set, or its declared fingerprint disagrees with the pinned passport. |
| `peer.revoked_at_epoch` | A participating kernel's passport is revoked at the pinned epoch. |
| `signature.server_a_invalid` | tool_server_a's signature does not verify under its passport key. |
| `signature.server_b_invalid` | tool_server_b's signature does not verify under its passport key. |
| `policy.verdict_disagreement` | The two kernels' policy verdicts disagree, or joint_disposition is inconsistent. |
| `capability.lease_expired_or_unknown` | The named capability lease cannot be resolved or is past its `expires_at_unix_ms`. |
| `governance.receipt_required_missing` | A receipt-backed class lacks a `governance_receipt_ref`. |
| `consistency.anchor_unverified` | A `totally-ordered` predicate's anchor cannot be reconciled with the verifier's view. |
| `consistency.quorum_underpopulated` | A `quorum-required` predicate's envelope lacks the declared quorum's signatures. |

---

## 8. Composition With Workflow Receipts

A chio workflow receipt
([../crates/platform/chio-workflow/src/receipt.rs](../crates/platform/chio-workflow/src/receipt.rs))
captures an N-step skill execution as a single signed artifact. When
the steps cross trust boundaries, each step is itself a
bilateral-cosign-invocation predicate. The composition rule:

1. Each step MAY produce one bilateral-cosign-invocation Statement
   (DSSE-enveloped). The Statement's subject is the step's
   `tool_receipt_id`.
2. The workflow receipt's body lists per-step records, each carrying
   the SHA-256 of the corresponding step's bilateral-cosign-invocation
   Statement payload (not just the underlying tool receipt).
3. The workflow receipt is itself a Statement under a separate
   predicate type (provisionally
   `https://in-toto.io/attestation/chio-workflow-receipt/v1`, to be
   specified in a sibling proposal). Its `subject` is the
   canonical-JSON SHA-256 of the
   [`WorkflowReceiptBody`](../crates/platform/chio-workflow/src/receipt.rs).
4. A verifier of the workflow receipt SHOULD verify each referenced
   bilateral-cosign-invocation predicate independently. Failure of any
   one step's predicate verification MUST be surfaced; the workflow
   receipt itself MAY still verify its own signature, but the
   composite assertion "every cross-org step jointly committed" is
   only true when every step-level predicate verifies.

This separation lets verifiers walk the DAG bottom-up: confirm each
joint commit at the leaves, then confirm the workflow receipt's roll-up
signature at the root. The bilateral-cosign-invocation predicate is
the leaf primitive; the workflow-receipt predicate is the composition
primitive.

---

## 9. Composition With Rekor

The DSSE envelope MAY be additionally submitted to a Sigstore Rekor v2
instance for transparency-log evidence. Recommended Rekor entry kind:
`dsse` (Rekor v2's native DSSE entry). The envelope is anchored
verbatim; no chio-specific transformation is required.

This composition is a **free property**. The verification contract in
section 7 does not depend on Rekor inclusion. A Rekor-anchored envelope
gains:

- Public, append-only proof that the envelope existed at the inclusion
  time, defending against retroactive forgery if both kernels' audit
  stores are later compromised.
- A discoverable index for third-party auditors who do not have direct
  access to either kernel's receipt store.

A Rekor inclusion proof MAY be carried alongside the envelope in a
Sigstore Bundle. Verifiers SHOULD treat Rekor inclusion as **additional
evidence**, not as a substitute for the bilateral verification
contract: a Rekor-anchored envelope that fails section 7 is invalid;
a non-Rekor-anchored envelope that satisfies section 7 is valid. Chio
already integrates with Sigstore at
[../crates/trust/chio-attest-verify/src/lib.rs](../crates/trust/chio-attest-verify/src/lib.rs);
the inverse (writing chio receipts into Rekor) is a small extension.

---

## 10. Comparison Table

| Property | bilateral-cosign-invocation/v1 (this proposal) | runtime-trace/v0.1 | slsa-provenance/v1 | single-party DSSE on Rekor |
| --- | --- | --- | --- | --- |
| Subject | content-hash of a runtime invocation event | one or more built artifacts | one or more built artifacts | arbitrary payload |
| Number of signers | exactly two (or n in `n_of_m` mode) | one (the monitor's identity) | one (the builder's identity) | one (the signer's identity) |
| Cross-org semantics | yes; named, ordered signers from two distinct kernels | no; monitor is single party | no; builder is single party | no; one signer per envelope |
| Per-action capability binding | yes (`capability_lease_ref`) | no | no (build-config rather than per-action) | no |
| Policy-verdict agreement contract | yes (`policy_evaluation_summary` MUST agree) | no | no | no |
| Workflow composition primitive | yes (sibling workflow-receipt predicate) | no | no (build, not workflow) | no |
| Consistency-model declaration | yes (CRDT / totally-ordered / quorum) | no | no | no |
| Transparency-log anchoring | optional (Rekor v2) | optional | optional | required (by the Rekor model) |
| What it proves | both kernels independently evaluated and jointly committed to the same canonical action under named capabilities | a monitor observed these events during a build | this artifact was produced by this builder under this configuration | this signer signed this payload |
| What it does NOT prove | that any third party observed the action; that the action's effects are durable beyond the kernels' audit stores | cross-org consent; per-action capability scoping | runtime invocation; multi-party intent | multi-party intent; capability scoping; workflow context |

The structural slice that bilateral-cosign-invocation occupies is the
**joint-commit-at-action-time** slice. Sigstore + in-toto + SLSA in
their current form do not occupy it. A multi-signer DSSE envelope on
Rekor is mechanically possible today but lacks the predicate vocabulary
to express what the multi-signing means: a verifier sees two
signatures and has no in-toto-supplied way to know whether they are
two independent assertions or a single joint commit.

---

## 11. Open Questions for the WG

1. **Predicate adoption vs sibling envelope.** Does in-toto want to
   absorb a multi-signer predicate type into its core vocabulary, or
   prefer a sibling envelope that **wraps** Statement and carries the
   multi-signer semantics out-of-band? The former keeps tooling simple;
   the latter keeps the Statement layer minimal.
2. **DSSE threshold vs named-set semantics.** DSSE permits `(t,n)`
   thresholds. This proposal narrows that to a **named, ordered set**
   (signatures keyed by passport fingerprints declared in the predicate
   body). Should in-toto define a recommended "named multi-signer"
   pattern other predicates can reuse?
3. **Subject as event-hash vs file-hash.** This proposal points
   `subject.digest` at the canonical-JSON SHA-256 of a runtime
   `ChioReceipt`. Is a content-hash of an in-memory event a legitimate
   subject, or should runtime predicates declare a side-channel event
   identifier field instead?
4. **Capability-lease referencing.** Is there appetite for an in-toto
   standard "capability reference" sub-type that other runtime
   predicates (and a future runtime-trace v1) could share?
5. **Composition with workflow / DAG predicates.** Does the WG have a
   preferred shape for "Statement that references other Statements as
   composite parts" (Bundle, Manifest, or a new Composition predicate)
   that this proposal should align with?

---

## 12. Engagement Plan

The chio maintainers intend the following next steps:

1. **In-toto attestation issues.** File this proposal as an issue
   against `in-toto/attestation` referencing the canonical URI
   `https://in-toto.io/attestation/bilateral-cosign-invocation/v1` and
   inviting review by Aditya Sirish A Yelgundhalli and the broader WG.
2. **OpenSSF AI/ML Security WG.** Present at the next WG call as a
   "predicate-shape proposal that arose from cross-vendor agent
   action attestation" and solicit cross-pollination with the
   AI/ML-specific predicates the WG is sketching.
3. **CoSAI Workstream 4.** Share with the Secure AI Software Supply
   Chain workstream as adjacent prior art relevant to their runtime
   invocation receipt discussions.
4. **ITE drafting.** If the in-toto WG indicates appetite, draft an
   in-toto Enhancement (ITE) using this document as the seed text,
   carrying it through the standard ITE review process.
5. **Reference implementation.** Keep the chio-namespaced strict predicate
   implementation covered by production tests, then switch emission to the
   canonical URI if the in-toto WG accepts it. The existing
   `chio.bilateral-signature-slice.v1` helper remains compatibility-only and
   must not be treated as strict Chio predicate evidence.

If the WG declines or the discussion stalls, this document remains the written
record of the structural gap that motivates the chio-namespaced predicate.
