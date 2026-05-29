# Model cards: binding refusal contract

Status: shipped
Trust-boundary verdict satisfied: [docs/trust-boundary-browser-signing.md](../trust-boundary-browser-signing.md)
Last updated: 2026-04-30

This page is a one-page narrative of the policy-bound model-card
surface. It explains the binding refusal contract a provider walks
through before the kernel allows a tool call to leave the trust boundary,
names the source-of-truth crates, and points at the tests that lock the
contract.

## 1. The contract in one breath

A model card is a signed declaration binding:

```
   weights_hash               -> the loaded weights this card describes
   allowed_capability_set     -> the maximum scope the kernel may grant
   banned_tools               -> tools the kernel must not route to
   training_data_class        -> coarse-grained data classification
   issuer / issued_at / expires_at -> liveness and provenance fields
```

Schema is locked at `spec/schemas/model-card.v1.json`; canonical-JSON
encoding (RFC 8785) is the on-the-wire byte form cosign signatures
are taken over. The card crate lives at `crates/chio-weights/`.

When `policy.weights_card_required = required` (or
`required_with_pin`), the kernel refuses to bind a provider unless
all three predicates hold:

1. the provider's loaded `weights_hash` matches a signed card,
2. the requested capability set is a (proper or equal) subset of
   the card's `allowed_capability_set`,
3. no requested tool intersects the card's `banned_tools`.

Failures map to stable URN codes:

- `urn:chio:error:weights:card-mismatch`
- `urn:chio:error:weights:scope-not-subset`
- `urn:chio:error:weights:tool-banned`

Banned-tool intersection rejects at provider bind, not at first
call, so the operator catches the mistake before the bad routing
ships.

## 2. Verification path

The card cosign bundle helper
(`crates/chio-weights/src/bundle.rs`) consumes
`chio_attest_verify::SigstoreVerifier::verify_bundle` from
[`crates/chio-attest-verify/`](../../crates/chio-attest-verify/).
This release does not introduce a new trust root or a new signature path;
the existing cosign bundle verifier (and the PQ-hybrid surface) is consumed
verbatim.

`policy.weights_card_required = required_with_pin` adds an issuer SAN regex
pin from the provider matrix. Invalid
combinations (`required` with no issuer configured) reject at
policy load (`crates/chio-policy/src/weights.rs`), not at first
bind, so the failure surfaces immediately at deployment.

## 3. Operational equivalence

Two model cards A and B are operationally equivalent when, given the
canonical scenario corpus from the verdict-equality oracle, providers bound
under each card produce verdict-equivalent outputs at every scenario.

The cross-provider equivalence test
(`crates/chio-weights/tests/equivalence.rs`) consumes the verdict-equality
oracle, not a forked copy. PR CI runs the smoke subset gated by
`--features smoke` (one fixture per provider in the canonical 8-provider
cross-provider matrix at
`crates/chio-provider-conformance/fixtures/cross_provider/manifest.toml`).
The full 8-provider * 12-fixture nightly sweep (96 fixtures) runs through
the existing nightly conformance lane.

The equivalence claim has two halves:

1. Under a single card, the kernel verdict bytes are
   byte-identical across all eight providers in the matrix. The
   oracle is `assert_canonical_bytes_eq` over the normalized
   verdict and receipt bodies.
2. Under two cards with distinct `weights_hash` but identical
   `allowed_capability_set`, the verdict bytes (with the card_id
   projection stripped) are byte-identical. The cards bind the
   kernel binding context, not the verdict body, so verdict-
   level equivalence is the property the oracle checks.

A divergence here means the cards are not operationally
equivalent and the oracle catches it before publication.

## 4. Lineage anchoring

Publishing a card to the public registry emits a
`ModelCardLineageAnchor` artifact (`crates/chio-weights/src/lineage.rs`)
whose digest format mirrors
`chio_lineage::anchor::AnchoredFrontier`. The anchor binds:

```
   sha256(card_canonical_bytes)
   subject_digest_sha256        // from VerifiedAttestation
   certificate_identity
   certificate_oidc_issuer
   rekor_log_index
   rekor_inclusion_verified
```

The anchor reuses the `chio-lineage` `FrontierDigest`, `CanonicalSource`,
and `SigningState` shapes verbatim so the public registry serves a single
artifact format across both lineage-graph and model-card anchors. PQ-hybrid
signing populates the `SigningState::Signed` slot when wired; absence is
recorded as `SigningState::UnsignedSoftDepAbsent`.

## 5. CLI surface

Operators bind a card to a provider through:

```
chio bind <provider> --card <path-to-card.json>
```

The `chio bind` subcommand at
`crates/chio-cli/src/commands/bind.rs` loads the card, runs the
cosign bundle verify, attaches the card to the provider binding
context, and prints the resolved
`(weights_hash, allowed_capability_set)` so the operator can
sanity-check before promoting to production policy.

## 6. Threat-model coverage

| Threat ID | coverage_state | Closed by |
| --- | --- | --- |
| `weights_hash_spoof` | partial | see coverage.yaml |

The partial state is documented inline in `spec/security/coverage.yaml`
under `partial_reason`: the kernel binding refusal verifies the
cosign-attested `weights_hash`, `allowed_capability_set`, and `banned_tools`
tuple, but loaded-weight recomputation depends on `chio-providers` exposing a
recomputable digest. Until that lands, the provider-supplied hash is the
attested input. The gap surfaces under the Partial heading of
`docs/security/threat-coverage.md` once the threat-model doc generator runs.

`covered` and `partial` both PASS the threat-model-coverage CI gate.

## 7. Pointers

- Card crate: `crates/chio-weights/`
- Schema: `spec/schemas/model-card.v1.json`
- Cosign bundle helper: `crates/chio-weights/src/bundle.rs`
- Kernel binding refusal: `crates/chio-kernel/src/weights_binding.rs`
- Policy: `crates/chio-policy/src/weights.rs`
- CLI: `crates/chio-cli/src/commands/bind.rs`
- Lineage anchor: `crates/chio-weights/src/lineage.rs`
- Equivalence oracle: `crates/chio-weights/tests/equivalence.rs`
- Coverage map: `spec/security/coverage.yaml`
