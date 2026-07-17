# chio-weights

Chio's signed model-card surface: `ModelCard` binds a provider's
`(weights_hash, allowed_capability_set, banned_tools, training_data_class)`
to a cosign-signed envelope, and the kernel refuses to bind a provider whose
loaded weights or requested scopes do not match the card.

The crate owns the card schema and canonical-JSON encoding, a cosign bundle
verifier built on `chio-attest-verify`, and a lineage-anchor projection for
published cards. It does not implement the kernel's bind-time refusal gates
itself; `chio-kernel` composes this crate's types into that decision.

## Responsibilities

- Define the v1 model-card schema (`ModelCard`) and its RFC 8785
  canonical-JSON encoding, locked against `spec/schemas/model-card.v1.json`.
- Validate card structure: `weights_hash` shape, required text fields,
  `expires_at >= issued_at`, and `StringSet` entry hygiene.
- Verify a cosign-signed model card bundle (`verify_model_card_bundle`),
  delegating the cryptographic path to `chio-attest-verify` and checking
  issuer agreement and liveness on top.
- Derive a lineage-anchor proof for a published, verified card
  (`anchor_model_card` / `verify_model_card_anchor`), reusing
  `chio-lineage`'s anchor digest and signing-state shapes.
- Compute the SHA-256 `weights_hash` of a runtime-loaded weights blob
  (`weights_hash_of`) for the kernel to compare against a card.

## Public API

- `card::{ModelCard, StringSet, CARD_VERSION_V1, weights_hash_of}` - the
  card schema, its sorted-set field type, and the hash helper.
- `bundle::{verify_model_card_bundle, VerifiedModelCard}` - cosign bundle
  verification, pairing the parsed card with the upstream attestation.
- `lineage::{anchor_model_card, verify_model_card_anchor,
  ModelCardLineageAnchor, MODEL_CARD_ANCHOR_SCHEMA}` - lineage anchoring
  for published cards.
- `error::WeightsError` - typed errors carrying stable
  `urn:chio:error:weights:*` codes.

All items above are re-exported at the crate root (`chio_weights::ModelCard`,
not just `chio_weights::card::ModelCard`).

## Usage

```rust
use chio_weights::{ModelCard, StringSet};
use chrono::Utc;

let issued = Utc::now();
let card = ModelCard::new(
    "0".repeat(64),
    StringSet::new(["tool:read", "tool:write"]),
    StringSet::new(["tool:exec"]),
    "public-internet",
    "https://example.com/issuer",
    issued,
    issued + chrono::Duration::days(30),
)?;
let bytes = card.to_canonical_json()?;
```

## Feature flags

| Flag    | Effect |
|---------|--------|
| `smoke` | Enables `tests/equivalence.rs`'s 8-fixture cross-provider smoke subset (PR CI gate). The full 8-provider x 12-fixture sweep runs nightly through a separate conformance lane, not this crate. |
| `kani`  | Declared for tooling opt-in only. The Kani harness module is gated on the `kani` cfg the Kani toolchain sets, not on this feature; no production code path depends on it. |

## Testing

`cargo test -p chio-weights`

Golden-vector coverage in `tests/canonical_json.rs` pins the byte output
against `tests/golden/model_card_minimal_v1.json`; regenerate it with
`cargo run -p chio-weights --example dump_minimal_card`.

## See also

- `chio-attest-verify` - the Sigstore/cosign verification this crate wraps.
- `chio-lineage` - the anchor digest and signing-state shapes `lineage` reuses.
- `chio-core-types` - canonical-JSON encoding (`canonical::canonical_json_bytes`)
  this crate encodes and decodes cards with.
- `chio-kernel` - `weights_binding.rs` composes `ModelCard`, `StringSet`, and
  `WeightsError` into the three-gate provider-bind refusal.
- `chio-cli` - `chio bind --card` loads and displays a card, optionally
  verifying its cosign bundle.
