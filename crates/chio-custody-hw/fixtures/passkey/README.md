# Pinned WebAuthn fixture corpus

This is a JSON-descriptor corpus that pins the failure-mode taxonomy the
verifier must enforce (replayed challenge, mismatched origin, expired
challenge, malformed CBOR, plus four positive shapes). The descriptors
carry the intended verifier verdict and the registry URN every negative
case must surface.

Tests that need byte-pinned WebAuthn assertions use the custody hardware
integration fixtures. The descriptor schema stays compatible with those
fixtures through the optional `assertion_b64`, `relying_party_id`, and
`origin` fields.

## Schema

Each `*.json` file under `positive/` and `negative/` carries:

```jsonc
{
  "id": "human-readable identifier",
  "kind": "positive" | "negative",
  // Failure category (negative only). Maps 1:1 to a urn:chio:error:custody:*
  // row in spec/errors/registry.yaml.
  "failure_mode": "replayed-challenge" | "mismatched-origin"
                | "expired-challenge" | "malformed-cbor",
  // Stable URN the verifier MUST surface for this fixture.
  "expected_urn": "urn:chio:error:custody:*"
}
```

The byte-pinned WebAuthn assertion corpus lives in the custody hardware
integration fixtures that call `webauthn-rs` directly. This descriptor corpus
is intentionally narrower: it pins the stable fixture taxonomy and expected
URNs consumed by tests that do not need authenticator wire bytes.
