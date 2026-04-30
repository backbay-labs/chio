# Pinned WebAuthn fixture corpus

P1 ships a JSON-descriptor corpus that pins the failure-mode taxonomy the
M10 narrative requires (replayed challenge, mismatched origin, expired
challenge, malformed CBOR, plus four positive shapes). The descriptors
carry the intended verifier verdict and the registry URN every negative
case must surface.

P2 will replace each descriptor with a byte-pinned WebAuthn assertion
captured from a real authenticator. The descriptor schema is forward
compatible: P2 adds an `assertion_b64` field carrying the wire bytes and a
`relying_party_id` / `origin` pair the verifier was configured with at
capture time.

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

TODO(security): P2 wires a real `webauthn-rs` `start_passkey_authentication`
state plus byte-pinned `PublicKeyCredential` JSON so the verifier actually
exercises the cryptographic path. P1 only proves the corpus directory
shape and the verdict taxonomy.
