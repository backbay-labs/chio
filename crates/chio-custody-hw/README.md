# chio-custody-hw

`chio-custody-hw` is Chio's hardware custody surface. It provides a WebAuthn
assertion verifier, the audience-pinned `PasskeyCapability` envelope, and an
issuer service that signs every capability it mints through a configured
signing backend (`Ed25519Backend`, the FIPS P-256/P-384 backends, or
`HybridBackend` under the `pq` feature). The issuer fails closed if no signing
backend is wired and never emits an unsigned capability. Issuance is gated by a
per-subject rate limiter, a per-credential replay nonce store, and the
revocation cascade, all consulted before a signature is produced.

Use this crate to mint and verify hardware-backed (passkey) Chio capabilities.
