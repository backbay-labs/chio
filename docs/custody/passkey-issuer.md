# Passkey issuer: provenance chain

Status: shipped
Verdict satisfied: [docs/trust-boundary-browser-signing.md](../trust-boundary-browser-signing.md)
Last updated: 2026-04-30

This page is a one-page narrative of the passkey custody surface that
Chio ships. It explains the provenance chain a browser-issued capability
walks before the kernel admits it, names the source-of-truth crates,
and points at the tests that lock the contract.

## 1. The chain in one breath

```
   passkey assertion (WebAuthn)
        |
        v
   server-side issuer (chio-custody-hw)
        |    verifies assertion against pinned credential
        |    mints a 5-minute audience-pinned PasskeyCapability
        |    signs the capability via the HybridBackend
        |
        v
   HybridBackend-signed capability envelope
        |    audience, scope_set, exp, credential_id, challenge_nonce
        |    canonical-JSON encoding (RFC 8785) for signing bytes
        |
        v
   browser holds capability bytes only
        |    @chio-protocol/passkey TS helper at sdks/typescript/packages/passkey/
        |    zero key material; one navigator.credentials.get + one fetch
        |
        v
   kernel admission (chio-kernel)
        |    PasskeyCapabilityVerifier delegates to chio-custody-hw
        |    audience match, expiry, replay guard, scope subset, revocation
        |
        v
   verdict
```

The browser never holds a signing key. It holds a short-lived,
audience-pinned capability that can only be presented to the audience
the issuer pinned, only inside the issuer-set expiry window, and only
once (replay guard).

## 2. The verdict this surface satisfies

The browser-signing verdict at
[`docs/trust-boundary-browser-signing.md`](../trust-boundary-browser-signing.md)
named four required pieces of evidence before any browser-resident
signing material was reconsidered. This surface lands all four, except it does
not introduce a browser-held key at all:

| Evidence requirement | Satisfaction |
| --- | --- |
| Named server-side authority that issues browser subkeys | `chio-custody-hw` issuer at `crates/chio-custody-hw/src/issuer.rs` mounted by the control plane |
| Signed provisioning envelope with origin, audience, scope, expiry, issuer metadata | `PasskeyCapability` envelope at `crates/chio-custody-hw/src/capability.rs`; canonical-JSON encoding; 5-minute fixed `exp` clocked off the kernel clock |
| Receipt-visible delegation chain | `(passkey credential id) -> (issuer HybridBackend signing key) -> (capability)` chain recorded in audit logs and surfaced through the kernel verdict path |
| Verifier path tracing every signed receipt to a server-side root without trusting browser material | `PasskeyCapabilityVerifier` at `crates/chio-kernel/src/custody.rs` delegates to `chio-custody-hw` and rejects on any link breaking |

Delegated signing was not added. The browser still does not sign;
it presents an authenticator assertion and receives an opaque
capability whose signature is made by a HybridBackend-backed server-side key.

## 3. Audience pinning

Every minted capability carries an explicit `audience` field. The
audience-confusion property test
(`crates/chio-custody-hw/tests/audience_confusion.rs`) generates
capabilities for audience A and asserts that verification for audience
B always fails, including under bit-flips on the audience field of
the signed envelope. The kernel verifier rejects audience mismatch
fail-closed; the threat-model row `audience_confusion` is marked
`covered` in [`spec/security/coverage.yaml`](../../spec/security/coverage.yaml).

## 4. Replay resistance

The issuer maintains a durable nonce store keyed by
`(credential_id, challenge_nonce)`. The production default is the
SQLite-backed `PasskeyNonceStore` at
`crates/chio-custody-hw/src/nonce_store.rs`; the in-memory store is
test-only and is documented as such in the rustdoc. A replayed
assertion rejects with
`urn:chio:error:custody:replay-detected`. The
`crates/chio-custody-hw/tests/replay_resistance.rs` integration test
locks the contract.

## 5. Revocation cascade

When the issuer marks a credential revoked, it pushes a revocation
entry into the revocation oracle
(`crates/chio-revocation-oracle/`) keyed by
`(issuer_id, credential_id)`. The kernel rejects capabilities whose
credential is revoked at the next revocation epoch. The end-to-end test
`crates/chio-custody-hw/tests/end_to_end.rs` exercises the full path:
present passkey, get capability, call kernel, revoke at issuer, next
call denies within the revocation epoch (configured to one second in the
test harness).

## 6. PQ-hybrid posture

Capabilities sign through the `HybridBackend` so
the audience pin survives PQ migration. With
`crypto_floor=allow_classical`, capabilities are byte-identical to
the classical case; with `crypto_floor=allow_hybrid`, capabilities
follow the `hybrid:` prefix discipline without changing the
verifier surface.

## 7. Threat-model coverage

| Threat ID | coverage_state | Closed by |
| --- | --- | --- |
| `passkey_credential_theft` | covered | passkey custody surface |
| `audience_confusion` | covered | passkey custody surface |

Both rows ship covered in `spec/security/coverage.yaml`. The full
register is at `spec/security/chio-threat-model.v1.json`.

## 8. Pointers

- Issuer crate: `crates/chio-custody-hw/`
- Browser helper: `sdks/typescript/packages/passkey/`
- Demo: `docs/demo/passkey/index.html`
- Verdict: `docs/trust-boundary-browser-signing.md`
- Coverage map: `spec/security/coverage.yaml`
