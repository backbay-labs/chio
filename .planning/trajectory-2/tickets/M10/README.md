# M10: Hardware Custody + Policy-Bound Model Cards

**Wave:** W4  |  **Trust-boundary:** yes  |  **Tickets:** 33  |  **Effort:** 41.00 days

## In one paragraph

M10 ships `chio-custody-hw`: a WebAuthn passkey assertion mints a five-minute audience-pinned capability signed via M03's hybrid backend, with revocation cascading through M04's oracle and zero key material in the browser. It also lands `chio-weights` model cards binding `(weights_hash, allowed_capabilities, banned_tools)` and `arc bind` for refusal-on-mismatch. M10 is the substitute promised by trajectory-1 M08.P3's rejection of in-browser signing.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 4 | Pin webauthn-rs + base64ct + coset; open audit doc; append three threat-model rows |
| P1 | 6 | `chio-custody-hw` skeleton + `PasskeyVerifier` + `PasskeyCapability` + issuer service + fixtures + custody error rows |
| P2 | 6 | M03 HybridBackend mint path + nonce store + M04 revocation cascade + audience proptest + kernel verifier |
| P3 | 6 | `@chio/passkey` TS package + browser flow + demo + revocation e2e + 30 KB gzipped budget |
| P4 | 6 | `chio-weights` skeleton + model card schema + cosign helper + `policy.weights_card_required` + `arc bind` |
| P5 | 5 | Lineage anchoring, cross-provider equivalence test, threat-model coverage, audit close, docs |

## Load-bearing artifacts

- `crates/chio-custody-hw/` (M10.P1.T1 scaffolds)
- `crates/chio-custody-hw/fixtures/passkey/` (M10.P1.T5)
- `urn:chio:error:custody:*` registry rows (M10.P1.T6; M01 dependency)
- `PasskeyNonceStore` SQLite impl (M10.P2.T2)
- `sdks/typescript/packages/passkey/` `@chio/passkey` (M10.P3.T1)
- `crates/chio-weights/` + `spec/schemas/model-card.v1.json` (P4.T1, P4.T2)
- `policy.weights_card_required` enum (M10.P4.T4)
- `arc bind <provider> --card <path>` subcommand (M10.P4.T6)

## Cross-trajectory deps

- trajectory-1 M08.P3 verdict (`docs/trust-boundary-browser-signing.md`) - M10 is the promised server-side issuer substitute
- trajectory-2 M01 error registry - custody/weights `urn:chio:error:*` rows (hard dep on M01.P1.T1)
- trajectory-2 M03 HybridBackend - issuer mint path consumer (hard dep on M03.P2.T2)
- trajectory-2 M04 revocation oracle - credential-revoke cascade (hard dep on M04.P1)
- trajectory-2 M05 threat-model gate - covers `passkey_credential_theft`, `audience_confusion`, `weights_hash_spoof`
- trajectory-2 M07 verdict-equality oracle - cross-provider equivalence test consumer (M10.P5.T2)
- trajectory-2 M09 lineage - model-card anchor proofs (soft_dep on M10.P5.T1)

## Locked decisions

- D23 WebAuthn assertion is authn, not signing material; browser holds zero capability material; issuer mints audience-pinned five-minute capability bound to credential id
- D24 Both halves in scope; if pressure, custody (P0-P3) ships and model cards (P4-P5) penciled for follow-on (P4/P5 tagged "descope candidate")

## Active freezes

- `m10-custody-issuer-pivot` (`crates/chio-custody-hw/**`, `sdks/typescript/packages/passkey/src/**`): opens at M10.P1.T1, closes at M10.P3.T5

## When this milestone is done

- `cargo test -p chio-custody-hw` green; replay-attack test, audience-confusion proptest, pinned WebAuthn fixture corpus all pass.
- `cargo test -p chio-weights` green; model card canonical-JSON vectors lock the schema; cosign verify path consumes `chio-attest-verify`.
- `arc bind <provider> --card <path>` succeeds against fixture provider + card; refusal paths tested with the three new error codes.
- End-to-end revocation: passkey -> issuer-minted capability -> kernel call permitted -> revoke at issuer -> next call denies within the M04 epoch.
- `@chio/passkey` published under `@chio` org with semver, < 30 KB gzipped, demo page renders the full flow.
- M05 threat-model coverage marks `passkey_credential_theft`, `audience_confusion`, and `weights_hash_spoof` covered.
- `policy.weights_card_required` rejects invalid combinations at load time (fail-closed).
