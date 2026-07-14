# chio-credentials

`chio-credentials` implements Chio's native Agent Passport format: portable,
Ed25519-signed reputation credentials that an agent presents to a relying
party as verifiable evidence of its operating history. It owns issuance,
verification, presentation exchange, lifecycle tracking, and cross-issuer
portability for that format, plus lossy projections into the OID4VCI, OID4VP,
SD-JWT VC, and JWT VC JSON standards.

The crate is pure data and cryptography: it performs no I/O, depends on no
kernel or storage layer, and forbids `unsafe`. Every fallible function takes
the current time as an explicit parameter rather than reading a clock, so
verification is deterministic. `chio-control-plane` hosts its issuance,
presentation, discovery, and reputation-import functions as HTTP endpoints;
`chio-cli` exposes the same functions as commands.

## Responsibilities

- Issue and verify canonically-signed `ReputationCredential`s that wrap a
  `chio-reputation` scorecard under `did:chio` issuer and subject identities.
- Bundle credentials into an unsigned `AgentPassport`, aggregating Merkle
  roots and enterprise-identity provenance across the bundle, and verify the
  bundle as a unit.
- Run challenge/response presentation exchanges bound to a verifier nonce and
  validity window, with optional evaluation against a `PassportVerifierPolicy`.
- Track passport lifecycle state (active, stale, superseded, revoked,
  not-found), enforce which fields each state may carry, and bridge revoked
  entries into `chio-revocation-oracle`.
- Verify and evaluate cross-issuer portfolios, signed subject-migration
  records, and signed trust packs that let a subject's passport history carry
  across issuer and subject-identifier changes.
- Project native passports into OID4VCI issuance, OID4VP presentation,
  SD-JWT VC, and JWT VC JSON, and verify those projections back to native
  passport identifiers.
- Publish and verify signed public discovery documents for issuers,
  verifiers, and transparency logs; construction fails unless the document
  declares itself informational-only, explicit-import-required, and
  manual-review-required.
- Import and score portable reputation summaries and negative events from
  other issuers under a local weighting profile.
- Synthesize a coarse `TrustTier` from a compliance score and behavioral-
  anomaly flag.

## Public API

- `AgentPassport`, `ReputationCredential`, `CredentialError` - the native
  artifact and the crate-wide error type.
- `issue_reputation_credential` (+ `_with_enterprise_identity`),
  `verify_reputation_credential`, `build_agent_passport`,
  `passport_artifact_id`, `verify_agent_passport`, `present_agent_passport`,
  `evaluate_agent_passport` - core issuance and verification.
- `create_passport_presentation_challenge` (+ `_with_reference`),
  `verify_passport_presentation_challenge`,
  `respond_to_passport_presentation_challenge`,
  `verify_passport_presentation_response` (+ `_with_policy`) -
  challenge/response presentation exchange.
- `PassportVerifierPolicy`, `create_signed_passport_verifier_policy`,
  `verify_signed_passport_verifier_policy`,
  `ensure_signed_passport_verifier_policy_active` - signed, publishable
  verifier acceptance policy.
- `PassportLifecycleState`, `PassportLifecycleRecord`,
  `PassportLifecycleResolution`, `PassportStatusDistribution` - passport
  lifecycle tracking and its projection into `chio-revocation-oracle`.
- `CrossIssuerPortfolio`, `verify_cross_issuer_portfolio`,
  `evaluate_cross_issuer_portfolio`, `create_signed_cross_issuer_migration`,
  `create_signed_cross_issuer_trust_pack` - multi-issuer portfolio
  verification and subject migration.
- `issue_chio_passport_sd_jwt_vc`, `verify_chio_passport_sd_jwt_vc`,
  `PortableEd25519Jwk`, `build_portable_jwks` - SD-JWT VC projection
  (`application/dc+sd-jwt`, selective disclosure).
- `issue_chio_passport_jwt_vc_json`, `verify_chio_passport_jwt_vc_json` -
  JWT VC JSON projection (`jwt_vc_json`, no selective disclosure).
- `Oid4vciCredentialIssuerMetadata`,
  `default_oid4vci_passport_issuer_metadata` (+ `_with_status_distribution`,
  `_with_signing_key`), `build_oid4vci_passport_offer`,
  `Oid4vciCredentialRequest`, `Oid4vciCredentialResponse` - OID4VCI issuance.
- `Oid4vpRequestObject`, `sign_oid4vp_request_object`,
  `verify_signed_oid4vp_request_object` (+ `_with_any_key`),
  `respond_to_oid4vp_request`, `verify_oid4vp_direct_post_response`
  (+ `_with_any_issuer_key`), `WalletExchangeDescriptor` - OID4VP
  presentation.
- `create_signed_public_issuer_discovery`,
  `create_signed_public_verifier_discovery`,
  `create_signed_public_discovery_transparency`,
  `PublicDiscoveryImportGuardrails` - guardrailed public discovery documents.
- `build_portable_reputation_summary_artifact`,
  `build_portable_negative_event_artifact`, `evaluate_portable_reputation`,
  `PortableReputationWeightingProfile` - cross-operator reputation import.
- `trust_tier::{synthesize_trust_tier, TrustTier}` - coarse trust tier from a
  compliance score and anomaly flag.

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Enables `chio_credentials::fuzz`, the libFuzzer entry points (`fuzz_jwt_vc_verify`, `fuzz_oid4vp_presentation`) used by the standalone `fuzz/` workspace. Off by default. |
| `dudect` | Enables the `dudect_jwt_verify` timing-leak harness (`tests/dudect/jwt_verify.rs`) that statistically checks `verify_chio_passport_jwt_vc_json` for data-dependent timing. Off by default so `cargo test` stays fast and deterministic. |

## Testing

- `cargo test -p chio-credentials` - unit tests (`src/tests.rs` plus inline
  `discovery_tests`/`portable_reputation_tests` modules) and integration
  tests (`tests/integration_smoke.rs`, `tests/trust_tier.rs`,
  `tests/schema_negative.rs`).
- `tests/property_passport.rs` - proptest invariants over the passport
  lifecycle state machine; the four test names are load-bearing and must not
  be renamed (see the file's module doc).
- `cargo test -p chio-credentials --features dudect --release jwt_verify` -
  opt-in dudect timing-leak lane, excluded from the default run.
- `cargo mutants --config crates/trust/chio-credentials/mutants.toml
  --package chio-credentials` - focused mutation testing over `lib.rs` and
  `trust_tier.rs`.
- Fuzz targets `jwt_vc_verify` and `oid4vp_presentation` live in the
  standalone `fuzz/` workspace and require the `fuzz` feature.

## See also

- `chio-core` - `Keypair`/`PublicKey`/`Signature`, canonical JSON signing,
  and `SignedExportEnvelope`, which this crate builds every artifact on top
  of.
- `chio-did` - `did:chio` identity parsing and verification-method
  derivation for issuer, subject, and verifier identities.
- `chio-reputation` - `LocalReputationScorecard`, the metrics payload every
  `ReputationCredential` wraps.
- `chio-revocation-oracle` - receives the `PassportRevocationEvent`s bridged
  from revoked lifecycle records; this crate does not implement revocation
  checking itself.
- `chio-control-plane` - hosts this crate's issuance, presentation,
  discovery, and reputation-import functions as HTTP endpoints.
- `chio-cli` - exposes passport issuance, verification, certification, and
  local-reputation functions as CLI commands.
