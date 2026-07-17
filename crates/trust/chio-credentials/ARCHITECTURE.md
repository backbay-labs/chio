# chio-credentials architecture

## Overview

`chio-credentials` is a pure library: no I/O, no runtime state,
`forbid(unsafe_code)`, and every fallible function takes the current time as
an explicit `now: u64` parameter instead of reading a clock. It sits in the
trust layer next to `chio-did` and `chio-reputation`, not in the kernel's
request-evaluation path; it has no dependency on `chio-kernel`. The native
`AgentPassport`/`ReputationCredential` structs are the single source of
truth, and OID4VCI, OID4VP, SD-JWT VC, and JWT VC JSON are lossy,
standards-compliant projections derived from them, never independent trust
sources. `chio-control-plane` hosts the issuance, presentation, and discovery
endpoints this crate implements; `chio-cli` exposes the same functions as
commands.

## Module map

Every file under `src/` except `trust_tier.rs` and the feature-gated
`fuzz.rs` is `include!`-d directly into `lib.rs` rather than declared with
`mod`, so they share one flat `chio_credentials` namespace and one set of
imports declared at the top of `lib.rs`. `cargo-mutants` treats `lib.rs` as
the single mutation entry point for this reason (`mutants.toml`).

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Shared imports, schema-constant strings, `include!` assembly, `pub mod trust_tier`, feature-gated `pub mod fuzz`. |
| `src/artifact.rs` | `CredentialError` (the error type for every fallible operation in the crate), `ReputationCredential`/`CredentialProof`, `ChioCredentialEvidence`, `EnterpriseIdentityProvenance`. |
| `src/challenge.rs` | Core issuance and verification (`issue_reputation_credential`, `verify_reputation_credential`, `build_agent_passport`, `verify_agent_passport`, `present_agent_passport`, `evaluate_agent_passport`) and the presentation-challenge types plus their construction/verification. |
| `src/passport.rs` | `AgentPassport`; lifecycle types and their field-consistency validation (`PassportLifecycleRecord`, `PassportLifecycleResolution`, `PassportStatusDistribution`); `PassportVerifierPolicy` and its threshold validation. |
| `src/presentation.rs` | Holder-side response construction (`respond_to_passport_presentation_challenge`) and verifier-side response verification (`verify_passport_presentation_response`, `_with_policy`). |
| `src/policy.rs` | Private policy-evaluation engine (`evaluate_credential_against_policy` and its metric-threshold helpers) used by `challenge.rs` and `presentation.rs`. Exposes no public API. |
| `src/registry.rs` | Signed, publishable verifier-policy documents: `create_signed_passport_verifier_policy`, `verify_signed_passport_verifier_policy`, `ensure_signed_passport_verifier_policy_active`. |
| `src/cross_issuer.rs` | `CrossIssuerPortfolio`, signed subject-migration records, signed trust packs, and their verification/evaluation functions. |
| `src/portable_sd_jwt.rs` | SD-JWT VC (`application/dc+sd-jwt`) projection: JWK helpers, type metadata, `issue_chio_passport_sd_jwt_vc`, `verify_chio_passport_sd_jwt_vc`, disclosure encode/decode. |
| `src/portable_jwt_vc.rs` | `jwt_vc_json` projection (no selective disclosure): type metadata, `issue_chio_passport_jwt_vc_json`, `verify_chio_passport_jwt_vc_json`. |
| `src/oid4vci.rs` | OID4VCI issuer metadata, credential offers, token and credential request/response types, and their cross-validation against issuer metadata. |
| `src/oid4vp.rs` | OID4VP request objects, DCQL query, wallet-exchange descriptors and transaction state, verifier metadata, `direct_post.jwt` response verification; also the shared compact-JWT sign/decode helpers reused by `oid4vci.rs` and the portable-projection modules. |
| `src/discovery.rs` | Signed public issuer/verifier/transparency discovery documents, gated by mandatory `PublicDiscoveryImportGuardrails`. |
| `src/portable_reputation.rs` | Cross-operator reputation import: `PortableReputationSummaryArtifact`/`PortableNegativeEventArtifact` (signed via `chio_core`'s `SignedExportEnvelope`), `PortableReputationWeightingProfile`, `evaluate_portable_reputation`. |
| `src/trust_tier.rs` | `pub mod trust_tier`: `TrustTier` and `synthesize_trust_tier`, re-exported at the crate root and embedded as the optional `AgentPassport.trust_tier` field. |
| `src/fuzz.rs` | `pub mod fuzz`, feature-gated: libFuzzer entry points for the standalone `fuzz/` workspace. |
| `src/tests.rs` | `include!`-d `#[cfg(test)] mod tests`, the crate's internal unit-test suite. |

## Credential and passport lifecycle

1. An issuer holds a `LocalReputationScorecard` (from `chio-reputation`) and
   calls `issue_reputation_credential` to wrap it in a canonically-signed
   `ReputationCredential` bound to the subject's `did:chio` identity.
2. `build_agent_passport` bundles one or more same-subject credentials into
   an unsigned `AgentPassport`; the passport's `issued_at`/`valid_until`
   window is the intersection of its credentials' windows, and its Merkle
   roots and enterprise-identity provenance are aggregated, deduplicated, and
   sorted from the credential set.
3. A verifier issues a `PassportPresentationChallenge` (nonce, validity
   window, optional issuer allowlist, credential cap, and embedded or
   referenced `PassportVerifierPolicy`). The holder calls
   `respond_to_passport_presentation_challenge`, which re-verifies the
   passport, filters it through the challenge's presentation options
   (`present_agent_passport`), and signs the result with the holder's key.
4. The verifier calls `verify_passport_presentation_response` (or
   `_with_policy`), which re-verifies the challenge, the passport, and the
   holder's proof; checks the proof timestamp falls inside the challenge
   window; and optionally runs `evaluate_agent_passport` against the
   resolved policy to produce an accept/reject decision with per-credential
   reasons.

Independent surfaces that build on the same primitives without sitting on
this path:

- Portable projection: a verified passport feeds
  `build_chio_passport_portable_projection`, which
  `portable_sd_jwt.rs`/`portable_jwt_vc.rs` turn into a compact SD-JWT VC or
  JWT VC JSON; OID4VP wraps the SD-JWT projection in a signed
  request/response exchange bound to a verifier's `client_id`, nonce, and
  state.
- Cross-issuer portability: `cross_issuer.rs` independently re-verifies each
  portfolio entry's embedded passport and cross-checks any migration record
  before aggregating issuers across entries.
- Portable reputation import: `evaluate_portable_reputation` runs
  independently of the passport format, scoring signed
  `PortableReputationSummaryArtifact`/`PortableNegativeEventArtifact` sets
  from other issuers under a local weighting profile.

## Invariants and failure modes

- Every fallible function returns `Result<_, CredentialError>`;
  `unwrap`/`expect` are denied outside `#[cfg(test)]`
  (`#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` in
  `lib.rs`).
- `now` is always an explicit caller-supplied unix timestamp; the crate never
  reads the system clock, so verification is reproducible from an artifact
  plus a timestamp.
- Validity windows are checked inclusive at both ends; several integration
  tests pin exact-boundary behavior (`portable_credentials_expire_at_exact_exp`,
  `oid4vp_artifacts_expire_at_exact_exp`,
  `signed_verifier_policy_activation_window_is_inclusive`).
- Native structs (`AgentPassport`, `PassportPresentationChallenge`,
  `PassportPresentationResponse`, `SignedPassportVerifierPolicy`, and
  similar) use `deny_unknown_fields`, so malformed or extended JSON fails at
  parse time before any signature or business-rule check runs.
- Signed artifacts follow one of two patterns: a hand-rolled
  `body: T, signature: Signature` pair verified with
  `Keypair::sign_canonical`/`PublicKey::verify_canonical` (or `.verify()`
  over `canonical_json_bytes`), or `chio_core`'s generic
  `SignedExportEnvelope<T>` (used only for portable reputation summaries and
  negative events).
- `PassportLifecycleRecord` (the persisted lifecycle entry) rejects `Stale`
  and `NotFound` status outright; only `PassportLifecycleResolution` (the
  query-time answer) may report those states.
- Public discovery documents reject construction unless
  `PublicDiscoveryImportGuardrails` keeps `informational_only`,
  `requires_explicit_policy_import`, and `requires_manual_review` all
  `true`; there is no code path in this crate that produces a discovery
  document a relying party could auto-trust.
- Cross-issuer portfolio verification requires every migration referenced by
  an entry to name that entry's subject, issuer, and passport explicitly; an
  entry whose subject differs from the portfolio subject without a matching
  migration record is rejected.
- Portable reputation evaluation rejects unverifiable, expired, stale,
  subject-mismatched, disallowed-issuer, duplicate-issuer, or (if
  configured) probationary summaries and negative events individually,
  recording why in `PortableReputationEvaluation::findings`; a
  `blocking_event_kinds` match zeroes the effective score regardless of
  accumulated positive signal.
- `PassportLifecycleRecord::to_revocation_event` is read-only: it projects a
  `Revoked` record into `chio_revocation_oracle::PassportRevocationEvent`
  without mutating the record, and returns `Ok(None)` for any non-revoked
  state.
- `PassportPresentationVerification::replay_state` is always `None` from
  this crate; nonce/challenge replay tracking is the caller's
  responsibility.

## Dependencies

Internal: `chio-core` supplies `Keypair`/`PublicKey`/`Signature`, canonical
JSON signing, `sha256_hex`, the portable-claim-catalog and identity-binding
constants, session and enterprise-identity types, and `SignedExportEnvelope`.
`chio-did` supplies `DidChio` parsing and verification-method derivation for
`did:chio` identities. `chio-reputation` supplies `LocalReputationScorecard`
and its metric types, the payload every `ReputationCredential` wraps.
`chio-revocation-oracle` receives the `PassportRevocationEvent` bridged from
revoked lifecycle records; this crate does not implement revocation checking
itself. No dependency is aliased via `package = ...`.

External: `serde`/`serde_json` for every wire artifact, `chrono` (`clock`
feature) for RFC 3339 conversion, `base64` and `sha2` for JWK thumbprints and
SD-JWT digests, `rand_core` (`getrandom`) for SD-JWT disclosure salts,
`thiserror` for `CredentialError`.
