# chio-guard-registry

OCI distribution client for `.arcguard` wasm-component guard artifacts:
digest-pinned pull, tag-addressed publish, a content-addressed on-disk cache,
and a fail-closed offline/online load policy. Registry transport and artifact
shape checks live here; Sigstore bundle verification is delegated to
`chio-attest-verify`. The runtime that later executes fetched modules is
`chio-wasm-guards`.

## Responsibilities

- Parse and validate digest-pinned pull references (`GuardOciRef`) and
  tag-addressed publish references (`GuardPublishRef`); both require an
  explicit registry.
- Pull and push the normative three-layer Chio guard artifact (WIT, wasm
  module, guard manifest) over OCI, matching layers by media type and
  rejecting any other layer count or a duplicate media type.
- Discover Sigstore bundle material through OCI 1.1 referrers when the caller
  does not supply bundle bytes directly.
- Write and re-validate a content-addressed on-disk cache (`GuardCache`),
  independently recomputing digests rather than trusting registry- or
  cache-reported values.
- Gate every guard load, online or offline, through `load_guard_with_policy`:
  missing cache files, tampered cache files, and unverified Rekor inclusion
  all deny before a guard is admitted.
- Reconcile Ed25519 and Sigstore verification results (`verify_dual_mode`) and
  emit a structured `chio.guard.verify` event for every load decision.

## Public API

- `oci::{GuardRegistryClient, GuardRegistryConfig, GuardOciRef,
  RegistryCredentials, Sha256Digest, PulledGuardArtifact, GuardRegistryError}`
  - reference parsing and the OCI client (`try_new`, `pull_guard_artifact`,
  `pull_sigstore_bundle_referrer`).
- `pull::{GuardPullRequest, GuardPullResponse, GuardPullSigstoreBundleSource}`
  - `GuardRegistryClient::pull_guard_to_cache`, the combined pull, verify, and
  cache-write entry point.
- `publish::{GuardPublishRef, GuardPublishArtifact, GuardPublishArtifactInput,
  GuardArtifactConfig, GuardPublishResponse}` - `GuardRegistryClient::publish_guard_artifact`
  and artifact construction.
- `cache::{GuardCache, GuardCacheLayout, GuardCacheArtifact,
  CachedGuardArtifact}` and the `CACHE_*` file-name constants - the on-disk layout.
- `offline::{load_guard_with_policy, GuardOfflineLoadRequest, GuardOfflineLoad,
  GuardOfflineLoadError, GuardNetworkState}` - the fail-closed load gate.
- `verify::{GuardSigstoreVerifier, verify_dual_mode, GuardVerificationReport,
  GuardVerificationKind, GuardLoadEvent, CHIO_GUARD_VERIFY_EVENT}` - Sigstore
  verification wiring and structured events.
- Re-exported from `chio-attest-verify`: `AttestVerifier`, `ExpectedIdentity`,
  `SigstoreVerifier`, `VerifiedAttestation`, `AttestError`.
- `marketplace::{GuardMarketplaceBlock, GuardPrice}` (feature `marketplace`) -
  optional pricing and reputation-floor fields parsed from a guard manifest.

## Feature flags

| Flag | Effect |
|------|--------|
| `marketplace` | Enables the `marketplace` module and its `chio-reputation` dependency; parses optional `price`/`reputation_floor` fields out of a guard manifest layer. Off by default so the pull/verify/cache paths keep an unchanged dependency footprint. |
| `pq` | Forwards to `chio-attest-verify/pq`. Exists only so `tests/cosign_under_crypto_floor.rs` can exercise `GuardSigstoreVerifier::verify_bundle` under all three `crypto_floor` settings; cosign payload bytes are not hybrid-signed. |

## Testing

```
cargo test -p chio-guard-registry                # unit tests + most integration tests
cargo test -p chio-guard-registry --features pq  # adds the crypto-floor cosign regression
```

`tests/zot_integration.rs` pulls a `project-zot/zot` container via
`testcontainers` and needs a working Docker daemon.

## See also

- `chio-attest-verify` - Sigstore bundle and Fulcio/Rekor identity
  verification; this crate delegates to it via `GuardSigstoreVerifier`.
- `chio-wasm-guards` - runtime that executes fetched guard modules.
- `chio-egress-contract` - typed HTTP egress policy enforced on the
  referrer/blob/token HTTP path.
- `chio-cli` - primary consumer, driving guard publish, pull, and marketplace
  listing.
