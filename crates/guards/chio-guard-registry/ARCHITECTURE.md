# chio-guard-registry architecture

## Overview

`chio-guard-registry` is an untrusted-edge client: one side speaks OCI
distribution to a registry, the other side writes validated bytes to a local
content-addressed cache. Every value that crosses that boundary (registry-reported
digests, descriptor metadata, referrer manifests, cached files) is treated as
adversarial and re-derived from raw bytes before it is trusted. Ed25519
manifest-signature verification is not implemented here; callers supply it as
a closure. This crate implements Sigstore bundle verification (delegated to
`chio-attest-verify`), fail-closed cache admission, and dual-mode reconciliation.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations and re-exports; `#![forbid(unsafe_code)]`. |
| `src/oci.rs` | `Sha256Digest` and `GuardOciRef` parsing, `GuardRegistryClient` construction, digest-pinned pull (`pull_guard_artifact`), OCI 1.1 referrer discovery and blob fetch for Sigstore bundles (`pull_sigstore_bundle_referrer`), and the egress-contracted HTTP path (bearer-token auth, referrers, blobs) used outside `oci-distribution`. |
| `src/publish.rs` | `GuardPublishRef` (tag-addressed, digest rejected), `GuardArtifactConfig`, `GuardPublishArtifact::build` (normative three-layer assembly), and `GuardRegistryClient::publish_guard_artifact`. |
| `src/pull.rs` | `GuardRegistryClient::pull_guard_to_cache`: orchestrates pull, manifest-digest checks, Sigstore bundle resolution (caller-supplied or referrer), pre-admission verification, and cache write. |
| `src/cache.rs` | `GuardCache` / `GuardCacheLayout`, content-addressed file layout, and `validate_cache_admission`, which independently recomputes the manifest digest and every descriptor digest/media-type/size before any file is written or re-admitted. |
| `src/offline.rs` | `load_guard_with_policy`: the fail-closed gate between "cache is present and unmodified" and "the caller's verification closure says allow." |
| `src/verify.rs` | `GuardSigstoreVerifier` (wraps `chio_attest_verify::AttestVerifier`), `verify_dual_mode`, `GuardVerificationReport::admits_guard_load`, and the structured `GuardLoadEvent` / `CHIO_GUARD_VERIFY_EVENT` audit shape. |
| `src/marketplace.rs` (feature `marketplace`) | `GuardMarketplaceBlock`, `GuardPrice`: optional pricing/reputation fields parsed out of the guard manifest layer JSON. |

## Pull and cache-admission flow

1. `GuardOciRef::from_str` requires the `oci://` scheme, an explicit registry,
   and a lower-case `sha256:` digest with no accompanying tag.
2. `pull_guard_to_cache` pulls the raw manifest and checks its digest against
   the pinned reference, then pulls the artifact (`pull_guard_artifact`),
   which requires the config media type and exactly three layers matched by
   media type, order-independent.
3. If the registry reports its own manifest digest, that is checked against
   the pinned reference too.
4. Sigstore bundle bytes come from the caller (`sigstore_bundle_json`) or,
   absent that, from OCI referrer discovery; caller-supplied bytes win when
   both exist.
5. When a Sigstore verifier and expected identity are both configured, the
   bundle is verified against the pulled module bytes before cache admission;
   a configured policy with no bundle found denies (`SigstoreBundleNotFound`).
6. `GuardCache::write_artifact` re-validates everything from raw bytes
   (`validate_cache_admission`) before writing any file, and removes a stale
   bundle file when the current pull found none, so a later Sigstore-backed
   load cannot inherit old material.
7. A later load, online or offline, calls `load_guard_with_policy`, which
   re-checks file presence, re-runs the same cache-admission validation
   (`validate_cached_artifact_layout`), then calls the caller-supplied
   verification closure and requires `GuardVerificationReport::admits_guard_load()`
   (Sigstore-bearing paths must carry Chio-verified Rekor inclusion;
   Ed25519-only does not, since Rekor is a Sigstore-only concern).

## Invariants and failure modes

- Pull references are digest-pinned; publish references are tag-addressed and
  reject a digest. Both require an explicit registry (`localhost`, a dotted
  host, or a host:port), so neither can silently resolve against Docker Hub.
- Cache admission is media-type-keyed, not position-keyed: layers can arrive
  in any order and are matched by their declared media type, with duplicates
  rejected.
- Cache writes are all-or-nothing: any descriptor digest, media type, or size
  mismatch fails before `create_dir_all` or any file write.
- `load_guard_with_policy` performs no network I/O. Online callers must
  populate the cache first; offline callers get a deterministic
  `OfflineCacheMiss` when files are missing.
- `GuardVerificationReport::admits_guard_load` denies `SigstoreOnly` /
  `DualVerified` reports unless `rekor_inclusion_verified == Some(true)`; a
  report built via `verify_cached_layout_report_only` can carry `Some(false)`
  and is meant for diagnostics, not admission.
- `verify_dual_mode` runs both the Ed25519 and Sigstore closures
  unconditionally, so both errors are observable, then requires their digests
  and identities to agree and requires Sigstore Rekor inclusion.
- Egress hardening (`chio-egress-contract`: scheme allowlist, loopback /
  link-local / IPv6-ULA denial by default, a 3-hop redirect cap, a 16 MiB
  response cap) applies to the hand-rolled referrers/blob/bearer-token HTTP
  path in `oci.rs`. The `oci-distribution::Client` pull/push path (manifest
  and layer transport) runs on its own internal HTTP stack and shares only
  the HTTP-vs-HTTPS registry allowlist, not the rest of the contract.

## Dependencies

`chio-attest-verify` supplies `AttestVerifier`, `SigstoreVerifier`, and
`ExpectedIdentity`; this crate re-exports them and wraps bundle verification in
`GuardSigstoreVerifier`. `chio-egress-contract` (feature `reqwest-egress`)
supplies `HttpEgressContract` and the contracted `reqwest` client used for
referrer/blob/token requests. `chio-reputation` is pulled in only by the
`marketplace` feature, for `ReputationTier`. `oci-distribution` is the OCI
registry transport and manifest/descriptor model. `sha2` computes every digest
independently of registry- or cache-reported values.

## Extension points

Callers implement `chio_attest_verify::AttestVerifier` to plug in a Sigstore
verifier other than `SigstoreVerifier`, and supply their own Ed25519
verification as a closure to `load_guard_with_policy` / `verify_dual_mode`.
