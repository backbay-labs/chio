# chio-guard-registry Architecture

`chio-guard-registry` owns distribution of `.arcguard` wasm-component artifacts
through OCI registries. It validates pull and publish references, normalizes
guard artifact layers, writes content-addressed cache entries, and gates cached
loads through signature verification policy.

## Boundaries

- `oci-distribution` owns registry transport and descriptor parsing.
- `chio-attest-verify` owns Sigstore bundle and identity verification. This
  crate retrieves caller-supplied bundle bytes first, otherwise attempts OCI
  referrer discovery, then passes the material to `chio-attest-verify`.
- `chio-wasm-guards` owns runtime execution of fetched guard modules.
- This crate owns the guard artifact OCI shape, cache file layout, publish and
  pull reference policy, offline load admission, and verification-event mapping.

## Trust Invariants

- Pull references must use `oci://`, include an explicit registry, and be pinned
  by a lowercase `sha256:` digest.
- Publish references must use `oci://`, include an explicit registry, include an
  explicit tag, and must not be digest-pinned.
- Guard artifacts have exactly three normalized Chio layers: WIT, wasm module,
  and guard manifest.
- Registry-reported and cached manifest digests must match the digest pinned in
  the pull reference before cache writes are admitted.
- Cache admission validates the OCI descriptors for config, WIT, wasm module,
  and guard manifest bytes before writing any artifact files.
- Sigstore cache material comes from explicit caller-supplied bundle bytes or
  OCI referrers. Caller-supplied bytes win when both are available.
- When Sigstore policy is supplied, pull verifies bundle/artifact binding before
  cache admission and denies if no bundle is found. Without Sigstore policy,
  any cached bundle is explicitly unverified and later loads must verify it.
- Pulls that find no caller-supplied or referrer Sigstore bytes remove any stale
  bundle file for the same digest, so later Sigstore-backed loads cannot inherit
  old local verification material.
- Offline cache loads fail closed when files are missing or when Sigstore Rekor
  inclusion is not verified for Sigstore-backed modes.
- Offline cache loads revalidate the pinned manifest digest and config, WIT,
  wasm module, and guard-manifest descriptor media type, digest, and size before
  signature verification can allow admission.

## Testing Focus

Unit tests cover reference parsing, registry config hardening, artifact shape,
publish artifact layer order, cache layout, offline admission, and dual-mode
verification reconciliation. Integration tests exercise registry paths and
cosign verification behavior when the required fixtures and runtime services
are available.
