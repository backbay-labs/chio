# chio-guard-registry Architecture

`chio-guard-registry` owns distribution of `.arcguard` wasm-component artifacts
through OCI registries. It validates pull and publish references, normalizes
guard artifact layers, writes content-addressed cache entries, and gates cached
loads through signature verification policy.

## Boundaries

- `oci-distribution` owns registry transport and descriptor parsing.
- `chio-attest-verify` owns caller-supplied Sigstore bundle and identity
  verification. This crate does not discover Sigstore material through OCI
  referrers.
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
- Sigstore cache material comes from explicit caller-supplied bundle bytes. Pull
  does not synthesize an empty bundle and does not claim registry referrer
  retrieval.
- Pulls without caller-supplied Sigstore bytes remove any stale bundle file for
  the same digest, so later Sigstore-backed loads cannot inherit old local
  verification material.
- Offline cache loads fail closed when files are missing or when Sigstore Rekor
  inclusion is not verified for Sigstore-backed modes.

## Testing Focus

Unit tests cover reference parsing, registry config hardening, artifact shape,
publish artifact layer order, cache layout, offline admission, and dual-mode
verification reconciliation. Integration tests exercise registry paths and
cosign verification behavior when the required fixtures and runtime services
are available.
