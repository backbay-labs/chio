# chio-attest-verify Architecture

## Boundary

`chio-attest-verify` owns the workspace attestation trust boundary. It is the only crate allowed to call Sigstore verification APIs directly, and it exposes common traits for supply-chain attestation and TEE quote verification.

## Internal Surfaces

The crate is split into the public verifier facade in `lib`, Sigstore bundle and detached-signature verification in `sigstore`, tenant policy parsing and loading in `policy` and `policy_loader`, quote binding primitives in `quote`, and optional Nitro, SEV-SNP, and TDX backends behind `tee-quotes`.

## Trust Invariants

The trust boundary is exact acceptance. A successful attestation or quote result means the signed bytes, certificate identity, OIDC issuer, trust root, TEE collateral, TCB status, and report-data binding all satisfied their declared preconditions. A successful tenant-policy load means the policy structure, signature, signing identity, and staleness horizon were all accepted before a tenant identity can be resolved.

## Current Hardening

Current hardening: tenant policy text fields and list entries now reject blank and surrounding-whitespace values before regex compilation or signature verification, so an empty regex string cannot become a valid `ExpectedIdentity` source.

## Verification Focus

Tests should separate policy parsing failures from cryptographic verification failures, cover stale policy loads, and keep optional TEE quote paths behind explicit feature-gated checks.
