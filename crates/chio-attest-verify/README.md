# chio-attest-verify

Single source of truth for Sigstore verification across the chio workspace.
M09 (release-archive verification), M06 (WASM guard signing), and M02 (fuzz
target for the verifier) all consume this crate; no other crate is permitted
to call `sigstore-rs` directly.

## Trait surface

The crate exposes a single `AttestVerifier` trait and one production impl,
`SigstoreVerifier`. The trait surface is fixed and consumed verbatim by
M06's guard registry and M02's fuzz harness:

```rust
use chio_attest_verify::{AttestVerifier, ExpectedIdentity, SigstoreVerifier};

let verifier = SigstoreVerifier::with_embedded_root()?;
let expected = ExpectedIdentity {
    certificate_identity_regexp:
        r"https://github\.com/backbay/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"
            .into(),
    certificate_oidc_issuer: "https://token.actions.githubusercontent.com".into(),
};
let claims = verifier.verify_bundle(&artifact_bytes, &bundle_json_bytes, &expected)?;
assert!(claims.rekor_inclusion_verified);
```

### `verify_bundle`

The strongest assertion the crate provides. Consumes a Sigstore protobuf
Bundle (cert chain + signature + Rekor transparency entry) and runs the
full keyless flow against the embedded Fulcio trust root, including Rekor
log-entry consistency.

### `verify_blob` / `verify_bytes`

For detached `(artifact, signature, leaf-cert)` triples that do not carry
a Rekor inclusion proof. These paths perform certificate-chain validation
against Fulcio, OIDC issuer match, identity SAN regex match, certificate
validity-window check, and signature verification, but mark the resulting
`VerifiedAttestation.rekor_inclusion_verified = false`. Callers that
require the strongest keyless assertion should prefer `verify_bundle`.

## Embedded TUF trust root

The crate ships the Sigstore Public Good Instance trust root in tree under
`sigstore-root/`:

- `root.json` is the TUF root (kept for the quarterly re-bake job and
  audit trail).
- `trusted_root.json` is the runtime artifact consumed via `include_bytes!`.

`build.rs` fails the compile if either file is missing. The quarterly
CODEOWNERS-reviewed re-bake job described in
`.planning/trajectory/09-supply-chain-attestation.md` refreshes both files
in lockstep.

## OIDC issuer regex

For chio's GitHub-hosted release workflows the canonical
`ExpectedIdentity` is:

- `certificate_oidc_issuer = "https://token.actions.githubusercontent.com"`
- `certificate_identity_regexp =
  "https://github\.com/backbay/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"`

The verifier anchors the regex with `^...$` internally; callers may omit
or include their own anchors without behavioural difference.

## Integration tests

`tests/integration.rs` exercises the real `SigstoreVerifier` against the
embedded trust root. The hermetic test suite covers the fail-closed
contract on every trait method:

- `constructor_loads_embedded_trust_root`: the embedded TUF JSON parses
  and yields a usable `dyn AttestVerifier`.
- `verify_bundle_rejects_malformed_json`: garbage JSON surfaces as
  `AttestError::Malformed`.
- `verify_bundle_rejects_empty_bundle_object`: a syntactically valid but
  semantically empty bundle is rejected.
- `verify_bytes_rejects_random_garbage`: non-PEM/non-DER certificate
  inputs are rejected before signature verification.
- `verify_bytes_rejects_self_signed_cert_against_fulcio_root`: a leaf
  that does not chain to Fulcio is rejected at the chain-validation step.
- `verify_blob_returns_io_error_for_missing_artifact`: missing artifact
  paths surface as `AttestError::Io`.

The positive end-to-end keyless flow requires a Fulcio-issued certificate
from a real OIDC workflow run, which is not hermetically reproducible
inside `cargo test`. The M09 release-binaries CI workflow exercises that
path online via `cosign verify-blob` against published release archives.

## Forbidden constructs

This is a trust-boundary crate. The following are forbidden in any file
under `src/` (enforced at the lint level and by reviewer checklist):

- `unwrap_used` and `expect_used` (clippy `forbid`).
- `todo!()`, `unimplemented!()`, and bare `panic!()` in any verification
  path (per EXECUTION-BOARD.md "No verifier or trust-boundary stubs").
- Direct `sigstore-rs` imports from any crate other than this one.
