# chio-core

Unified import surface for the Chio protocol. `chio-core` re-exports the
canonical protocol types from `chio-core-types` (capabilities, receipts,
canonical JSON, signing, Merkle proofs, sessions) alongside the economic and
trust domain crates, and owns three contracts that belong to no single
lower-level crate: the extension and official-stack model, the public identity
and wallet network model, and the portable-standards catalog.

The crate is pure data and cryptography. It performs no I/O and holds no runtime
state, so it compiles for WASM, embedded, and `alloc`-only targets, and forbids
`unsafe`. Reach for `chio-kernel` when you need request evaluation and receipt
signing rather than the types alone.

## Responsibilities

- Expose one `chio_core::*` import path over `chio-core-types` and the domain
  crates, so consumers depend on a single entry point instead of a dozen.
- Own the extension contract (`extension`): which Chio surfaces are canonical
  truth, which seams are replaceable, and how third-party implementations
  negotiate against the official stack.
- Own the identity network contract (`identity_network`): public identity
  profiles, wallet directory entries, and routing manifests that widen outward
  identity without replacing the native `did:chio` provenance anchor.
- Own the portable standards (`standards`): claim catalog, portable identity
  binding, and governed-authorization binding constants.

## Public API

Re-exported from `chio-core-types`:

- `canonical` - RFC 8785 canonical JSON (`canonical_json_bytes`, `CanonicalBytes`).
- `capability`, `session`, `message`, `manifest`, `receipt` - protocol artifacts.
- `crypto` - Ed25519 signing backends, `Keypair`, `SignedCanonicalPayload`; the
  `pq` feature adds ML-DSA-65 and hybrid backends.
- `hashing`, `merkle` - `sha256`, `Hash`, `MerkleTree`, `MerkleProof`.
- `signed_artifact` - the signed-artifact schema registry.
- `AgentId`, `CapabilityId`, `ServerId`.

Re-exported domain crates: `appraisal`, `autonomy`, `credit`, `federation`,
`governance`, `listing`, `market`, `open_market`, `underwriting`, `web3`.

Owned in this crate:

- `extension::{validate_extension_inventory, validate_official_stack_package,
  validate_extension_manifest, negotiate_extension, validate_qualification_matrix}`
- `identity_network::{validate_public_identity_profile,
  validate_public_wallet_directory_entry, validate_public_wallet_routing_manifest,
  validate_identity_interop_qualification_matrix}`
- `standards::{ChioPortableClaimCatalog, ChioPortableIdentityBinding,
  ChioGovernedAuthorizationBinding}`

## Feature flags

| Flag | Effect |
|------|--------|
| `pq` | Enables post-quantum signing via `chio-core-types/pq` (ML-DSA-65 and hybrid backends). |

## Testing

`cargo test -p chio-core`

## See also

- `chio-core-types` - defines the canonical protocol types re-exported here.
- `chio-kernel` - request evaluation, guard pipeline, and receipt signing built on these types.
