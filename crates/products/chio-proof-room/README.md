# chio-proof-room

`chio-proof-room` is the standalone HTTP server and CLI behind the Chio
Docker quickstart: it verifies a Proof Room bundle (or a bare
transaction-passport fixture) by recomputing verifier reports from source
artifacts, then serves the verified dashboard, bundle assets, and fixture
catalog. Its verification and fixture machinery is `pub(crate)`; the public
surface is a handful of standalone-verification functions plus the axum
router/server constructors.

## Responsibilities

- Verify a Proof Room bundle manifest (`chio.proof-room.bundle.v1`) against
  `spec/schemas/chio-proof-room/v1/`: DSSE signature, claim-to-artifact
  binding, receipt-coverage matrix, and negative-case replay.
- Recompute the transaction passport's verifier report from source artifacts,
  routing evidence-graph subsets to the domain verifier crate(s) a policy's
  `required_claims` demand, rather than trusting the bundle's claimed report.
- Serve the verified bundle, a static dashboard UI, and a fixture catalog
  over HTTP, restricted to an allow-list computed from the manifest.
- Accept uploaded bundles at `/proof-room/upload/verify` and report the
  verification verdict.
- Ship the `chio-proof-room` binary used by the Docker quickstart image.

## Public API

Bundle verification (crate root):

- `verify_proof_room_bundle(manifest_path: &Path) -> Result<(), ProofRoomError>`
- `verify_proof_room_quickstart(bundle: &Path, doctor_report: Option<&Path>) -> Result<(), ProofRoomError>`
- `build_proof_room_source_verifier_report(bundle_root: &Path, transaction_passport_path: &Path) -> Result<serde_json::Value, String>`
- `validate_proof_room_bundle_relative_path(relative_path: &str) -> Result<(), String>`
- `ProofRoomError` - `Validation`, `Io`, `Json`, `ListenAddress`, `Serve`.

Serving (`server`, re-exported at the crate root):

- `serve_proof_room(config: ProofRoomServeConfig) -> Result<(), ProofRoomError>` - verify, then bind and serve.
- `proof_room_router`, `proof_room_router_with_fixture_root`, `proof_room_router_with_optional_ui_root` - construct the axum `Router` directly.
- `build_proof_room_fixture_catalog_json(_with_fixture_root)`, `proof_room_fixture_asset_response`, `proof_room_served_bundle_paths`, `resolve_proof_room_served_asset_path`, `proof_room_content_type`, `is_proof_room_bundle_namespace`, `parse_listen_addr`.

BBS crypto-context recomputation (`crypto_context`):

- `crypto_context_verified_report_bytes_with_bbs`, `crypto_context_rejected_report_bytes_with_bbs`.

Binary `chio-proof-room` (`src/main.rs`):

```
chio-proof-room --bundle <dir> --ui-dir <dir> [--fixture-root <dir>] [--listen <addr>] [--doctor-report <path>] [--verify-only]
```

## Usage

```bash
cargo run -p chio-proof-room -- \
  --bundle fixtures/proof-room/first-run/single-call-authority/proof-room-bundle \
  --verify-only \
  --doctor-report /tmp/chio-proof-room-doctor.json
```

## Testing

Unit tests live in `src/tests/` (`catalog`, `core`, `source`, `support`); the
integration test in `tests/cli.rs` spawns the built `chio-proof-room` binary
against the checked-in fixture bundle.

```bash
cargo test -p chio-proof-room
```

## See also

- `chio-transaction-passport` - root passport, evidence-graph, and
  runtime-security verification this crate recomputes reports from.
- `chio-swarm-authority` - `verify_swarm_authority_bundle`, called on this
  crate's public proof-verification path.
- `chio-runtime-proof-parity` - both validators
  (`validate_runtime_proof_parity_report`,
  `validate_runtime_proof_regeneration_artifacts`) are called here against a
  runtime evidence graph.
- `chio-cli` - the full Chio CLI; has a broader `proof` command surface built
  on the same dashboard.
- `chio-http-serve` - server hygiene (connection caps, graceful drain)
  wrapped around this crate's axum router.
