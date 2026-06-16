# chio-proof-room

`chio-proof-room` is the focused Proof Room server used by the Docker
quickstart and standalone verifier surface. It verifies a Proof Room bundle
before serving the dashboard, bundle report, fixture catalog, and allow-listed
bundle assets.

Use this crate when you need the dedicated `chio-proof-room` binary without
building the full `chio` CLI image.

```bash
cargo run -p chio-proof-room --bin chio-proof-room -- \
  --bundle fixtures/proof-room/first-run/single-call-authority/proof-room-bundle \
  --ui-dir crates/products/chio-cli/dashboard/dist
```

## Verification

```bash
cargo test -p chio-proof-room
```
