# Proof Room Quickstart

This quickstart uses the checked-in first-run fixture. It does not claim any
public availability state: public release, package publication, hosted demo,
chain transaction, or Rekor entry. Those remain governed by
`fixtures/proof-room/first-run/single-call-authority/release-truth.json`.

## Source Checkout

From the repository root:

```bash
source scripts/proof-room-quickstart-env.sh
cargo run -p chio-cli -- proof doctor --scenario single-call-authority --root . --json
cargo run -p chio-cli -- proof serve fixtures/proof-room/first-run/single-call-authority/proof-room-bundle --listen 127.0.0.1:7391
cargo run -p chio-proof-room -- \
  --bundle fixtures/proof-room/first-run/single-call-authority/proof-room-bundle \
  --verify-only \
  --doctor-report /tmp/chio-proof-room-doctor.json
```

Open `http://127.0.0.1:7391/?view=proof-room`. The page reads
`manifest.json` and `ui/proof-room-static/load-report.json`; the displayed
verdict comes from the verifier report bound by the bundle manifest.
The `chio-proof-room --verify-only` command checks the same bundle without
starting the server, which is useful for container health checks and release
qualification.

## Docker Quickstart

The Docker target packages the focused `chio-proof-room` server, dashboard
assets, and proof fixture without building the full `chio-cli` binary:

```bash
docker build -f deploy/docker/Dockerfile --target chio-proof-room-quickstart -t chio-proof-room:local .
docker run --rm -p 127.0.0.1:7391:7391 chio-proof-room:local
```

The container runs `/usr/local/bin/chio-proof-room`, verifies the Proof Room
bundle before serving, and writes a quickstart doctor report to
`/opt/chio/proof-doctor-report.json`. In this checkout the release-truth
fixture marks Docker quickstart evidence captured by the local runtime smoke
artifact bound into the Proof Room bundle.

## Release Truth

Run the supporting gates:

```bash
scripts/check-proof-room-source-quickstart.sh
scripts/check-chio-proof-room-release-truth.sh
scripts/check-chio-proof-room-docker-quickstart.sh
```

If Docker is installed but the daemon is unavailable, the Docker quickstart
gate reports that runtime smoke evidence was skipped. Set
`CHIO_REQUIRE_DOCKER_DAEMON=1` in release qualification to make that condition
fail closed.
