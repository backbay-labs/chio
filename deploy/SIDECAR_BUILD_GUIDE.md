# Chio Sidecar Build Guide

## Overview

`deploy/docker/Dockerfile.sidecar` produces a minimal runtime image for the `chio` sidecar
binary. The image is a two-stage build: stage 1 compiles a release `chio`
binary against the committed `Cargo.lock`, and stage 2 ships only that
binary plus `tini` and CA roots on top of a stripped Alpine base. The final
image runs as a non-root `chio:chio` user (uid/gid 10001) with
`CHIO_HOME=/var/lib/chio`.

## Build

Build the image from the repository root:

```bash
docker build -f deploy/docker/Dockerfile.sidecar -t chio-sidecar:local .
```

The builder stage installs `protoc` because `chio-envoy-ext-authz` (reachable
transitively through the workspace) invokes `tonic-build` at compile time.
CI installs `protobuf-compiler` for the same reason; keep the Docker image
consistent so any future dependency change that pulls
`chio-envoy-ext-authz` into `chio-cli`'s transitive graph does not silently
break the Docker build.

The build copies the full workspace so that path dependencies resolve. Keep
the `COPY` list in `deploy/docker/Dockerfile.sidecar` in sync with anything the Rust
build reaches at compile time:

- `wit/` is consumed by `chio-wasm-guards` via
  `wasmtime::component::bindgen!` (reached through the
  `chio-cli -> chio-wasm-guards` path dependency).
- `examples/`, `formal/`, and `tests/` are declared as workspace members,
  so their absence would break the workspace `Cargo.lock` resolution.
- `sdks/` holds non-workspace-member SDKs today (Python packages, TS
  packages, `chio-lambda-extension` with its own nested workspace), but
  the layout is structured so future Rust members under `sdks/...` can
  join the root workspace without silently breaking this image. Copying
  the tree keeps the Docker build consistent with
  `cargo build --workspace` when that happens.

The vendored Envoy protos consumed by `chio-envoy-ext-authz`'s
`tonic-build` live under `crates/protocol/chio-envoy-ext-authz/proto` (not a
top-level `proto/`), so the existing `COPY crates ./crates` line covers
them transparently. No separate top-level `COPY proto` is required.

`formal/` is copied so that `cargo build --workspace` `Cargo.lock`
resolution stays consistent with CI, but the Docker build itself only runs
`cargo build --package chio-cli --bin chio`. `chio-cli` does not depend on
any formal-methods crate, and the current `formal/` contents (diff-tests
plus lean4) have no Rust `build.rs` that invokes `lake`, so Lean and elan
do not need to be installed in this image. If a `formal/` member later
declares a `chio-cli` edge or a Rust build script that shells out to
`lake`, install elan alongside `protoc` in the builder `apk` step.

## Run

```bash
docker run --rm -p 8939:8939 chio-sidecar:local <subcommand> [args...]
```

There is no useful zero-argument default: the `chio` subcommands require
operator input (policy path, wrapped MCP server command, etc.). The image
therefore defaults `CMD` to `--help` so `docker run <image>` prints usage
instead of crashing at startup.

## Deployment

Production deployments MUST override `CMD` (or the compose / Kubernetes
`args`) with a real subcommand, for example:

```bash
chio mcp serve-http \
  --policy /etc/chio/policy.yaml \
  --server-id my-tool
```

Both `chio run` and `chio mcp serve-http` require `--policy` plus
additional positional input, so the image falls through to `--help` on a
bare invocation rather than exiting non-zero before the health endpoint
opens. Operators override `CMD` with the real subcommand and flags at
deploy time.
