# syntax=docker/dockerfile:1.7
# Chio CLI image. Builds the `chio` binary plus the optional trust/MCP demo
# stages. Base images are digest-pinned to match Dockerfile.sidecar /
# Dockerfile.tee; bump the digests in lockstep with those files.

ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.22
ARG NODE_VERSION=22

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION}@sha256:3c06253e433c1b2ac2c279a98226d385d25c5f324138ab2861a5414bfa6855f9 AS rust-builder
RUN apk add --no-cache build-base cmake perl pkgconf
WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY examples ./examples
COPY formal/diff-tests ./formal/diff-tests
COPY tests/e2e ./tests/e2e

RUN cargo build --release --locked -p chio-cli --bin chio

FROM node:${NODE_VERSION}-alpine@sha256:968df39aedcea65eeb078fb336ed7191baf48f972b4479711397108be0966920 AS dashboard-builder
WORKDIR /workspace/crates/chio-cli/dashboard

COPY crates/chio-cli/dashboard/package.json ./
COPY crates/chio-cli/dashboard/package-lock.json ./
RUN npm ci --no-fund --no-audit

COPY crates/chio-cli/dashboard/index.html ./
COPY crates/chio-cli/dashboard/tsconfig.json ./
COPY crates/chio-cli/dashboard/tsconfig.app.json ./
COPY crates/chio-cli/dashboard/vite.config.ts ./
COPY crates/chio-cli/dashboard/src ./src

RUN npm run build

FROM alpine:${ALPINE_VERSION}@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS chio
# `tini` is PID 1 so the kernel reaps zombies and forwards signals; the demo
# stages below run their real command via `exec` so signals reach it directly.
# A dedicated non-root `chio` user (UID/GID 10001, matching the sidecar/TEE
# images) owns the runtime state directories so nothing runs as root.
RUN apk add --no-cache ca-certificates libgcc libstdc++ tini \
 && addgroup -S -g 10001 chio \
 && adduser  -S -u 10001 -G chio -h /home/chio -s /sbin/nologin chio \
 && mkdir -p /var/lib/chio /opt/chio \
 && chown -R chio:chio /var/lib/chio /opt/chio /home/chio
COPY --from=rust-builder /workspace/target/release/chio /usr/local/bin/chio
RUN chmod 0755 /usr/local/bin/chio

LABEL org.opencontainers.image.title="chio" \
      org.opencontainers.image.description="Chio capability kernel CLI" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/backbay-labs/chio"

USER chio:chio
ENTRYPOINT ["/sbin/tini", "--", "chio"]
CMD ["--help"]

FROM chio AS chio-trust-demo
WORKDIR /opt/chio
COPY --from=dashboard-builder --chown=chio:chio /workspace/crates/chio-cli/dashboard/dist ./dashboard/dist
EXPOSE 8940
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /sbin/tini -- /usr/local/bin/chio --receipt-db /var/lib/chio/receipts.sqlite --revocation-db /var/lib/chio/revocations.sqlite --authority-db /var/lib/chio/authority.sqlite --budget-db /var/lib/chio/budgets.sqlite trust serve --listen 0.0.0.0:8940 --service-token \"${CHIO_SERVICE_TOKEN:-demo-token}\""]

FROM chio AS chio-mcp-demo
USER root
RUN apk add --no-cache python3
WORKDIR /opt/chio
COPY --chown=chio:chio examples/docker/mock_mcp_server.py ./examples/mock_mcp_server.py
COPY --chown=chio:chio examples/docker/policy.yaml ./examples/policy.yaml
USER chio:chio
EXPOSE 8931
ENTRYPOINT []
CMD ["/bin/sh", "-lc", "exec /sbin/tini -- /usr/local/bin/chio --control-url \"${CHIO_CONTROL_URL:-http://chio-trust-demo:8940}\" --control-token \"${CHIO_CONTROL_TOKEN:-demo-token}\" mcp serve-http --policy /opt/chio/examples/policy.yaml --server-id wrapped-http-mock --server-name \"Wrapped HTTP Mock\" --listen 0.0.0.0:8931 --auth-token \"${CHIO_AUTH_TOKEN:-demo-token}\" -- python3 /opt/chio/examples/mock_mcp_server.py"]
