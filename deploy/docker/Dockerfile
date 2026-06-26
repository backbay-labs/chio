# syntax=docker/dockerfile:1.7
# Chio CLI image. Builds the `chio` binary plus the optional trust/MCP demo
# stages. Base images are digest-pinned to match Dockerfile.sidecar /
# Dockerfile.tee; bump the digests in lockstep with those files.

ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.22
ARG NODE_VERSION=22

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION}@sha256:3c06253e433c1b2ac2c279a98226d385d25c5f324138ab2861a5414bfa6855f9 AS rust-builder
RUN apk add --no-cache build-base cmake openssl-dev pkgconf
WORKDIR /workspace

COPY deploy/docker/chio-workspace/Cargo.toml ./Cargo.toml
COPY deploy/docker/chio-workspace/Cargo.lock ./Cargo.lock
COPY .cargo ./.cargo
COPY crates ./crates
COPY examples/chio-3vendor/fixtures/runtime-spine/scenario.json ./examples/chio-3vendor/fixtures/runtime-spine/scenario.json
COPY fixtures/proof-room ./fixtures/proof-room
COPY spec ./spec
COPY wit ./wit

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo metadata --format-version 1 --locked >/dev/null \
 && cargo build --profile docker-release --locked -p chio-cli --bin chio \
 && cp target/docker-release/chio /chio

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION}@sha256:3c06253e433c1b2ac2c279a98226d385d25c5f324138ab2861a5414bfa6855f9 AS proof-room-builder
WORKDIR /workspace

COPY deploy/docker/proof-room-workspace/Cargo.toml ./Cargo.toml
COPY deploy/docker/proof-room-workspace/Cargo.lock ./Cargo.lock
COPY crates/core/chio-core-types ./crates/core/chio-core-types
COPY crates/economy/chio-appraisal ./crates/economy/chio-appraisal
COPY crates/economy/chio-credit ./crates/economy/chio-credit
COPY crates/economy/chio-underwriting ./crates/economy/chio-underwriting
COPY crates/economy/chio-web3 ./crates/economy/chio-web3
COPY crates/kernel/chio-runtime-proof-parity ./crates/kernel/chio-runtime-proof-parity
COPY crates/kernel/chio-swarm-authority ./crates/kernel/chio-swarm-authority
COPY crates/platform/chio-agent-web-interop ./crates/platform/chio-agent-web-interop
COPY crates/platform/chio-commerce-order ./crates/platform/chio-commerce-order
COPY crates/platform/chio-enterprise-export ./crates/platform/chio-enterprise-export
COPY crates/platform/chio-risk-comptroller ./crates/platform/chio-risk-comptroller
COPY crates/platform/chio-transaction-passport ./crates/platform/chio-transaction-passport
COPY crates/platform/chio-trust-market-context ./crates/platform/chio-trust-market-context
COPY crates/platform/chio-workflow-preflight ./crates/platform/chio-workflow-preflight
COPY crates/trust/chio-disclosure-lineage ./crates/trust/chio-disclosure-lineage
COPY crates/tooling/chio-spec-codegen ./crates/tooling/chio-spec-codegen
COPY crates/tooling/chio-test-support ./crates/tooling/chio-test-support
COPY crates/products/proof_fixture_build.rs ./crates/products/proof_fixture_build.rs
COPY crates/products/chio-proof-room ./crates/products/chio-proof-room
COPY spec/schemas/chio-proof-room ./spec/schemas/chio-proof-room
COPY spec/schemas/chio-runtime ./spec/schemas/chio-runtime
COPY spec/schemas/chio-transaction ./spec/schemas/chio-transaction
COPY fixtures/proof-room/catalog.json ./fixtures/proof-room/catalog.json
COPY fixtures/proof-room/first-run/single-call-authority ./fixtures/proof-room/first-run/single-call-authority

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo metadata --format-version 1 --locked >/dev/null \
 && cargo build --release --locked -p chio-proof-room --bin chio-proof-room \
 && cp target/release/chio-proof-room /chio-proof-room

FROM node:${NODE_VERSION}-alpine@sha256:968df39aedcea65eeb078fb336ed7191baf48f972b4479711397108be0966920 AS dashboard-builder
WORKDIR /workspace/crates/products/chio-cli/dashboard

COPY crates/products/chio-cli/dashboard/package.json ./
COPY crates/products/chio-cli/dashboard/package-lock.json ./
RUN npm ci --no-fund --no-audit

COPY crates/products/chio-cli/dashboard/index.html ./
COPY crates/products/chio-cli/dashboard/tsconfig.json ./
COPY crates/products/chio-cli/dashboard/tsconfig.app.json ./
COPY crates/products/chio-cli/dashboard/vite.config.ts ./
COPY crates/products/chio-cli/dashboard/src ./src

RUN npm run build

FROM alpine:${ALPINE_VERSION}@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS chio
# `tini` is PID 1 so the kernel reaps zombies and forwards signals; the demo
# stages below run their real command via `exec` so signals reach it directly.
# A dedicated non-root `chio` user (UID/GID 10001, matching the sidecar/TEE
# images) owns the runtime state directories so nothing runs as root.
RUN apk add --no-cache ca-certificates libgcc libstdc++ libssl3 libcrypto3 tini \
 && addgroup -S -g 10001 chio \
 && adduser  -S -u 10001 -G chio -h /home/chio -s /sbin/nologin chio \
 && mkdir -p /var/lib/chio /opt/chio \
 && chown -R chio:chio /var/lib/chio /opt/chio /home/chio
COPY --from=rust-builder /chio /usr/local/bin/chio
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
COPY --from=dashboard-builder --chown=chio:chio /workspace/crates/products/chio-cli/dashboard/dist ./dashboard/dist
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

FROM alpine:${ALPINE_VERSION}@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS chio-proof-room-quickstart
WORKDIR /opt/chio
RUN apk add --no-cache ca-certificates tini \
 && addgroup -S -g 10001 chio \
 && adduser  -S -u 10001 -G chio -h /home/chio -s /sbin/nologin chio \
 && mkdir -p /opt/chio /home/chio \
 && chown -R chio:chio /opt/chio /home/chio
COPY --from=proof-room-builder /chio-proof-room /usr/local/bin/chio-proof-room
RUN chmod 0755 /usr/local/bin/chio-proof-room
COPY --from=dashboard-builder --chown=chio:chio /workspace/crates/products/chio-cli/dashboard/dist ./dashboard/dist
COPY --chown=chio:chio fixtures/proof-room ./fixtures/proof-room
ENV CHIO_PROOF_ROOM_UI_DIR=/opt/chio/dashboard/dist
ENV CHIO_PROOF_FIXTURE_ROOT=/opt/chio/fixtures/proof-room
ENV CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS=31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa
ENV CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a
ENV CHIO_TRANSACTION_TRUSTED_ROOT_KEYS=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96
ENV CHIO_SWARM_TRUSTED_WITNESS_KEYS=43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de
ENV CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS=e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa
ENV CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS=e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa
EXPOSE 7391
USER chio:chio
ENTRYPOINT []
CMD ["/sbin/tini", "--", "/usr/local/bin/chio-proof-room", "--bundle", "/opt/chio/fixtures/proof-room/first-run/single-call-authority/proof-room-bundle", "--ui-dir", "/opt/chio/dashboard/dist", "--fixture-root", "/opt/chio/fixtures/proof-room", "--listen", "0.0.0.0:7391", "--doctor-report", "/opt/chio/proof-doctor-report.json"]
