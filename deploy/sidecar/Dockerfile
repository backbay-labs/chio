# syntax=docker/dockerfile:1.7
#
# Chio sidecar image.
#
# Build:
#   docker build -f deploy/sidecar/Dockerfile -t ghcr.io/backbay-labs/chio-sidecar:latest .
#
# The sidecar exposes :9090 and responds to GET /chio/health. It is configured
# entirely via CLI flags (see the ENTRYPOINT/CMD notes below): the route and
# scope table come from the OpenAPI document passed with `--spec`, receipts are
# written to the durable store at `--receipt-store`, and the signing seed is read
# from the file at `--authority-seed-file`
# (see docs/protocols/CLOUD-SIDECAR-INTEGRATION.md). If the process cannot start
# serving the health endpoint it exits non-zero and the platform marks the
# container unhealthy (fail closed).

ARG RUST_VERSION=1.93
ARG DEBIAN_VERSION=bookworm

# -----------------------------------------------------------------------------
# Stage 1: build the chio-sidecar binary.
# -----------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder

ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=5 \
    RUSTFLAGS="-C strip=symbols"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        libssl-dev \
        pkg-config \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# `wit/` is consumed by chio-wasm-guards via
# `wasmtime::component::bindgen!(path = "../../wit/chio-guard.wit")`,
# which resolves at compile time. chio-cli enables the component backend,
# so the wit directory MUST be in the build context or `cargo build -p
# chio-cli --bin chio` fails with a missing-path error.
COPY wit ./wit
COPY examples ./examples
COPY formal ./formal
COPY tests ./tests

# The sidecar is the `chio` binary from chio-cli, run as `chio api protect`
# (reverse proxy) or `chio mcp serve-http` (MCP edge). If a dedicated
# chio-sidecar bin is introduced, replace the --bin arg accordingly.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p chio-cli --bin chio \
 && mkdir -p /out \
 && cp /build/target/release/chio /out/chio-sidecar

# -----------------------------------------------------------------------------
# Stage 2: healthcheck helper (distroless has no shell or curl).
# We bake a tiny statically linked HTTP probe in a throwaway stage. The
# install + relocate step packs curl plus all its shared-library deps into
# a single /out directory using the Debian multiarch dir derived from
# dpkg-architecture, so the runtime COPY below works unmodified on both
# linux/amd64 and linux/arm64 (where libs live at aarch64-linux-gnu
# instead of x86_64-linux-gnu).
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}-slim AS healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /out/bin /out/lib \
    && cp /usr/bin/curl /out/bin/curl \
    && ARCH_DIR="$(dpkg-architecture -qDEB_HOST_MULTIARCH)" \
    && for dep in libcurl.so.4 libnghttp2.so.14 libidn2.so.0 librtmp.so.1 \
                  libssh2.so.1 libpsl.so.5 libgssapi_krb5.so.2 \
                  libldap-2.5.so.0 liblber-2.5.so.0 libzstd.so.1 \
                  libbrotlidec.so.1 libbrotlicommon.so.1; do \
         src="/usr/lib/${ARCH_DIR}/${dep}"; \
         if [ -e "$src" ]; then \
           # `cp -L` dereferences the symlink and writes the actual
           # shared-library payload to the soname filename. Debian
           # `libcurl.so.4` and friends are symlinks to versioned
           # `.so.X.Y.Z` files; `cp -a` would preserve the symlink,
           # leaving a dangling reference in the distroless runtime
           # where the versioned target is absent. ld.so resolves
           # binaries by soname, so the dereferenced copy is enough.
           cp -L "$src" "/out/lib/${dep}"; \
         fi; \
       done

# -----------------------------------------------------------------------------
# Stage 3: runtime image. Distroless cc-debian12 nonroot (uid 65532).
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Metadata.
LABEL org.opencontainers.image.title="chio-sidecar" \
      org.opencontainers.image.description="Chio kernel sidecar for multi-container platforms" \
      org.opencontainers.image.source="https://github.com/backbay-labs/chio" \
      org.opencontainers.image.licenses="Apache-2.0"

# Runtime config default (overridable at deploy time). CHIO_LOG_LEVEL is
# consumed via ${VAR} interpolation when a config/policy file is loaded.
ENV CHIO_LOG_LEVEL=info

# Copy the binary and the healthcheck helper from earlier stages. The
# healthcheck stage has already arch-normalized curl + its shared libs
# into /out/{bin,lib}, so the runtime image no longer hardcodes the
# x86_64-linux-gnu multiarch path. distroless/cc-debian12 already has
# /usr/lib on the default ld.so search path, so dropping libs there
# resolves for both amd64 and arm64 builds.
COPY --from=builder /out/chio-sidecar /usr/local/bin/chio-sidecar
COPY --from=healthcheck /out/bin/curl /usr/bin/curl
COPY --from=healthcheck /out/lib/ /usr/lib/

# Nonroot (uid/gid 65532) is already the default user in distroless:nonroot;
# make it explicit so manifests that introspect the image know.
USER 65532:65532

EXPOSE 9090

# Container liveness: recycle only when the process itself is unreachable. A
# dependency blip must not recycle a serving container, so this uses the
# process-only /chio/live route; platform readiness gates on /chio/health.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/bin/curl", "-fsS", "http://localhost:9090/chio/live"]

ENTRYPOINT ["/usr/local/bin/chio-sidecar"]
# No zero-argument default is meaningful: every chio subcommand needs
# operator input (policy path, wrapped server command, etc.). Default to
# --help so `docker run <image>` prints usage; operators override this at
# deploy time with the real subcommand, e.g. `chio mcp serve-http --policy
# /etc/chio/policy.yaml --server-id my-tool -- npx
# @modelcontextprotocol/server-filesystem /data`.
CMD ["--help"]
