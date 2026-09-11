FROM rust:1.94.1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake pkg-config libssl-dev protobuf-compiler && rm -rf /var/lib/apt/lists/*
ENV CARGO_BUILD_JOBS=2
WORKDIR /source
COPY . .
RUN cargo build --locked --profile docker-release -p chio-envoy-ext-authz --features runtime --bin chio-envoy-ext-authz
FROM build AS authority-build
RUN cargo build --locked --profile docker-release -p chio-cli --bin chio
FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS authority
COPY --from=authority-build /source/target/docker-release/chio /usr/local/bin/chio
USER 65532:65532
EXPOSE 9097
ENTRYPOINT ["chio"]
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /source/target/docker-release/chio-envoy-ext-authz /usr/local/bin/chio-envoy-ext-authz
USER 65532:65532
EXPOSE 9091 9092
ENTRYPOINT ["chio-envoy-ext-authz"]
