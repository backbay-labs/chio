FROM rust:1.94.1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake pkg-config libssl-dev protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN cargo build --locked --release -p chio-envoy-ext-authz --features runtime --bin chio-envoy-ext-authz
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /source/target/release/chio-envoy-ext-authz /usr/local/bin/chio-envoy-ext-authz
USER 65532:65532
EXPOSE 9091 9092
ENTRYPOINT ["chio-envoy-ext-authz"]
