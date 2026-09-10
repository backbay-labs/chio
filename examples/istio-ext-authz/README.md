# Govern an API through Envoy

Run a notes API behind Envoy, with Chio deciding whether each request may reach the handler. A signed grant permits a write. Revoking it refuses the next write, and an unavailable authority stops dispatch. The proxy returns the exact admission receipt ID on both allowed and denied responses.

## Run the complete local application

Use Rust 1.94.1, Python 3, and Envoy 1.39.1. From the Chio source root:

```sh
cargo build --locked --release -p chio-cli --bin chio
cargo build --locked --release -p chio-envoy-ext-authz --features runtime
export PATH="$PWD/target/release:$PATH"
python3 examples/istio-ext-authz/local/run.py
```

Envoy must be installed as `envoy` on PATH. `local/install-envoy.py` downloads the checksum-pinned Linux x86_64 executable used by CI; other platforms can use Envoy's container or their supported Envoy installation. `CHIO_BIN`, `CHIO_EXT_AUTHZ_BIN` and `ENVOY_BIN` optionally select existing executables.

The launcher starts all four processes, issues a five-minute local grant, and keeps the API running at `http://127.0.0.1:10000/notes`. Configuration is in `local/envoy.yaml` and `local/openapi.yaml`. Notes, the authority seed, selected verifier key and receipts persist under `local/.state/`. The signed grant is retained in `local/.state/capability.json` with private file permissions. Ctrl-C stops only this launcher's processes.

To run the complete check instead, while the application is stopped:

```sh
python3 examples/istio-ext-authz/local/run.py --check
```

This saves one note, refuses an ungranted write, revokes the issued grant, refuses another write using the same grant, and stops the authority to check that an outage causes no additional effect. It preserves your existing notes and writes `local/.state/verification.json`.

## The running adapter

The executable implements Envoy's v3 gRPC `Authorization/Check` service and an HTTP health server. It requires an explicit Chio HTTP authority origin and an independently selected kernel public key:

```sh
chio-envoy-ext-authz \
  --authority-url http://127.0.0.1:9097 \
  --trusted-kernel-key-file trusted-kernel-key.txt
```

The default listeners are loopback ports 9091 (gRPC) and 9092 (health). `/healthz` reports process liveness; `/readyz` checks authority connectivity. `--listen`, `--health-listen` and `--timeout-ms` configure deployment values. The authority must support `/chio/evaluate` and return a signed Chio HTTP receipt.

For each request the bridge chooses a fresh request ID, binds the complete buffered body, path, query, method and session, and verifies the returned receipt's signer, signature, content-addressed ID, request binding and mediated authorization semantics. Replayed, malformed, oversized, advisory, untrusted and mismatched responses fail closed. Authority redirects are disabled. Repeated query keys and incomplete request bodies are refused rather than silently normalized into a different request.

`X-Chio-Capability` carries the complete signed grant to the configured authority. It is removed before upstream dispatch. `Authorization` and mTLS principal metadata are not promoted into verified Chio caller identities by this bridge. Configure the authority's actual authentication/grants for your workload. A receipt records admission; read the notes API or your own application records to establish the resulting effect.

## Build the container

The supplied Dockerfile builds the executable; no custom authorization service is left to implement.

```sh
docker build -f examples/istio-ext-authz/Dockerfile -t chio-ext-authz:local .
```

The image runs as UID/GID 65532 and exposes 9091 and 9092. Configure its arguments exactly as for the executable. Mount the selected public key read-only. Only the authority holds signing material.

## Connect an Istio workload

Use `deployment.json` to select your built image by digest, the authority origin reachable from the adapter, and the public key selected by the authority operator. Generate the concrete Kubernetes resources:

```sh
python3 examples/istio-ext-authz/deploy.py deployment.json > chio-ext-authz.json
kubectl apply -f chio-ext-authz.json
```

`deploy.py --help` describes the required JSON fields. Empty values are rejected. This creates the namespace, key ConfigMap, adapter Deployment, and Service. `00-chio-sidecar-deployment.yaml` documents the resource contract used by the generator. No demo signing secret or unimplemented image is installed.

Merge the provider from `01-meshconfig-patch.yaml` into your existing Istio installation configuration, preserving other extension providers. Apply `02-authorization-policy.yaml` to workloads labeled `chio.world/secured=true` in `agent-tools`. All their HTTP paths except `/healthz` pass through Chio, including requests with missing credentials. The protected service's OpenAPI policy determines which operations require authority.

The gRPC provider buffers at most 65,536 bytes, rejects partial bodies and disables fail-open and route-cache clearing. Keep the bridge and authority reachable only by trusted infrastructure; the local authority's mint/revoke API is an operator interface. The local Envoy application qualifies the data path independently of Kubernetes. Deployment qualification must also exercise your chosen Istio version, workload routes, networking and image.

See Istio's [gRPC provider contract](https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/#MeshConfig-ExtensionProvider-EnvoyExternalAuthorizationGrpcProvider) and [external authorization setup](https://istio.io/latest/docs/tasks/security/authorization/authz-custom/).
