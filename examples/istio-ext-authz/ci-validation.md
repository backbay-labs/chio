# Validation

`cargo test -p chio-envoy-ext-authz --features runtime` covers protocol translation, independent Envoy v3 wire bytes, real loopback HTTP authority calls, trusted request-bound receipts, refusal associations, malformed/oversized replies, replay, wrong signer, changed body, advisory results, redirects, timeouts and unavailable authorities.

`cargo clippy -p chio-envoy-ext-authz --features runtime --all-targets -- -D warnings` checks the executable and test targets.

`local/run.py --check` uses the actual Envoy executable, Chio authority, adapter and persisted notes API. It checks the real saved effect, revocation and authority outage. Its captured HTTP receipt IDs describe admission decisions, not independent evidence of handler completion.

Kubernetes configuration is generated from explicit operator values. The gRPC provider configuration follows Istio's published MeshConfig schema. A successful local proxy check does not establish a successful deployment to an arbitrary Istio cluster.
