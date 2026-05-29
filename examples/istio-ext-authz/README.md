# Istio ext_authz integration for Chio

Reference Kubernetes manifests and walkthrough for plugging the Chio
`chio-envoy-ext-authz` gRPC adapter into an Istio service mesh via
`MeshConfig.extensionProviders` and `AuthorizationPolicy` with the `CUSTOM`
action.

> **What this example proves.** An Istio mesh configured with the reference
> `AuthorizationPolicy` routes ext_authz checks to the Chio adapter.
> Responses passing the mesh carry an `x-chio-receipt-id` header that
> identifies the signed receipt the kernel produced.

## Contents

| File | Purpose |
|------|---------|
| `00-chio-sidecar-deployment.yaml` | `chio-system` namespace + `chio-sidecar` Deployment/Service/ConfigMap/Secret for the gRPC ext_authz adapter (port 9091) and health endpoint (port 9090). |
| `01-meshconfig-patch.yaml`       | `IstioOperator` overlay that registers Chio under `meshConfig.extensionProviders` as the `chio-ext-authz` provider. |
| `02-authorization-policy.yaml`   | Three `AuthorizationPolicy` objects: a `CUSTOM` policy routing matched traffic to Chio, a `DENY` backstop for unauthenticated requests, and an `ALLOW` policy for kubelet probes. |
| `03-demo-workload.yaml`          | `agent-tools` namespace with an opted-in go-httpbin deployment, Service, and VirtualService used to exercise the allow/deny flow. |
| `test-harness.sh`                | Bash harness that `kubectl port-forward`s the demo Service and asserts the allow response carries `x-chio-receipt-id` and the deny response is `403`. |
| `ci-validation.md`               | Static-validation recipes (`kubeconform`, `istioctl analyze`) suitable for CI. |

## Prerequisites

- **Istio 1.22+**. Earlier 1.20/1.21 releases support gRPC ext_authz but the
  typed-header forwarding used here stabilised in 1.22.
- **Kubernetes 1.28+**. Required for the `security.istio.io/v1` and
  `networking.istio.io/v1` GA API versions used by the policies below.
- `kubectl` that can reach the target cluster.
- `istioctl` 1.22+ (for the MeshConfig install/patch and `proxy-config`
  verification commands).
- `curl` and `awk` on the workstation running `test-harness.sh`.
- A dedicated Chio Envoy ext_authz adapter image pushed to a registry your
  cluster can pull. The reference manifest uses
  `ghcr.io/backbay-labs/chio-ext-authz:latest` as a placeholder. Replace it with
  the adapter image you built and published for your environment. Do not use
  the generic `ghcr.io/backbay-labs/chio-sidecar` image here; that image is the
  HTTP sidecar and does not expose Envoy's gRPC `Authorization/Check`
  service.
- A capability token issued by a Chio capability authority (or the demo
  token the kernel accepts in shadow mode). Export it as
  `CHIO_DEMO_CAPABILITY_TOKEN` before running `test-harness.sh`.

## Step-by-step walkthrough

### 1. Create the Chio namespace and deploy the sidecar

```bash
kubectl apply -f examples/istio-ext-authz/00-chio-sidecar-deployment.yaml
kubectl -n chio-system rollout status deploy/chio-sidecar --timeout=120s
kubectl -n chio-system get svc chio-sidecar
```

Expected Service output:

```
NAME          TYPE        CLUSTER-IP      PORT(S)             AGE
chio-sidecar   ClusterIP   10.96.42.7      9091/TCP,9090/TCP   20s
```

Smoke-test the adapter from inside the cluster before wiring Istio at it:

```bash
kubectl run chio-smoke --rm -it --restart=Never \
  --image=curlimages/curl:8.9.1 -- \
  curl -sS http://chio-sidecar.chio-system.svc.cluster.local:9090/health
```

A `200 OK` with body `{"status":"ok"}` confirms the sidecar is live.

### 2. Register Chio as an ext_authz provider in Istio

Pick the install path that matches how your mesh was provisioned.

**Fresh install (recommended for new clusters):**

```bash
istioctl install -y \
  -f examples/istio-ext-authz/01-meshconfig-patch.yaml
```

**Existing mesh managed via `IstioOperator`:**

```bash
kubectl -n istio-system apply \
  -f examples/istio-ext-authz/01-meshconfig-patch.yaml
kubectl -n istio-system rollout restart deploy/istiod
```

**Existing mesh managed via the `istio` ConfigMap:** merge the
`extensionProviders` entry from `01-meshconfig-patch.yaml` into
`data.mesh.extensionProviders` in the `istio` ConfigMap:

```bash
kubectl -n istio-system get cm istio -o yaml > /tmp/istio-cm.yaml
# edit /tmp/istio-cm.yaml: add the extensionProvider stanza under data.mesh
kubectl -n istio-system apply -f /tmp/istio-cm.yaml
kubectl -n istio-system rollout restart deploy/istiod
```

Verify the provider was picked up:

```bash
kubectl -n istio-system logs deploy/istiod | grep -i extensionprovider
istioctl proxy-config bootstrap -n istio-system deploy/istiod \
  | grep -A3 chio-ext-authz
```

### 3. Deploy the demo workload and AuthorizationPolicy

```bash
kubectl apply -f examples/istio-ext-authz/03-demo-workload.yaml
kubectl -n agent-tools rollout status deploy/demo-tool --timeout=120s
kubectl apply -f examples/istio-ext-authz/02-authorization-policy.yaml
kubectl -n agent-tools get authorizationpolicies
```

Expected:

```
NAME                         ACTION     AGE
chio-tool-authorization       CUSTOM     5s
chio-deny-unauthenticated     DENY       5s
chio-allow-health-probes      ALLOW      5s
```

Confirm Envoy picked up the provider reference for the demo pod:

```bash
POD="$(kubectl -n agent-tools get pod \
  -l app.kubernetes.io/name=demo-tool \
  -o jsonpath='{.items[0].metadata.name}')"
istioctl proxy-config listener -n agent-tools "${POD}" \
  --port 8080 -o json | grep chio-ext-authz
```

### 4. Verify allow/deny with the test harness

```bash
export CHIO_DEMO_CAPABILITY_TOKEN="$(cat ~/.chio/demo.token)"
./examples/istio-ext-authz/test-harness.sh
```

The harness:
1. Opens a `kubectl port-forward` to `svc/demo-tool:80`.
2. Sends `POST /tools/hello` with `x-chio-capability-token` and asserts
   HTTP 200 with an `x-chio-receipt-id` header.
3. Sends `POST /tools/hello` without credentials and asserts HTTP 403.

Expected tail output:

```
istio-ext-authz test-harness: PASS
  artifacts: .../examples/istio-ext-authz/.artifacts/20260416T...
  allow receipt id: 01k6b1...-....
  deny status:      403
```

### 5. Manual curl verification (optional)

```bash
kubectl -n agent-tools port-forward svc/demo-tool 18080:80 &

# Allow path: Chio evaluates and injects x-chio-receipt-id
curl -i -X POST \
  -H "x-chio-capability-token: ${CHIO_DEMO_CAPABILITY_TOKEN}" \
  --data '{"hello":"world"}' \
  http://127.0.0.1:18080/tools/hello

# Deny path: the DENY AuthorizationPolicy rejects before Chio
curl -i -X POST --data '{}' http://127.0.0.1:18080/tools/hello
```

Allow response headers include (order not significant):

```
HTTP/1.1 200 OK
x-chio-receipt-id: 01k6b1k3v...-0c7f
x-chio-policy-hash: sha256:...
x-chio-verdict: allow
```

Deny response:

```
HTTP/1.1 403 Forbidden
x-chio-denial-guard: IstioAuthorization
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| All requests 403 (including authenticated) | Chio pod not ready or MeshConfig not reloaded | `kubectl -n chio-system get pods`; `istioctl proxy-config bootstrap ... | grep chio-ext-authz` |
| Allowed requests missing `x-chio-receipt-id` | `includeRequestHeadersInCheck` omitted or ext_authz in HTTP mode | Re-apply `01-meshconfig-patch.yaml`; confirm `envoyExtAuthzGrpc` is used |
| `AuthorizationPolicy` rejected at apply | API version mismatch (v1beta1 vs v1) | Ensure the cluster runs Istio 1.22+ and `security.istio.io/v1` is served |
| Port-forward drops immediately | Pod not labelled `chio.world/secured=true` | `kubectl -n agent-tools get pod -l app.kubernetes.io/name=demo-tool --show-labels` |
| 503 from demo pod | Istio sidecar injection disabled on `agent-tools` | Re-label: `kubectl label ns agent-tools istio-injection=enabled --overwrite` |

## Teardown

```bash
kubectl delete -f examples/istio-ext-authz/02-authorization-policy.yaml
kubectl delete -f examples/istio-ext-authz/03-demo-workload.yaml
kubectl delete -f examples/istio-ext-authz/00-chio-sidecar-deployment.yaml
# Optional: remove the extension provider from MeshConfig by editing the
# `istio` ConfigMap (or reinstall without 01-meshconfig-patch.yaml).
```

## See also

- `docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md` section 6 -- architectural
  rationale for the Istio layering.
- `crates/chio-envoy-ext-authz/` -- Envoy ext_authz gRPC adapter source.
- `deploy/cloud-run`, `deploy/ecs`, `deploy/azure` -- managed multi-container
  sidecar deploy targets.
- `examples/istio-ext-authz/ci-validation.md` -- how to validate these
  manifests in CI without a live cluster.
