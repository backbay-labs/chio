# chio-k8s-controller

A Kubernetes controller that extends the Chio protocol to batch `Job` workloads. Jobs carrying the
`chio.world/governed: "true"` label get a capability grant minted at
creation, per-pod receipts aggregated across the Job's lifecycle, and the
grant released at completion or failure alongside a signed `JobReceipt`.

## Design

The controller uses `sigs.k8s.io/controller-runtime` with cache-backed
clients; it does not open raw watches via `client-go`. The single reconciler
(`internal/reconciler.JobReconciler`) handles four lifecycle points:

1. **New governed Job.** The controller adds the finalizer
   `chio.world/capability-finalizer`, calls the sidecar's
   `POST /v1/capabilities/mint`, and persists the grant on the Job as
   annotations (`chio.world/capability-id`,
   `chio.world/capability-token`,
   `chio.world/capability-expires-at`).
2. **Running Job.** Pods owned by the Job are watched (`Owns(&corev1.Pod{})`).
   Each reconciliation caused by a Pod update re-enters the Job reconciler,
   which harvests any `chio.world/receipt` annotations the sidecar posted
   onto the Pod.
3. **Completed / failed Job.** The reconciler calls
   `POST /v1/capabilities/release`, aggregates the harvested pod receipts
   into a `JobReceipt`, and posts it to `POST /v1/receipts`. It then removes
   its finalizer.
4. **Job deletion.** If a user deletes a governed Job before it terminates,
   the finalizer ensures the reconciler gets a last chance to release the
   grant before the Job object is garbage-collected.

### Fail-closed behavior

If the Chio sidecar is unreachable at mint time (HTTP transport error or
5xx), the reconciler **records a warning event and requeues** with
exponential backoff. It does **not** persist an empty / placeholder
capability, so Pods created by the Job remain ungoverned and will be
rejected by the Chio admission webhook. Receipt submission uses a bounded
exponential backoff (`DefaultRetryPolicy`: base 2s, cap 2m, max 8 attempts);
once attempts are exhausted the reconciler surfaces `ChioReceiptDropped`
and allows the finalizer to be removed so that the Job is not wedged
forever.

### Idempotency

Every mutation is gated on the presence (or absence) of an annotation the
reconciler itself sets. A capability is minted only when
`chio.world/capability-id` is empty. Release is gated on
`chio.world/released-at`. Receipt submission is gated on
`chio.world/receipt-id`. Running `Reconcile` repeatedly on a stable Job
converges without additional sidecar calls.

## Configuration

| Flag                         | Default                                                   | Description                         |
|------------------------------|-----------------------------------------------------------|-------------------------------------|
| `--metrics-bind-address`     | `:8080`                                                   | Controller-runtime metrics.         |
| `--health-probe-bind-address`| `:8081`                                                   | Liveness / readiness probe server.  |
| `--leader-elect`             | `false`                                                   | Enable leader election.             |
| `--leader-election-namespace`| `chio-system`                                              | Namespace for the leader lease.     |
| `--chio-sidecar-url`          | `http://chio-sidecar.chio-system.svc.cluster.local:9090`    | Chio sidecar base URL.               |
| `--chio-sidecar-control-token`| `""`                                                     | Bearer token for remote sidecar control APIs; required for non-loopback sidecars. |
| `--chio-request-timeout`      | `10s`                                                     | HTTP timeout for sidecar calls.     |
| `--max-concurrent-reconciles`| `4`                                                       | Parallelism.                        |

The sidecar URL can also be provided via the `CHIO_SIDECAR_URL` environment
variable. The control token can be provided via
`CHIO_SIDECAR_CONTROL_TOKEN`.

If `CHIO_SIDECAR_URL` points at a non-loopback sidecar service, configure the
same `CHIO_SIDECAR_CONTROL_TOKEN` on both the controller and the sidecar. The
shipped `config/manager/manager.yaml` requires that token via the
`chio-sidecar-control` Secret.

## Installation

```bash
make docker-build IMG=ghcr.io/backbay-labs/chio-k8s-controller:dev
kind load docker-image ghcr.io/backbay-labs/chio-k8s-controller:dev   # or push to a registry
make deploy
```

The manifests under `config/` create the `chio-system` namespace, a
`ServiceAccount`, a `ClusterRole` + `ClusterRoleBinding`, and the
`Deployment`. Override the image via the `IMG` env var when running
`make docker-build` / the corresponding image edit in
`config/manager/manager.yaml` before deploying.

## End-to-end demo

With the controller running and a Chio sidecar reachable at the configured
URL:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: chio-demo
  namespace: default
  labels:
    chio.world/governed: "true"
  annotations:
    chio.world/scopes: "tools:search,tools:fetch"
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: worker
          image: ghcr.io/backbay-labs/chio-demo-job:latest
```

Apply it with `kubectl apply -f demo.yaml`. Watch the annotations land:

```bash
kubectl get job chio-demo -o jsonpath='{.metadata.annotations}' | jq
kubectl get events --field-selector involvedObject.name=chio-demo
```

On completion the events will show `ChioCapabilityMinted`,
`ChioCapabilityReleased`, and `ChioReceiptSubmitted`. The `chio.world/receipt-id`
annotation carries the ID assigned by the Chio receipt store.

## Development

```bash
make build       # go build ./...
make test        # go test ./... -race -count=1
make lint        # golangci-lint (or go vet + gofmt -l)
make docker-build
```

The test suite uses `sigs.k8s.io/controller-runtime/pkg/client/fake` plus a
stub `ChioClient` so unit tests run without a live cluster or sidecar. One
test additionally drives the real Chio client against an `httptest.Server`
to cover the HTTP wire format.

## File map

```
cmd/chio-controller/main.go           entrypoint
internal/chio/{client,types}.go       sidecar HTTP client + data types
internal/reconciler/job_reconciler.go core reconcile loop
internal/reconciler/job_reconciler_test.go tests
config/rbac/role.yaml                ClusterRole + ClusterRoleBinding
config/manager/manager.yaml          Namespace, ServiceAccount, Deployment
Dockerfile                           multi-stage, distroless, non-root
Makefile                             build / test / lint / deploy targets
```
