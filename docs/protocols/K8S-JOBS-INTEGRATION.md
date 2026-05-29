# Kubernetes Jobs/CronJobs Integration: Job-Level Capability Grants

> **Status**: Tier 3 -- proposed April 2026
> **Priority**: Exploratory -- extends the existing K8s integration (CRD +
> admission webhooks) from pod-level admission to job-level capability
> lifecycle. Jobs and CronJobs get time-bounded, scope-limited capability
> grants that expire when the job completes.

## 1. Why Extend the K8s Integration

Chio already ships K8s primitives:

- `ChioPolicy` CRD -- declares capability scopes and selectors
- Validating webhook -- rejects pods that violate policy
- Mutating webhook -- injects Chio sidecar into annotated pods

These work at pod admission time. But Kubernetes Jobs and CronJobs have a
lifecycle that maps more naturally to Chio's capability model:

- A **Job** has a defined start and end. Its capability grant should be
  time-bounded to the job's lifetime.
- A **CronJob** runs on a schedule. Each spawned Job should acquire its
  own grant, not inherit a standing one.
- A **Job with parallelism** spawns multiple pods. All pods in the Job
  share the same grant but each gets its own receipt chain.

### What This Adds Beyond Pod Admission

| Existing (pod-level) | Extended (job-level) |
|----------------------|----------------------|
| Sidecar injected at pod creation | Grant acquired at Job creation, released at completion |
| Policy checked once at admission | Policy evaluated per-pod and per-Job-lifecycle |
| No coordination across Job pods | Shared grant token across all pods in a Job |
| No CronJob awareness | Per-schedule capability evaluation |
| Manual receipt collection | Job completion triggers receipt aggregation |

## 2. Architecture

### 2.1 Job Controller

A custom Kubernetes controller watches Job resources and manages Chio
capability lifecycle:

```
K8s API Server
     |
     v
+------------------------------------+
| Chio Job Controller                 |
|                                    |
| Watch: Jobs, CronJobs              |
| On Job create:                     |
|   1. Evaluate Job against policy   |
|   2. Acquire capability grant      |
|   3. Inject grant token as Secret  |
|   4. Mutate pod template with      |
|      sidecar + grant reference     |
|                                    |
| On Job complete/fail:              |
|   1. Aggregate receipts from pods  |
|   2. Release capability grant      |
|   3. Write WorkflowReceipt         |
|   4. Update Job annotations        |
+------------------------------------+
     |
     v
Chio Kernel (cluster-scoped or per-namespace)
```

### 2.2 Grant Lifecycle

```
CronJob (schedule: "0 */6 * * *")
  |
  +---> Job (run 1, 06:00)
  |       |
  |       +-- Grant acquired (scope: "tools:etl", ttl: 2h)
  |       +-- Pod 1: sidecar evaluates each tool call against grant
  |       +-- Pod 2: sidecar evaluates each tool call against grant
  |       +-- Job completes -> grant released, receipts aggregated
  |
  +---> Job (run 2, 12:00)
  |       |
  |       +-- New grant acquired (re-evaluated -- policy may have changed)
  |       +-- ...
```

## 3. Custom Resource: `ChioJobGrant`

Extends the existing `ChioPolicy` CRD with job-specific fields:

```yaml
apiVersion: chio.world/v1alpha1
kind: ChioJobGrant
metadata:
  name: etl-pipeline-grant
  namespace: data-team
spec:
  # Selector: which Jobs this grant applies to
  jobSelector:
    matchLabels:
      app: etl-pipeline
      chio.world/governed: "true"

  # Capability scope for the Job
  capability:
    scopes:
      - "tools:database:read"
      - "tools:database:write"
      - "tools:s3:read"
    guards:
      - "data-residency"
      - "pii-filter"
    budget:
      maxCalls: 10000
      maxCostUSD: "50.00"

  # TTL: grant expires after this duration, regardless of Job state
  ttl: 4h

  # Parallelism: how grants distribute across Job pods
  parallelism:
    mode: shared    # shared | per-pod
    # shared: all pods use the same grant token, shared budget
    # per-pod: each pod gets its own grant, own budget slice

  # Receipt aggregation
  receipts:
    aggregate: true
    sink: chio-receipts    # ConfigMap/Secret name for receipt storage
    sinkType: s3          # s3 | configmap | external

  # CronJob-specific
  cronPolicy:
    evaluatePerRun: true  # Re-evaluate policy on each CronJob trigger
    denyOutsideWindow: true  # Deny if triggered outside schedule window
```

## 4. Controller Implementation

### 4.1 Job Admission (Go)

```go
package controller

import (
    "context"
    "fmt"

    batchv1 "k8s.io/api/batch/v1"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/reconcile"

    arcv1 "github.com/backbay-labs/chio/sdks/k8s/api/v1alpha1"
)

type JobReconciler struct {
    client.Client
    ChioKernel ChioKernelClient
}

func (r *JobReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    var job batchv1.Job
    if err := r.Get(ctx, req.NamespacedName, &job); err != nil {
        return reconcile.Result{}, client.IgnoreNotFound(err)
    }

    // Find matching ChioJobGrant
    grant, err := r.findMatchingGrant(ctx, &job)
    if err != nil {
        return reconcile.Result{}, err
    }
    if grant == nil {
        return reconcile.Result{}, nil // No Chio governance for this Job
    }

    switch {
    case job.Status.Active == 0 && job.Status.Succeeded == 0 && job.Status.Failed == 0:
        // Job just created -- acquire grant
        return r.handleJobCreated(ctx, &job, grant)

    case job.Status.Succeeded > 0 || job.Status.Failed > 0:
        // Job completed -- release grant, aggregate receipts
        return r.handleJobCompleted(ctx, &job, grant)

    default:
        // Job running -- check grant expiry
        return r.handleJobRunning(ctx, &job, grant)
    }
}

func (r *JobReconciler) handleJobCreated(
    ctx context.Context,
    job *batchv1.Job,
    grantSpec *arcv1.ChioJobGrant,
) (reconcile.Result, error) {
    // Acquire capability grant from Chio kernel
    token, err := r.ChioKernel.AcquireGrant(ctx, AcquireGrantRequest{
        Scopes:  grantSpec.Spec.Capability.Scopes,
        Guards:  grantSpec.Spec.Capability.Guards,
        Budget:  grantSpec.Spec.Capability.Budget,
        TTL:     grantSpec.Spec.TTL,
        Meta: map[string]string{
            "k8s.job.name":      job.Name,
            "k8s.job.namespace": job.Namespace,
            "k8s.job.uid":       string(job.UID),
        },
    })
    if err != nil {
        // Grant denied -- fail the Job
        return reconcile.Result{}, r.failJob(ctx, job, fmt.Sprintf("Chio grant denied: %v", err))
    }

    // Store grant token as a Secret
    secret := &corev1.Secret{
        ObjectMeta: metav1.ObjectMeta{
            Name:      fmt.Sprintf("chio-grant-%s", job.Name),
            Namespace: job.Namespace,
            OwnerReferences: []metav1.OwnerReference{
                *metav1.NewControllerRef(job, batchv1.SchemeGroupVersion.WithKind("Job")),
            },
        },
        StringData: map[string]string{
            "token": token.Token,
        },
    }
    if err := r.Create(ctx, secret); err != nil {
        return reconcile.Result{}, err
    }

    // Annotate Job with grant info
    job.Annotations["chio.world/grant-token-secret"] = secret.Name
    job.Annotations["chio.world/grant-scopes"] = fmt.Sprintf("%v", grantSpec.Spec.Capability.Scopes)
    return reconcile.Result{}, r.Update(ctx, job)
}
```

### 4.2 Pod Template Mutation

The mutating webhook injects the Chio sidecar and mounts the grant secret
into Job pods:

```yaml
# Mutated pod template (after webhook)
spec:
  containers:
    - name: worker
      image: my-app:latest
      env:
        - name: CHIO_GRANT_TOKEN
          valueFrom:
            secretKeyRef:
              name: chio-grant-etl-job-12345
              key: token
        - name: CHIO_SIDECAR_URL
          value: "http://localhost:9090"
    - name: chio-sidecar
      image: ghcr.io/backbay-labs/chio-sidecar:latest
      ports:
        - containerPort: 9090
      env:
        - name: CHIO_GRANT_TOKEN
          valueFrom:
            secretKeyRef:
              name: chio-grant-etl-job-12345
              key: token
      resources:
        requests:
          cpu: 50m
          memory: 32Mi
        limits:
          cpu: 200m
          memory: 64Mi
```

### 4.3 Job Completion Handler

```go
func (r *JobReconciler) handleJobCompleted(
    ctx context.Context,
    job *batchv1.Job,
    grantSpec *arcv1.ChioJobGrant,
) (reconcile.Result, error) {
    tokenSecret := job.Annotations["chio.world/grant-token-secret"]

    // Aggregate receipts from all pods in the Job
    pods, err := r.getJobPods(ctx, job)
    if err != nil {
        return reconcile.Result{}, err
    }

    var receiptIDs []string
    for _, pod := range pods {
        if rid, ok := pod.Annotations["chio.world/receipt-ids"]; ok {
            receiptIDs = append(receiptIDs, splitReceiptIDs(rid)...)
        }
    }

    // Finalize workflow receipt
    if len(receiptIDs) > 0 && grantSpec.Spec.Receipts.Aggregate {
        workflowReceipt, err := r.ChioKernel.FinalizeWorkflow(ctx, FinalizeRequest{
            StepReceiptIDs: receiptIDs,
            WorkflowID:     string(job.UID),
        })
        if err != nil {
            return reconcile.Result{}, err
        }
        job.Annotations["chio.world/workflow-receipt"] = workflowReceipt.ReceiptID
    }

    // Release the grant
    if err := r.ChioKernel.ReleaseGrant(ctx, tokenSecret); err != nil {
        return reconcile.Result{}, err
    }

    // Annotate Job with completion status
    job.Annotations["chio.world/grant-released"] = "true"
    job.Annotations["chio.world/receipt-count"] = fmt.Sprintf("%d", len(receiptIDs))

    return reconcile.Result{}, r.Update(ctx, job)
}
```

## 5. CronJob Integration

CronJobs spawn Jobs on a schedule. Each spawned Job gets its own grant:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: agent-etl
  labels:
    chio.world/governed: "true"
  annotations:
    chio.world/scope: "tools:etl"
    chio.world/guards: "data-residency,business-hours"
spec:
  schedule: "0 */6 * * *"
  jobTemplate:
    metadata:
      labels:
        chio.world/governed: "true"
    spec:
      template:
        spec:
          containers:
            - name: etl
              image: agent-etl:latest
```

The `business-hours` guard ensures the CronJob only materializes grants
during approved hours, even if Kubernetes fires the schedule at other times.

## 6. CLI Integration

```bash
# List active Job grants
chio k8s grants list --namespace data-team

# Inspect a Job's grant and receipts
chio k8s job inspect etl-job-12345 --namespace data-team

# Revoke a Job's grant (terminates the Job)
chio k8s grant revoke --job etl-job-12345 --namespace data-team

# View receipt chain for a completed Job
chio k8s job receipts etl-job-12345 --namespace data-team
```

## 7. Package Structure

```
sdks/k8s/
  crds/
    arcpolicy-crd.yaml          # Existing
    arcjobgrant-crd.yaml        # New: Job-specific grants
  controller/
    main.go                     # Existing controller entry
    job_reconciler.go           # New: Job lifecycle management
    cronjob_reconciler.go       # New: CronJob grant evaluation
    capability.go               # Existing: grant acquisition
    types.go                    # Extended: ChioJobGrant types
    controller_test.go          # Extended tests
  webhooks/
    validating-webhook.yaml     # Existing
    mutating-webhook.yaml       # Existing (extended for Jobs)
  helm/
    chio-k8s-controller/
      Chart.yaml
      values.yaml
      templates/
        deployment.yaml
        rbac.yaml
        crds.yaml
```

## 8. Relationship to Existing K8s Work

```
Existing K8s integration:
  ChioPolicy CRD -----> Admission webhooks -----> Pod-level sidecar injection
                                                       |
Extended (this doc):                                   |
  ChioJobGrant CRD --> Job controller --> Grant lifecycle --> Sidecar (shared grant)
                                     --> Receipt aggregation on Job complete
                                     --> CronJob per-run evaluation
```

The Job controller builds on the existing webhook infrastructure. It does
not replace it -- it adds lifecycle awareness that webhooks alone cannot
provide (admission is a single point-in-time check; Jobs have duration).

## 9. Open Questions

1. **Indexed Jobs.** Kubernetes Indexed Jobs assign each pod an index.
   Should Chio support per-index capability scoping (e.g., index 0 gets
   `data:region-us`, index 1 gets `data:region-eu`)?

2. **TTL controller.** Kubernetes has a TTL-after-finished controller that
   cleans up completed Jobs. Should the Chio grant TTL align with or be
   independent of the Job's TTL?

3. **Job suspend/resume.** Kubernetes 1.24+ supports suspending Jobs.
   Should suspending a Job also suspend (not revoke) the Chio grant?

4. **Argo Workflows / Tekton.** These are Kubernetes-native workflow
   engines that build on Jobs. Should the Job controller be aware of
   Argo/Tekton workflow annotations, or should those get their own
   integration?
