// Package reconciler contains the controller-runtime reconciler that mints
// and releases Chio capability grants for governed Kubernetes Jobs.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	chioapi "github.com/backbay-labs/chio-k8s-controller/internal/chio"
)

// Label and annotation keys used to coordinate with governed Jobs.
const (
	// LabelGoverned marks a Job as requiring Chio capability governance.
	// Only Jobs with this label set to "true" are reconciled.
	LabelGoverned = "chio.world/governed"

	// AnnotationScopes is a comma-separated list of scopes the Job wants.
	AnnotationScopes = "chio.world/scopes"

	// AnnotationCapabilityID records the ID of the minted capability.
	AnnotationCapabilityID = "chio.world/capability-id"

	// AnnotationCapabilityToken stores the serialized capability token on the
	// governed pod template so admission can validate the spawned Pods.
	AnnotationCapabilityToken = "chio.world/capability-token"

	// AnnotationCapabilityExpiresAt records the capability expiry (RFC3339).
	AnnotationCapabilityExpiresAt = "chio.world/capability-expires-at"

	// AnnotationReleased marks a Job as having had its capability released.
	AnnotationReleased = "chio.world/released-at"

	// AnnotationReceiptID records the ID of the submitted JobReceipt.
	AnnotationReceiptID = "chio.world/receipt-id"

	// PodAnnotationReceipt is read from governed Job pods to harvest receipts.
	PodAnnotationReceipt = "chio.world/receipt"

	// FinalizerName keeps the Job resource alive until we have released
	// the capability and emitted a JobReceipt.
	FinalizerName = "chio.world/capability-finalizer"
)

// ChioClient is the subset of chio.Client methods the reconciler needs.
//
// Declared as an interface so tests can inject a stub without taking a
// dependency on net/http.
type ChioClient interface {
	Mint(ctx context.Context, req chioapi.MintRequest) (*chioapi.CapabilityToken, error)
	Release(ctx context.Context, req chioapi.ReleaseRequest) error
	SubmitReceipt(ctx context.Context, receipt chioapi.JobReceipt) (string, error)
}

// RetryPolicy configures bounded exponential backoff for sidecar submission.
type RetryPolicy struct {
	// BaseDelay is the first requeue delay.
	BaseDelay time.Duration
	// MaxDelay caps the backoff.
	MaxDelay time.Duration
	// MaxAttempts bounds the total number of attempts the reconciler makes
	// for receipt submission before giving up and logging an error.
	MaxAttempts int
}

// DefaultRetryPolicy returns reasonable defaults.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		BaseDelay:   2 * time.Second,
		MaxDelay:    2 * time.Minute,
		MaxAttempts: 8,
	}
}

// JobReconciler reconciles batch/v1 Job objects and mediates Chio capability
// grants across the Job lifecycle.
type JobReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Chio     ChioClient
	Recorder record.EventRecorder
	Retry    RetryPolicy

	// MaxConcurrentReconciles bounds how many Reconcile goroutines run in
	// parallel. Zero (default) means the controller-runtime default of 1.
	// Wired through to controller.Options.MaxConcurrentReconciles so the
	// operator's CLI flag actually takes effect.
	MaxConcurrentReconciles int

	// attempts tracks retry counts keyed by (Job UID, phase) so receipt
	// submission retries do NOT consume the release retry budget (and
	// vice versa) - a flaky release path would otherwise exhaust
	// MaxAttempts before the first SubmitReceipt runs and land the Job
	// in ChioReceiptDropped without ever attempting the receipt.
	// attemptsMu guards concurrent access from multiple Reconcile workers
	// when MaxConcurrentReconciles > 1; without it, concurrent writes on
	// the plain map trigger Go's fatal "concurrent map writes" panic and
	// crash the controller under load.
	attemptsMu sync.Mutex
	attempts   map[attemptKey]int
}

// attemptKey composes a Job UID with a retry phase so the release and
// receipt paths each keep their own MaxAttempts budget.
type attemptKey struct {
	uid   types.UID
	phase retryPhase
}

type retryPhase uint8

const (
	retryPhaseRelease retryPhase = iota
	retryPhaseReceipt
)

// NewJobReconciler constructs a JobReconciler with default state.
func NewJobReconciler(c client.Client, scheme *runtime.Scheme, chio ChioClient, recorder record.EventRecorder) *JobReconciler {
	return &JobReconciler{
		Client:   c,
		Scheme:   scheme,
		Chio:     chio,
		Recorder: recorder,
		Retry:    DefaultRetryPolicy(),
		attempts: make(map[attemptKey]int),
	}
}

// SetupWithManager wires the reconciler into the controller-runtime manager.
//
// Jobs are admitted into the reconcile queue when either (a) they currently
// carry the governed label, or (b) they still hold our finalizer. The
// finalizer branch is load-bearing: if the governed label is removed from a
// previously-governed Job, deletion events still need to reach Reconcile so
// the Chio finalizer + capability can be cleaned up; otherwise the Job can be
// stuck terminating forever. Pods owned by a governed Job are watched so
// receipt annotations trigger reconciliation while the Job is still running.
func (r *JobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	governedOrFinalized := predicate.NewPredicateFuncs(func(o client.Object) bool {
		if o.GetLabels()[LabelGoverned] == "true" {
			return true
		}
		for _, f := range o.GetFinalizers() {
			if f == FinalizerName {
				return true
			}
		}
		return false
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(governedOrFinalized)).
		Owns(&corev1.Pod{}).
		WithOptions(r.controllerOptions()).
		Complete(r)
}

// controllerOptions exposes a hook so tests and main can tune concurrency.
// Defaults preserve the controller-runtime default of 1 worker when
// MaxConcurrentReconciles is zero.
func (r *JobReconciler) controllerOptions() controller.Options {
	return controller.Options{
		MaxConcurrentReconciles: r.MaxConcurrentReconciles,
	}
}

// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile drives the capability grant lifecycle for governed Jobs.
//
// The reconciler is idempotent: each phase of the lifecycle is gated on
// annotations and finalizers that the reconciler itself sets, so repeated
// invocations converge on the same state.
func (r *JobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("job", req.NamespacedName)

	var job batchv1.Job
	if err := r.Get(ctx, req.NamespacedName, &job); err != nil {
		if apierrors.IsNotFound(err) {
			// Nothing to do; cache will converge.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get job: %w", err)
	}

	// Handle deletion first so that if the governed label was removed
	// post-admission on a Job we had already finalized, we still run the
	// release + finalizer cleanup. Otherwise the Job would stay stuck
	// terminating with a dangling Chio finalizer.
	if !job.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&job, FinalizerName) {
			return r.handleDeletion(ctx, logger, &job)
		}
		// Being deleted without our finalizer: nothing for us to do.
		return ctrl.Result{}, nil
	}

	// Governed-label gate. The predicate already filtered, but we re-check
	// because the label can be removed post-admission. After we've cleared
	// any pending deletion, losing the label means the Job is no longer our
	// responsibility.
	if !isGoverned(&job) {
		logger.V(1).Info("ignoring ungoverned job")
		return ctrl.Result{}, nil
	}

	// Ensure we own a finalizer so we can release the grant even if the Job
	// is deleted before completing.
	if controllerutil.AddFinalizer(&job, FinalizerName) {
		if err := r.Update(ctx, &job); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		// The update will retrigger reconcile.
		return ctrl.Result{}, nil
	}

	// Mint the capability if not yet minted.
	if job.Annotations[AnnotationCapabilityID] == "" {
		if result, err := r.mintGrant(ctx, logger, &job); err != nil || !result.IsZero() {
			return result, err
		}
	}

	// Terminal state? Release + emit receipt.
	if phase, done := jobTerminalPhase(&job); done {
		return r.handleTerminal(ctx, logger, &job, phase)
	}

	// Otherwise the Job is still running. Do nothing; watches on Pods and
	// Jobs will wake us up again.
	return ctrl.Result{}, nil
}

// mintGrant requests a capability grant from the Chio sidecar and persists the
// result on the Job via annotations. On sidecar-unreachable it records an
// event and requeues.
func (r *JobReconciler) mintGrant(ctx context.Context, logger logr.Logger, job *batchv1.Job) (ctrl.Result, error) {
	scopes := parseScopes(job.Annotations[AnnotationScopes])
	req := chioapi.MintRequest{
		Subject: fmt.Sprintf("job/%s/%s", job.Namespace, job.Name),
		Scopes:  scopes,
		Labels:  job.Labels,
		JobUID:  string(job.UID),
	}

	token, err := r.Chio.Mint(ctx, req)
	if err != nil {
		if errors.Is(err, chioapi.ErrSidecarUnreachable) {
			r.event(job, corev1.EventTypeWarning, "ChioSidecarUnreachable",
				"failed to mint capability; requeueing: "+err.Error())
			return ctrl.Result{RequeueAfter: r.Retry.BaseDelay}, nil
		}
		r.event(job, corev1.EventTypeWarning, "ChioMintFailed", err.Error())
		return ctrl.Result{}, fmt.Errorf("mint capability: %w", err)
	}

	patch := client.MergeFrom(job.DeepCopy())
	if job.Annotations == nil {
		job.Annotations = map[string]string{}
	}
	if job.Spec.Template.Annotations == nil {
		job.Spec.Template.Annotations = map[string]string{}
	}
	job.Annotations[AnnotationCapabilityID] = token.ID
	delete(job.Annotations, AnnotationCapabilityToken)
	job.Annotations[AnnotationCapabilityExpiresAt] = token.ExpiresAt.UTC().Format(time.RFC3339)
	job.Spec.Template.Annotations[AnnotationCapabilityToken] = token.Token
	if err := r.Patch(ctx, job, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("persist capability annotation: %w", err)
	}

	logger.Info("minted capability", "capability_id", token.ID, "scopes", scopes)
	r.event(job, corev1.EventTypeNormal, "ChioCapabilityMinted",
		fmt.Sprintf("minted capability %s with %d scope(s)", token.ID, len(scopes)))
	return ctrl.Result{}, nil
}

// handleTerminal releases the grant, emits a JobReceipt, and drops the
// finalizer once both have succeeded.
func (r *JobReconciler) handleTerminal(ctx context.Context, logger logr.Logger, job *batchv1.Job, outcome string) (ctrl.Result, error) {
	capID := job.Annotations[AnnotationCapabilityID]

	// Release capability if still outstanding.
	if capID != "" && job.Annotations[AnnotationReleased] == "" {
		err := r.Chio.Release(ctx, chioapi.ReleaseRequest{
			CapabilityID: capID,
			JobUID:       string(job.UID),
			Reason:       outcome,
		})
		if err != nil {
			if errors.Is(err, chioapi.ErrSidecarUnreachable) {
				r.event(job, corev1.EventTypeWarning, "ChioSidecarUnreachable",
					"release deferred; requeueing: "+err.Error())
				return ctrl.Result{RequeueAfter: r.backoffFor(job.UID, retryPhaseRelease)}, nil
			}
			r.event(job, corev1.EventTypeWarning, "ChioReleaseFailed", err.Error())
			return ctrl.Result{}, fmt.Errorf("release capability: %w", err)
		}

		patch := client.MergeFrom(job.DeepCopy())
		if job.Annotations == nil {
			job.Annotations = map[string]string{}
		}
		job.Annotations[AnnotationReleased] = time.Now().UTC().Format(time.RFC3339)
		if err := r.Patch(ctx, job, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("persist release annotation: %w", err)
		}
		logger.Info("released capability", "capability_id", capID, "outcome", outcome)
		r.event(job, corev1.EventTypeNormal, "ChioCapabilityReleased",
			fmt.Sprintf("released capability %s (outcome=%s)", capID, outcome))
	}

	// Emit receipt if not yet submitted.
	if job.Annotations[AnnotationReceiptID] == "" {
		steps, err := r.collectStepReceipts(ctx, job)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("collect pod receipts: %w", err)
		}

		receipt := chioapi.JobReceipt{
			JobName:      job.Name,
			Namespace:    job.Namespace,
			JobUID:       string(job.UID),
			CapabilityID: capID,
			Outcome:      outcome,
			StartedAt:    jobStartTime(job),
			CompletedAt:  jobCompletionTime(job),
			Steps:        steps,
		}

		id, err := r.Chio.SubmitReceipt(ctx, receipt)
		if err != nil {
			if errors.Is(err, chioapi.ErrSidecarUnreachable) {
				// Increment attempts first, THEN check the cap. Otherwise
				// the counter stays one behind the actual number of
				// attempts and a MaxAttempts=5 policy would schedule a
				// 6th sidecar submission before giving up. This uses
				// the receipt phase so the release retry budget stays
				// independent.
				backoff := r.backoffFor(job.UID, retryPhaseReceipt)
				if r.attemptExceeded(job.UID, retryPhaseReceipt) {
					r.event(job, corev1.EventTypeWarning, "ChioReceiptDropped",
						"exceeded max receipt submission attempts; giving up")
					// Fall through to finalizer removal so the Job can be deleted.
				} else {
					r.event(job, corev1.EventTypeWarning, "ChioSidecarUnreachable",
						"receipt submission deferred; requeueing: "+err.Error())
					return ctrl.Result{RequeueAfter: backoff}, nil
				}
			} else {
				r.event(job, corev1.EventTypeWarning, "ChioReceiptFailed", err.Error())
				return ctrl.Result{}, fmt.Errorf("submit receipt: %w", err)
			}
		} else {
			patch := client.MergeFrom(job.DeepCopy())
			if job.Annotations == nil {
				job.Annotations = map[string]string{}
			}
			job.Annotations[AnnotationReceiptID] = id
			if err := r.Patch(ctx, job, patch); err != nil {
				return ctrl.Result{}, fmt.Errorf("persist receipt annotation: %w", err)
			}
			logger.Info("submitted job receipt", "receipt_id", id, "steps", len(steps))
			r.event(job, corev1.EventTypeNormal, "ChioReceiptSubmitted",
				fmt.Sprintf("submitted JobReceipt %s (%d steps)", id, len(steps)))
		}
	}

	// Drop finalizer.
	if controllerutil.RemoveFinalizer(job, FinalizerName) {
		if err := r.Update(ctx, job); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
	}

	r.forgetAttempts(job.UID)
	return ctrl.Result{}, nil
}

// handleDeletion releases a capability on a Job being deleted. This is
// distinct from handleTerminal (which runs on Complete/Failed Jobs).
func (r *JobReconciler) handleDeletion(ctx context.Context, logger logr.Logger, job *batchv1.Job) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(job, FinalizerName) {
		return ctrl.Result{}, nil
	}

	capID := job.Annotations[AnnotationCapabilityID]
	if capID != "" && job.Annotations[AnnotationReleased] == "" {
		err := r.Chio.Release(ctx, chioapi.ReleaseRequest{
			CapabilityID: capID,
			JobUID:       string(job.UID),
			Reason:       "deleted",
		})
		if err != nil {
			if errors.Is(err, chioapi.ErrSidecarUnreachable) {
				r.event(job, corev1.EventTypeWarning, "ChioSidecarUnreachable",
					"release on delete deferred; requeueing: "+err.Error())
				return ctrl.Result{RequeueAfter: r.backoffFor(job.UID, retryPhaseRelease)}, nil
			}
			r.event(job, corev1.EventTypeWarning, "ChioReleaseFailed", err.Error())
			logger.Error(err, "release on delete failed; keeping finalizer and requeueing")
			return ctrl.Result{RequeueAfter: r.backoffFor(job.UID, retryPhaseRelease)}, nil
		}
	}

	controllerutil.RemoveFinalizer(job, FinalizerName)
	if err := r.Update(ctx, job); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer on delete: %w", err)
	}
	r.forgetAttempts(job.UID)
	return ctrl.Result{}, nil
}

// collectStepReceipts builds per-pod observations for inclusion in the
// aggregate JobReceipt the controller submits to the sidecar.
//
// The controller mints every authoritative field on the StepReceipt
// (PodName, Phase, ObservedAt) from objects it observes through the
// apiserver. Any payload the workload wrote to its own
// `chio.world/receipt` annotation is captured separately under
// AdvisoryPodAnnotation with Source=AdvisoryPodAnnotationSource and is
// explicitly NOT treated as authoritative receipt content. Pod annotations
// are user-owned, so allowing them to flow verbatim into the mediated
// JobReceipt would let any actor with create-pod rights write into the
// authoritative audit trail.
//
// We list all pods in the Job's namespace and filter by ownership. We
// deliberately avoid relying on the `controller-uid` label (which the Job
// controller sets by default on most clusters but is not part of the
// stable contract) because a label-only filter would fail on fake clients
// and on clusters that customize the label.
func (r *JobReconciler) collectStepReceipts(ctx context.Context, job *batchv1.Job) ([]chioapi.StepReceipt, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(job.Namespace)); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	steps := make([]chioapi.StepReceipt, 0, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		if !isOwnedByJob(p, job) {
			continue
		}
		step := chioapi.StepReceipt{
			PodName:    p.Name,
			Phase:      string(p.Status.Phase),
			ObservedAt: now,
		}
		if advisory := buildAdvisoryPodAnnotation(p.Annotations[PodAnnotationReceipt]); advisory != nil {
			step.AdvisoryPodAnnotation = advisory
		} else if p.Annotations[PodAnnotationReceipt] == "" {
			// No annotation and no other content worth surfacing; skip the
			// pod entirely to preserve prior behaviour of only emitting
			// step entries for pods that actually produced something.
			continue
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// buildAdvisoryPodAnnotation wraps a pod's raw receipt annotation in the
// advisory envelope, applying the AdvisoryPodAnnotationMaxBytes cap. Empty
// input yields nil so the StepReceipt's AdvisoryPodAnnotation field is
// omitted on the wire.
func buildAdvisoryPodAnnotation(raw string) *chioapi.AdvisoryPodAnnotation {
	if raw == "" {
		return nil
	}
	payload := raw
	truncated := false
	if len(payload) > chioapi.AdvisoryPodAnnotationMaxBytes {
		payload = payload[:chioapi.AdvisoryPodAnnotationMaxBytes]
		truncated = true
	}
	return &chioapi.AdvisoryPodAnnotation{
		Source:        chioapi.AdvisoryPodAnnotationSource,
		AnnotationKey: PodAnnotationReceipt,
		Payload:       payload,
		Truncated:     truncated,
	}
}

func (r *JobReconciler) event(obj client.Object, eventType, reason, message string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Event(obj, eventType, reason, message)
}

// backoffFor returns an exponentially growing delay keyed by (Job UID,
// phase). Each phase keeps an independent retry budget so a flaky
// release path cannot consume the receipt budget and trigger a
// premature ChioReceiptDropped.
func (r *JobReconciler) backoffFor(uid types.UID, phase retryPhase) time.Duration {
	r.attemptsMu.Lock()
	defer r.attemptsMu.Unlock()
	k := attemptKey{uid: uid, phase: phase}
	r.attempts[k]++
	n := r.attempts[k]
	if n < 1 {
		n = 1
	}
	d := r.Retry.BaseDelay
	for i := 1; i < n && d < r.Retry.MaxDelay; i++ {
		d *= 2
	}
	if d > r.Retry.MaxDelay {
		d = r.Retry.MaxDelay
	}
	return d
}

func (r *JobReconciler) attemptExceeded(uid types.UID, phase retryPhase) bool {
	r.attemptsMu.Lock()
	defer r.attemptsMu.Unlock()
	return r.attempts[attemptKey{uid: uid, phase: phase}] >= r.Retry.MaxAttempts
}

// forgetAttempts drops the retry counters for both phases when the Job
// leaves the reconcile lifecycle (release + receipt both done, or
// finalizer removed).
func (r *JobReconciler) forgetAttempts(uid types.UID) {
	r.attemptsMu.Lock()
	defer r.attemptsMu.Unlock()
	delete(r.attempts, attemptKey{uid: uid, phase: retryPhaseRelease})
	delete(r.attempts, attemptKey{uid: uid, phase: retryPhaseReceipt})
}

// isGoverned returns true if a Job carries the governed label set to "true".
func isGoverned(job *batchv1.Job) bool {
	return job.Labels[LabelGoverned] == "true"
}

// jobTerminalPhase reports whether a Job has reached a terminal state and,
// if so, whether it succeeded or failed.
func jobTerminalPhase(job *batchv1.Job) (string, bool) {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return "succeeded", true
		case batchv1.JobFailed:
			return "failed", true
		}
	}
	return "", false
}

func jobStartTime(job *batchv1.Job) time.Time {
	if job.Status.StartTime != nil {
		return job.Status.StartTime.UTC()
	}
	return job.CreationTimestamp.UTC()
}

func jobCompletionTime(job *batchv1.Job) time.Time {
	if job.Status.CompletionTime != nil {
		return job.Status.CompletionTime.UTC()
	}
	return time.Now().UTC()
}

func parseScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isOwnedByJob(pod *corev1.Pod, job *batchv1.Job) bool {
	for _, o := range pod.OwnerReferences {
		if o.Kind == "Job" && o.UID == job.UID {
			return true
		}
	}
	return false
}

// Compile-time assertion that JobReconciler satisfies the controller-runtime
// Reconciler interface.
var _ interface {
	Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
} = (*JobReconciler)(nil)
