package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	chioapi "github.com/backbay-labs/chio-k8s-controller/internal/chio"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("add clientgo scheme: %v", err)
	}
	if err := batchv1.AddToScheme(s); err != nil {
		t.Fatalf("add batchv1: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	return s
}

// stubChioClient is an in-memory implementation of the ChioClient interface
// used for unit tests. It records calls and can be configured to fail.
type stubChioClient struct {
	mu            sync.Mutex
	mintCalls     int
	releaseCalls  int
	receiptCalls  int
	mintErr       error
	releaseErr    error
	receiptErr    error
	lastMint      chioapi.MintRequest
	lastRelease   chioapi.ReleaseRequest
	lastReceipt   chioapi.JobReceipt
	nextCapID     string
	nextReceiptID string
}

func (s *stubChioClient) Mint(_ context.Context, req chioapi.MintRequest) (*chioapi.CapabilityToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mintCalls++
	s.lastMint = req
	if s.mintErr != nil {
		return nil, s.mintErr
	}
	id := s.nextCapID
	if id == "" {
		id = fmt.Sprintf("cap-%d", s.mintCalls)
	}
	return &chioapi.CapabilityToken{
		ID:        id,
		Token:     "token-" + id,
		Issuer:    "issuer-test",
		Subject:   req.Subject,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		Signature: "signature-test",
	}, nil
}

func (s *stubChioClient) Release(_ context.Context, req chioapi.ReleaseRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseCalls++
	s.lastRelease = req
	return s.releaseErr
}

func (s *stubChioClient) SubmitReceipt(_ context.Context, receipt chioapi.JobReceipt) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiptCalls++
	s.lastReceipt = receipt
	if s.receiptErr != nil {
		return "", s.receiptErr
	}
	id := s.nextReceiptID
	if id == "" {
		id = fmt.Sprintf("rcpt-%d", s.receiptCalls)
	}
	return id, nil
}

func (s *stubChioClient) counts() (mint, release, receipt int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mintCalls, s.releaseCalls, s.receiptCalls
}

func governedJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo",
			Namespace: "default",
			UID:       types.UID("job-uid-1"),
			Labels: map[string]string{
				LabelGoverned: "true",
			},
			Annotations: map[string]string{
				AnnotationScopes: "tools:search, tools:fetch",
			},
		},
	}
}

func ungovernedJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-ungov",
			Namespace: "default",
			UID:       types.UID("job-uid-2"),
		},
	}
}

func completedJob(base *batchv1.Job) *batchv1.Job {
	j := base.DeepCopy()
	j.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	j.Status.CompletionTime = &now
	j.Status.StartTime = &now
	return j
}

func failedJob(base *batchv1.Job) *batchv1.Job {
	j := base.DeepCopy()
	j.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	j.Status.StartTime = &now
	return j
}

func jobWithSuccessCriteriaMet(base *batchv1.Job) *batchv1.Job {
	j := base.DeepCopy()
	j.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	j.Status.StartTime = &now
	return j
}

func reconcileUntilStable(t *testing.T, r *JobReconciler, key types.NamespacedName) {
	t.Helper()
	// Reconcile a bounded number of times, exiting as soon as we get an empty
	// result with no requeue. This exercises idempotency.
	for i := 0; i < 10; i++ {
		res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("reconcile returned error on iteration %d: %v", i, err)
		}
		if res.Requeue || res.RequeueAfter > 0 {
			continue
		}
		// Reconcile once more to confirm stability; if it still returns empty,
		// we are done.
		res2, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("second reconcile error: %v", err)
		}
		if !res2.Requeue && res2.RequeueAfter == 0 {
			return
		}
	}
	t.Fatalf("reconcile did not stabilize")
}

func buildReconciler(t *testing.T, chio *stubChioClient, objs ...client.Object) (*JobReconciler, client.Client) {
	t.Helper()
	s := newScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&batchv1.Job{}).
		Build()
	r := NewJobReconciler(c, s, chio, record.NewFakeRecorder(32))
	// Shorten retry to keep tests fast.
	r.Retry = RetryPolicy{BaseDelay: 1 * time.Millisecond, MaxDelay: 2 * time.Millisecond, MaxAttempts: 3}
	return r, c
}

// Test (a): governed Job at creation mints a grant.
func TestReconcile_NewGovernedJob_MintsGrant(t *testing.T) {
	chio := &stubChioClient{nextCapID: "cap-abc"}
	job := governedJob()
	r, c := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	reconcileUntilStable(t, r, key)

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}

	if got.Annotations[AnnotationCapabilityID] != "cap-abc" {
		t.Fatalf("expected capability-id annotation, got %q", got.Annotations[AnnotationCapabilityID])
	}
	if got.Annotations[AnnotationCapabilityToken] != "" {
		t.Fatalf("expected no top-level capability-token annotation, got %q", got.Annotations[AnnotationCapabilityToken])
	}
	if got.Spec.Template.Annotations["chio.world/capability-token"] != "token-cap-abc" {
		t.Fatalf("expected pod-template capability-token annotation, got %q", got.Spec.Template.Annotations["chio.world/capability-token"])
	}
	if _, err := time.Parse(time.RFC3339, got.Annotations[AnnotationCapabilityExpiresAt]); err != nil {
		t.Fatalf("invalid expires-at annotation %q: %v", got.Annotations[AnnotationCapabilityExpiresAt], err)
	}
	if !containsFinalizer(&got, FinalizerName) {
		t.Fatalf("expected finalizer %q on job", FinalizerName)
	}

	mint, release, receipt := chio.counts()
	if mint != 1 {
		t.Fatalf("expected exactly 1 mint call, got %d", mint)
	}
	if release != 0 || receipt != 0 {
		t.Fatalf("expected no release/receipt calls yet, got release=%d receipt=%d", release, receipt)
	}
	if len(chio.lastMint.Scopes) != 2 || chio.lastMint.Scopes[0] != "tools:search" {
		t.Fatalf("unexpected mint scopes: %#v", chio.lastMint.Scopes)
	}
}

// Test (b): completed governed Job releases grant and emits receipt.
func TestReconcile_CompletedJob_ReleasesAndEmitsReceipt(t *testing.T) {
	chio := &stubChioClient{nextCapID: "cap-ok", nextReceiptID: "rcpt-ok"}
	job := governedJob()
	// Pre-set: the mint has already happened.
	job.Annotations[AnnotationCapabilityID] = "cap-ok"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-ok"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}
	// Mark complete.
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now

	// Add a pod owned by the job with a receipt annotation.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-xyz",
			Namespace: job.Namespace,
			UID:       types.UID("pod-1"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Job", UID: job.UID, Name: job.Name, APIVersion: "batch/v1"},
			},
			Annotations: map[string]string{
				PodAnnotationReceipt: `{"step":"search","ok":true}`,
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	r, _ := buildReconciler(t, chio, job, pod)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}
	reconcileUntilStable(t, r, key)

	mint, release, receipt := chio.counts()
	if mint != 0 {
		t.Fatalf("expected no new mint (already present), got %d", mint)
	}
	if release != 1 {
		t.Fatalf("expected 1 release call, got %d", release)
	}
	if receipt != 1 {
		t.Fatalf("expected 1 receipt submission, got %d", receipt)
	}
	if chio.lastRelease.Reason != "succeeded" {
		t.Fatalf("expected release reason=succeeded, got %q", chio.lastRelease.Reason)
	}
	if chio.lastReceipt.Outcome != "succeeded" {
		t.Fatalf("expected receipt outcome=succeeded, got %q", chio.lastReceipt.Outcome)
	}
	if len(chio.lastReceipt.Steps) != 1 {
		t.Fatalf("expected 1 step receipt, got %d", len(chio.lastReceipt.Steps))
	}
	if chio.lastReceipt.Steps[0].PodName != "demo-xyz" {
		t.Fatalf("unexpected step pod name: %q", chio.lastReceipt.Steps[0].PodName)
	}
}

// Test (c): failed governed Job releases grant and emits receipt with
// outcome=failed.
func TestReconcile_FailedJob_ReleasesAndEmitsReceipt(t *testing.T) {
	chio := &stubChioClient{}
	job := governedJob()
	job.Annotations[AnnotationCapabilityID] = "cap-fail"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-fail"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	job.Status.StartTime = &now

	r, _ := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}
	reconcileUntilStable(t, r, key)

	_, release, receipt := chio.counts()
	if release != 1 {
		t.Fatalf("expected 1 release call, got %d", release)
	}
	if receipt != 1 {
		t.Fatalf("expected 1 receipt submission, got %d", receipt)
	}
	if chio.lastRelease.Reason != "failed" {
		t.Fatalf("expected release reason=failed, got %q", chio.lastRelease.Reason)
	}
	if chio.lastReceipt.Outcome != "failed" {
		t.Fatalf("expected receipt outcome=failed, got %q", chio.lastReceipt.Outcome)
	}
}

func TestReconcile_JobSuccessCriteriaMet_WaitsForJobComplete(t *testing.T) {
	chio := &stubChioClient{}
	job := jobWithSuccessCriteriaMet(governedJob())
	job.Annotations[AnnotationCapabilityID] = "cap-pending-success"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-pending-success"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}

	r, c := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if res.Requeue || res.RequeueAfter > 0 {
		t.Fatalf("did not expect requeue for non-terminal success criteria: %#v", res)
	}

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	if !containsFinalizer(&got, FinalizerName) {
		t.Fatalf("expected finalizer to remain until JobComplete")
	}
	if got.Annotations[AnnotationReleased] != "" {
		t.Fatalf("did not expect released annotation before JobComplete")
	}
	if got.Annotations[AnnotationReceiptID] != "" {
		t.Fatalf("did not expect receipt annotation before JobComplete")
	}

	_, release, receipt := chio.counts()
	if release != 0 || receipt != 0 {
		t.Fatalf("expected no release or receipt submission before JobComplete, got release=%d receipt=%d", release, receipt)
	}
}

// Test (d): Jobs without the governed label are ignored entirely.
func TestReconcile_UngovernedJob_Ignored(t *testing.T) {
	chio := &stubChioClient{}
	job := ungovernedJob()
	r, c := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if res.Requeue || res.RequeueAfter > 0 {
		t.Fatalf("unexpected requeue for ungoverned job: %#v", res)
	}

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	if got.Annotations[AnnotationCapabilityID] != "" {
		t.Fatalf("ungoverned job should not have capability annotation, got %q",
			got.Annotations[AnnotationCapabilityID])
	}
	if containsFinalizer(&got, FinalizerName) {
		t.Fatalf("ungoverned job should not carry the finalizer")
	}

	mint, release, receipt := chio.counts()
	if mint != 0 || release != 0 || receipt != 0 {
		t.Fatalf("expected no chio calls for ungoverned job, got mint=%d release=%d receipt=%d",
			mint, release, receipt)
	}
}

// Fail-closed: if sidecar is unreachable during mint, requeue, don't proceed.
func TestReconcile_SidecarUnreachable_Requeues(t *testing.T) {
	chio := &stubChioClient{mintErr: fmt.Errorf("%w: connection refused", chioapi.ErrSidecarUnreachable)}
	job := governedJob()
	r, c := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	// First reconcile adds the finalizer; the call may or may not requeue.
	// The key assertion is that after at most a couple of reconciles, the
	// job has no capability annotation and the mint failure triggered a
	// requeue.
	var lastRes ctrl.Result
	for i := 0; i < 3; i++ {
		res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("reconcile error: %v", err)
		}
		lastRes = res
	}

	if lastRes.RequeueAfter == 0 && !lastRes.Requeue {
		t.Fatalf("expected requeue on sidecar unreachable, got %#v", lastRes)
	}

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	if got.Annotations[AnnotationCapabilityID] != "" {
		t.Fatalf("expected no capability annotation after unreachable sidecar, got %q",
			got.Annotations[AnnotationCapabilityID])
	}
}

func TestReconcile_DeleteReleaseLogicalError_KeepsFinalizer(t *testing.T) {
	chio := &stubChioClient{releaseErr: fmt.Errorf("chio: http://sidecar/v1/capabilities/release returned 400: bad request")}
	job := governedJob()
	job.Annotations[AnnotationCapabilityID] = "cap-delete"
	job.Finalizers = []string{FinalizerName}
	now := metav1.NewTime(time.Now().UTC())
	job.DeletionTimestamp = &now

	r, c := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if res.RequeueAfter == 0 && !res.Requeue {
		t.Fatalf("expected requeue after logical release failure, got %#v", res)
	}

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	if !containsFinalizer(&got, FinalizerName) {
		t.Fatalf("expected finalizer to remain after logical delete release failure")
	}
	if got.Annotations[AnnotationReleased] != "" {
		t.Fatalf("did not expect released annotation after failed delete release")
	}

	_, release, receipt := chio.counts()
	if release != 1 {
		t.Fatalf("expected 1 release attempt, got %d", release)
	}
	if receipt != 0 {
		t.Fatalf("expected no receipt submission on delete path, got %d", receipt)
	}
}

// Idempotency: reconciling a completed job twice must not cause duplicate
// release or receipt submission.
func TestReconcile_Idempotent(t *testing.T) {
	chio := &stubChioClient{}
	job := completedJob(governedJob())
	job.Annotations[AnnotationCapabilityID] = "cap-idem"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-idem"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}

	r, _ := buildReconciler(t, chio, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	// Run reconcile several times; we expect only 1 release + 1 receipt.
	for i := 0; i < 5; i++ {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("iter %d: reconcile error: %v", i, err)
		}
	}

	_, release, receipt := chio.counts()
	if release != 1 {
		t.Fatalf("expected exactly 1 release, got %d", release)
	}
	if receipt != 1 {
		t.Fatalf("expected exactly 1 receipt submission, got %d", receipt)
	}
}

// Integration-ish test: drive the real chio.Client against an httptest server.
func TestChioClient_EndToEndViaHTTPStub(t *testing.T) {
	var mintCount, releaseCount, receiptCount int32

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/capabilities/mint", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&mintCount, 1)
		var req chioapi.MintRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := chioapi.MintResponse{Capability: chioapi.CapabilityToken{
			ID:        "server-cap",
			Issuer:    "issuer-server",
			Subject:   req.Subject,
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
			Signature: "signature-server",
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/capabilities/release", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&releaseCount, 1)
		_ = json.NewEncoder(w).Encode(chioapi.ReleaseResponse{Released: true})
	})
	mux.HandleFunc("/v1/receipts", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receiptCount, 1)
		_ = json.NewEncoder(w).Encode(chioapi.SubmitReceiptResponse{ReceiptID: "rcpt-server", Accepted: true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := chioapi.NewClient(srv.URL, "", srv.Client())

	ctx := context.Background()
	cap, err := client.Mint(ctx, chioapi.MintRequest{Subject: "job/default/demo", Scopes: []string{"tools:search"}, JobUID: "u"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if cap.ID != "server-cap" {
		t.Fatalf("unexpected cap id: %q", cap.ID)
	}
	if err := client.Release(ctx, chioapi.ReleaseRequest{CapabilityID: cap.ID, JobUID: "u", Reason: "succeeded"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	rid, err := client.SubmitReceipt(ctx, chioapi.JobReceipt{JobName: "demo", Namespace: "default", JobUID: "u", Outcome: "succeeded"})
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if rid != "rcpt-server" {
		t.Fatalf("unexpected receipt id: %q", rid)
	}
	if atomic.LoadInt32(&mintCount) != 1 || atomic.LoadInt32(&releaseCount) != 1 || atomic.LoadInt32(&receiptCount) != 1 {
		t.Fatalf("unexpected call counts: mint=%d release=%d receipt=%d",
			mintCount, releaseCount, receiptCount)
	}
}

// 5xx responses from the sidecar should be reported as ErrSidecarUnreachable.
func TestChioClient_ServerError_IsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := chioapi.NewClient(srv.URL, "", srv.Client())
	_, err := client.Mint(context.Background(), chioapi.MintRequest{Subject: "job/x/y", JobUID: "u"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !isUnreachable(err) {
		t.Fatalf("expected ErrSidecarUnreachable, got %v", err)
	}
}

func TestChioClient_SendsControlBearerToken(t *testing.T) {
	var authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		resp := chioapi.MintResponse{Capability: chioapi.CapabilityToken{
			ID:        "server-cap",
			Issuer:    "issuer-server",
			Subject:   "job/default/demo",
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
			Signature: "signature-server",
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := chioapi.NewClient(srv.URL, "cluster-control-token", srv.Client())
	if _, err := client.Mint(
		context.Background(),
		chioapi.MintRequest{Subject: "job/default/demo", JobUID: "u"},
	); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if authHeader != "Bearer cluster-control-token" {
		t.Fatalf("expected bearer auth header, got %q", authHeader)
	}
}

// Receipt aggregation: backoff grows with retries.
func TestBackoff_GrowsExponentially(t *testing.T) {
	chio := &stubChioClient{}
	r, _ := buildReconciler(t, chio)
	r.Retry = RetryPolicy{BaseDelay: 1 * time.Millisecond, MaxDelay: 16 * time.Millisecond, MaxAttempts: 5}

	uid := types.UID("u")
	var last time.Duration
	for i := 0; i < 5; i++ {
		d := r.backoffFor(uid, retryPhaseReceipt)
		if d < last && d != r.Retry.MaxDelay {
			t.Fatalf("backoff decreased at iteration %d: %v -> %v", i, last, d)
		}
		last = d
	}
	if !r.attemptExceeded(uid, retryPhaseReceipt) {
		t.Fatalf("expected attemptExceeded to be true after MaxAttempts")
	}
	// Release phase has an independent budget.
	if r.attemptExceeded(uid, retryPhaseRelease) {
		t.Fatalf("release phase should not share the receipt budget")
	}
}

// TestPodAnnotationDoesNotFlowIntoMediatedReceiptDecision asserts that a
// malicious pod annotation cannot wash into the authoritative fields of the
// mediated JobReceipt. The pod claims a substituted job_name, namespace,
// capability_id, outcome, and rationale via its own
// `chio.world/receipt` annotation. The controller must keep its
// authoritative fields intact and surface the annotation only as
// AdvisoryPodAnnotation with Source=pod_annotation_unverified.
func TestPodAnnotationDoesNotFlowIntoMediatedReceiptDecision(t *testing.T) {
	chio := &stubChioClient{nextReceiptID: "rcpt-ok"}
	job := governedJob()
	job.Annotations[AnnotationCapabilityID] = "cap-authoritative"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-authoritative"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now

	maliciousPayload := `{` +
		`"job_name":"substituted-job",` +
		`"namespace":"attacker-controlled",` +
		`"capability_id":"cap-substituted",` +
		`"outcome":"succeeded",` +
		`"rationale":"approved-by-pod",` +
		`"decision":"allow"` +
		`}`

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-malicious",
			Namespace: job.Namespace,
			UID:       types.UID("pod-malicious"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Job", UID: job.UID, Name: job.Name, APIVersion: "batch/v1"},
			},
			Annotations: map[string]string{
				PodAnnotationReceipt: maliciousPayload,
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	r, _ := buildReconciler(t, chio, job, pod)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}
	reconcileUntilStable(t, r, key)

	rcpt := chio.lastReceipt
	if rcpt.JobName != job.Name {
		t.Fatalf("authoritative JobName overridden by pod annotation: got %q want %q", rcpt.JobName, job.Name)
	}
	if rcpt.Namespace != job.Namespace {
		t.Fatalf("authoritative Namespace overridden by pod annotation: got %q want %q", rcpt.Namespace, job.Namespace)
	}
	if rcpt.CapabilityID != "cap-authoritative" {
		t.Fatalf("authoritative CapabilityID overridden by pod annotation: got %q want %q", rcpt.CapabilityID, "cap-authoritative")
	}
	if rcpt.Outcome != "succeeded" {
		t.Fatalf("authoritative Outcome overridden by pod annotation: got %q want %q", rcpt.Outcome, "succeeded")
	}
	if rcpt.JobUID != string(job.UID) {
		t.Fatalf("authoritative JobUID overridden by pod annotation: got %q want %q", rcpt.JobUID, string(job.UID))
	}

	if len(rcpt.Steps) != 1 {
		t.Fatalf("expected exactly 1 step receipt, got %d", len(rcpt.Steps))
	}
	step := rcpt.Steps[0]
	if step.PodName != "demo-malicious" {
		t.Fatalf("controller-owned PodName overridden: got %q", step.PodName)
	}
	if step.AdvisoryPodAnnotation == nil {
		t.Fatalf("expected advisory pod annotation to be populated")
	}
	advisory := step.AdvisoryPodAnnotation
	if advisory.Source != chioapi.AdvisoryPodAnnotationSource {
		t.Fatalf("advisory source mismatch: got %q want %q", advisory.Source, chioapi.AdvisoryPodAnnotationSource)
	}
	if advisory.Source != "pod_annotation_unverified" {
		t.Fatalf("advisory source label drifted from the documented wire value: got %q", advisory.Source)
	}
	if advisory.AnnotationKey != PodAnnotationReceipt {
		t.Fatalf("advisory annotation key mismatch: got %q want %q", advisory.AnnotationKey, PodAnnotationReceipt)
	}
	if advisory.Payload != maliciousPayload {
		t.Fatalf("advisory payload did not preserve the verbatim annotation bytes")
	}
	if advisory.Truncated {
		t.Fatalf("did not expect Truncated=true for a small payload")
	}

	// Serialize the JobReceipt the way the sidecar will see it and verify the
	// advisory tag is exposed under its documented field name and source so
	// downstream consumers cannot miss the trust boundary.
	wire, err := json.Marshal(rcpt)
	if err != nil {
		t.Fatalf("marshal job receipt: %v", err)
	}
	wireStr := string(wire)
	if !strings.Contains(wireStr, `"advisory_pod_annotation"`) {
		t.Fatalf("expected advisory_pod_annotation field on the wire, got %s", wireStr)
	}
	if !strings.Contains(wireStr, `"source":"pod_annotation_unverified"`) {
		t.Fatalf("expected pod_annotation_unverified source on the wire, got %s", wireStr)
	}
}

// TestPodAnnotationOversizedPayloadIsTruncated asserts that a 64 KiB
// annotation is bounded to AdvisoryPodAnnotationMaxBytes and reported as
// Truncated.
func TestPodAnnotationOversizedPayloadIsTruncated(t *testing.T) {
	chio := &stubChioClient{nextReceiptID: "rcpt-trunc"}
	job := governedJob()
	job.Annotations[AnnotationCapabilityID] = "cap-trunc"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-trunc"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now

	oversized := strings.Repeat("A", 64*1024)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-big",
			Namespace: job.Namespace,
			UID:       types.UID("pod-big"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Job", UID: job.UID, Name: job.Name, APIVersion: "batch/v1"},
			},
			Annotations: map[string]string{
				PodAnnotationReceipt: oversized,
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	r, _ := buildReconciler(t, chio, job, pod)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}
	reconcileUntilStable(t, r, key)

	if len(chio.lastReceipt.Steps) != 1 {
		t.Fatalf("expected 1 step receipt, got %d", len(chio.lastReceipt.Steps))
	}
	advisory := chio.lastReceipt.Steps[0].AdvisoryPodAnnotation
	if advisory == nil {
		t.Fatalf("expected advisory pod annotation to be populated")
	}
	if !advisory.Truncated {
		t.Fatalf("expected Truncated=true for 64 KiB annotation")
	}
	if len(advisory.Payload) != chioapi.AdvisoryPodAnnotationMaxBytes {
		t.Fatalf("expected payload bounded to %d bytes, got %d", chioapi.AdvisoryPodAnnotationMaxBytes, len(advisory.Payload))
	}
	if chioapi.AdvisoryPodAnnotationMaxBytes != 32*1024 {
		t.Fatalf("AdvisoryPodAnnotationMaxBytes drifted from the 32 KiB contract: got %d", chioapi.AdvisoryPodAnnotationMaxBytes)
	}
}

// TestControllerOwnedScopeIsAuthoritative is a regression for the prior fix:
// scopes are minted from the Job's controller-readable AnnotationScopes
// value, and a pod-supplied override of the scope claim must not elevate
// the controller-minted MintRequest scope set or the recorded mediated
// receipt fields.
func TestControllerOwnedScopeIsAuthoritative(t *testing.T) {
	chio := &stubChioClient{nextCapID: "cap-scope", nextReceiptID: "rcpt-scope"}
	job := governedJob()
	// Authoritative scopes are inherited from governedJob(): "tools:search, tools:fetch".
	job.Finalizers = []string{FinalizerName}

	// Pod attempts to claim an elevated scope via its receipt annotation.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-scope",
			Namespace: job.Namespace,
			UID:       types.UID("pod-scope"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Job", UID: job.UID, Name: job.Name, APIVersion: "batch/v1"},
			},
			Annotations: map[string]string{
				PodAnnotationReceipt: `{"scopes":["tools:admin","tools:exfiltrate"],"granted_scopes":["tools:root"]}`,
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	r, c := buildReconciler(t, chio, job, pod)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	// Drive through mint.
	reconcileUntilStable(t, r, key)

	// Mint request must reflect the controller-readable Job annotation only.
	if len(chio.lastMint.Scopes) != 2 {
		t.Fatalf("expected controller-owned scope set of length 2, got %#v", chio.lastMint.Scopes)
	}
	for _, s := range chio.lastMint.Scopes {
		if s == "tools:admin" || s == "tools:exfiltrate" || s == "tools:root" {
			t.Fatalf("pod-supplied scope leaked into mint request: %v", chio.lastMint.Scopes)
		}
	}
	if chio.lastMint.Scopes[0] != "tools:search" || chio.lastMint.Scopes[1] != "tools:fetch" {
		t.Fatalf("unexpected controller-minted scopes: %#v", chio.lastMint.Scopes)
	}

	// Now mark the job complete so the receipt phase runs.
	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	got.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	got.Status.StartTime = &now
	got.Status.CompletionTime = &now
	if err := c.Status().Update(context.Background(), &got); err != nil {
		t.Fatalf("status update: %v", err)
	}

	reconcileUntilStable(t, r, key)

	rcpt := chio.lastReceipt
	if rcpt.CapabilityID != "cap-scope" {
		t.Fatalf("authoritative CapabilityID overridden: got %q", rcpt.CapabilityID)
	}
	// Advisory annotation must surface the pod's claim under the advisory
	// envelope only, never as an authoritative field on the JobReceipt.
	if len(rcpt.Steps) != 1 {
		t.Fatalf("expected 1 step receipt, got %d", len(rcpt.Steps))
	}
	advisory := rcpt.Steps[0].AdvisoryPodAnnotation
	if advisory == nil {
		t.Fatalf("expected advisory pod annotation to be populated")
	}
	if advisory.Source != chioapi.AdvisoryPodAnnotationSource {
		t.Fatalf("advisory source mismatch: got %q", advisory.Source)
	}
	if !strings.Contains(advisory.Payload, "tools:admin") {
		t.Fatalf("advisory payload should preserve the workload's claim verbatim, got %q", advisory.Payload)
	}
}

func containsFinalizer(job *batchv1.Job, name string) bool {
	for _, f := range job.Finalizers {
		if f == name {
			return true
		}
	}
	return false
}

func isUnreachable(err error) bool {
	return err != nil && (err == chioapi.ErrSidecarUnreachable || errorsIs(err, chioapi.ErrSidecarUnreachable))
}

// errorsIs is a local wrapper so test code compiles without re-importing
// errors in both directions.
func errorsIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
