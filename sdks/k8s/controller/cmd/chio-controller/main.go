// Command chio-controller is the entrypoint for the Chio K8s Job controller.
//
// The controller watches batch/v1 Job objects labeled
// chio.world/governed=true, mints a Chio capability grant at creation,
// harvests per-pod receipts across the Job lifecycle, and releases the grant
// while emitting a JobReceipt on Job completion or failure.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	chioapi "github.com/backbay-labs/chio-k8s-controller/internal/chio"
	"github.com/backbay-labs/chio-k8s-controller/internal/reconciler"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	if err := run(); err != nil {
		// main is the only place os.Exit is used per project policy.
		fmt.Fprintf(os.Stderr, "chio-controller: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		metricsAddr             string
		probeAddr               string
		leaderElect             bool
		leaderNamespace         string
		chioSidecarURL          string
		chioSidecarControlToken string
		chioRequestTimeout      time.Duration
		reconcileConcurrency    int
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&leaderElect, "leader-elect", false,
		"Enable leader election for controller manager.")
	flag.StringVar(&leaderNamespace, "leader-election-namespace", "chio-system",
		"Namespace used for leader election lease.")
	flag.StringVar(&chioSidecarURL, "chio-sidecar-url",
		envDefault("CHIO_SIDECAR_URL", "http://chio-sidecar.chio-system.svc.cluster.local:9090"),
		"Base URL of the Chio sidecar HTTP API.")
	flag.StringVar(&chioSidecarControlToken, "chio-sidecar-control-token",
		envDefault("CHIO_SIDECAR_CONTROL_TOKEN", ""),
		"Optional bearer token used for remote Chio sidecar control endpoints.")
	flag.DurationVar(&chioRequestTimeout, "chio-request-timeout", 10*time.Second,
		"HTTP timeout for requests to the Chio sidecar.")
	flag.IntVar(&reconcileConcurrency, "max-concurrent-reconciles", 4,
		"Max concurrent Job reconciles.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	logger := ctrl.Log.WithName("chio-controller")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          leaderElect,
		LeaderElectionID:        "chio-k8s-controller.chio.world",
		LeaderElectionNamespace: leaderNamespace,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// Honor the --chio-request-timeout flag instead of falling back to the
	// client's internal 10s default when nil is passed.
	httpClient := &http.Client{Timeout: chioRequestTimeout}
	chioClient := chioapi.NewClient(chioSidecarURL, chioSidecarControlToken, httpClient)
	recorder := mgr.GetEventRecorderFor("chio-k8s-controller")

	r := reconciler.NewJobReconciler(mgr.GetClient(), mgr.GetScheme(), chioClient, recorder)
	// Honor the --max-concurrent-reconciles flag so operator-configured
	// concurrency is actually applied to the controller options.
	r.MaxConcurrentReconciles = reconcileConcurrency
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}

	logger.Info("starting chio-controller",
		"sidecar", chioSidecarURL,
		"sidecar_control_token_configured", chioSidecarControlToken != "",
		"leader_elect", leaderElect,
		"concurrency", reconcileConcurrency,
	)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
