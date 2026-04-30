// M07.P6.T4: k8s admission-webhook deployment-shape verdict-matrix driver.
//
// The driver loads the canonical scenario corpus from
// crates/chio-conformance/verdict_matrix/scenarios/ and emits a JSON report
// on stdout shaped as (verdict, reason_code, scope_set) per scenario by
// invoking the trajectory-1 sdks/k8s/webhooks admission surface through the
// controller test harness. The controller does not embed kernel evaluation;
// it forwards admission requests to a Chio sidecar. The deployment-shape
// driver mirrors the trajectory-1 TypeScript node-http driver contract: an
// operator-supplied sidecar URL is read from CHIO_VERDICT_MATRIX_SIDECAR_URL
// (with CHIO_SIDECAR_URL fallback). Without that variable, every scenario
// is reported as unsupported with a diagnostic that names the missing
// variable.
//
// The controller-test-harness wiring is operator-tactical and out of
// M07.P6.T4 scope; the scaffold registers the driver shape so the M02
// hash-pinned manifest can enumerate `k8s-admission-webhook` and the
// `verdict_matrix.deployment_shape_smoke` integration test can assert the
// registration.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	driverName         = "k8s-admission-webhook"
	matrixRole         = "deployment-shape"
	underlyingDriver   = "rust-kernel"
	sidecarEnv         = "CHIO_VERDICT_MATRIX_SIDECAR_URL"
	sidecarFallbackEnv = "CHIO_SIDECAR_URL"
	scenarioSchema     = "chio.verdict-matrix.scenario.v1"
)

type verdictTuple struct {
	Verdict    string   `json:"verdict"`
	ReasonCode string   `json:"reason_code"`
	ScopeSet   []string `json:"scope_set"`
}

type scenario struct {
	Schema   string       `json:"schema"`
	ID       string       `json:"id"`
	Category string       `json:"category"`
	Requires []string     `json:"requires"`
	Expected verdictTuple `json:"expected"`
}

type outcome struct {
	ScenarioID string        `json:"scenario_id"`
	Status     string        `json:"status"`
	Expected   verdictTuple  `json:"expected"`
	Actual     *verdictTuple `json:"actual,omitempty"`
	Diagnostic string        `json:"diagnostic,omitempty"`
}

type report struct {
	Driver           string    `json:"driver"`
	MatrixRole       string    `json:"matrix_role"`
	UnderlyingDriver string    `json:"underlying_driver"`
	Total            int       `json:"total"`
	Passed           int       `json:"passed"`
	Failed           int       `json:"failed"`
	Unsupported      int       `json:"unsupported"`
	Outcomes         []outcome `json:"outcomes"`
}

func main() {
	root := flag.String("scenario-root", defaultScenarioRoot(), "scenario corpus root")
	flag.Parse()

	sidecarURL := strings.TrimSpace(os.Getenv(sidecarEnv))
	if sidecarURL == "" {
		sidecarURL = strings.TrimSpace(os.Getenv(sidecarFallbackEnv))
	}

	r, err := runDriver(*root, sidecarURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if r.Failed > 0 {
		os.Exit(1)
	}
}

func defaultScenarioRoot() string {
	root, err := repoRoot()
	if err != nil {
		return "crates/chio-conformance/verdict_matrix/scenarios"
	}
	return filepath.Join(root, "crates/chio-conformance/verdict_matrix/scenarios")
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if exists(filepath.Join(dir, "Cargo.toml")) &&
			exists(filepath.Join(dir, "crates/chio-conformance/verdict_matrix")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find repo root")
		}
		dir = parent
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadScenarios(root string) ([]scenario, error) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("scenario root %q does not exist or is not a directory", root)
	}
	var paths []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".json" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	scenarios := make([]scenario, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var s scenario
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if s.Schema != scenarioSchema {
			return nil, fmt.Errorf("%s has unsupported scenario schema %q", path, s.Schema)
		}
		scenarios = append(scenarios, s)
	}
	return scenarios, nil
}

func normalize(t verdictTuple) verdictTuple {
	scopes := append([]string{}, t.ScopeSet...)
	sort.Strings(scopes)
	t.ScopeSet = scopes
	return t
}

func runDriver(root, sidecarURL string) (*report, error) {
	scenarios, err := loadScenarios(root)
	if err != nil {
		return nil, err
	}
	outcomes := make([]outcome, 0, len(scenarios))
	for _, s := range scenarios {
		var diagnostic string
		if strings.TrimSpace(sidecarURL) == "" {
			diagnostic = fmt.Sprintf(
				"set %s (or %s) to a live Chio sidecar; "+
					"the k8s admission-webhook controller does not embed kernel evaluation",
				sidecarEnv, sidecarFallbackEnv)
		} else {
			diagnostic = "k8s admission-webhook controller test harness wiring is " +
				"operator-tactical; the M07.P6.T4 scaffold registers the driver shape only"
		}
		outcomes = append(outcomes, outcome{
			ScenarioID: s.ID,
			Status:     "unsupported",
			Expected:   normalize(s.Expected),
			Actual:     nil,
			Diagnostic: diagnostic,
		})
	}
	r := &report{
		Driver:           driverName,
		MatrixRole:       matrixRole,
		UnderlyingDriver: underlyingDriver,
		Total:            len(outcomes),
		Outcomes:         outcomes,
	}
	for _, o := range outcomes {
		switch o.Status {
		case "pass":
			r.Passed++
		case "fail":
			r.Failed++
		case "unsupported":
			r.Unsupported++
		}
	}
	return r, nil
}
