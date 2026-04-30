package chio

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVerdictMatrixGoDriverMatchesCorpus(t *testing.T) {
	root := filepath.Clean("../../..")
	driverPath := filepath.Join(
		root,
		"crates/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go",
	)
	scenarioRoot := filepath.Join(
		root,
		"crates/chio-conformance/verdict_matrix/scenarios",
	)
	cmd := exec.Command(
		"go",
		"run",
		driverPath,
		"--scenario-root",
		scenarioRoot,
	)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("verdict matrix driver failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("verdict matrix driver failed: %v", err)
	}

	var report struct {
		Driver      string                    `json:"driver"`
		Total       int                       `json:"total"`
		Passed      int                       `json:"passed"`
		Failed      int                       `json:"failed"`
		Unsupported int                       `json:"unsupported"`
		Tuples      map[string]map[string]any `json:"tuples"`
		Outcomes    []struct {
			ScenarioID string `json:"scenario_id"`
			Status     string `json:"status"`
			Diagnostic string `json:"diagnostic"`
		} `json:"outcomes"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode verdict matrix report: %v\n%s", err, output)
	}

	if report.Driver != "go-http-sdk" {
		t.Fatalf("expected go-http-sdk driver, got %q", report.Driver)
	}
	if report.Total != 48 || report.Passed != 0 || report.Failed != 0 || report.Unsupported != 48 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if len(report.Tuples) != 0 {
		t.Fatalf("expected no tuples for unsupported Go SDK scenarios, got %d", len(report.Tuples))
	}
	if len(report.Outcomes) != 48 {
		t.Fatalf("expected 48 outcomes, got %d", len(report.Outcomes))
	}
	for _, outcome := range report.Outcomes {
		if outcome.Status != "unsupported" {
			t.Fatalf("expected unsupported outcome for %s, got %s", outcome.ScenarioID, outcome.Status)
		}
		if outcome.Diagnostic == "" {
			t.Fatalf("expected unsupported diagnostic for %s", outcome.ScenarioID)
		}
	}
}
