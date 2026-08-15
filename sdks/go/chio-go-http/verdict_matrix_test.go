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
		"crates/tooling/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go",
	)
	scenarioRoot := filepath.Join(
		root,
		"crates/tooling/chio-conformance/verdict_matrix/scenarios",
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
	if report.Total != 60 || report.Passed != 60 || report.Failed != 0 || report.Unsupported != 0 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if len(report.Tuples) != 60 {
		t.Fatalf("expected 60 tuples for active Go SDK scenarios, got %d", len(report.Tuples))
	}
	if len(report.Outcomes) != 60 {
		t.Fatalf("expected 60 outcomes, got %d", len(report.Outcomes))
	}
	for _, outcome := range report.Outcomes {
		if outcome.Status != "pass" {
			t.Fatalf("expected pass outcome for %s, got %s", outcome.ScenarioID, outcome.Status)
		}
		if outcome.Diagnostic != "" {
			t.Fatalf("expected empty diagnostic for %s, got %q", outcome.ScenarioID, outcome.Diagnostic)
		}
	}
	traceMissing := report.Tuples["replay-verdict-004-missing-trace"]
	if traceMissing["verdict"] != "error" || traceMissing["reason_code"] != "urn:chio:error:replay:trace-not-found" {
		t.Fatalf("unexpected trace-missing tuple: %+v", traceMissing)
	}
	revokedRead := report.Tuples["revocation-propagation-002-revoked-read"]
	if revokedRead["verdict"] != "deny" || revokedRead["reason_code"] != "urn:chio:error:capability:revoked" {
		t.Fatalf("unexpected revoked-read tuple: %+v", revokedRead)
	}
	outputMask := report.Tuples["redaction-determinism-002-output-mask-read"]
	if outputMask["verdict"] != "allow" || outputMask["reason_code"] != "urn:chio:error:guard:output-redacted" {
		t.Fatalf("unexpected output-mask tuple: %+v", outputMask)
	}
	carrierAdmitted := report.Tuples["delivery-contract-001-carrier-admitted-read"]
	if carrierAdmitted["verdict"] != "deny" || carrierAdmitted["reason_code"] != "urn:chio:error:kernel:delivery-contract-unsupported-carrier" {
		t.Fatalf("unexpected carrier-admitted tuple: %+v", carrierAdmitted)
	}
	digestMismatch := report.Tuples["delivery-contract-006-mismatched-read"]
	if digestMismatch["verdict"] != "deny" || digestMismatch["reason_code"] != "urn:chio:error:kernel:delivery-contract-digest-mismatch" {
		t.Fatalf("unexpected digest-mismatch tuple: %+v", digestMismatch)
	}
}
