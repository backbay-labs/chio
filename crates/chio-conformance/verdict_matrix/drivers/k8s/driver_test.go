// M07.P6.T4: k8s admission-webhook driver smoke tests.
//
// Active execution against a live Chio sidecar through the controller test
// harness is operator-tactical and out of P6 scope. These tests cover the
// scenario-corpus loader, the verdict-tuple normalizer, and the
// unsupported-without-sidecar path.

package main

import (
	"strings"
	"testing"
)

func TestDriverConstants(t *testing.T) {
	if driverName != "k8s-admission-webhook" {
		t.Fatalf("driverName = %q, want %q", driverName, "k8s-admission-webhook")
	}
	if matrixRole != "deployment-shape" {
		t.Fatalf("matrixRole = %q, want %q", matrixRole, "deployment-shape")
	}
	if underlyingDriver != "rust-kernel" {
		t.Fatalf("underlyingDriver = %q, want %q", underlyingDriver, "rust-kernel")
	}
}

func TestNormalizeSortsScopes(t *testing.T) {
	tuple := verdictTuple{
		Verdict:    "allow",
		ReasonCode: "urn:chio:error:none",
		ScopeSet:   []string{"tool:write", "tool:read"},
	}
	got := normalize(tuple)
	want := []string{"tool:read", "tool:write"}
	if len(got.ScopeSet) != len(want) {
		t.Fatalf("got len %d, want %d", len(got.ScopeSet), len(want))
	}
	for i, scope := range want {
		if got.ScopeSet[i] != scope {
			t.Fatalf("scope_set[%d] = %q, want %q", i, got.ScopeSet[i], scope)
		}
	}
}

func TestRunDriverReportsUnsupportedWithoutSidecar(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Skipf("not running inside the chio repository: %v", err)
	}
	scenarioRoot := root + "/crates/chio-conformance/verdict_matrix/scenarios"
	r, err := runDriver(scenarioRoot, "")
	if err != nil {
		t.Fatalf("runDriver failed: %v", err)
	}
	if r.Driver != driverName {
		t.Fatalf("driver = %q, want %q", r.Driver, driverName)
	}
	if r.Total == 0 {
		t.Fatal("expected scenarios to load from the corpus")
	}
	if r.Unsupported != r.Total {
		t.Fatalf("unsupported = %d, want %d", r.Unsupported, r.Total)
	}
	if r.Passed != 0 || r.Failed != 0 {
		t.Fatalf("expected 0 passed and 0 failed; got passed=%d failed=%d", r.Passed, r.Failed)
	}
	first := r.Outcomes[0]
	if first.Status != "unsupported" {
		t.Fatalf("first outcome status = %q, want %q", first.Status, "unsupported")
	}
	if !strings.Contains(first.Diagnostic, sidecarEnv) {
		t.Fatalf("diagnostic %q must name the sidecar env var", first.Diagnostic)
	}
}
