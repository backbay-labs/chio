// k8s admission-webhook driver smoke tests.
//
// Cover the scenario-corpus loader, the verdict-tuple normalizer, the
// /chio/evaluate response decoder, the set-but-unreachable fail gate, and the
// unsupported-without-sidecar path. Live execution against a running Chio
// sidecar is covered by the operator-supplied CHIO_VERDICT_MATRIX_SIDECAR_URL
// integration path.

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

func TestRunDriverRecordsFailWhenSidecarIsSetButUnreachable(t *testing.T) {
	// A sidecar URL pointing at a closed port must surface as fail, never a
	// silent skip: a set-but-broken sidecar cannot pass.
	root, err := repoRoot()
	if err != nil {
		t.Skipf("not running inside the chio repository: %v", err)
	}
	scenarioRoot := root + "/crates/chio-conformance/verdict_matrix/scenarios"
	r, err := runDriver(scenarioRoot, "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("runDriver failed: %v", err)
	}
	if r.Total == 0 {
		t.Fatal("expected scenarios to load from the corpus")
	}
	if r.Unsupported != 0 {
		t.Fatalf("unsupported = %d, want 0", r.Unsupported)
	}
	if r.Passed != 0 {
		t.Fatalf("passed = %d, want 0", r.Passed)
	}
	if r.Failed != r.Total {
		t.Fatalf("failed = %d, want %d", r.Failed, r.Total)
	}
	if r.Outcomes[0].Status != "fail" {
		t.Fatalf("first outcome status = %q, want fail", r.Outcomes[0].Status)
	}
}

func TestTupleFromEvaluateResponseAllowWithMatrixMetadata(t *testing.T) {
	raw := []byte(`{"verdict":{"verdict":"allow"},"receipt":{"metadata":{"verdict_matrix":` +
		`{"reason_code":"urn:chio:error:none","scope_set":["tool:write","tool:read"]}}}}`)
	tuple, err := tupleFromEvaluateResponse(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if tuple.Verdict != "allow" {
		t.Fatalf("verdict = %q, want allow", tuple.Verdict)
	}
	if tuple.ReasonCode != "urn:chio:error:none" {
		t.Fatalf("reason_code = %q, want urn:chio:error:none", tuple.ReasonCode)
	}
	want := []string{"tool:read", "tool:write"}
	if len(tuple.ScopeSet) != len(want) {
		t.Fatalf("scope_set len = %d, want %d", len(tuple.ScopeSet), len(want))
	}
	for i, scope := range want {
		if tuple.ScopeSet[i] != scope {
			t.Fatalf("scope_set[%d] = %q, want %q", i, tuple.ScopeSet[i], scope)
		}
	}
}

func TestTupleFromEvaluateResponseDenyFallsBackToReason(t *testing.T) {
	raw := []byte(`{"verdict":{"verdict":"deny","reason":"urn:chio:error:capability:revoked",` +
		`"guard":"capability"},"receipt":{"metadata":{}}}`)
	tuple, err := tupleFromEvaluateResponse(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if tuple.Verdict != "deny" {
		t.Fatalf("verdict = %q, want deny", tuple.Verdict)
	}
	if tuple.ReasonCode != "urn:chio:error:capability:revoked" {
		t.Fatalf("reason_code = %q, want urn:chio:error:capability:revoked", tuple.ReasonCode)
	}
	if len(tuple.ScopeSet) != 0 {
		t.Fatalf("scope_set len = %d, want 0", len(tuple.ScopeSet))
	}
}

func TestScenarioToHTTPRequestSetsToolCallFieldsAndGetForRead(t *testing.T) {
	s := scenario{
		ID: "capability-subset-001-read-exact",
		Script: scenarioScript{
			Operation:        "tool.call",
			Tool:             "files.read",
			InputJSON:        "{}",
			CapabilityScopes: []string{"tool:read"},
		},
	}
	req := scenarioToHTTPRequest(s)
	if req["method"] != "GET" {
		t.Fatalf("method = %v, want GET", req["method"])
	}
	if req["tool_server"] != matrixServerID {
		t.Fatalf("tool_server = %v, want %q", req["tool_server"], matrixServerID)
	}
	if req["tool_name"] != "files.read" {
		t.Fatalf("tool_name = %v, want files.read", req["tool_name"])
	}
	if req["path"] != "/chio/tools/verdict-matrix/files.read" {
		t.Fatalf("path = %v, want reserved /chio/tools path", req["path"])
	}
	if req["route_pattern"] != req["path"] {
		t.Fatalf("route_pattern = %v, want path-derived route", req["route_pattern"])
	}
	if _, ok := req["body_hash"]; ok {
		t.Fatal("GET request must not carry a body hash")
	}
}
