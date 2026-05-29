// k8s admission-webhook deployment-shape verdict-matrix driver.
//
// The driver loads the canonical scenario corpus from
// crates/chio-conformance/verdict_matrix/scenarios/ and emits a JSON report
// on stdout shaped as (verdict, reason_code, scope_set) per scenario by
// forwarding each scenario to a Chio sidecar over the production
// POST /chio/evaluate wire surface. The sdks/k8s/webhooks admission controller
// does not embed kernel evaluation; it relays admission requests to a Chio
// sidecar, so this deployment-shape driver mirrors that contract exactly.
//
// Runtime-availability gate: the sidecar URL is read from
// CHIO_VERDICT_MATRIX_SIDECAR_URL (with CHIO_SIDECAR_URL fallback). When a
// sidecar URL is present the driver issues a real HTTP POST per scenario,
// parses the verdict and the verdict_matrix receipt metadata, and emits a
// pass/fail tuple against the scenario's expected tuple; a sidecar that is
// set-but-unreachable surfaces as a fail (never a silent skip). Without that
// variable, every scenario is reported as unsupported with a diagnostic that
// names the missing variable, because the controller has no in-process kernel
// and therefore no verdict it can honestly emit on its own.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	driverName         = "k8s-admission-webhook"
	matrixRole         = "deployment-shape"
	underlyingDriver   = "rust-kernel"
	sidecarEnv         = "CHIO_VERDICT_MATRIX_SIDECAR_URL"
	sidecarFallbackEnv = "CHIO_SIDECAR_URL"
	scenarioSchema     = "chio.verdict-matrix.scenario.v1"
	matrixServerID     = "verdict-matrix"
	reasonNone         = "urn:chio:error:none"
	reasonKernel       = "urn:chio:error:kernel:internal-error"
	evaluatePath       = "/chio/evaluate"
)

const requestTimestampSecs = 1700000000

type verdictTuple struct {
	Verdict    string   `json:"verdict"`
	ReasonCode string   `json:"reason_code"`
	ScopeSet   []string `json:"scope_set"`
}

type scenarioScript struct {
	Operation        string   `json:"operation"`
	Tool             string   `json:"tool"`
	InputJSON        string   `json:"input_json"`
	CapabilityScopes []string `json:"capability_scopes"`
}

type scenario struct {
	Schema   string         `json:"schema"`
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Requires []string       `json:"requires"`
	Script   scenarioScript `json:"script"`
	Expected verdictTuple   `json:"expected"`
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

func methodForTool(tool string) string {
	if strings.HasSuffix(tool, ".read") || strings.HasSuffix(tool, ".get") || tool == "metrics.query" {
		return "GET"
	}
	return "POST"
}

// scenarioToHTTPRequest builds the ChioHttpRequest body for a scenario,
// populating the tool-call fields the sidecar's capability-scope evaluator
// reads. Mirrors the node-http transport-client driver so the deployment
// shapes share one wire contract.
func scenarioToHTTPRequest(s scenario) map[string]interface{} {
	tool := s.Script.Tool
	method := methodForTool(tool)
	var arguments interface{}
	if err := json.Unmarshal([]byte(s.Script.InputJSON), &arguments); err != nil {
		arguments = nil
	}
	bodyLength := 0
	req := map[string]interface{}{
		"request_id": "req-" + s.ID,
		"method":     method,
		"path":       "/" + strings.ReplaceAll(tool, ".", "/"),
		"query":      map[string]interface{}{},
		"headers": map[string]interface{}{
			"content-type": "application/json",
		},
		"caller": map[string]interface{}{
			"subject":     "agent:" + s.ID,
			"auth_method": map[string]interface{}{"method": "anonymous"},
			"verified":    true,
			"agent_id":    "agent:" + s.ID,
		},
		"route_pattern": matrixServerID + ":" + tool,
		"capability_id": "cap-" + s.ID,
		"tool_server":   matrixServerID,
		"tool_name":     tool,
		"arguments":     arguments,
		"timestamp":     requestTimestampSecs,
	}
	if method != "GET" && method != "HEAD" {
		bodyLength = len([]byte(s.Script.InputJSON))
		if bodyLength > 0 {
			req["body_hash"] = strings.Repeat("0", 64)
		}
	}
	req["body_length"] = bodyLength
	return req
}

func capabilityTokenFor(s scenario) string {
	token := map[string]interface{}{
		"id":     "cap-" + s.ID,
		"scopes": s.Script.CapabilityScopes,
	}
	if token["scopes"] == nil {
		token["scopes"] = []string{}
	}
	raw, err := json.Marshal(token)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// tupleFromEvaluateResponse derives the matrix verdict tuple from a
// /chio/evaluate response body. The authoritative reason_code and scope_set
// come from receipt.metadata.verdict_matrix; the verdict tag falls back to the
// deny reason when the matrix metadata is absent.
func tupleFromEvaluateResponse(raw []byte) (verdictTuple, error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return verdictTuple{}, err
	}
	verdictObj, _ := parsed["verdict"].(map[string]interface{})
	verdictTag, _ := verdictObj["verdict"].(string)
	verdict := "error"
	switch verdictTag {
	case "allow":
		verdict = "allow"
	case "deny":
		verdict = "deny"
	}

	var matrix map[string]interface{}
	if receipt, ok := parsed["receipt"].(map[string]interface{}); ok {
		if metadata, ok := receipt["metadata"].(map[string]interface{}); ok {
			matrix, _ = metadata["verdict_matrix"].(map[string]interface{})
		}
	}

	reasonCode := reasonFromVerdict(verdictTag, verdictObj)
	if matrix != nil {
		if rc, ok := matrix["reason_code"].(string); ok {
			reasonCode = rc
		}
	}

	scopeSet := []string{}
	if matrix != nil {
		if scopes, ok := matrix["scope_set"].([]interface{}); ok {
			for _, scope := range scopes {
				if s, ok := scope.(string); ok {
					scopeSet = append(scopeSet, s)
				}
			}
		}
	}
	sort.Strings(scopeSet)
	return verdictTuple{Verdict: verdict, ReasonCode: reasonCode, ScopeSet: scopeSet}, nil
}

func reasonFromVerdict(verdictTag string, verdictObj map[string]interface{}) string {
	switch verdictTag {
	case "allow":
		return reasonNone
	case "deny":
		if reason, ok := verdictObj["reason"].(string); ok {
			return reason
		}
		return reasonKernel
	default:
		return reasonKernel
	}
}

func tupleEqual(a, b verdictTuple) bool {
	if a.Verdict != b.Verdict || a.ReasonCode != b.ReasonCode || len(a.ScopeSet) != len(b.ScopeSet) {
		return false
	}
	for i := range a.ScopeSet {
		if a.ScopeSet[i] != b.ScopeSet[i] {
			return false
		}
	}
	return true
}

func evaluateScenario(client *http.Client, baseURL string, s scenario) outcome {
	expected := normalize(s.Expected)
	body, err := json.Marshal(scenarioToHTTPRequest(s))
	if err != nil {
		return failOutcome(s.ID, expected, fmt.Sprintf("failed to encode request: %v", err))
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+evaluatePath, bytes.NewReader(body))
	if err != nil {
		return failOutcome(s.ID, expected, fmt.Sprintf("failed to build request: %v", err))
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-chio-capability", capabilityTokenFor(s))
	resp, err := client.Do(req)
	if err != nil {
		return failOutcome(s.ID, expected, fmt.Sprintf("sidecar POST failed: %v", err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return failOutcome(s.ID, expected, fmt.Sprintf("failed to read sidecar response: %v", err))
	}
	if resp.StatusCode/100 != 2 {
		return failOutcome(s.ID, expected, fmt.Sprintf("sidecar returned %d: %s", resp.StatusCode, string(raw)))
	}
	actualTuple, err := tupleFromEvaluateResponse(raw)
	if err != nil {
		return failOutcome(s.ID, expected, fmt.Sprintf("failed to parse sidecar response: %v", err))
	}
	actual := normalize(actualTuple)
	if tupleEqual(actual, expected) {
		return outcome{ScenarioID: s.ID, Status: "pass", Expected: expected, Actual: &actual}
	}
	return outcome{
		ScenarioID: s.ID,
		Status:     "fail",
		Expected:   expected,
		Actual:     &actual,
		Diagnostic: "tuple mismatch against sidecar verdict",
	}
}

func failOutcome(id string, expected verdictTuple, diagnostic string) outcome {
	return outcome{ScenarioID: id, Status: "fail", Expected: expected, Diagnostic: diagnostic}
}

func runDriver(root, sidecarURL string) (*report, error) {
	scenarios, err := loadScenarios(root)
	if err != nil {
		return nil, err
	}
	sidecar := strings.TrimRight(strings.TrimSpace(sidecarURL), "/")
	var client *http.Client
	if sidecar != "" {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	outcomes := make([]outcome, 0, len(scenarios))
	for _, s := range scenarios {
		if sidecar == "" {
			outcomes = append(outcomes, outcome{
				ScenarioID: s.ID,
				Status:     "unsupported",
				Expected:   normalize(s.Expected),
				Actual:     nil,
				Diagnostic: fmt.Sprintf(
					"set %s (or %s) to a live Chio sidecar; "+
						"the k8s admission-webhook controller does not embed kernel evaluation",
					sidecarEnv, sidecarFallbackEnv),
			})
			continue
		}
		if s.Category == "capability" || s.Category == "revocation" {
			outcomes = append(outcomes, outcome{
				ScenarioID: s.ID,
				Status:     "unsupported",
				Expected:   normalize(s.Expected),
				Actual:     nil,
				Diagnostic: fmt.Sprintf(
					"k8s deployment-shape relay has no signed CapabilityToken builder; "+
						"sidecar evaluation of %s scenarios requires a signed CapabilityToken "+
						"(issuer + signature + time-valid) per chio-http-core authority validate_capability_token",
					s.Category),
			})
			continue
		}

		outcomes = append(outcomes, evaluateScenario(client, sidecar, s))
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
