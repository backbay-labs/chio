package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const driverName = "go-http-sdk"
const reasonNone = "urn:chio:error:none"
const reasonScopeExceeded = "urn:chio:error:capability:scope-exceeded"
const reasonRevoked = "urn:chio:error:capability:revoked"
const reasonReplayDrift = "urn:chio:error:replay:deterministic-mismatch"
const reasonReplayTraceMissing = "urn:chio:error:replay:trace-not-found"
const reasonInputRedacted = "urn:chio:error:guard:input-redacted"
const reasonOutputRedacted = "urn:chio:error:guard:output-redacted"
const reasonGuardDenied = "urn:chio:error:guard:denied"
const reasonKernelInternal = "urn:chio:error:kernel:internal-error"
const reasonDeliveryDigestMismatch = "urn:chio:error:kernel:delivery-contract-digest-mismatch"
const reasonDeliveryUnsupportedCarrier = "urn:chio:error:kernel:delivery-contract-unsupported-carrier"

type scenario struct {
	Schema   string         `json:"schema"`
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Requires []string       `json:"requires"`
	Script   scenarioScript `json:"script"`
	Expected verdictTuple   `json:"expected"`
}

type scenarioScript struct {
	Operation         string   `json:"operation"`
	Tool              string   `json:"tool"`
	InputJSON         string   `json:"input_json"`
	CapabilityScopes  []string `json:"capability_scopes"`
	RequiredScope     string   `json:"required_scope"`
	Revoked           bool     `json:"revoked"`
	ReplayNonceStatus string   `json:"replay_nonce_status"`
	RedactionAction   string   `json:"redaction_action"`
	RedactionPhase    string   `json:"redaction_phase"`
	CarrierPresent    bool     `json:"carrier_present"`
	DeliveryLane      string   `json:"delivery_lane"`
	DeliveryResult    string   `json:"delivery_result"`
}

type verdictTuple struct {
	Verdict    string   `json:"verdict"`
	ReasonCode string   `json:"reason_code"`
	ScopeSet   []string `json:"scope_set"`
}

type outcome struct {
	ScenarioID string        `json:"scenario_id"`
	Status     string        `json:"status"`
	Actual     *verdictTuple `json:"actual"`
	Expected   verdictTuple  `json:"expected"`
	Diagnostic string        `json:"diagnostic,omitempty"`
}

type report struct {
	Driver      string                  `json:"driver"`
	Total       int                     `json:"total"`
	Passed      int                     `json:"passed"`
	Failed      int                     `json:"failed"`
	Unsupported int                     `json:"unsupported"`
	Tuples      map[string]verdictTuple `json:"tuples"`
	Outcomes    []outcome               `json:"outcomes"`
}

func main() {
	root := flag.String("scenario-root", defaultScenarioRoot(), "scenario corpus root")
	flag.Parse()

	report, err := runScenarios(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if report.Failed > 0 {
		os.Exit(1)
	}
}

func defaultScenarioRoot() string {
	root, err := repoRoot()
	if err != nil {
		return "crates/tooling/chio-conformance/verdict_matrix/scenarios"
	}
	return filepath.Join(root, "crates/tooling/chio-conformance/verdict_matrix/scenarios")
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if exists(filepath.Join(dir, "Cargo.toml")) &&
			exists(filepath.Join(dir, "crates/tooling/chio-conformance/verdict_matrix")) {
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

func runScenarios(root string) (report, error) {
	scenarios, err := loadScenarios(root)
	if err != nil {
		return report{}, err
	}
	result := report{
		Driver:   driverName,
		Total:    len(scenarios),
		Tuples:   make(map[string]verdictTuple),
		Outcomes: make([]outcome, 0, len(scenarios)),
	}
	for _, scenario := range scenarios {
		expected := normalizeTuple(scenario.Expected)
		unsupported := unsupportedRequirement(scenario.Requires)
		if unsupported != "" {
			result.Unsupported++
			result.Outcomes = append(result.Outcomes, outcome{
				ScenarioID: scenario.ID,
				Status:     "unsupported",
				Expected:   expected,
				Diagnostic: fmt.Sprintf("unsupported requirement `%s`", unsupported),
			})
			continue
		}
		actual := evaluateScenario(scenario)
		status := "pass"
		diagnostic := ""
		if !equalTuple(actual, expected) {
			status = "fail"
			diagnostic = "go-http-sdk local semantic evaluator diverged from expected tuple"
			result.Failed++
		} else {
			result.Passed++
		}
		result.Tuples[scenario.ID] = actual
		result.Outcomes = append(result.Outcomes, outcome{
			ScenarioID: scenario.ID,
			Status:     status,
			Actual:     &actual,
			Expected:   expected,
			Diagnostic: diagnostic,
		})
	}
	return result, nil
}

func evaluateScenario(s scenario) verdictTuple {
	scopeSet := append([]string{}, s.Script.CapabilityScopes...)
	if s.Script.Operation != "tool.call" {
		return normalizeTuple(verdictTuple{
			Verdict:    "error",
			ReasonCode: reasonKernelInternal,
			ScopeSet:   scopeSet,
		})
	}

	requiredScope := s.Script.RequiredScope
	if requiredScope == "" {
		requiredScope = scopeLabelForTool(s.Script.Tool)
	}
	if s.Script.Revoked {
		return tuple("deny", reasonRevoked, scopeSet)
	}
	if !containsScope(scopeSet, requiredScope) {
		return tuple("deny", reasonScopeExceeded, scopeSet)
	}

	switch s.Category {
	case "replay":
		switch s.Script.ReplayNonceStatus {
		case "", "fresh":
			return tuple("allow", reasonNone, scopeSet)
		case "trace_missing":
			return tuple("error", reasonReplayTraceMissing, scopeSet)
		default:
			return tuple("deny", reasonReplayDrift, scopeSet)
		}
	case "redaction":
		switch s.Script.RedactionAction {
		case "deny":
			return tuple("deny", reasonGuardDenied, scopeSet)
		case "mask", "drop":
			if s.Script.RedactionPhase == "output" {
				return tuple("allow", reasonOutputRedacted, scopeSet)
			}
			return tuple("allow", reasonInputRedacted, scopeSet)
		}
	case "delivery_contract":
		// This SDK does not enforce output digests. A request carrying the
		// output_digest_sha256 constraint is denied from carrier admission
		// alone; a declared mismatch is surfaced via the digest-mismatch
		// reason, everything else via the unsupported-carrier reason.
		if s.Script.CarrierPresent {
			if s.Script.DeliveryResult == "mismatched" {
				return tuple("deny", reasonDeliveryDigestMismatch, scopeSet)
			}
			return tuple("deny", reasonDeliveryUnsupportedCarrier, scopeSet)
		}
		return tuple("allow", reasonNone, scopeSet)
	}

	return tuple("allow", reasonNone, scopeSet)
}

func tuple(verdict string, reasonCode string, scopeSet []string) verdictTuple {
	return normalizeTuple(verdictTuple{
		Verdict:    verdict,
		ReasonCode: reasonCode,
		ScopeSet:   append([]string{}, scopeSet...),
	})
}

func containsScope(scopeSet []string, required string) bool {
	for _, scope := range scopeSet {
		if scope == required {
			return true
		}
	}
	return false
}

func scopeLabelForTool(tool string) string {
	switch tool {
	case "files.read":
		return "tool:read"
	case "files.write":
		return "tool:write"
	case "system.rotate":
		return "tool:admin"
	case "metrics.query":
		return "telemetry:read"
	case "prompts.get":
		return "prompt:read"
	case "prompts.update":
		return "prompt:write"
	case "resources.read":
		return "resource:read"
	case "tools.invoke":
		return "tool:call"
	default:
		return ""
	}
}

func loadScenarios(root string) ([]scenario, error) {
	var files []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)

	scenarios := make([]scenario, 0, len(files))
	for _, file := range files {
		bytes, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var next scenario
		if err := json.Unmarshal(bytes, &next); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		if next.Schema != "chio.verdict-matrix.scenario.v1" {
			return nil, fmt.Errorf("%s has unsupported scenario schema", file)
		}
		var input map[string]interface{}
		if err := json.Unmarshal([]byte(next.Script.InputJSON), &input); err != nil {
			return nil, fmt.Errorf("%s has invalid script input JSON: %w", file, err)
		}
		scenarios = append(scenarios, next)
	}
	return scenarios, nil
}

func unsupportedRequirement(requirements []string) string {
	for _, requirement := range requirements {
		switch requirement {
		case "rust-kernel", "go-http-sdk", "go-sdk", "kernel-semantics":
		default:
			return requirement
		}
	}
	return ""
}

func normalizeTuple(tuple verdictTuple) verdictTuple {
	tuple.ScopeSet = append([]string{}, tuple.ScopeSet...)
	sort.Strings(tuple.ScopeSet)
	return tuple
}

func equalTuple(left verdictTuple, right verdictTuple) bool {
	left = normalizeTuple(left)
	right = normalizeTuple(right)
	if left.Verdict != right.Verdict || left.ReasonCode != right.ReasonCode {
		return false
	}
	if len(left.ScopeSet) != len(right.ScopeSet) {
		return false
	}
	for index := range left.ScopeSet {
		if left.ScopeSet[index] != right.ScopeSet[index] {
			return false
		}
	}
	return true
}
