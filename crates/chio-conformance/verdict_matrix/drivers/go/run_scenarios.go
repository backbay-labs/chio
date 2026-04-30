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
		diagnostic := "go-http-sdk delegates matrix verdicts to a sidecar and has no local semantic evaluator"
		if scenario.Script.Operation != "tool.call" {
			diagnostic = "go-http-sdk does not emit non-tool-call verdicts"
		}
		result.Unsupported++
		result.Outcomes = append(result.Outcomes, outcome{
			ScenarioID: scenario.ID,
			Status:     "unsupported",
			Expected:   expected,
			Diagnostic: diagnostic,
		})
	}
	return result, nil
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
