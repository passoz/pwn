package gates_test

import (
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

func TestValidateTaskAtomicityNumbersTasksWithoutID(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{
			map[string]any{"id": "T1", "components": []any{"core"}},
			map[string]any{"spec_reference": "CAP-1, CAP-2", "components": []any{"api", "web"}},
		},
	})

	findings := gates.ValidateTaskAtomicity(workDir)
	// A segunda task não tem id: o índice (2) a identifica.
	spec := requireFinding(t, findings, "FIND-ATOMIC-SPEC-2")
	if spec.Severity != contract.SeverityMedium || spec.TargetRefs[0] != "CAP-1, CAP-2" {
		t.Fatalf("finding = %+v", spec)
	}
	comp := requireFinding(t, findings, "FIND-ATOMIC-COMP-2")
	if comp.Description != "Task 2 cobre 2 componentes (api, web)" {
		t.Fatalf("description = %q", comp.Description)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestValidateTaskAtomicityCountsBehaviorConjunctions(t *testing.T) {
	cases := []struct {
		name     string
		behavior string
		flagged  bool
		count    string
	}{
		{"três conjunções ainda é atômica", "valida e grava e envia e registra", false, ""},
		{"quatro conjunções em português", "valida e grava e envia e registra e avisa", true, "4"},
		{"conjunções em inglês e português somam", "parse and load e save and log e done", true, "4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := newWork(t)
			writeJSON(t, workDir, "plan.json", map[string]any{
				"tasks": []any{map[string]any{"id": "T1", "behavior": tc.behavior}},
			})
			findings := gates.ValidateTaskAtomicity(workDir)
			if !tc.flagged {
				if len(findings) != 0 {
					t.Fatalf("findings = %+v", findings)
				}
				return
			}
			finding := requireFinding(t, findings, "FIND-ATOMIC-BEHAVIOR-T1")
			if finding.Severity != contract.SeverityLow || !strings.Contains(finding.Description, "("+tc.count+" conjunções)") {
				t.Fatalf("finding = %+v", finding)
			}
		})
	}
}

func TestComputeWorkCoverageIgnoresNonObjectTasks(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{
			"texto solto",
			map[string]any{"id": "T1", "contract_id": "CTR-1", "acceptance_criteria": []any{map[string]any{"command": "x"}}},
			map[string]any{"id": "T2", "contract_id": "", "acceptance_criteria": []any{}},
		},
	})

	coverage := gates.ComputeWorkCoverage(workDir)
	if coverage.Tasks != 3 || coverage.TasksWithContract != 1 || coverage.TasksWithACs != 1 {
		t.Fatalf("coverage = %+v", coverage)
	}
}
