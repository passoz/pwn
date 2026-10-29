package gates_test

import (
	"reflect"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

// atomicPlan é um plano atômico de referência.
func atomicPlan() map[string]any {
	return map[string]any{
		"work_id":      "0001",
		"title":        "Plano atômico",
		"components":   []any{map[string]any{"name": "core", "purpose": "Componente principal"}},
		"global_gates": []any{"`bun test` — a suíte completa permanece verde"},
		"tasks": []any{
			map[string]any{
				"id":                   "1.1",
				"title":                "Implementar capacidade única",
				"requirement_id":       "FR-001",
				"behavior":             "entrega a capacidade declarada",
				"components":           []any{"core"},
				"files":                []any{"src/core/x.ts", "tests/x.test.ts"},
				"implementation_files": []any{"src/core/x.ts"},
				"test_files":           []any{"tests/x.test.ts"},
				"red":                  map[string]any{"command": "bun test tests/x.test.ts", "description": "a asserção X-001 falha antes da implementação"},
				"implementation_steps": []any{"RED", "GREEN"},
				"acceptance_criteria":  []any{map[string]any{"command": "bun test tests/x.test.ts", "description": "o comportamento X-001 é observado"}},
				"spec_reference":       "CAP-001",
				"contract_id":          "CTR-001",
			},
		},
	}
}

func TestValidateTaskAtomicityClean(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", atomicPlan())

	if findings := gates.ValidateTaskAtomicity(workDir); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestValidateTaskAtomicityAdvisoryFindings(t *testing.T) {
	workDir := newWork(t)
	plan := atomicPlan()
	tasks := plan["tasks"].([]any)
	task := tasks[0].(map[string]any)
	task["id"] = "2.1"
	task["spec_reference"] = "CAP-001 + CAP-002"
	task["components"] = []any{"core", "cli"}
	writeJSON(t, workDir, "plan.json", plan)

	byID := findingIDs(gates.ValidateTaskAtomicity(workDir))
	specFinding, ok := byID["FIND-ATOMIC-SPEC-2.1"]
	if !ok {
		t.Fatalf("findings = %+v", byID)
	}
	if specFinding.Severity != contract.SeverityMedium || specFinding.Type != contract.FindingCoverageGap ||
		specFinding.ResolutionOwner != "planner" || specFinding.Status != contract.FindingStatusOpen {
		t.Fatalf("specFinding = %+v", specFinding)
	}
	if specFinding.RequiredResolution != "Dividir a task para referenciar uma única capability" {
		t.Fatalf("required_resolution = %q", specFinding.RequiredResolution)
	}

	componentFinding, ok := byID["FIND-ATOMIC-COMP-2.1"]
	if !ok {
		t.Fatalf("findings = %+v", byID)
	}
	if componentFinding.Severity != contract.SeverityLow {
		t.Fatalf("severity = %q", componentFinding.Severity)
	}
	if !reflect.DeepEqual(componentFinding.TargetRefs, []string{"core", "cli"}) {
		t.Fatalf("target_refs = %v", componentFinding.TargetRefs)
	}
	if componentFinding.RequiredResolution != "Dividir a task por componente ou justificar o acoplamento" {
		t.Fatalf("required_resolution = %q", componentFinding.RequiredResolution)
	}

	// Atomicidade é advisory: nunca bloqueia o gate.
	if result := gates.EvaluateGateSpecPlan("0001", workDir).Result; result != gates.ResultPassWithNotes {
		t.Fatalf("result = %q", result)
	}
}

func TestValidateTaskAtomicityMissingPlan(t *testing.T) {
	workDir := newWork(t)
	if findings := gates.ValidateTaskAtomicity(workDir); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestComputeWorkCoverageEmptyDirectory(t *testing.T) {
	workDir := newWork(t)
	got := gates.ComputeWorkCoverage(workDir)
	if got != (gates.WorkCoverage{}) {
		t.Fatalf("coverage = %+v", got)
	}
}

func TestComputeWorkCoverageCounts(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"work_id":      "0001",
		"requirements": []any{map[string]any{"id": "FR-001"}, map[string]any{"id": "FR-002"}},
	})
	writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{"FR-001"}})
	writeJSON(t, workDir, "spec.json", map[string]any{
		"capabilities": []any{
			map[string]any{"id": "CAP-001", "rules": []any{"BR-001"}},
			map[string]any{"id": "CAP-002", "rules": []any{}},
		},
	})
	writeJSON(t, workDir, "plan.json", atomicPlan())

	want := gates.WorkCoverage{
		Requirements:          2,
		AcceptedRequirements:  1,
		Capabilities:          2,
		CapabilitiesWithRules: 1,
		Tasks:                 1,
		TasksWithContract:     1,
		TasksWithACs:          1,
	}
	if got := gates.ComputeWorkCoverage(workDir); got != want {
		t.Fatalf("coverage = %+v, want %+v", got, want)
	}
}

func TestEvaluateAllGatesCanonicalOrder(t *testing.T) {
	workDir := newWork(t)

	outputs := gates.EvaluateAllGates("0001", workDir)
	if len(outputs) != 5 {
		t.Fatalf("outputs = %d", len(outputs))
	}
	wanted := []string{
		"GATE-DISC-REQ",
		"GATE-REQ-PRD",
		"GATE-PRD-SPEC",
		"GATE-SPEC-PLAN",
		"GATE-PLAN-CONTRACT",
	}
	for index, output := range outputs {
		if output.Gate != wanted[index] {
			t.Fatalf("gate[%d] = %q", index, output.Gate)
		}
		// Não para no primeiro gate bloqueado: todos os artefatos estão ausentes.
		if output.Result != gates.ResultBlocked {
			t.Fatalf("gate[%d] result = %q", index, output.Result)
		}
	}
}
