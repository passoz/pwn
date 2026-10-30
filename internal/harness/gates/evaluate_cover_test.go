package gates_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

// requireFinding falha quando o achado esperado não existe e o devolve.
func requireFinding(t *testing.T, findings []contract.Finding, id string) contract.Finding {
	t.Helper()
	finding, ok := findingIDs(findings)[id]
	if !ok {
		t.Fatalf("achado %s ausente em %+v", id, findings)
	}
	return finding
}

func TestGatesReportMalformedJSONAsCriticalFinding(t *testing.T) {
	workDir := newWork(t)
	const broken = "{ isto não é json"
	writeRawFile(t, workDir, "discovery.json", "{}")
	writeRawFile(t, workDir, "requirements.json", broken)
	writeRawFile(t, workDir, "prd.json", broken)
	writeRawFile(t, workDir, "spec.json", broken)
	writeRawFile(t, workDir, "plan.json", broken)

	cases := []struct {
		name     string
		output   gates.GateOutput
		findID   string
		prefix   string
		resolver string
	}{
		{"disc-req", gates.EvaluateGateDiscReq("0001", workDir), "FIND-ERR-01", "Erro ao ler JSON de requisitos: ", "product-owner"},
		{"req-prd", gates.EvaluateGateReqPrd("0001", workDir), "FIND-PRD-ERR", "Erro na leitura do prd.json: ", "product-owner"},
		{"prd-spec", gates.EvaluateGatePrdSpec("0001", workDir), "FIND-SPEC-ERR", "Erro ao ler spec.json: ", "architect"},
		{"spec-plan", gates.EvaluateGateSpecPlan("0001", workDir), "FIND-PLAN-ERR", "Erro ao ler plan.json: ", "planner"},
		{"plan-contract", gates.EvaluateGatePlanContract("0001", workDir), "FIND-CTR-ERR", "Erro ao ler plan.json: ", "planner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.output.Result != gates.ResultBlocked {
				t.Fatalf("result = %q", tc.output.Result)
			}
			if tc.output.Summary.Covered != 0 {
				t.Fatalf("covered = %d", tc.output.Summary.Covered)
			}
			finding := requireFinding(t, tc.output.Findings, tc.findID)
			if finding.Severity != contract.SeverityCritical || finding.Type != contract.FindingAmbiguity {
				t.Fatalf("finding = %+v", finding)
			}
			if !strings.HasPrefix(finding.Description, tc.prefix) || len(finding.Description) == len(tc.prefix) {
				t.Fatalf("description = %q", finding.Description)
			}
			if finding.ResolutionOwner != tc.resolver {
				t.Fatalf("owner = %q", finding.ResolutionOwner)
			}
		})
	}
}

func TestGateSpecPlanBlocksPlanWithoutTasks(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "spec.json", map[string]any{"capabilities": []any{}})
	writeJSON(t, workDir, "plan.json", map[string]any{"tasks": []any{}})

	output := gates.EvaluateGateSpecPlan("0001", workDir)
	if output.Result != gates.ResultBlocked || output.Summary.Covered != 0 {
		t.Fatalf("result/covered = %q/%d", output.Result, output.Summary.Covered)
	}
	finding := requireFinding(t, output.Findings, "FIND-PLAN-02")
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingCoverageGap {
		t.Fatalf("finding = %+v", finding)
	}
}

func TestGatePlanContractNamesTasksWithoutContract(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{
			map[string]any{"id": "T9"},
			map[string]any{"id": 7},
			map[string]any{"id": "T1", "contract_id": "CTR-INEXISTENTE"},
			"texto solto",
		},
	})

	output := gates.EvaluateGatePlanContract("0001", workDir)
	if output.Result != gates.ResultBlocked || output.Summary.Covered != 4 {
		t.Fatalf("result/covered = %q/%d", output.Result, output.Summary.Covered)
	}
	ids := findingIDs(output.Findings)
	for _, id := range []string{"FIND-CTR-TASK-T9", "FIND-CTR-TASK-7", "FIND-CTR-TASK-null"} {
		finding, ok := ids[id]
		if !ok {
			t.Fatalf("achado %s ausente em %+v", id, output.Findings)
		}
		if finding.Severity != contract.SeverityHigh {
			t.Fatalf("%s severity = %q", id, finding.Severity)
		}
	}
	if _, ok := ids["FIND-CTR-TASK-T1"]; ok {
		t.Fatal("task com contract_id não deve gerar FIND-CTR-TASK")
	}
	if finding := ids["FIND-CTR-TASK-7"]; finding.Description != "Task 7 não vincula contract_id congelado" {
		t.Fatalf("description = %q", finding.Description)
	}
	// O contrato referenciado não existe: o gate acusa a lacuna semântica.
	requireFinding(t, output.Findings, "FIND-SEM-CTR-MISSING-T1")
}

func TestGateDiscReqEmptyCriteriaDetection(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "discovery.json", map[string]any{"problem": "x"})
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"requirements": []any{
			map[string]any{"id": "R1", "acceptance_criteria": ""},
			map[string]any{"id": "R2", "acceptance_criteria": map[string]any{"length": 0}},
			map[string]any{"id": "R3", "acceptance_criteria": map[string]any{}},
			map[string]any{"id": "R4", "acceptance_criteria": 5},
			map[string]any{"id": "R5", "acceptance_criteria": false},
			map[string]any{"id": "R6", "acceptance_criteria": "texto"},
			map[string]any{"acceptance_criteria": []any{}},
			map[string]any{"id": 9, "acceptance_criteria": []any{}},
			"texto solto",
		},
	})

	output := gates.EvaluateGateDiscReq("0001", workDir)
	if output.Summary.Covered != 9 {
		t.Fatalf("covered = %d", output.Summary.Covered)
	}
	flagged := map[string]contract.Finding{}
	for _, finding := range output.Findings {
		if strings.HasPrefix(finding.ID, "FIND-REQ-") {
			flagged[finding.ID] = finding
		}
	}
	for _, id := range []string{"FIND-REQ-1", "FIND-REQ-2", "FIND-REQ-5", "FIND-REQ-7", "FIND-REQ-8", "FIND-REQ-9"} {
		if _, ok := flagged[id]; !ok {
			t.Fatalf("%s deveria ser achado; achados = %v", id, flagged)
		}
	}
	for _, id := range []string{"FIND-REQ-3", "FIND-REQ-4", "FIND-REQ-6"} {
		if _, ok := flagged[id]; ok {
			t.Fatalf("%s não deveria ser achado", id)
		}
	}
	if len(flagged) != 6 {
		t.Fatalf("achados FIND-REQ = %v", flagged)
	}
	if got := flagged["FIND-REQ-7"].SourceRefs; len(got) != 1 || got[0] != "REQ-7" {
		t.Fatalf("source_refs sem id = %v", got)
	}
	if got := flagged["FIND-REQ-7"].Description; got != "Requisito 7 sem critérios de aceite observáveis" {
		t.Fatalf("description sem id = %q", got)
	}
	if got := flagged["FIND-REQ-8"].SourceRefs; len(got) != 1 || got[0] != "9" {
		t.Fatalf("source_refs id numérico = %v", got)
	}
}

func TestGateDiscReqRequirementsFallbackFollowsTruthiness(t *testing.T) {
	stories := []any{map[string]any{"id": "US-1", "acceptance_criteria": []any{"ok"}}}
	cases := []struct {
		name         string
		requirements any
		covered      int
	}{
		{"zero é falsy e cai nas user_stories", 0, 1},
		{"false é falsy e cai nas user_stories", false, 1},
		{"string vazia é falsy e cai nas user_stories", "", 1},
		{"número truthy não é lista", 5, 0},
		{"true não é lista", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := newWork(t)
			writeJSON(t, workDir, "discovery.json", map[string]any{"problem": "x"})
			writeJSON(t, workDir, "requirements.json", map[string]any{
				"requirements": tc.requirements,
				"user_stories": stories,
			})
			output := gates.EvaluateGateDiscReq("0001", workDir)
			if output.Summary.Covered != tc.covered {
				t.Fatalf("covered = %d, want %d", output.Summary.Covered, tc.covered)
			}
		})
	}
}

func TestGatePrdSpecStringifiesAcceptedRequirementIDs(t *testing.T) {
	workDir := newWork(t)
	writeRawFile(t, workDir, "prd.json",
		`{"accepted_requirements": [true, false, 5, 1.5, 1e21, null, {"a": 1}, "FR-1"]}`)
	writeJSON(t, workDir, "spec.json", map[string]any{"capabilities": []any{}})

	output := gates.EvaluateGatePrdSpec("0001", workDir)
	want := []string{"true", "false", "5", "1.5", "1e+21", "null", `{"a":1}`, "FR-1"}
	for _, id := range want {
		finding := requireFinding(t, output.Findings, "FIND-SEM-SPEC-COVER-"+id)
		if len(finding.TargetRefs) != 1 || finding.TargetRefs[0] != id {
			t.Fatalf("target_refs = %v, want [%s]", finding.TargetRefs, id)
		}
		if finding.Severity != contract.SeverityHigh {
			t.Fatalf("severity = %q", finding.Severity)
		}
	}
	if output.Result != gates.ResultBlocked {
		t.Fatalf("result = %q", output.Result)
	}
}

func TestGatePrdSpecIgnoresNonIterableMatrix(t *testing.T) {
	spec := map[string]any{"capabilities": []any{map[string]any{"id": "CAP-9", "rules": []any{"RULE-1"}}}}
	cases := []struct {
		name       string
		matrix     any
		wantFinded bool
	}{
		{"matriz vazia acusa capability sem vínculo", []any{}, true},
		{"matriz truthy que não é lista não é verificável", "abc", false},
		{"matriz ausente é lista vazia", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := newWork(t)
			writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{}})
			writeJSON(t, workDir, "spec.json", spec)
			writeJSON(t, workDir, "traceability-matrix.json", map[string]any{"matrix": tc.matrix})

			output := gates.EvaluateGatePrdSpec("0001", workDir)
			_, found := findingIDs(output.Findings)["FIND-SPEC-TRACE-CAP-9"]
			if found != tc.wantFinded {
				t.Fatalf("FIND-SPEC-TRACE-CAP-9 presente = %v, want %v; achados = %+v", found, tc.wantFinded, output.Findings)
			}
		})
	}
}

func TestInputVersionsJSONRoundTripKeepsOrder(t *testing.T) {
	versions := gates.InputVersions{{Key: "z", Value: "1"}, {Key: "a", Value: "2"}}
	data, err := json.Marshal(versions)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(data) != `{"z":"1","a":"2"}` {
		t.Fatalf("json = %s", data)
	}
	var decoded gates.InputVersions
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if keys := strings.Join(inputVersionKeys(decoded), ","); keys != "z,a" {
		t.Fatalf("ordem = %s", keys)
	}
	if value, ok := decoded.Get("a"); !ok || value != "2" {
		t.Fatalf("Get(a) = %q, %v", value, ok)
	}
	if value, ok := decoded.Get("ausente"); ok || value != "" {
		t.Fatalf("Get(ausente) = %q, %v", value, ok)
	}

	var nilVersions gates.InputVersions
	empty, err := json.Marshal(nilVersions)
	if err != nil || string(empty) != "{}" {
		t.Fatalf("nil marshal = %s, %v", empty, err)
	}
}

func TestInputVersionsUnmarshalRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]string{
		"array":             `["a"]`,
		"valor não string":  `{"a": 1}`,
		"objeto truncado":   `{"a": "1"`,
		"valor aninhado":    `{"a": {"b": "c"}}`,
		"null não é objeto": `null`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			var versions gates.InputVersions
			if err := json.Unmarshal([]byte(document), &versions); err == nil {
				t.Fatalf("esperava erro para %s, got %v", document, versions)
			}
		})
	}
}
