package gates_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

// newWork cria um diretório temporário de Work.
func newWork(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// writeJSON grava um valor JSON no diretório do Work.
func writeJSON(t *testing.T, workDir, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(workDir, name), append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// writeInitializedWork grava os artefatos do template de initWorkDirectory.
func writeInitializedWork(t *testing.T, workID, workDir string) {
	t.Helper()
	writeJSON(t, workDir, "discovery.json", map[string]any{
		"work_id":     workID,
		"problem":     "Descrição do problema",
		"actors":      []any{"ACT-001"},
		"objectives":  []any{"Objetivo principal"},
		"constraints": []any{"Restrição de tecnologia/tempo"},
	})
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"work_id": workID,
		"requirements": []any{
			map[string]any{
				"id":                  "FR-001",
				"title":               "Primeiro Requisito Funcional",
				"user_story":          "Como operador, quero funcionalidade X para beneficio Y",
				"acceptance_criteria": []any{"Critério 1 observável"},
			},
		},
	})
	writeJSON(t, workDir, "prd.json", map[string]any{
		"$schema":               "https://pwn.dev/schemas/prd.schema.json",
		"id":                    "PRD-" + workID,
		"title":                 "PRD do Work " + workID,
		"status":                "draft",
		"scenario":              "greenfield",
		"requirements":          []any{map[string]any{"id": "FR-001", "type": "functional", "statement": "Primeiro requisito funcional"}},
		"accepted_requirements": []any{"FR-001"},
	})
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"work_id": workID,
		"matrix": []any{
			map[string]any{
				"origin":         "DISC-001",
				"requirement_id": "FR-001",
				"decision_id":    "TD-001",
				"spec_section":   "SPEC-001",
				"task_id":        "T-001",
				"contract_id":    "CTR-001",
				"evidence_id":    "EVD-001",
				"status":         "planned",
			},
		},
	})
}

// taskValida é a task de referência: RED/AC focados, arquivos concretos e
// spec_reference única.
func taskValida(overrides map[string]any) map[string]any {
	task := map[string]any{
		"id":                   "1.1",
		"spec_reference":       "CAP-001",
		"components":           []any{"core"},
		"acceptance_criteria":  []any{map[string]any{"command": "bun test tests/x.test.ts", "description": "roda o teste focado do módulo x"}},
		"red":                  map[string]any{"command": "bun test tests/x.test.ts", "description": "falha antes da implementação"},
		"implementation_files": []any{"src/x.ts"},
		"test_files":           []any{"tests/x.test.ts"},
	}
	for key, value := range overrides {
		task[key] = value
	}
	return task
}

// contratoValido é o contrato mínimo legível: escopo, orçamento, risco e
// comandos de aceitação.
func contratoValido(overrides map[string]any) map[string]any {
	taskContract := map[string]any{
		"risk":                map[string]any{"level": "L1"},
		"scope_contract":      map[string]any{"write_allow": []any{"src/x.ts"}},
		"budget_contract":     map[string]any{"max_tokens": 10000},
		"acceptance_contract": map[string]any{"commands": []any{"bun test tests/x.test.ts"}},
	}
	for key, value := range overrides {
		taskContract[key] = value
	}
	return taskContract
}

func findingIDs(findings []contract.Finding) map[string]contract.Finding {
	byID := make(map[string]contract.Finding, len(findings))
	for _, finding := range findings {
		byID[finding.ID] = finding
	}
	return byID
}

// ── Gates básicos ──────────────────────────────────────────────────

func TestGateDiscReqInitializedWorkPasses(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0002", workDir)

	output := gates.EvaluateGateDiscReq("0002", workDir)
	if output.Gate != "GATE-DISC-REQ" {
		t.Fatalf("gate = %q", output.Gate)
	}
	if output.Result != gates.ResultPass {
		t.Fatalf("result = %q, findings = %+v", output.Result, output.Findings)
	}
	if output.Summary.Covered != 1 {
		t.Fatalf("covered = %d", output.Summary.Covered)
	}
	if keys := inputVersionKeys(output.InputVersions); strings.Join(keys, ",") != "discovery,requirements,traceability_matrix" {
		t.Fatalf("input_versions = %v", keys)
	}
}

func TestGateDiscReqMissingArtifactsBlocks(t *testing.T) {
	workDir := newWork(t)

	output := gates.EvaluateGateDiscReq("0002", workDir)
	if output.Result != gates.ResultBlocked {
		t.Fatalf("result = %q", output.Result)
	}
	if len(output.Findings) < 2 || output.Findings[0].ID != "FIND-001" || output.Findings[1].ID != "FIND-002" {
		t.Fatalf("findings = %+v", output.Findings)
	}
	if output.Findings[0].Severity != contract.SeverityCritical {
		t.Fatalf("severity = %q", output.Findings[0].Severity)
	}
}

func TestGateReqPrdCountsAcceptedRequirements(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0003", workDir)

	output := gates.EvaluateGateReqPrd("0003", workDir)
	if output.Gate != "GATE-REQ-PRD" || output.Result != gates.ResultPass {
		t.Fatalf("gate/result = %q/%q, findings = %+v", output.Gate, output.Result, output.Findings)
	}
	if output.Summary.Covered != 1 {
		t.Fatalf("covered = %d", output.Summary.Covered)
	}
}

func TestGatePrdSpecMissingSpecBlocks(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0004", workDir)

	output := gates.EvaluateGatePrdSpec("0004", workDir)
	if output.Gate != "GATE-PRD-SPEC" || output.Result != gates.ResultBlocked {
		t.Fatalf("gate/result = %q/%q", output.Gate, output.Result)
	}
	found := false
	for _, finding := range output.Findings {
		if finding.Type == contract.FindingCoverageGap && finding.ID == "FIND-SPEC-01" {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %+v", output.Findings)
	}
}

func inputVersionKeys(versions gates.InputVersions) []string {
	keys := make([]string, len(versions))
	for index, field := range versions {
		keys[index] = field.Key
	}
	return keys
}

// ── Rastreabilidade ────────────────────────────────────────────────

func TestValidateFullTraceabilityMissingMatrix(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0005", workDir)
	if err := os.Remove(filepath.Join(workDir, "traceability-matrix.json")); err != nil {
		t.Fatalf("remove matrix: %v", err)
	}

	findings := gates.ValidateFullTraceability(workDir, "0005")
	if len(findings) == 0 {
		t.Fatal("findings vazios")
	}
	if findings[0].ID != "FIND-TRACE-FULL-001" || findings[0].Type != contract.FindingTraceabilityGap ||
		findings[0].Severity != contract.SeverityCritical {
		t.Fatalf("findings[0] = %+v", findings[0])
	}
}

func TestValidateFullTraceabilityEmptyFields(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"work_id": "0006",
		"matrix": []any{
			map[string]any{
				"origin":         "DISC-001",
				"requirement_id": "",
				"decision_id":    "TD-001",
				"spec_section":   "SPEC-001",
				"task_id":        "T-001",
				"contract_id":    "",
				"evidence_id":    "EVD-001",
				"status":         "planned",
			},
		},
	})

	findings := gates.ValidateFullTraceability(workDir, "0006")
	hasRequirement := false
	hasContract := false
	for _, finding := range findings {
		if strings.Contains(finding.Description, "requirement_id") {
			hasRequirement = true
		}
		if strings.Contains(finding.Description, "contract_id") {
			hasContract = true
		}
	}
	if !hasRequirement || !hasContract {
		t.Fatalf("findings = %+v", findings)
	}
}

// ── Validação semântica ────────────────────────────────────────────

func TestValidateSemanticTraceabilityNonObservableCriterion(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"requirements": []any{
			map[string]any{
				"id":                  "REQ-001",
				"title":               "Feature X",
				"acceptance_criteria": []any{"A interface sera agradavel"},
			},
		},
	})
	writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{"REQ-001"}})

	findings := gates.ValidateSemanticTraceability(workDir, "0007")
	if _, ok := findingIDs(findings)["FIND-SEM-PRD-AC-REQ-001"]; !ok {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestValidateSemanticTraceabilityUncoveredRequirement(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{"REQ-001"}})
	writeJSON(t, workDir, "spec.json", map[string]any{
		"capabilities": []any{
			map[string]any{"id": "CAP-001", "title": "Capacidade Y", "covered_requirements": []any{}},
		},
	})

	findings := gates.ValidateSemanticTraceability(workDir, "0008")
	byID := findingIDs(findings)
	finding, ok := byID["FIND-SEM-SPEC-COVER-REQ-001"]
	if !ok {
		t.Fatalf("findings = %+v", findings)
	}
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingCoverageGap {
		t.Fatalf("finding = %+v", finding)
	}
}

func TestValidateSemanticTraceabilityCapabilityWithoutImplementation(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{"REQ-001"}})
	writeJSON(t, workDir, "spec.json", map[string]any{
		"capabilities": []any{
			map[string]any{"id": "CAP-001", "title": "Capacidade Z", "covered_requirements": []any{"REQ-001"}},
		},
	})

	findings := gates.ValidateSemanticTraceability(workDir, "0009")
	if _, ok := findingIDs(findings)["FIND-SEM-SPEC-IMPL-CAP-001"]; !ok {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestValidateSemanticTraceabilityContractWithoutScopeOrBudget(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{
			map[string]any{"id": "T-001", "contract_id": "CTR-001", "complexity": "high"},
		},
	})
	writeJSON(t, workDir, "CTR-001.json", map[string]any{
		"risk":           map[string]any{"level": "L1"},
		"scope_contract": map[string]any{"write_allow": []any{}},
	})

	findings := gates.ValidateSemanticTraceability(workDir, "0010")
	byID := findingIDs(findings)
	for _, id := range []string{"FIND-SEM-CTR-SCOPE-CTR-001", "FIND-SEM-CTR-BUDGET-CTR-001", "FIND-SEM-CTR-RISK-CTR-001"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("falta %s em %+v", id, findings)
		}
	}
}

// ── Aceitação amarrada ao plano ────────────────────────────────────

func TestValidatePlanAcceptanceAcceptsReferencePlan(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "spec.json", map[string]any{
		"capabilities": []any{
			map[string]any{"id": "CAP-001", "title": "Capacidade X", "covered_requirements": []any{"FR-001"}, "rules": []any{"regra de negócio"}},
		},
	})
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"work_id": "0001",
		"matrix": []any{
			map[string]any{
				"origin": "DISC-001", "requirement_id": "FR-001", "decision_id": "TD-001",
				"spec_section": "CAP-001", "task_id": "1.1", "contract_id": "CTR-001",
				"evidence_id": "EVD-001", "status": "planned",
			},
		},
	})
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(nil)},
		"components": []any{
			map[string]any{"name": "core", "regression": "bun run check", "lint": "N/A", "build": "N/A", "security": "N/A"},
		},
	})

	if findings := gates.ValidatePlanAcceptance(workDir); len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
	if result := gates.EvaluateGateSpecPlan("0001", workDir).Result; result != gates.ResultPass {
		t.Fatalf("GATE-SPEC-PLAN = %q", result)
	}
	if result := gates.EvaluateGatePrdSpec("0001", workDir).Result; result != gates.ResultPass {
		t.Fatalf("GATE-PRD-SPEC = %q", result)
	}
}

func TestValidatePlanAcceptanceRejectsWholeSuiteAC(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"acceptance_criteria": []any{map[string]any{"command": "bun test", "description": "roda tudo"}},
		})},
	})

	byID := findingIDs(gates.ValidatePlanAcceptance(workDir))
	finding, ok := byID["FIND-AC-GENERIC-1.1-1"]
	if !ok {
		t.Fatalf("findings = %+v", byID)
	}
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingUnverifiableAcceptance {
		t.Fatalf("finding = %+v", finding)
	}
	if result := gates.EvaluateGateSpecPlan("0001", workDir).Result; result != gates.ResultBlocked {
		t.Fatalf("result = %q", result)
	}
}

func TestValidatePlanAcceptanceRejectsWholeSuiteRed(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"red": map[string]any{"command": "bun test", "description": "roda tudo"},
		})},
	})

	finding, ok := findingIDs(gates.ValidatePlanAcceptance(workDir))["FIND-RED-GENERIC-1.1"]
	if !ok {
		t.Fatal("FIND-RED-GENERIC-1.1 ausente")
	}
	if finding.Severity != contract.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func TestValidatePlanAcceptanceRejectsMissingArtifactsAndPlaceholders(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"acceptance_criteria":  []any{},
			"implementation_files": []any{},
			"test_files":           []any{"tests/"},
		})},
	})

	byID := findingIDs(gates.ValidatePlanAcceptance(workDir))
	for _, id := range []string{
		"FIND-AC-MISSING-1.1",
		"FIND-FILES-MISSING-1.1-implementation_files",
		"FIND-FILES-PLACEHOLDER-1.1-tests/",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("falta %s em %+v", id, byID)
		}
	}
}

func TestValidatePlanAcceptanceRejectsVacuousAC(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"acceptance_criteria": []any{map[string]any{"command": "true", "description": "passa sempre"}},
		})},
	})

	finding, ok := findingIDs(gates.ValidatePlanAcceptance(workDir))["FIND-AC-GENERIC-1.1-1"]
	if !ok {
		t.Fatal("FIND-AC-GENERIC-1.1-1 ausente")
	}
	if !strings.Contains(finding.Description, "não exercita comportamento") {
		t.Fatalf("description = %q", finding.Description)
	}
}

func TestValidatePlanAcceptanceRejectsGlobalGateAC(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"acceptance_criteria": []any{map[string]any{"command": "bun test", "description": "repete o gate"}},
		})},
		"global_gates": []any{"`bun test` — a suíte passa"},
	})

	finding, ok := findingIDs(gates.ValidatePlanAcceptance(workDir))["FIND-AC-GENERIC-1.1-1"]
	if !ok {
		t.Fatal("FIND-AC-GENERIC-1.1-1 ausente")
	}
	if !strings.Contains(finding.Description, "repete um gate") {
		t.Fatalf("description = %q", finding.Description)
	}
}

// ── Contrato congelado ─────────────────────────────────────────────

func TestGatePlanContractMissingContract(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{"contract_id": "CTR-999"})},
	})

	output := gates.EvaluateGatePlanContract("0001", workDir)
	finding, ok := findingIDs(output.Findings)["FIND-SEM-CTR-MISSING-1.1"]
	if !ok {
		t.Fatalf("findings = %+v", output.Findings)
	}
	if finding.Severity != contract.SeverityHigh || output.Result != gates.ResultBlocked {
		t.Fatalf("finding/result = %+v/%q", finding, output.Result)
	}
}

func TestGatePlanContractRejectsUnauthorizedAC(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{"contract_id": "CTR-001"})},
	})
	writeJSON(t, workDir, "CTR-001.json", contratoValido(map[string]any{
		"acceptance_contract": map[string]any{"commands": []any{"bun run check"}},
	}))

	finding, ok := findingIDs(gates.EvaluateGatePlanContract("0001", workDir).Findings)["FIND-SEM-CTR-AC-1.1-1"]
	if !ok {
		t.Fatal("FIND-SEM-CTR-AC-1.1-1 ausente")
	}
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingConflict {
		t.Fatalf("finding = %+v", finding)
	}
}

func TestGatePlanContractRequiresFrozenTestsFromRiskL3(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{"contract_id": "CTR-001"})},
	})

	writeJSON(t, workDir, "CTR-001.json", contratoValido(map[string]any{
		"risk":                map[string]any{"level": "L3"},
		"acceptance_contract": map[string]any{"commands": []any{"bun test"}},
	}))
	findings := findingIDs(gates.EvaluateGatePlanContract("0001", workDir).Findings)
	required, ok := findings["FIND-SEM-CTR-FROZEN-REQUIRED-1.1"]
	if !ok {
		t.Fatalf("findings = %+v", findings)
	}
	if required.Severity != contract.SeverityHigh {
		t.Fatalf("severity = %q", required.Severity)
	}

	writeJSON(t, workDir, "CTR-001.json", contratoValido(map[string]any{
		"risk":                map[string]any{"level": "L2"},
		"acceptance_contract": map[string]any{"commands": []any{"bun test"}},
	}))
	findings = findingIDs(gates.EvaluateGatePlanContract("0001", workDir).Findings)
	if _, ok := findings["FIND-SEM-CTR-FROZEN-REQUIRED-1.1"]; ok {
		t.Fatal("risco L2 não deve exigir frozen_tests")
	}
}

func TestGatePlanContractRejectsUnusedFrozenTest(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"contract_id":         "CTR-001",
			"acceptance_criteria": []any{map[string]any{"command": "bun test tests/y.test.ts", "description": "aponta para outro arquivo"}},
		})},
	})
	writeJSON(t, workDir, "CTR-001.json", contratoValido(map[string]any{
		"risk": map[string]any{"level": "L2"},
		"acceptance_contract": map[string]any{
			"commands":     []any{"bun test"},
			"frozen_tests": []any{map[string]any{"path": "tests/x.test.ts", "sha256": strings.Repeat("a", 64)}},
		},
	}))

	finding, ok := findingIDs(gates.EvaluateGatePlanContract("0001", workDir).Findings)["FIND-SEM-CTR-FROZEN-UNUSED-1.1-tests/x.test.ts"]
	if !ok {
		t.Fatal("FIND-SEM-CTR-FROZEN-UNUSED ausente")
	}
	if finding.Severity != contract.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}

	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{
			"contract_id":         "CTR-001",
			"acceptance_criteria": []any{map[string]any{"command": "bun test tests/x.test.ts", "description": "exercita o teste congelado"}},
		})},
	})
	findings := findingIDs(gates.EvaluateGatePlanContract("0001", workDir).Findings)
	if _, ok := findings["FIND-SEM-CTR-FROZEN-UNUSED-1.1-tests/x.test.ts"]; ok {
		t.Fatal("AC que cita o arquivo congelado não deve gerar o finding")
	}
}

func TestGatePlanContractRejectsMalformedFrozenTest(t *testing.T) {
	workDir := newWork(t)
	writeInitializedWork(t, "0001", workDir)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{"contract_id": "CTR-001"})},
	})
	writeJSON(t, workDir, "CTR-001.json", contratoValido(map[string]any{
		"risk": map[string]any{"level": "L2"},
		"acceptance_contract": map[string]any{
			"commands":     []any{"bun test"},
			"frozen_tests": []any{map[string]any{"path": "tests/x.test.ts"}},
		},
	}))

	finding, ok := findingIDs(gates.EvaluateGatePlanContract("0001", workDir).Findings)["FIND-SEM-CTR-FROZEN-INVALID-1.1"]
	if !ok {
		t.Fatal("FIND-SEM-CTR-FROZEN-INVALID-1.1 ausente")
	}
	if finding.Severity != contract.SeverityHigh {
		t.Fatalf("severity = %q", finding.Severity)
	}
}

func TestGateDiscReqFallsBackToUserStories(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "discovery.json", map[string]any{"work_id": "0098"})
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"work_id": "0098",
		"user_stories": []any{
			map[string]any{"id": "US-001"},
			map[string]any{"title": "sem id nem critérios"},
		},
	})
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"work_id": "0098",
		"matrix": []any{
			map[string]any{"origin": "DISC-001", "requirement_id": "US-001"},
		},
	})

	output := gates.EvaluateGateDiscReq("0098", workDir)
	if output.Summary.Covered != 2 {
		t.Fatalf("covered = %d", output.Summary.Covered)
	}
	byID := findingIDs(output.Findings)
	first, ok := byID["FIND-REQ-1"]
	if !ok {
		t.Fatalf("findings = %+v", output.Findings)
	}
	if !reflect.DeepEqual(first.SourceRefs, []string{"US-001"}) {
		t.Fatalf("source_refs = %v", first.SourceRefs)
	}
	second, ok := byID["FIND-REQ-2"]
	if !ok {
		t.Fatalf("findings = %+v", output.Findings)
	}
	if !reflect.DeepEqual(second.SourceRefs, []string{"REQ-2"}) {
		t.Fatalf("source_refs = %v", second.SourceRefs)
	}
	if output.Result != gates.ResultBlocked {
		t.Fatalf("result = %q", output.Result)
	}
}

func TestLoadTraceabilityMatrixTyped(t *testing.T) {
	workDir := newWork(t)
	if matrix := gates.LoadTraceabilityMatrix(workDir); matrix != nil {
		t.Fatalf("matrix = %+v", matrix)
	}
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"work_id": "0001",
		"matrix": []any{
			map[string]any{
				"origin": "DISC-001", "requirement_id": "FR-001", "decision_id": "TD-001",
				"spec_section": "CAP-001", "task_id": "1.1", "contract_id": "CTR-001",
				"evidence_id": "EVD-001", "status": "planned",
			},
		},
	})

	matrix := gates.LoadTraceabilityMatrix(workDir)
	if matrix == nil || matrix.WorkID != "0001" || len(matrix.Matrix) != 1 {
		t.Fatalf("matrix = %+v", matrix)
	}
	if matrix.Matrix[0] != (gates.TraceabilityEntry{
		Origin: "DISC-001", RequirementID: "FR-001", DecisionID: "TD-001",
		SpecSection: "CAP-001", TaskID: "1.1", ContractID: "CTR-001",
		EvidenceID: "EVD-001", Status: "planned",
	}) {
		t.Fatalf("entry = %+v", matrix.Matrix[0])
	}
}
