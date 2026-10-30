package gates_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

// refuteFinding falha quando o achado existe.
func refuteFinding(t *testing.T, findings []contract.Finding, id string) {
	t.Helper()
	if _, ok := findingIDs(findings)[id]; ok {
		t.Fatalf("achado %s não deveria existir", id)
	}
}

func TestFrozenTestsRequiredFollowsRiskLevel(t *testing.T) {
	want := map[contract.RiskLevel]bool{
		contract.RiskL0: false,
		contract.RiskL1: false,
		contract.RiskL2: false,
		contract.RiskL3: true,
		contract.RiskL4: true,
	}
	for risk, required := range want {
		if got := gates.FrozenTestsRequired(risk); got != required {
			t.Fatalf("FrozenTestsRequired(%s) = %v, want %v", risk, got, required)
		}
	}
}

func TestSemanticTraceabilityPRDRules(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"requirements": []any{
			map[string]any{"acceptance_criteria": []any{"sem id é ignorado"}, "status": "rejected"},
			map[string]any{"id": "R2", "acceptance_criteria": []any{5, nil, true}},
			map[string]any{"id": "R3", "acceptance_criteria": []any{"`go test ./...` passa"}},
			map[string]any{"id": "R4", "status": "rejected"},
			map[string]any{"id": "R5", "status": "rejected", "rejection_rationale": "fora do escopo"},
			map[string]any{"id": "R6", "status": "deferred"},
			"texto solto",
		},
	})
	writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{"R2", "R3"}})

	findings := gates.ValidateSemanticTraceability(workDir, "0001")

	// Critério que não é texto nunca é observável.
	ac := requireFinding(t, findings, "FIND-SEM-PRD-AC-R2")
	if ac.Severity != contract.SeverityMedium || ac.Type != contract.FindingUnverifiableAcceptance {
		t.Fatalf("finding = %+v", ac)
	}
	refuteFinding(t, findings, "FIND-SEM-PRD-AC-R3")

	rejected := requireFinding(t, findings, "FIND-SEM-PRD-REJ-R4")
	if rejected.Severity != contract.SeverityLow || rejected.Type != contract.FindingAmbiguity {
		t.Fatalf("finding = %+v", rejected)
	}
	refuteFinding(t, findings, "FIND-SEM-PRD-REJ-R5")
	refuteFinding(t, findings, "FIND-SEM-PRD-REJ-R6")
	for _, finding := range findings {
		if strings.HasSuffix(finding.ID, "-") {
			t.Fatalf("requisito sem id gerou achado: %+v", finding)
		}
	}
}

func TestSemanticTraceabilitySpecCoverage(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "prd.json", map[string]any{"accepted_requirements": []any{"R1", "R2", "R3", "R4"}})
	writeJSON(t, workDir, "spec.json", map[string]any{
		"capabilities": []any{
			"texto solto",
			map[string]any{"rules": []any{"sem id"}},
			map[string]any{"id": "CAP-A", "api_endpoints": []any{"GET /a"}},
			map[string]any{"id": "CAP-B", "data_models": []any{"Modelo"}},
			map[string]any{"id": "CAP-C"},
			map[string]any{"id": "CAP-D", "covered_requirements": []any{"R1"}, "rules": []any{"RULE-1"}},
		},
	})
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"matrix": []any{
			map[string]any{"spec_section": "CAP-A"},
			map[string]any{"requirement_id": "R2", "spec_section": "CAP-A"},
			map[string]any{"requirement_id": "R3", "spec_section": "CAP-INEXISTENTE"},
		},
	})

	findings := gates.ValidateSemanticTraceability(workDir, "0001")

	// Capability só com título.
	impl := requireFinding(t, findings, "FIND-SEM-SPEC-IMPL-CAP-C")
	if impl.Severity != contract.SeverityMedium || impl.Type != contract.FindingCoverageGap {
		t.Fatalf("finding = %+v", impl)
	}
	for _, id := range []string{"FIND-SEM-SPEC-IMPL-CAP-A", "FIND-SEM-SPEC-IMPL-CAP-B", "FIND-SEM-SPEC-IMPL-CAP-D"} {
		refuteFinding(t, findings, id)
	}
	// R1 coberto por covered_requirements, R2 pela matriz; R3 aponta capability
	// inexistente e R4 não é citado.
	refuteFinding(t, findings, "FIND-SEM-SPEC-COVER-R1")
	refuteFinding(t, findings, "FIND-SEM-SPEC-COVER-R2")
	requireFinding(t, findings, "FIND-SEM-SPEC-COVER-R3")
	requireFinding(t, findings, "FIND-SEM-SPEC-COVER-R4")
}

func TestValidatePlanAcceptanceNumbersTasksWithoutID(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(nil), map[string]any{"spec_reference": "CAP-001"}},
	})

	findings := gates.ValidatePlanAcceptance(workDir)
	// A segunda task não tem id: o índice (2) a identifica.
	missing := requireFinding(t, findings, "FIND-AC-MISSING-2")
	if len(missing.TargetRefs) != 1 || missing.TargetRefs[0] != "2" {
		t.Fatalf("target_refs = %v", missing.TargetRefs)
	}
	requireFinding(t, findings, "FIND-RED-MISSING-2")
	refuteFinding(t, findings, "FIND-AC-MISSING-1.1")
}

func TestValidateContractSemanticsSkipsAndReportsUnreadableContracts(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{
			"texto solto",
			map[string]any{"id": "T2"},
			map[string]any{"id": "T3", "contract_id": "CTR-3"},
			map[string]any{"id": "T4", "contract_id": "CTR-4"},
			map[string]any{"id": "T5", "contract_id": "CTR-5"},
		},
	})
	// JSON que não é objeto, objeto de tipo incompatível e arquivo ausente.
	writeRawFile(t, workDir, "CTR-3.json", "[1, 2]")
	writeRawFile(t, workDir, "CTR-4.json", `{"risk": "alto"}`)

	findings := gates.ValidateSemanticTraceability(workDir, "0001")

	for _, id := range []string{"T3", "T4"} {
		finding := requireFinding(t, findings, "FIND-SEM-CTR-UNREADABLE-"+id)
		if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingAmbiguity {
			t.Fatalf("finding = %+v", finding)
		}
		if !strings.HasSuffix(finding.Description, "não é um JSON legível") {
			t.Fatalf("description = %q", finding.Description)
		}
	}
	missing := requireFinding(t, findings, "FIND-SEM-CTR-MISSING-T5")
	if len(missing.TargetRefs) != 1 || missing.TargetRefs[0] != "CTR-5" {
		t.Fatalf("target_refs = %v", missing.TargetRefs)
	}
	// Task sem contract_id e item que não é objeto não geram achado de contrato.
	refuteFinding(t, findings, "FIND-SEM-CTR-MISSING-T2")
	refuteFinding(t, findings, "FIND-SEM-CTR-UNREADABLE-T2")
}

func TestValidateContractSemanticsAcceptsLegacyScopeAliases(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "plan.json", map[string]any{
		"tasks": []any{taskValida(map[string]any{"contract_id": "CTR-LEGADO"})},
	})
	// `scope` e `budget` são os aliases legados de scope_contract e budget_contract.
	writeJSON(t, workDir, "CTR-LEGADO.json", map[string]any{
		"risk":                map[string]any{"level": "L1"},
		"scope":               map[string]any{"write_allow": []any{"src/x.ts"}},
		"budget":              map[string]any{"max_tokens": 10000},
		"acceptance_contract": map[string]any{"commands": []any{"bun test tests/x.test.ts"}},
	})

	findings := gates.ValidateSemanticTraceability(workDir, "0001")
	refuteFinding(t, findings, "FIND-SEM-CTR-SCOPE-CTR-LEGADO")
	refuteFinding(t, findings, "FIND-SEM-CTR-BUDGET-CTR-LEGADO")

	// Sem os aliases, o mesmo contrato perde escopo e budget.
	writeJSON(t, workDir, "CTR-LEGADO.json", map[string]any{
		"risk":                map[string]any{"level": "L1"},
		"acceptance_contract": map[string]any{"commands": []any{"bun test tests/x.test.ts"}},
	})
	findings = gates.ValidateSemanticTraceability(workDir, "0001")
	requireFinding(t, findings, "FIND-SEM-CTR-SCOPE-CTR-LEGADO")
	requireFinding(t, findings, "FIND-SEM-CTR-BUDGET-CTR-LEGADO")
}

func TestValidateFullTraceabilityRejectsNonObjectMatrix(t *testing.T) {
	workDir := newWork(t)
	writeRawFile(t, workDir, "traceability-matrix.json", `[{"origin": "DISC-001"}]`)

	findings := gates.ValidateFullTraceability(workDir, "0001")
	finding := requireFinding(t, findings, "FIND-TRACE-FULL-001")
	if finding.Severity != contract.SeverityCritical {
		t.Fatalf("severity = %q", finding.Severity)
	}
	if loaded := gates.LoadTraceabilityMatrix(workDir); loaded != nil {
		t.Fatalf("matriz que não é objeto deveria virar nil, got %+v", loaded)
	}
}

func TestValidateFullTraceabilityFlagsPlaceholderValue(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"matrix": []any{map[string]any{
			"origin":         "PLACEHOLDER-origin",
			"requirement_id": "PLACEHOLDER-other",
		}},
	})

	findings := gates.ValidateFullTraceability(workDir, "0001")
	origin := requireFinding(t, findings, "FIND-TRACE-FULL-CHAIN-0-origin")
	if len(origin.TargetRefs) != 1 || origin.TargetRefs[0] != "PLACEHOLDER-origin" {
		t.Fatalf("target_refs = %v", origin.TargetRefs)
	}
	// Só o placeholder do próprio campo conta: PLACEHOLDER-other é um valor real
	// para requirement_id.
	refuteFinding(t, findings, "FIND-TRACE-FULL-CHAIN-0-requirement_id")
	empty := requireFinding(t, findings, "FIND-TRACE-FULL-CHAIN-0-decision_id")
	if len(empty.TargetRefs) != 1 || empty.TargetRefs[0] != "" {
		t.Fatalf("target_refs = %q", empty.TargetRefs)
	}
}

func TestValidateFullTraceabilityVerifiesReferencedArtifacts(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "requirements.json", map[string]any{})
	writeJSON(t, workDir, "CTR-777.json", map[string]any{})
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"matrix": []any{map[string]any{
			"origin":         "DISC-001",
			"requirement_id": "FR-777",
			"decision_id":    "TD-777",
			"spec_section":   "CAP-777",
			"task_id":        "T-777",
			"contract_id":    "CTR-777",
			"evidence_id":    "EVD-777",
		}},
	})

	findings := gates.ValidateFullTraceability(workDir, "0001")
	// requirements.json casa o padrão do requisito e CTR-777.json casa o id do
	// contrato; nenhum arquivo casa a evidência.
	refuteFinding(t, findings, "FIND-TRACE-VERIFY-FR-777")
	refuteFinding(t, findings, "FIND-TRACE-VERIFY-CTR-777")
	evidence := requireFinding(t, findings, "FIND-TRACE-VERIFY-EVD-777")
	if evidence.Severity != contract.SeverityMedium || evidence.Type != contract.FindingTraceabilityGap {
		t.Fatalf("finding = %+v", evidence)
	}
	if len(evidence.TargetRefs) != 1 || evidence.TargetRefs[0] != "EVD-777" {
		t.Fatalf("target_refs = %v", evidence.TargetRefs)
	}

	// Um arquivo cujo nome casa o padrão de evidência resolve a referência.
	writeJSON(t, workDir, "evidence-log.json", map[string]any{})
	findings = gates.ValidateFullTraceability(workDir, "0001")
	refuteFinding(t, findings, "FIND-TRACE-VERIFY-EVD-777")
}

func TestValidateFullTraceabilityFlagsMissingContractAndRequirementFiles(t *testing.T) {
	workDir := newWork(t)
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"matrix": []any{map[string]any{
			"origin":         "DISC-001",
			"requirement_id": "FR-9",
			"decision_id":    "TD-9",
			"spec_section":   "CAP-9",
			"task_id":        "T-9",
			"contract_id":    "CTR-9",
			"evidence_id":    "EVD-9",
		}},
	})
	if err := os.Mkdir(filepath.Join(workDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	findings := gates.ValidateFullTraceability(workDir, "0001")
	for _, id := range []string{"FIND-TRACE-VERIFY-FR-9", "FIND-TRACE-VERIFY-CTR-9", "FIND-TRACE-VERIFY-EVD-9"} {
		requireFinding(t, findings, id)
	}
}
