package contract_test

import (
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

const sampleContractID = "CTR-001"
const sampleContractPath = ".pwn/work/0001/CTR-001.json"

func semanticInput(taskContract contract.TaskContractV4, taskID string) contract.SemanticInput {
	return contract.SemanticInput{
		Contract:     taskContract,
		ContractID:   sampleContractID,
		ContractPath: sampleContractPath,
		Task:         contract.SemanticTask{ID: taskID, Complexity: "medium"},
	}
}

func validSHA() string { return strings.Repeat("a", 64) }

func TestValidateSemanticsClean(t *testing.T) {
	input := semanticInput(defaultContract(t, contract.RiskL2), "1.1")
	if findings := contract.ValidateSemantics(input); len(findings) != 0 {
		t.Fatalf("findings = %+v, quer nenhum", findings)
	}
}

func TestValidateSemanticsEmptyScope(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL2)
	taskContract.ScopeContract.WriteAllow = nil

	findings := contract.ValidateSemantics(semanticInput(taskContract, "1.1"))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, quer 1", findings)
	}
	finding := findings[0]
	if finding.ID != "FIND-SEM-CTR-SCOPE-"+sampleContractID {
		t.Fatalf("id = %q", finding.ID)
	}
	if finding.Severity != contract.SeverityMedium || finding.Type != contract.FindingCoverageGap {
		t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
	}
	if !equalStrings(finding.SourceRefs, []string{sampleContractPath, contract.PlanFileName}) {
		t.Fatalf("source_refs = %v", finding.SourceRefs)
	}
	if !equalStrings(finding.TargetRefs, []string{"1.1"}) {
		t.Fatalf("target_refs = %v", finding.TargetRefs)
	}
	if finding.Description != "Contrato CTR-001 não declara nenhum arquivo em write_allow — impossível verificar escopo" {
		t.Fatalf("description = %q", finding.Description)
	}
	if finding.RequiredResolution != "Adicionar padrões de arquivo ao scope.write_allow" {
		t.Fatalf("required_resolution = %q", finding.RequiredResolution)
	}
	if finding.ResolutionOwner != "architect" || finding.Status != contract.FindingStatusOpen {
		t.Fatalf("owner/status = %q/%q", finding.ResolutionOwner, finding.Status)
	}
}

func TestValidateSemanticsMissingBudget(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL2)
	taskContract.BudgetContract = contract.BudgetContract{}

	findings := contract.ValidateSemantics(semanticInput(taskContract, "1.1"))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, quer 1", findings)
	}
	finding := findings[0]
	if finding.ID != "FIND-SEM-CTR-BUDGET-"+sampleContractID {
		t.Fatalf("id = %q", finding.ID)
	}
	if finding.Severity != contract.SeverityMedium || finding.Type != contract.FindingCoverageGap {
		t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
	}
	if finding.Description != "Contrato CTR-001 não define limites de budget — sem enforcement de custo/tempo" {
		t.Fatalf("description = %q", finding.Description)
	}
	if finding.RequiredResolution != "Adicionar max_tokens, max_cost_usd ou max_duration_minutes" {
		t.Fatalf("required_resolution = %q", finding.RequiredResolution)
	}
}

func TestValidateSemanticsBudgetAlternatives(t *testing.T) {
	for _, budget := range []contract.BudgetContract{
		{MaxTokens: new(1000)},
		{MaxCostUSD: new(0.5)},
		{MaxDurationMinutes: new(5)},
	} {
		taskContract := defaultContract(t, contract.RiskL2)
		taskContract.BudgetContract = budget
		if findings := contract.ValidateSemantics(semanticInput(taskContract, "1.1")); len(findings) != 0 {
			t.Fatalf("budget %+v gerou findings %+v", budget, findings)
		}
	}
}

func TestValidateSemanticsRiskMismatch(t *testing.T) {
	tests := []struct {
		complexity  string
		risk        contract.RiskLevel
		wantFinding bool
	}{
		{"high", contract.RiskL1, true},
		{"critical", contract.RiskL0, true},
		{"architectural", contract.RiskL1, true},
		{"medium", contract.RiskL1, false},
		{"high", contract.RiskL2, false},
		{"unknown", contract.RiskL1, false},
	}

	for _, test := range tests {
		t.Run(test.complexity+"/"+string(test.risk), func(t *testing.T) {
			input := semanticInput(defaultContract(t, test.risk), "1.1")
			input.Task.Complexity = test.complexity
			findings := contract.ValidateSemantics(input)
			if !test.wantFinding {
				if len(findings) != 0 {
					t.Fatalf("findings = %+v, quer nenhum", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, quer 1", findings)
			}
			finding := findings[0]
			if finding.ID != "FIND-SEM-CTR-RISK-"+sampleContractID {
				t.Fatalf("id = %q", finding.ID)
			}
			if finding.Severity != contract.SeverityMedium || finding.Type != contract.FindingConflict {
				t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
			}
			want := "Task 1.1 é de alta complexidade mas o contrato é risco " + string(test.risk) + " — sub-classificação de risco"
			if finding.Description != want {
				t.Fatalf("description = %q, quer %q", finding.Description, want)
			}
		})
	}
}

func TestValidateSemanticsRiskDefaultsToL1(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL2)
	taskContract.Risk.Level = ""
	input := semanticInput(taskContract, "1.1")
	input.Task.Complexity = "high"

	findings := contract.ValidateSemantics(input)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, quer 1", findings)
	}
	want := "Task 1.1 é de alta complexidade mas o contrato é risco L1 — sub-classificação de risco"
	if findings[0].Description != want {
		t.Fatalf("description = %q, quer %q", findings[0].Description, want)
	}
}

func TestValidateSemanticsUnauthorizedAC(t *testing.T) {
	input := semanticInput(defaultContract(t, contract.RiskL2), "1.1")
	input.Task.AcceptanceCriteria = []string{"bun test tests/a.test.ts", "pytest -q"}

	findings := contract.ValidateSemantics(input)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, quer 1", findings)
	}
	finding := findings[0]
	if finding.ID != "FIND-SEM-CTR-AC-1.1-2" {
		t.Fatalf("id = %q", finding.ID)
	}
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingConflict {
		t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
	}
	want := "AC-2 da task 1.1 (`pytest -q`) não é autorizado por acceptance_contract.commands do CTR-001"
	if finding.Description != want {
		t.Fatalf("description = %q, quer %q", finding.Description, want)
	}
	if finding.RequiredResolution != "Incluir o comando (ou um prefixo estrutural dele) nos comandos de aceitação do contrato" {
		t.Fatalf("required_resolution = %q", finding.RequiredResolution)
	}
}

func TestValidateSemanticsAuthorizationIsStructural(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL2)
	taskContract.AcceptanceContract.Commands = []string{"bun test"}

	tests := []struct {
		name       string
		command    string
		authorized bool
	}{
		{"prefixo estrutural", "bun test tests/a.test.ts", true},
		{"flags extras", "bun test --filter a", true},
		{"programa diferente", "go test ./...", false},
		{"argumento diferente", "bun run tests/a.test.ts", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := semanticInput(taskContract, "1.1")
			input.Task.AcceptanceCriteria = []string{test.command}
			findings := contract.ValidateSemantics(input)
			if test.authorized && len(findings) != 0 {
				t.Fatalf("findings = %+v, quer nenhum", findings)
			}
			if !test.authorized && len(findings) != 1 {
				t.Fatalf("findings = %+v, quer 1", findings)
			}
		})
	}

	quoted := defaultContract(t, contract.RiskL2)
	quoted.AcceptanceContract.Commands = []string{`bun test "tests/a b.test.ts"`}
	input := semanticInput(quoted, "1.1")
	input.Task.AcceptanceCriteria = []string{`bun test "tests/a b.test.ts"`}
	if findings := contract.ValidateSemantics(input); len(findings) != 0 {
		t.Fatalf("comando citado gerou findings %+v", findings)
	}
}

func TestValidateSemanticsFrozenInvalid(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL2)
	taskContract.AcceptanceContract.FrozenTests = []contract.FrozenTest{{Path: "tests/a.test.ts", SHA256: "abc"}}

	findings := contract.ValidateSemantics(semanticInput(taskContract, "1.1"))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, quer 1", findings)
	}
	finding := findings[0]
	if finding.ID != "FIND-SEM-CTR-FROZEN-INVALID-1.1" {
		t.Fatalf("id = %q", finding.ID)
	}
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingAmbiguity {
		t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
	}
	if finding.Description != "acceptance_contract.frozen_tests do CTR-001 tem entradas sem { path, sha256 } válidos" {
		t.Fatalf("description = %q", finding.Description)
	}
}

func TestValidateSemanticsFrozenRequired(t *testing.T) {
	for _, frozen := range [][]contract.FrozenTest{nil, {}} {
		taskContract := defaultContract(t, contract.RiskL3)
		taskContract.AcceptanceContract.FrozenTests = frozen

		findings := contract.ValidateSemantics(semanticInput(taskContract, "1.1"))
		if len(findings) != 1 {
			t.Fatalf("frozen %+v: findings = %+v, quer 1", frozen, findings)
		}
		finding := findings[0]
		if finding.ID != "FIND-SEM-CTR-FROZEN-REQUIRED-1.1" {
			t.Fatalf("id = %q", finding.ID)
		}
		if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingUnverifiableAcceptance {
			t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
		}
		want := "Task 1.1 é risco L3: exige testes de aceitação escritos e congelados antes da implementação"
		if finding.Description != want {
			t.Fatalf("description = %q, quer %q", finding.Description, want)
		}
		if finding.ResolutionOwner != "architect" {
			t.Fatalf("owner = %q", finding.ResolutionOwner)
		}
	}
}

func TestValidateSemanticsFrozenUnused(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL3)
	taskContract.AcceptanceContract.FrozenTests = []contract.FrozenTest{{Path: "tests/a.test.ts", SHA256: validSHA()}}

	findings := contract.ValidateSemantics(semanticInput(taskContract, "1.1"))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, quer 1", findings)
	}
	finding := findings[0]
	if finding.ID != "FIND-SEM-CTR-FROZEN-UNUSED-1.1-tests/a.test.ts" {
		t.Fatalf("id = %q", finding.ID)
	}
	if finding.Severity != contract.SeverityHigh || finding.Type != contract.FindingUnverifiableAcceptance {
		t.Fatalf("severity/type = %q/%q", finding.Severity, finding.Type)
	}
	if !equalStrings(finding.TargetRefs, []string{"1.1", "tests/a.test.ts"}) {
		t.Fatalf("target_refs = %v", finding.TargetRefs)
	}
	if finding.ResolutionOwner != "planner" {
		t.Fatalf("owner = %q", finding.ResolutionOwner)
	}
}

func TestValidateSemanticsFrozenUsed(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL3)
	taskContract.AcceptanceContract.Commands = []string{"bun test"}
	taskContract.AcceptanceContract.FrozenTests = []contract.FrozenTest{{Path: "tests/a.test.ts", SHA256: validSHA()}}

	input := semanticInput(taskContract, "1.1")
	input.Task.AcceptanceCriteria = []string{"bun test tests/a.test.ts"}
	if findings := contract.ValidateSemantics(input); len(findings) != 0 {
		t.Fatalf("findings = %+v, quer nenhum", findings)
	}

	directory := semanticInput(taskContract, "1.1")
	directory.Task.AcceptanceCriteria = []string{"bun test tests/"}
	if findings := contract.ValidateSemantics(directory); len(findings) != 0 {
		t.Fatalf("referência por diretório gerou findings %+v", findings)
	}
}

func TestValidateSemanticsMultipleFindings(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL1)
	taskContract.ScopeContract.WriteAllow = nil
	taskContract.BudgetContract = contract.BudgetContract{}
	taskContract.AcceptanceContract.Commands = []string{"bun test"}

	input := semanticInput(taskContract, "1.1")
	input.Task.Complexity = "critical"
	input.Task.AcceptanceCriteria = []string{"pytest -q"}

	findings := contract.ValidateSemantics(input)
	if len(findings) != 4 {
		t.Fatalf("findings = %+v, quer 4", findings)
	}
	got := []string{findings[0].ID, findings[1].ID, findings[2].ID, findings[3].ID}
	want := []string{
		"FIND-SEM-CTR-SCOPE-" + sampleContractID,
		"FIND-SEM-CTR-BUDGET-" + sampleContractID,
		"FIND-SEM-CTR-RISK-" + sampleContractID,
		"FIND-SEM-CTR-AC-1.1-1",
	}
	if !equalStrings(got, want) {
		t.Fatalf("ids = %v, quer %v", got, want)
	}
}
