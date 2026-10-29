package contract_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

// defaultContract cria um contrato válido para os testes.
func defaultContract(t *testing.T, risk contract.RiskLevel) contract.TaskContractV4 {
	t.Helper()
	taskContract, err := contract.CreateDefaultContractV4("1.1", "0001", "Task Teste", risk, nil)
	if err != nil {
		t.Fatalf("CreateDefaultContractV4(%q) devolveu erro: %v", risk, err)
	}
	return taskContract
}

func TestCreateDefaultContractV4Dimensions(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL2)

	if taskContract.ContractVersion != contract.ContractVersionV4 {
		t.Fatalf("contract_version = %q, quer %q", taskContract.ContractVersion, contract.ContractVersionV4)
	}
	if taskContract.TaskID != "1.1" || taskContract.WorkID != "0001" || taskContract.Title != "Task Teste" {
		t.Fatalf("identidade do contrato divergiu: %+v", taskContract)
	}
	if taskContract.Risk.Level != contract.RiskL2 {
		t.Fatalf("risk.level = %q, quer L2", taskContract.Risk.Level)
	}
	if got, want := taskContract.Risk.Reasons, []string{"Task 1.1 classificada como L2"}; !equalStrings(got, want) {
		t.Fatalf("risk.reasons = %v, quer %v", got, want)
	}
	if taskContract.ValidationStrategy != contract.StrategyRegressionGuarded {
		t.Fatalf("validation_strategy = %q", taskContract.ValidationStrategy)
	}
	if len(taskContract.BehavioralContract.Scenarios) != 2 {
		t.Fatalf("cenários = %d, quer 2", len(taskContract.BehavioralContract.Scenarios))
	}
	if taskContract.BehavioralContract.Scenarios[0].ID != "SCENARIO-1.1-01" {
		t.Fatalf("id do cenário = %q", taskContract.BehavioralContract.Scenarios[0].ID)
	}
	wantGiven := "Dado que a tarefa \"Task Teste\" foi atribuída com risco L2"
	if taskContract.BehavioralContract.Scenarios[0].Given != wantGiven {
		t.Fatalf("given = %q, quer %q", taskContract.BehavioralContract.Scenarios[0].Given, wantGiven)
	}
	if !equalStrings(taskContract.ChangeContract.TargetFiles, []string{"src/**"}) {
		t.Fatalf("target_files = %v", taskContract.ChangeContract.TargetFiles)
	}
	if !equalStrings(taskContract.ChangeContract.AffectedComponents, []string{"core"}) {
		t.Fatalf("affected_components = %v", taskContract.ChangeContract.AffectedComponents)
	}
	if !equalStrings(taskContract.AcceptanceContract.Commands, []string{"bun test"}) {
		t.Fatalf("commands = %v", taskContract.AcceptanceContract.Commands)
	}
	if !equalStrings(taskContract.AcceptanceContract.RequiredEvidence, []string{"evidence.json"}) {
		t.Fatalf("required_evidence = %v", taskContract.AcceptanceContract.RequiredEvidence)
	}
	if !equalStrings(taskContract.ScopeContract.WriteAllow, []string{"src/**", "tests/**"}) {
		t.Fatalf("write_allow = %v", taskContract.ScopeContract.WriteAllow)
	}
	if !equalStrings(taskContract.ScopeContract.WriteDeny, []string{".git/**", "package.json", ".env*"}) {
		t.Fatalf("write_deny = %v", taskContract.ScopeContract.WriteDeny)
	}
	if !equalStrings(taskContract.ScopeContract.OutOfScope, []string{"Mudanças de infraestrutura ou banco não especificadas"}) {
		t.Fatalf("out_of_scope = %v", taskContract.ScopeContract.OutOfScope)
	}
	if taskContract.EscalationContract.OnWriteViolation != contract.OnWriteViolationBlockAndEscalate {
		t.Fatalf("on_write_violation = %q", taskContract.EscalationContract.OnWriteViolation)
	}
}

func TestCreateDefaultContractV4BudgetByRisk(t *testing.T) {
	tests := []struct {
		risk       contract.RiskLevel
		tokens     int
		cost       float64
		duration   int
		attempts   int
		llm        int
		tools      int
		shell      int
		strategy   contract.ValidationStrategy
		invariants int
		budgetEsc  string
		attemptEsc string
	}{
		{contract.RiskL0, 10_000, 0.10, 5, 2, 10, 20, 5, contract.StrategyRegressionGuarded, 2, contract.OnBudgetExceededEscalateToStrongAgent, contract.OnAttemptFailedRetryWithStrong},
		{contract.RiskL1, 30_000, 0.30, 10, 3, 20, 40, 10, contract.StrategyRegressionGuarded, 2, contract.OnBudgetExceededEscalateToStrongAgent, contract.OnAttemptFailedRetryWithStrong},
		{contract.RiskL2, 50_000, 0.50, 15, 5, 30, 60, 15, contract.StrategyRegressionGuarded, 2, contract.OnBudgetExceededEscalateToStrongAgent, contract.OnAttemptFailedRetryWithStrong},
		{contract.RiskL3, 100_000, 2.00, 30, 5, 50, 100, 30, contract.StrategyTDDStrict, 3, contract.OnBudgetExceededEscalateToStrongAgent, contract.OnAttemptFailedRetryWithStrong},
		{contract.RiskL4, 200_000, 5.00, 60, 3, 30, 50, 10, contract.StrategyTDDStrict, 3, contract.OnBudgetExceededHumanReview, contract.OnAttemptFailedHumanReview},
	}

	for _, test := range tests {
		t.Run(string(test.risk), func(t *testing.T) {
			taskContract := defaultContract(t, test.risk)
			budget := taskContract.BudgetContract

			if got := derefInt(budget.MaxTokens); got != test.tokens {
				t.Fatalf("max_tokens = %d, quer %d", got, test.tokens)
			}
			if got := derefFloat(budget.MaxCostUSD); got != test.cost {
				t.Fatalf("max_cost_usd = %v, quer %v", got, test.cost)
			}
			if got := derefInt(budget.MaxDurationMinutes); got != test.duration {
				t.Fatalf("max_duration_minutes = %d, quer %d", got, test.duration)
			}
			if budget.MaxAgentAttempts != test.attempts {
				t.Fatalf("max_agent_attempts = %d, quer %d", budget.MaxAgentAttempts, test.attempts)
			}
			if got := derefInt(budget.MaxLLMCalls); got != test.llm {
				t.Fatalf("max_llm_calls = %d, quer %d", got, test.llm)
			}
			if got := derefInt(budget.MaxToolCalls); got != test.tools {
				t.Fatalf("max_tool_calls = %d, quer %d", got, test.tools)
			}
			if got := derefInt(budget.MaxShellExecutions); got != test.shell {
				t.Fatalf("max_shell_executions = %d, quer %d", got, test.shell)
			}
			if taskContract.ValidationStrategy != test.strategy {
				t.Fatalf("validation_strategy = %q, quer %q", taskContract.ValidationStrategy, test.strategy)
			}
			if got := len(taskContract.ArchitectureContract.Invariants); got != test.invariants {
				t.Fatalf("invariantes = %d, quer %d", got, test.invariants)
			}
			if taskContract.EscalationContract.OnBudgetExceeded != test.budgetEsc {
				t.Fatalf("on_budget_exceeded = %q, quer %q", taskContract.EscalationContract.OnBudgetExceeded, test.budgetEsc)
			}
			if taskContract.EscalationContract.OnAttemptFailed != test.attemptEsc {
				t.Fatalf("on_attempt_failed = %q, quer %q", taskContract.EscalationContract.OnAttemptFailed, test.attemptEsc)
			}
		})
	}
}

func TestCreateDefaultContractV4Overrides(t *testing.T) {
	taskContract, err := contract.CreateDefaultContractV4("T-003", "0001", "Custom Task", contract.RiskL2, &contract.DefaultOptions{
		WriteAllow: []string{"lib/**"},
		WriteDeny:  []string{"node_modules/**"},
		Invariants: []string{"Custom invariant"},
		Scenarios: []contract.Scenario{{
			ID:    "SC-001",
			Given: "Custom given",
			When:  "Custom when",
			Then:  "Custom then",
		}},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if !equalStrings(taskContract.ScopeContract.WriteAllow, []string{"lib/**"}) {
		t.Fatalf("write_allow = %v", taskContract.ScopeContract.WriteAllow)
	}
	if !equalStrings(taskContract.ChangeContract.TargetFiles, []string{"lib/**"}) {
		t.Fatalf("target_files = %v", taskContract.ChangeContract.TargetFiles)
	}
	if !equalStrings(taskContract.ScopeContract.WriteDeny, []string{"node_modules/**"}) {
		t.Fatalf("write_deny = %v", taskContract.ScopeContract.WriteDeny)
	}
	if !equalStrings(taskContract.ArchitectureContract.Invariants, []string{"Custom invariant"}) {
		t.Fatalf("invariants = %v", taskContract.ArchitectureContract.Invariants)
	}
	if len(taskContract.BehavioralContract.Scenarios) != 1 || taskContract.BehavioralContract.Scenarios[0].ID != "SC-001" {
		t.Fatalf("scenarios = %+v", taskContract.BehavioralContract.Scenarios)
	}
}

func TestCreateDefaultContractV4EmptyOptionsReplaceDefaults(t *testing.T) {
	taskContract, err := contract.CreateDefaultContractV4("T-004", "0001", "Empty", contract.RiskL1, &contract.DefaultOptions{
		WriteAllow: []string{},
		WriteDeny:  []string{},
		Invariants: []string{},
		Scenarios:  []contract.Scenario{},
	})
	if err != nil {
		t.Fatalf("erro: %v", err)
	}
	if taskContract.ScopeContract.WriteAllow == nil || len(taskContract.ScopeContract.WriteAllow) != 0 {
		t.Fatalf("write_allow = %v, quer slice vazio", taskContract.ScopeContract.WriteAllow)
	}
	if taskContract.ChangeContract.TargetFiles == nil || len(taskContract.ChangeContract.TargetFiles) != 0 {
		t.Fatalf("target_files = %v, quer slice vazio", taskContract.ChangeContract.TargetFiles)
	}
	if taskContract.ScopeContract.WriteDeny == nil || len(taskContract.ScopeContract.WriteDeny) != 0 {
		t.Fatalf("write_deny = %v, quer slice vazio", taskContract.ScopeContract.WriteDeny)
	}
	if taskContract.ArchitectureContract.Invariants == nil || len(taskContract.ArchitectureContract.Invariants) != 0 {
		t.Fatalf("invariants = %v, quer slice vazio", taskContract.ArchitectureContract.Invariants)
	}
	if taskContract.BehavioralContract.Scenarios == nil || len(taskContract.BehavioralContract.Scenarios) != 0 {
		t.Fatalf("scenarios = %v, quer slice vazio", taskContract.BehavioralContract.Scenarios)
	}
}

func TestCreateDefaultContractV4RiskArgument(t *testing.T) {
	empty, err := contract.CreateDefaultContractV4("T-005", "0001", "Empty Risk", "", nil)
	if err != nil {
		t.Fatalf("risco vazio devolveu erro: %v", err)
	}
	if empty.Risk.Level != contract.RiskL1 {
		t.Fatalf("risco vazio = %q, quer L1", empty.Risk.Level)
	}

	if _, err := contract.CreateDefaultContractV4("T-006", "0001", "Bad Risk", "L9", nil); !errors.Is(err, contract.ErrInvalidRiskLevel) {
		t.Fatalf("risco inválido devolveu %v, quer ErrInvalidRiskLevel", err)
	}
}

func TestTaskContractV4JSONShape(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL1)
	encoded, err := json.Marshal(taskContract)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"contract_version", "task_id", "work_id", "title", "risk", "validation_strategy",
		"behavioral_contract", "change_contract", "architecture_contract", "acceptance_contract",
		"scope_contract", "budget_contract", "escalation_contract",
	} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("campo %q ausente no JSON: %s", key, encoded)
		}
	}
	budget, ok := decoded["budget_contract"].(map[string]any)
	if !ok {
		t.Fatalf("budget_contract não é objeto: %s", encoded)
	}
	for _, key := range []string{"max_tokens", "max_cost_usd", "max_duration_minutes", "max_agent_attempts", "max_llm_calls", "max_tool_calls", "max_shell_executions"} {
		if _, ok := budget[key]; !ok {
			t.Fatalf("campo budget %q ausente: %s", key, encoded)
		}
	}
	acceptance, ok := decoded["acceptance_contract"].(map[string]any)
	if !ok {
		t.Fatalf("acceptance_contract não é objeto: %s", encoded)
	}
	if _, ok := acceptance["frozen_tests"]; ok {
		t.Fatalf("frozen_tests não deveria aparecer sem congelamento: %s", encoded)
	}
	scope, ok := decoded["scope_contract"].(map[string]any)
	if !ok {
		t.Fatalf("scope_contract não é objeto: %s", encoded)
	}
	if _, ok := scope["out_of_scope"]; !ok {
		t.Fatalf("out_of_scope ausente: %s", encoded)
	}

	// A ordem dos campos acompanha a interface do TypeScript.
	order := []string{"contract_version", "task_id", "work_id", "title", "risk", "validation_strategy",
		"behavioral_contract", "change_contract", "architecture_contract", "acceptance_contract",
		"scope_contract", "budget_contract", "escalation_contract"}
	previous := -1
	for _, key := range order {
		index := strings.Index(string(encoded), "\""+key+"\"")
		if index <= previous {
			t.Fatalf("campo %q fora de ordem em %s", key, encoded)
		}
		previous = index
	}
}

func TestTaskContractV4OptionalFieldsOmitted(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL1)
	taskContract.AcceptanceContract.FrozenTests = nil
	taskContract.ScopeContract.OutOfScope = nil
	taskContract.BudgetContract.MaxTokens = nil
	encoded, err := json.Marshal(taskContract)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"frozen_tests", "out_of_scope", "max_tokens"} {
		if strings.Contains(string(encoded), "\""+key+"\"") {
			t.Fatalf("campo opcional %q deveria ser omitido: %s", key, encoded)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func derefFloat(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}
