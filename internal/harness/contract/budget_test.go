package contract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

func TestEvaluateBudget(t *testing.T) {
	tests := []struct {
		name        string
		usage       contract.BudgetUsage
		wantNil     bool
		wantReason  contract.BudgetViolationReason
		wantLimit   float64
		wantActual  float64
		wantMessage string
	}{
		{
			name:    "consumo dentro do budget",
			usage:   contract.BudgetUsage{},
			wantNil: true,
		},
		{
			name:        "tentativas no limite",
			usage:       contract.BudgetUsage{AgentAttempts: 2},
			wantReason:  contract.BudgetReasonMaxAgentAttempts,
			wantLimit:   2,
			wantActual:  2,
			wantMessage: "Limite de tentativas do agente excedido: 2/2",
		},
		{
			name:        "chamadas LLM no limite",
			usage:       contract.BudgetUsage{LLMCalls: 10},
			wantReason:  contract.BudgetReasonMaxLLMCalls,
			wantLimit:   10,
			wantActual:  10,
			wantMessage: "Limite de chamadas LLM excedido: 10/10",
		},
		{
			name:        "chamadas de ferramenta no limite",
			usage:       contract.BudgetUsage{ToolCalls: 20},
			wantReason:  contract.BudgetReasonMaxToolCalls,
			wantLimit:   20,
			wantActual:  20,
			wantMessage: "Limite de chamadas de ferramenta excedido: 20/20",
		},
		{
			name:        "execucoes shell no limite",
			usage:       contract.BudgetUsage{ShellExecutions: 5},
			wantReason:  contract.BudgetReasonMaxShellExecutions,
			wantLimit:   5,
			wantActual:  5,
			wantMessage: "Limite de execuções shell excedido: 5/5",
		},
		{
			name:        "duracao no limite",
			usage:       contract.BudgetUsage{DurationMs: 300_000},
			wantReason:  contract.BudgetReasonMaxDurationMinutes,
			wantLimit:   5,
			wantActual:  5,
			wantMessage: "Limite de duração excedido: 5.0min/5min",
		},
		{
			name:        "tokens no limite",
			usage:       contract.BudgetUsage{Tokens: 10_000},
			wantReason:  contract.BudgetReasonMaxTokens,
			wantLimit:   10_000,
			wantActual:  10_000,
			wantMessage: "Limite de tokens excedido: 10000/10000",
		},
		{
			name:        "custo no limite",
			usage:       contract.BudgetUsage{CostUSD: 0.10},
			wantReason:  contract.BudgetReasonMaxCostUSD,
			wantLimit:   0.10,
			wantActual:  0.10,
			wantMessage: "Limite de custo excedido: $0.1000/$0.1",
		},
		{
			name: "tudo excedido devolve a primeira checagem",
			usage: contract.BudgetUsage{
				Tokens: 99_999, CostUSD: 1, DurationMs: 999_999,
				AgentAttempts: 2, LLMCalls: 99, ToolCalls: 99, ShellExecutions: 99,
			},
			wantReason:  contract.BudgetReasonMaxAgentAttempts,
			wantLimit:   2,
			wantActual:  2,
			wantMessage: "Limite de tentativas do agente excedido: 2/2",
		},
	}

	budget, err := contract.BudgetForRisk(contract.RiskL0)
	if err != nil {
		t.Fatalf("BudgetForRisk: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			violation := contract.EvaluateBudget(budget, test.usage)
			if test.wantNil {
				if violation != nil {
					t.Fatalf("violação = %+v, quer nil", violation)
				}
				return
			}
			if violation == nil {
				t.Fatal("violação = nil")
			}
			if violation.Reason != test.wantReason {
				t.Fatalf("reason = %q, quer %q", violation.Reason, test.wantReason)
			}
			if violation.Limit != test.wantLimit {
				t.Fatalf("limit = %v, quer %v", violation.Limit, test.wantLimit)
			}
			if violation.Actual != test.wantActual {
				t.Fatalf("actual = %v, quer %v", violation.Actual, test.wantActual)
			}
			if violation.Message != test.wantMessage {
				t.Fatalf("message = %q, quer %q", violation.Message, test.wantMessage)
			}
		})
	}
}

func TestEvaluateBudgetBelowLimits(t *testing.T) {
	budget, err := contract.BudgetForRisk(contract.RiskL0)
	if err != nil {
		t.Fatalf("BudgetForRisk: %v", err)
	}
	usage := contract.BudgetUsage{
		Tokens:          9_999,
		CostUSD:         0.09,
		DurationMs:      299_999,
		AgentAttempts:   1,
		LLMCalls:        9,
		ToolCalls:       19,
		ShellExecutions: 4,
	}
	if violation := contract.EvaluateBudget(budget, usage); violation != nil {
		t.Fatalf("violação = %+v, quer nil", violation)
	}
}

func TestEvaluateBudgetAbsentOptionalLimits(t *testing.T) {
	budget := contract.BudgetContract{MaxAgentAttempts: 3}
	if violation := contract.EvaluateBudget(budget, contract.BudgetUsage{Tokens: 1_000_000, CostUSD: 99, DurationMs: 99_999_999, LLMCalls: 1000}); violation != nil {
		t.Fatalf("violação = %+v, quer nil", violation)
	}
	violation := contract.EvaluateBudget(budget, contract.BudgetUsage{AgentAttempts: 3})
	if violation == nil || violation.Reason != contract.BudgetReasonMaxAgentAttempts {
		t.Fatalf("violação = %+v, quer max_agent_attempts", violation)
	}
}

func TestBudgetControllerRecordsAndInterrupts(t *testing.T) {
	taskContract := defaultContract(t, contract.RiskL0)
	controller := contract.NewBudgetController(taskContract)

	if controller.ShouldInterrupt() {
		t.Fatal("controlador novo não deveria interromper")
	}
	controller.RecordTokens(1_000)
	controller.RecordCost(0.01)
	controller.RecordLLMCall()
	controller.RecordToolCall()
	controller.RecordShellExecution()
	controller.RecordAgentAttempt()

	usage := controller.GetUsage()
	if usage.Tokens != 1_000 || usage.CostUSD != 0.01 || usage.LLMCalls != 1 || usage.ToolCalls != 1 || usage.ShellExecutions != 1 || usage.AgentAttempts != 1 {
		t.Fatalf("usage = %+v", usage)
	}
	if usage.DurationMs < 0 {
		t.Fatalf("durationMs = %d, quer >= 0", usage.DurationMs)
	}

	controller.RecordAgentAttempt()
	violation := controller.CheckBudget()
	if violation == nil || violation.Reason != contract.BudgetReasonMaxAgentAttempts {
		t.Fatalf("violação = %+v, quer max_agent_attempts", violation)
	}
	if !controller.ShouldInterrupt() {
		t.Fatal("ShouldInterrupt = false com tentativas no limite")
	}
}

func TestBudgetControllerSaveAndLoad(t *testing.T) {
	controller := contract.NewBudgetController(defaultContract(t, contract.RiskL1))
	controller.RecordTokens(500)
	controller.RecordCost(0.05)
	controller.RecordAgentAttempt()
	controller.RecordLLMCall()
	controller.RecordToolCall()
	controller.RecordShellExecution()

	path := filepath.Join(t.TempDir(), "nested", "usage.json")
	if err := controller.SaveUsage(path); err != nil {
		t.Fatalf("SaveUsage: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("JSON gravado é inválido: %v", err)
	}
	for _, key := range []string{"tokens", "costUsd", "durationMs", "agentAttempts", "llmCalls", "toolCalls", "shellExecutions"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("chave %q ausente em %s", key, raw)
		}
	}

	loaded, ok := contract.LoadBudgetUsage(path)
	if !ok {
		t.Fatal("LoadBudgetUsage devolveu ok=false")
	}
	if loaded.Tokens != 500 || loaded.CostUSD != 0.05 || loaded.AgentAttempts != 1 || loaded.LLMCalls != 1 || loaded.ToolCalls != 1 || loaded.ShellExecutions != 1 {
		t.Fatalf("usage carregado = %+v", loaded)
	}
}

func TestLoadBudgetUsageMissingOrInvalid(t *testing.T) {
	if _, ok := contract.LoadBudgetUsage(filepath.Join(t.TempDir(), "absent.json")); ok {
		t.Fatal("arquivo ausente deveria devolver ok=false")
	}
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, ok := contract.LoadBudgetUsage(path); ok {
		t.Fatal("JSON inválido deveria devolver ok=false")
	}
}
