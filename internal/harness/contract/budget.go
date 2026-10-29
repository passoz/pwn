package contract

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// BudgetViolationReason identifica qual limite foi excedido.
type BudgetViolationReason string

const (
	BudgetReasonMaxTokens          BudgetViolationReason = "max_tokens"
	BudgetReasonMaxCostUSD         BudgetViolationReason = "max_cost_usd"
	BudgetReasonMaxDurationMinutes BudgetViolationReason = "max_duration_minutes"
	BudgetReasonMaxAgentAttempts   BudgetViolationReason = "max_agent_attempts"
	BudgetReasonMaxLLMCalls        BudgetViolationReason = "max_llm_calls"
	BudgetReasonMaxToolCalls       BudgetViolationReason = "max_tool_calls"
	BudgetReasonMaxShellExecutions BudgetViolationReason = "max_shell_executions"
)

// BudgetViolation é a primeira violação encontrada, na ordem do TypeScript.
type BudgetViolation struct {
	Reason  BudgetViolationReason `json:"reason"`
	Limit   float64               `json:"limit"`
	Actual  float64               `json:"actual"`
	Message string                `json:"message"`
}

// BudgetUsage acumula o consumo em unidades distintas.
type BudgetUsage struct {
	Tokens          int     `json:"tokens"`
	CostUSD         float64 `json:"costUsd"`
	DurationMs      int64   `json:"durationMs"`
	AgentAttempts   int     `json:"agentAttempts"`
	LLMCalls        int     `json:"llmCalls"`
	ToolCalls       int     `json:"toolCalls"`
	ShellExecutions int     `json:"shellExecutions"`
}

// BudgetController transforma o budget declarativo em limite executável.
//
// As unidades são contadas separadamente: tentativas do agente, chamadas LLM,
// chamadas de ferramenta e execuções shell.
type BudgetController struct {
	contract TaskContractV4
	usage    BudgetUsage
	start    time.Time
	now      func() time.Time
}

// NewBudgetController cria o controlador com o relógio do sistema.
func NewBudgetController(taskContract TaskContractV4) *BudgetController {
	return &BudgetController{
		contract: taskContract,
		start:    time.Now(),
		now:      time.Now,
	}
}

// RecordTokens registra os tokens de uma chamada LLM.
func (b *BudgetController) RecordTokens(count int) { b.usage.Tokens += count }

// RecordCost registra o custo de uma chamada LLM.
func (b *BudgetController) RecordCost(usd float64) { b.usage.CostUSD += usd }

// RecordAgentAttempt registra uma tentativa de alto nível do agente.
func (b *BudgetController) RecordAgentAttempt() {
	b.usage.AgentAttempts++
	b.usage.DurationMs = b.now().Sub(b.start).Milliseconds()
}

// RecordLLMCall registra uma chamada de prompt.
func (b *BudgetController) RecordLLMCall() { b.usage.LLMCalls++ }

// RecordToolCall registra uma invocação de ferramenta.
func (b *BudgetController) RecordToolCall() { b.usage.ToolCalls++ }

// RecordShellExecution registra um processo shell spawnado.
func (b *BudgetController) RecordShellExecution() { b.usage.ShellExecutions++ }

// GetUsage devolve o consumo atual com a duração recalculada.
func (b *BudgetController) GetUsage() BudgetUsage {
	usage := b.usage
	usage.DurationMs = b.now().Sub(b.start).Milliseconds()
	return usage
}

// CheckBudget devolve a primeira violação, ou nil quando o consumo está dentro
// do contrato.
func (b *BudgetController) CheckBudget() *BudgetViolation {
	return EvaluateBudget(b.contract.BudgetContract, b.GetUsage())
}

// ShouldInterrupt informa se algum limite foi excedido.
func (b *BudgetController) ShouldInterrupt() bool {
	return b.CheckBudget() != nil
}

// SaveUsage persiste o consumo atual em JSON, no mesmo formato do TypeScript.
func (b *BudgetController) SaveUsage(path string) error {
	data, err := json.MarshalIndent(b.GetUsage(), "", "  ")
	if err != nil {
		return fmt.Errorf("serializar budget de %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("criar diretório do budget de %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("gravar budget de %s: %w", path, err)
	}
	return nil
}

// LoadBudgetUsage lê um consumo persistido. Devolve ok=false quando o arquivo
// não existe ou não é JSON válido, como o loadUsage do TypeScript.
func LoadBudgetUsage(path string) (BudgetUsage, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BudgetUsage{}, false
	}
	var usage BudgetUsage
	if err := json.Unmarshal(data, &usage); err != nil {
		return BudgetUsage{}, false
	}
	return usage, true
}

// EvaluateBudget confere o consumo contra o budget. A ordem das checagens é a
// mesma do TypeScript: tentativas, LLM, ferramenta, shell, duração, tokens e
// custo. O limite é atingido com `>=`.
func EvaluateBudget(budget BudgetContract, usage BudgetUsage) *BudgetViolation {
	if max := budget.MaxAgentAttempts; usage.AgentAttempts >= max {
		return &BudgetViolation{
			Reason:  BudgetReasonMaxAgentAttempts,
			Limit:   float64(max),
			Actual:  float64(usage.AgentAttempts),
			Message: fmt.Sprintf("Limite de tentativas do agente excedido: %d/%d", usage.AgentAttempts, max),
		}
	}
	if budget.MaxLLMCalls != nil && usage.LLMCalls >= *budget.MaxLLMCalls {
		return &BudgetViolation{
			Reason:  BudgetReasonMaxLLMCalls,
			Limit:   float64(*budget.MaxLLMCalls),
			Actual:  float64(usage.LLMCalls),
			Message: fmt.Sprintf("Limite de chamadas LLM excedido: %d/%d", usage.LLMCalls, *budget.MaxLLMCalls),
		}
	}
	if budget.MaxToolCalls != nil && usage.ToolCalls >= *budget.MaxToolCalls {
		return &BudgetViolation{
			Reason:  BudgetReasonMaxToolCalls,
			Limit:   float64(*budget.MaxToolCalls),
			Actual:  float64(usage.ToolCalls),
			Message: fmt.Sprintf("Limite de chamadas de ferramenta excedido: %d/%d", usage.ToolCalls, *budget.MaxToolCalls),
		}
	}
	if budget.MaxShellExecutions != nil && usage.ShellExecutions >= *budget.MaxShellExecutions {
		return &BudgetViolation{
			Reason:  BudgetReasonMaxShellExecutions,
			Limit:   float64(*budget.MaxShellExecutions),
			Actual:  float64(usage.ShellExecutions),
			Message: fmt.Sprintf("Limite de execuções shell excedido: %d/%d", usage.ShellExecutions, *budget.MaxShellExecutions),
		}
	}
	if budget.MaxDurationMinutes != nil {
		minutes := float64(usage.DurationMs) / 60_000
		limit := *budget.MaxDurationMinutes
		if minutes >= float64(limit) {
			return &BudgetViolation{
				Reason:  BudgetReasonMaxDurationMinutes,
				Limit:   float64(limit),
				Actual:  math.Round(minutes*10) / 10,
				Message: fmt.Sprintf("Limite de duração excedido: %smin/%dmin", strconv.FormatFloat(minutes, 'f', 1, 64), limit),
			}
		}
	}
	if budget.MaxTokens != nil && usage.Tokens >= *budget.MaxTokens {
		return &BudgetViolation{
			Reason:  BudgetReasonMaxTokens,
			Limit:   float64(*budget.MaxTokens),
			Actual:  float64(usage.Tokens),
			Message: fmt.Sprintf("Limite de tokens excedido: %d/%d", usage.Tokens, *budget.MaxTokens),
		}
	}
	if budget.MaxCostUSD != nil && usage.CostUSD >= *budget.MaxCostUSD {
		return &BudgetViolation{
			Reason:  BudgetReasonMaxCostUSD,
			Limit:   *budget.MaxCostUSD,
			Actual:  usage.CostUSD,
			Message: fmt.Sprintf("Limite de custo excedido: $%.4f/$%s", usage.CostUSD, formatBudgetNumber(*budget.MaxCostUSD)),
		}
	}
	return nil
}

// formatBudgetNumber imprime o limite como `String(number)` do JavaScript.
func formatBudgetNumber(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}
