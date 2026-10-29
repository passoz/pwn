// Package contract porta src/core/contract-engine.ts e src/core/contract-guard.ts.
//
// O contrato V4 é a fronteira de execução de uma task: sete dimensões declaradas
// (behavioral, change, architecture, acceptance, scope, budget e escalation) mais
// o risco. O pacote entrega:
//
//   - os tipos com os mesmos campos JSON do TypeScript;
//   - CreateDefaultContractV4 com os mesmos defaults, escalados por risco;
//   - DeriveTaskRisk, a classificação heurística de `--risk auto`;
//   - BudgetController, que transforma o budget declarativo em limite executável;
//   - o Diff Guard (CheckFileAgainstScope, InvalidScopePattern e
//     CheckDiffAgainstContract), que usa internal/platform/glob;
//   - ValidateSemantics, a parte pura da validação semântica do contrato.
//
// O pacote não lê ambiente, não abre arquivo de contrato e não executa processo.
// A leitura do JSON do Work pertence aos pacotes de camada superior.
package contract

import (
	"errors"
	"fmt"
)

// ContractVersionV4 é a única versão aceita pelo contrato congelado.
const ContractVersionV4 = "4.0"

// RiskLevel é o nível de risco de uma task. L4 nunca é atribuído por heurística:
// ele suspende a execução para revisão humana.
type RiskLevel string

const (
	RiskL0 RiskLevel = "L0"
	RiskL1 RiskLevel = "L1"
	RiskL2 RiskLevel = "L2"
	RiskL3 RiskLevel = "L3"
	RiskL4 RiskLevel = "L4"
)

// riskOrder é a ordem crescente de risco.
var riskOrder = []RiskLevel{RiskL0, RiskL1, RiskL2, RiskL3, RiskL4}

// ErrInvalidRiskLevel indica um risco fora de L0..L4.
var ErrInvalidRiskLevel = errors.New("nível de risco inválido")

// Valid informa se o nível está em L0..L4.
func (r RiskLevel) Valid() bool {
	return r.Rank() >= 0
}

// Rank devolve a posição do nível em L0..L4. Devolve -1 para nível inválido.
func (r RiskLevel) Rank() int {
	for index, level := range riskOrder {
		if level == r {
			return index
		}
	}
	return -1
}

// AtLeast informa se o nível é igual ou superior a minimum. Nível inválido nunca
// satisfaz a comparação.
func (r RiskLevel) AtLeast(minimum RiskLevel) bool {
	rank, floor := r.Rank(), minimum.Rank()
	return rank >= 0 && floor >= 0 && rank >= floor
}

// ParseRiskLevel converte e valida um nível lido de JSON ou de argumento.
func ParseRiskLevel(value string) (RiskLevel, error) {
	level := RiskLevel(value)
	if !level.Valid() {
		return "", fmt.Errorf("%w: %q (use L0, L1, L2, L3 ou L4)", ErrInvalidRiskLevel, value)
	}
	return level, nil
}

// ValidationStrategy é a estratégia de validação declarada no contrato.
type ValidationStrategy string

const (
	StrategyTDDStrict         ValidationStrategy = "tdd-strict"
	StrategyContractFirst     ValidationStrategy = "contract-first"
	StrategyRegressionGuarded ValidationStrategy = "regression-guarded"
	StrategyVisualContract    ValidationStrategy = "visual-contract"
)

// Ações de escalação. Os valores são literais do TypeScript e entram no JSON.
const (
	OnWriteViolationBlockAndEscalate = "block_and_escalate"

	OnBudgetExceededEscalateToStrongAgent = "escalate_to_strong_agent"
	OnBudgetExceededHumanReview           = "human_review"

	OnAttemptFailedRetryWithStrong = "retry_with_strong"
	OnAttemptFailedHumanReview     = "human_review"
)

// TaskContractV4 é o contrato congelado de uma task. A ordem dos campos segue a
// interface do TypeScript para que o JSON serializado mantenha a mesma forma.
type TaskContractV4 struct {
	ContractVersion      string               `json:"contract_version"`
	TaskID               string               `json:"task_id"`
	WorkID               string               `json:"work_id"`
	Title                string               `json:"title"`
	Risk                 RiskContract         `json:"risk"`
	ValidationStrategy   ValidationStrategy   `json:"validation_strategy"`
	BehavioralContract   BehavioralContract   `json:"behavioral_contract"`
	ChangeContract       ChangeContract       `json:"change_contract"`
	ArchitectureContract ArchitectureContract `json:"architecture_contract"`
	AcceptanceContract   AcceptanceContract   `json:"acceptance_contract"`
	ScopeContract        ScopeContract        `json:"scope_contract"`
	BudgetContract       BudgetContract       `json:"budget_contract"`
	EscalationContract   EscalationContract   `json:"escalation_contract"`
}

// RiskContract declara o nível e os motivos da classificação.
type RiskContract struct {
	Level   RiskLevel `json:"level"`
	Reasons []string  `json:"reasons"`
}

// Scenario é um cenário dado/quando/então do contrato comportamental.
type Scenario struct {
	ID    string `json:"id"`
	Given string `json:"given"`
	When  string `json:"when"`
	Then  string `json:"then"`
}

// BehavioralContract declara os cenários observáveis.
type BehavioralContract struct {
	Scenarios []Scenario `json:"scenarios"`
}

// ChangeContract declara onde a mudança pode tocar.
type ChangeContract struct {
	TargetFiles        []string `json:"target_files"`
	AffectedComponents []string `json:"affected_components"`
}

// ArchitectureContract declara as invariantes que a mudança não pode violar.
type ArchitectureContract struct {
	Invariants []string `json:"invariants"`
}

// FrozenTest é um teste de aceitação congelado antes da implementação. O audit
// recusa a atestação quando o sha256 muda.
type FrozenTest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// AcceptanceContract declara os comandos e as evidências exigidas.
type AcceptanceContract struct {
	Commands         []string     `json:"commands"`
	RequiredEvidence []string     `json:"required_evidence"`
	FrozenTests      []FrozenTest `json:"frozen_tests,omitempty"`
}

// ScopeContract declara a allowlist e a denylist de escrita. OutOfScope é
// opcional porque contratos V4 anteriores à padronização podem omiti-lo.
type ScopeContract struct {
	WriteAllow []string `json:"write_allow"`
	WriteDeny  []string `json:"write_deny"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
}

// BudgetContract declara os limites executáveis. Os ponteiros preservam a
// diferença entre limite ausente e limite zero, como `undefined` no TypeScript.
type BudgetContract struct {
	MaxTokens          *int     `json:"max_tokens,omitempty"`
	MaxCostUSD         *float64 `json:"max_cost_usd,omitempty"`
	MaxDurationMinutes *int     `json:"max_duration_minutes,omitempty"`
	MaxAgentAttempts   int      `json:"max_agent_attempts"`
	MaxLLMCalls        *int     `json:"max_llm_calls,omitempty"`
	MaxToolCalls       *int     `json:"max_tool_calls,omitempty"`
	MaxShellExecutions *int     `json:"max_shell_executions,omitempty"`
}

// EscalationContract declara o que fazer em cada falha.
type EscalationContract struct {
	OnWriteViolation string `json:"on_write_violation"`
	OnBudgetExceeded string `json:"on_budget_exceeded"`
	OnAttemptFailed  string `json:"on_attempt_failed"`
}

// IsHighRisk informa se o risco exige TDD estrito e revisão.
func IsHighRisk(level RiskLevel) bool {
	return level == RiskL3 || level == RiskL4
}

// ValidationStrategyForRisk devolve a estratégia implícita do nível de risco.
func ValidationStrategyForRisk(level RiskLevel) ValidationStrategy {
	if IsHighRisk(level) {
		return StrategyTDDStrict
	}
	return StrategyRegressionGuarded
}

// riskLabel é a forma usada nas mensagens default, igual ao TypeScript.
func riskLabel(level RiskLevel) string { return string(level) }
