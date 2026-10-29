package contract

import "fmt"

// DefaultOptions são os overrides aceitos por CreateDefaultContractV4.
//
// Um campo nil usa o default do TypeScript. Um slice não nil, mesmo vazio,
// substitui o default — a mesma distinção entre `undefined` e `[]`.
type DefaultOptions struct {
	WriteAllow []string
	WriteDeny  []string
	Invariants []string
	Scenarios  []Scenario
}

// budgetDefaults é a tabela de budget por risco, sem ponteiros para que cada
// contrato receba valores independentes.
type budgetDefaults struct {
	maxTokens          int
	maxCostUSD         float64
	maxDurationMinutes int
	maxAgentAttempts   int
	maxLLMCalls        int
	maxToolCalls       int
	maxShellExecutions int
}

var budgetsByRisk = map[RiskLevel]budgetDefaults{
	RiskL0: {10_000, 0.10, 5, 2, 10, 20, 5},
	RiskL1: {30_000, 0.30, 10, 3, 20, 40, 10},
	RiskL2: {50_000, 0.50, 15, 5, 30, 60, 15},
	RiskL3: {100_000, 2.00, 30, 5, 50, 100, 30},
	RiskL4: {200_000, 5.00, 60, 3, 30, 50, 10},
}

// BudgetForRisk devolve o budget default do nível de risco.
func BudgetForRisk(level RiskLevel) (BudgetContract, error) {
	defaults, ok := budgetsByRisk[level]
	if !ok {
		return BudgetContract{}, fmt.Errorf("%w: %q", ErrInvalidRiskLevel, level)
	}
	return BudgetContract{
		MaxTokens:          new(defaults.maxTokens),
		MaxCostUSD:         new(defaults.maxCostUSD),
		MaxDurationMinutes: new(defaults.maxDurationMinutes),
		MaxAgentAttempts:   defaults.maxAgentAttempts,
		MaxLLMCalls:        new(defaults.maxLLMCalls),
		MaxToolCalls:       new(defaults.maxToolCalls),
		MaxShellExecutions: new(defaults.maxShellExecutions),
	}, nil
}

// CreateDefaultContractV4 cria o contrato com os defaults do TypeScript.
//
// O risco vazio usa L1, como o parâmetro default da referência. Um risco fora
// de L0..L4 devolve ErrInvalidRiskLevel em vez de gerar um contrato sem budget.
func CreateDefaultContractV4(taskID, workID, title string, risk RiskLevel, options *DefaultOptions) (TaskContractV4, error) {
	if risk == "" {
		risk = RiskL1
	}
	budget, err := BudgetForRisk(risk)
	if err != nil {
		return TaskContractV4{}, err
	}

	var writeAllow, writeDeny, invariants []string
	var scenarios []Scenario
	if options != nil {
		writeAllow = options.WriteAllow
		writeDeny = options.WriteDeny
		invariants = options.Invariants
		scenarios = options.Scenarios
	}

	targetFiles := cloneStrings(writeAllow)
	if targetFiles == nil {
		targetFiles = []string{"src/**"}
	}
	scopeAllow := cloneStrings(writeAllow)
	if scopeAllow == nil {
		scopeAllow = []string{"src/**", "tests/**"}
	}
	if writeDeny == nil {
		writeDeny = []string{".git/**", "package.json", ".env*"}
	} else {
		writeDeny = cloneStrings(writeDeny)
	}

	if scenarios == nil {
		scenarios = []Scenario{
			{
				ID:    fmt.Sprintf("SCENARIO-%s-01", taskID),
				Given: fmt.Sprintf("Dado que a tarefa \"%s\" foi atribuída com risco %s", title, riskLabel(risk)),
				When:  fmt.Sprintf("Quando o agente executa a tarefa %s", taskID),
				Then:  "Então o resultado deve ser funcional, sem regressões e dentro do escopo declarado",
			},
			{
				ID:    fmt.Sprintf("SCENARIO-%s-02", taskID),
				Given: "Dado que existem invariantes arquiteturais definidos",
				When:  "Quando o agente modifica código",
				Then:  "Então as invariantes permanecem intactas",
			},
		}
	} else {
		scenarios = make([]Scenario, len(scenarios))
		copy(scenarios, options.Scenarios)
	}

	if invariants == nil {
		invariants = []string{
			"Não quebrar retrocompatibilidade nem expor dados sensíveis",
			"Manter cobertura de testes existente",
		}
		if IsHighRisk(risk) {
			invariants = append(invariants, "Exigir revisão humana para mudanças estruturais")
		}
	} else {
		invariants = cloneStrings(invariants)
	}

	return TaskContractV4{
		ContractVersion:    ContractVersionV4,
		TaskID:             taskID,
		WorkID:             workID,
		Title:              title,
		Risk:               RiskContract{Level: risk, Reasons: []string{fmt.Sprintf("Task %s classificada como %s", taskID, riskLabel(risk))}},
		ValidationStrategy: ValidationStrategyForRisk(risk),
		BehavioralContract: BehavioralContract{Scenarios: scenarios},
		ChangeContract: ChangeContract{
			TargetFiles:        targetFiles,
			AffectedComponents: []string{"core"},
		},
		ArchitectureContract: ArchitectureContract{Invariants: invariants},
		AcceptanceContract: AcceptanceContract{
			Commands:         []string{"bun test"},
			RequiredEvidence: []string{"evidence.json"},
		},
		ScopeContract: ScopeContract{
			WriteAllow: scopeAllow,
			WriteDeny:  writeDeny,
			OutOfScope: []string{"Mudanças de infraestrutura ou banco não especificadas"},
		},
		BudgetContract: budget,
		EscalationContract: EscalationContract{
			OnWriteViolation: OnWriteViolationBlockAndEscalate,
			OnBudgetExceeded: budgetEscalation(risk),
			OnAttemptFailed:  attemptEscalation(risk),
		},
	}, nil
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func budgetEscalation(risk RiskLevel) string {
	if risk == RiskL4 {
		return OnBudgetExceededHumanReview
	}
	return OnBudgetExceededEscalateToStrongAgent
}

func attemptEscalation(risk RiskLevel) string {
	if risk == RiskL4 {
		return OnAttemptFailedHumanReview
	}
	return OnAttemptFailedRetryWithStrong
}
