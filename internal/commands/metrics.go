package commands

import (
	"fmt"
	"strconv"

	"github.com/passoz/pwn/internal/harness/metrics"
)

// Metrics porta `pwn metrics list|optimize`.
func (r *Runner) Metrics(subcommand string, args []string) int {
	switch subcommand {
	case "list":
		return r.metricsList()
	case "optimize":
		return r.metricsOptimize()
	default:
		fmt.Fprintf(r.errOut(), "Subcomando desconhecido para 'pwn metrics': %s\n", subcommand)
		fmt.Fprint(r.out(), "\nUso:\n")
		fmt.Fprint(r.out(), "  pwn metrics list       Exibe o histórico de métricas e custos registrados\n")
		fmt.Fprint(r.out(), "  pwn metrics optimize   Gera sugestões de otimização de routing de modelos\n")
		return 1
	}
}

func (r *Runner) metricsList() int {
	fmt.Fprint(r.out(), "=== [pwn metrics list] Telemetria e Consumo de Métricas ===\n\n")

	entries, err := metrics.Read(r.rootDir())
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprint(r.out(), "Nenhuma métrica registrada em .pwn/metrics.jsonl ainda.\n")
		return 0
	}

	totalCost := 0.0
	totalTokens := 0
	for _, entry := range entries {
		totalCost += entry.CostUSD
		totalTokens += entry.TokensInput + entry.TokensOutput
		fmt.Fprintf(r.out(), "[%s] Run: %s | Task: %s | Role: %s (%s)\n",
			upper(string(entry.Status)), entry.RunID, entry.TaskID, entry.AgentRole, entry.Model)
		sandbox := "NÃO (--no-isolation)"
		if entry.Isolated {
			sandbox = "sim"
		}
		fmt.Fprintf(r.out(), "  Tokens: %d | Custo: $%s | Duração: %dms | Tentativas: %d | Sandbox: %s\n\n",
			entry.TokensInput+entry.TokensOutput,
			strconv.FormatFloat(entry.CostUSD, 'f', 4, 64),
			entry.DurationMs,
			entry.Attempts,
			sandbox,
		)
	}

	fmt.Fprint(r.out(), "--------------------------------------------------------------------------------\n")
	fmt.Fprintf(r.out(), "Total de Execuções: %d\n", len(entries))
	fmt.Fprintf(r.out(), "Consumo Total de Tokens: %d\n", totalTokens)
	fmt.Fprintf(r.out(), "Custo Total Estimado: $%s USD\n", strconv.FormatFloat(totalCost, 'f', 4, 64))
	return 0
}

func (r *Runner) metricsOptimize() int {
	fmt.Fprint(r.out(), "=== [pwn metrics optimize] Sugestões Declarativas de Otimização de Routing ===\n\n")

	suggestions, err := metrics.Optimize(r.rootDir())
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if len(suggestions) == 0 {
		fmt.Fprint(r.out(), "Sem histórico de métricas suficiente para recomendar otimização de routing.\n")
		fmt.Fprint(r.out(), "Rode tarefas com \"pwn work run\" primeiro; as sugestões aparecem quando houver execuções registradas.\n")
		return 0
	}

	for index, suggestion := range suggestions {
		fmt.Fprintf(r.out(), "[Sugestão #%d] Papel Atual: %s (%s) -> Recomendado: %s\n",
			index+1, suggestion.AgentRole, suggestion.CurrentModel, suggestion.RecommendedRole)
		fmt.Fprintf(r.out(), "  Motivo: %s\n", suggestion.Reason)
		fmt.Fprintf(r.out(), "  Economia Estimada: %d%%\n\n", suggestion.EstimatedSavingsPercent)
	}
	fmt.Fprint(r.out(), "NOTA: Nenhuma alteração de arquivo é feita automaticamente. As recomendações são apenas consultivas.\n")
	return 0
}
