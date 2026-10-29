package commands

import (
	"fmt"

	"github.com/passoz/pwn/internal/harness/queue"
)

// Queue porta `pwn queue list|approve|reject`.
func (r *Runner) Queue(subcommand string, args []string) int {
	switch subcommand {
	case "list":
		return r.queueList()
	case "approve":
		return r.queueUpdate(args, queue.StatusApproved)
	case "reject":
		return r.queueUpdate(args, queue.StatusRejected)
	default:
		fmt.Fprintf(r.errOut(), "Subcomando desconhecido para 'pwn queue': %s\n", subcommand)
		fmt.Fprint(r.out(), "\nUso:\n")
		fmt.Fprint(r.out(), "  pwn queue list      Lista itens em aguardo na fila de revisão AFK\n")
		fmt.Fprint(r.out(), "  pwn queue approve   Aprova um item suspenso na fila\n")
		fmt.Fprint(r.out(), "  pwn queue reject    Rejeita um item suspenso na fila\n")
		return 1
	}
}

func (r *Runner) queueList() int {
	fmt.Fprint(r.out(), "=== [pwn queue list] Fila de Revisão Humana (AFK) ===\n\n")

	items, err := queue.List(r.rootDir())
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if len(items) == 0 {
		fmt.Fprint(r.out(), "Nenhuma tarefa pendente na fila de revisão queue/review/.\n")
		return 0
	}

	for _, item := range items {
		fmt.Fprintf(r.out(), "[%s] Run: %s | Work: %s | Task: %s\n", upper(string(item.Status)), item.RunID, item.WorkID, item.TaskID)
		fmt.Fprintf(r.out(), "  Título: %s\n", item.Title)
		fmt.Fprintf(r.out(), "  Motivo: %s (Risco: %s)\n", item.Reason, item.RiskLevel)
		fmt.Fprintf(r.out(), "  Pausado em: %s | Criado em: %s\n\n", item.PausedAtStep, item.CreatedAt)
	}
	return 0
}

func (r *Runner) queueUpdate(args []string, status queue.Status) int {
	action := "approve"
	if status == queue.StatusRejected {
		action = "reject"
	}

	runID := ""
	if len(args) > 0 {
		runID = args[0]
	}
	if runID == "" {
		fmt.Fprintf(r.errOut(), "Uso: pwn queue %s <run-id>\n", action)
		return 1
	}

	updated, err := queue.UpdateStatus(runID, status, r.rootDir())
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if updated == nil {
		fmt.Fprintf(r.errOut(), "Run %s não encontrada na fila de revisão.\n", runID)
		return 1
	}

	if status == queue.StatusApproved {
		fmt.Fprintf(r.out(), "✓ Run %s aprovada com sucesso! O pipeline pode ser retomado.\n", runID)
	} else {
		fmt.Fprintf(r.out(), "✗ Run %s rejeitada. A execução foi cancelada.\n", runID)
	}
	return 0
}
