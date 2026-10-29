package commands

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/batch"
	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/proc"
)

const batchUsage = `pwn work batch plan [--work NNNN] [--jobs N]        Mostra o próximo lote paralelo e por que cada task ficou de fora
pwn work batch prepare [--work NNNN] [--jobs N] [--tasks 1.2,1.3]
                                                    Cria um worktree por task do lote (um agente por worktree)
pwn work batch integrate [--work NNNN] [--timeout-seconds S] [-- <regressão do plano>]
                                                    Integra as entregas prontas: um commit por task + evidência local
pwn work batch rebase <task>                        Refaz uma task retida sobre o HEAD atual (3-way)
pwn work batch abort                                Descarta o lote ativo (worktrees e branches)`

func batchJobs(raw string) (int, error) {
	if raw == "" {
		return proc.DefaultConcurrency(), nil
	}
	jobs, err := strconv.Atoi(raw)
	if err != nil || jobs < 1 {
		return 0, fmt.Errorf("--jobs inválido: '%s' (esperado inteiro >= 1)", raw)
	}
	return jobs, nil
}

func printDeferred(out interface{ Write([]byte) (int, error) }, deferred []batch.Deferral) {
	if len(deferred) == 0 {
		return
	}
	fmt.Fprint(out, "\nFora do lote:\n")
	for _, entry := range deferred {
		fmt.Fprintf(out, "  %s — %s\n", entry.ID, entry.Reason)
	}
}

func finalStep(workID string) string {
	return fmt.Sprintf("todas as tasks do Work %s estão integradas: rode 'pwn verify run-all --work %s' (uma verificação, na árvore final) e marque [x] em ordem de plano", workID, workID)
}

func printRebase(out interface{ Write([]byte) (int, error) }, result batch.RebaseResult) {
	fmt.Fprintf(out, "=== [pwn work batch rebase] %s refeita sobre %s ===\n", result.TaskID, result.Base[:min(12, len(result.Base))])
	fmt.Fprintf(out, "  worktree: %s\n", result.Worktree)
	if len(result.Conflicts) > 0 {
		fmt.Fprintf(out, "\nConflitos em %d arquivo(s) — resolva no worktree (o harness não escolhe a resolução):\n", len(result.Conflicts))
		for _, file := range result.Conflicts {
			fmt.Fprintf(out, "  %s\n", file)
		}
		fmt.Fprint(out, "Edite os marcadores, depois: git add <arquivos>\n")
		return
	}
	fmt.Fprint(out, "\nEntrega reaplicada sem conflitos.\n")
	if result.Evidence.Stage == "VERIFIED" && !result.Evidence.Stale && len(result.Conflicts) == 0 {
		fmt.Fprintf(out, "Evidência local preservada (%s). Rode: pwn work batch integrate\n", result.Evidence.Stage)
		return
	}
	fmt.Fprintf(out, "\nEvidência local caducou (%s%s): um arquivo declarado mudou na mescla.\n", result.Evidence.Stage, map[bool]string{true: ", STALE", false: ""}[result.Evidence.Stale])
	fmt.Fprintf(out, "Refaça no worktree: audit baseline → red → green → verify. A entrega original está em %s.\n", result.PatchFile)
}

func (r *Runner) workBatch(args []string) int {
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	own := args
	command := []string(nil)
	if separator != -1 {
		own = args[:separator]
		command = args[separator+1:]
	}
	action := ""
	if len(own) > 0 && !strings.HasPrefix(own[0], "--") {
		action = own[0]
	}
	workID := flagValue(own, "--work")
	if workID == "" {
		workID = work.GetLatestWorkID(r.rootDir())
	}
	jobs, err := batchJobs(flagValue(own, "--jobs"))
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err)
		return 1
	}
	timeout := 600
	if raw := flagValue(own, "--timeout-seconds"); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value <= 0 {
			fmt.Fprintf(r.errOut(), "✗ --timeout-seconds inválido: '%s' (esperado número > 0)\n", raw)
			return 1
		}
		timeout = value
	}
	ctx := context.Background()

	switch action {
	case "plan":
		fmt.Fprintf(r.out(), "=== [pwn work batch plan] Work %s ===\n", workID)
		active, readErr := batch.ReadBatch(r.rootDir())
		if readErr != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", readErr)
			return 1
		}
		if active != nil {
			fmt.Fprintf(r.out(), "Lote ativo %s (Work %s, base %s):\n", active.BatchID, active.WorkID, active.Base[:min(12, len(active.Base))])
			for _, task := range active.Tasks {
				fmt.Fprintf(r.out(), "  %s — %s\n      worktree: %s\n", task.ID, task.Title, task.Worktree)
			}
			fmt.Fprint(r.out(), "\nIntegre com 'pwn work batch integrate' ou descarte com 'pwn work batch abort' antes do próximo lote.\n")
			return 0
		}
		tasks, collectErr := batch.CollectSchedulableTasks(ctx, workID, r.rootDir())
		if collectErr != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", collectErr)
			return 1
		}
		schedule := batch.PlanNextBatch(tasks, jobs, workID, nil)
		integrated := "nenhuma"
		if len(schedule.Integrated) > 0 {
			integrated = strings.Join(schedule.Integrated, ", ")
		}
		fmt.Fprintf(r.out(), "Integradas: %s\n", integrated)
		if len(schedule.Batch) > 0 {
			fmt.Fprint(r.out(), "\nPróximo lote:\n")
			for _, task := range schedule.Batch {
				fmt.Fprintf(r.out(), "  %s — %s\n", task.ID, task.Title)
			}
		} else if len(schedule.Deferred) == 0 {
			fmt.Fprintf(r.out(), "\n%s\n", finalStep(workID))
		} else {
			fmt.Fprint(r.out(), "\nNenhuma task pronta para lote.\n")
		}
		printDeferred(r.out(), schedule.Deferred)
		return 0

	case "prepare":
		only := []string(nil)
		if raw := flagValue(own, "--tasks"); raw != "" {
			for _, part := range strings.Split(raw, ",") {
				if value := strings.TrimSpace(part); value != "" {
					only = append(only, value)
				}
			}
		}
		result, prepareErr := batch.PrepareBatch(ctx, batch.PrepareOptions{Root: r.rootDir(), WorkID: workID, Jobs: jobs, Only: only})
		if prepareErr != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", prepareErr)
			return 1
		}
		if result.Manifest == nil {
			fmt.Fprintf(r.out(), "=== [pwn work batch prepare] Work %s ===\n", workID)
			if len(result.Schedule.Deferred) == 0 {
				fmt.Fprintln(r.out(), finalStep(workID))
				return 0
			}
			fmt.Fprint(r.errOut(), "Nenhuma task pronta para lote; nada foi criado.\n")
			printDeferred(r.errOut(), result.Schedule.Deferred)
			return 1
		}
		manifest := result.Manifest
		fmt.Fprintf(r.out(), "=== [pwn work batch prepare] Work %s — lote %s (base %s) ===\n", workID, manifest.BatchID, manifest.Base[:min(12, len(manifest.Base))])
		for _, task := range manifest.Tasks {
			fmt.Fprintf(r.out(), "  %s — %s\n      worktree: %s\n", task.ID, task.Title, task.Worktree)
		}
		printDeferred(r.out(), result.Schedule.Deferred)
		fmt.Fprintf(r.out(), "\nUm agente por worktree (cwd = worktree):\n  pwn task capsule <task> %s\n  pwn work audit baseline|red|green|verify --work %s --task <task> -- <comando do plano>\n", workID, workID)
		fmt.Fprint(r.out(), "Não rode pwn verify nos worktrees: o recibo amarra a árvore inteira e a integração a muda.\n")
		fmt.Fprint(r.out(), "Quando todos terminarem: pwn work batch integrate -- <comando de regressão do plano>\n")
		return 0

	case "integrate":
		options := batch.IntegrateOptions{Root: r.rootDir(), WorkID: workID}
		if len(command) > 0 {
			options.Regression = &batch.RegressionOptions{Command: command, TimeoutSeconds: timeout}
		}
		result, integrateErr := batch.IntegrateBatch(ctx, options)
		if integrateErr != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", integrateErr)
			return 1
		}
		fmt.Fprintf(r.out(), "=== [pwn work batch integrate] Lote %s (Work %s) ===\n", result.BatchID, result.WorkID)
		for _, entry := range result.Integrated {
			fmt.Fprintf(r.out(), "✓ %s → commit %s (%d arquivo(s))\n", entry.ID, entry.Commit[:min(12, len(entry.Commit))], len(entry.Files))
		}
		for _, entry := range result.Failed {
			fmt.Fprintf(r.errOut(), "✗ %s\n", entry.ID)
			for _, reason := range entry.Reasons {
				fmt.Fprintf(r.errOut(), "    %s\n", reason)
			}
		}
		for _, warning := range result.Warnings {
			fmt.Fprintf(r.errOut(), "⚠  %s\n", warning)
		}
		if len(result.Remaining) > 0 {
			fmt.Fprintf(r.errOut(), "\nContinuam no lote: %s — corrija nos worktrees e rode integrate de novo, ou descarte com 'pwn work batch abort'.\n", strings.Join(result.Remaining, ", "))
		} else {
			tasks, collectErr := batch.CollectSchedulableTasks(ctx, result.WorkID, r.rootDir())
			if collectErr == nil {
				schedule := batch.PlanNextBatch(tasks, 1, result.WorkID, nil)
				if len(schedule.Batch) > 0 || len(schedule.Deferred) > 0 {
					fmt.Fprintf(r.out(), "\nLote concluído. Próximo: pwn work batch plan --work %s\n", result.WorkID)
				} else {
					fmt.Fprintf(r.out(), "\nLote concluído; %s.\n", finalStep(result.WorkID))
				}
			}
		}
		if len(result.Failed) > 0 {
			return 1
		}
		return 0

	case "rebase":
		taskID := ""
		if len(own) > 1 && !strings.HasPrefix(own[1], "--") {
			taskID = own[1]
		}
		if taskID == "" {
			fmt.Fprint(r.errOut(), "✗ informe a task: pwn work batch rebase <task>\n")
			return 1
		}
		result, rebaseErr := batch.RebaseTask(ctx, batch.RebaseOptions{Root: r.rootDir(), TaskID: taskID})
		if rebaseErr != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", rebaseErr)
			return 1
		}
		printRebase(r.out(), result)
		if len(result.Conflicts) > 0 {
			return 1
		}
		return 0

	case "abort":
		manifest, abortErr := batch.AbortBatch(ctx, r.rootDir())
		if abortErr != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", abortErr)
			return 1
		}
		if manifest == nil {
			fmt.Fprintln(r.out(), "Nenhum lote ativo.")
			return 0
		}
		ids := make([]string, 0, len(manifest.Tasks))
		for _, task := range manifest.Tasks {
			ids = append(ids, task.ID)
		}
		fmt.Fprintf(r.out(), "Lote %s descartado; trabalho não integrado perdido em: %s\n", manifest.BatchID, strings.Join(ids, ", "))
		return 0

	default:
		fmt.Fprintf(r.errOut(), "Ação desconhecida para 'pwn work batch': %s\n\nUso:\n%s\n", action, batchUsage)
		return 1
	}
}
