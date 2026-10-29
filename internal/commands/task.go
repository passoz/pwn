package commands

import (
	"fmt"
	"os"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
)

// Task porta `pwn task <subcomando>` de src/commands/task.ts.
func (r *Runner) Task(subcommand string, args []string) int {
	switch subcommand {
	case "run":
		return r.taskRun(args)
	case "capsule":
		return r.taskCapsule(args)
	default:
		fmt.Fprintf(r.errOut(), "Subcomando desconhecido para 'pwn task': %s\n", subcommand)
		fmt.Fprint(r.out(), "\nUso:\n")
		fmt.Fprint(r.out(), "  pwn task run      Executa uma tarefa atômica isolada\n")
		fmt.Fprint(r.out(), "  pwn task capsule  Gera a cápsula de contexto mínima para a task\n")
		return 1
	}
}

// taskRun executa uma task atômica sob contrato e aciona a aceitação.
func (r *Runner) taskRun(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn task run] Executando task atômica sob contrato ===\n")
	workID := flagValue(args, "--work")
	taskID := flagValue(args, "--task")
	timeoutSeconds := timeoutSecondsValue(args)
	noIsolation := hasFlag(args, "--no-isolation")
	command := commandAfterSeparator(args)

	if workID == "" || taskID == "" || len(command) == 0 {
		fmt.Fprint(r.errOut(), "Uso: pwn task run --work NNNN --task 1.1 --timeout-seconds N -- <comando>\n")
		return 1
	}

	isolated := !noIsolation
	result := run.Run(contextBackground(), run.Options{
		WorkID:   workID,
		TaskID:   taskID,
		Command:  command,
		Timeout:  secondsToDuration(float64(timeoutSeconds)),
		RootDir:  r.rootDir(),
		Isolated: &isolated,
		Log:      r.errOut(),
	})
	if result.Stdout != "" {
		fmt.Fprintf(r.out(), "%s\n", result.Stdout)
	}
	if result.Stderr != "" {
		fmt.Fprintf(r.errOut(), "%s\n", result.Stderr)
	}
	if len(result.DiffViolations) > 0 {
		fmt.Fprint(r.errOut(), "\n[DIFF VIOLATION] Arquivos fora do escopo do contrato:\n")
		for _, violation := range result.DiffViolations {
			fmt.Fprintf(r.errOut(), "  - %s\n", violation)
		}
	}

	var verification *verify.AutoVerification
	if result.Suspended {
		fmt.Fprintf(r.errOut(), "\n[SUSPENDED] A task %s do Work %s não foi executada: aguarda decisão humana na fila AFK.\n", taskID, workID)
		fmt.Fprintf(r.errOut(), "Use 'pwn queue approve %s' para destravar (exit code %d).\n", result.RunID, result.Status)
	} else if result.Status == 0 {
		// A execução terminou: a aceitação independente roda sem depender do agente.
		auto := ctxVerify(r.rootDir(), workID, taskID, timeoutSeconds)
		verification = &auto
		verify.ReportAutoVerification(auto, r.out(), r.errOut())
	}
	if verification != nil && verification.Attempted && verification.Outcome != "pass" {
		return 1
	}
	return result.Status
}

// ctxVerify aciona a aceitação e transforma um erro em bloqueio explícito.
func ctxVerify(rootDir, workID, taskID string, timeoutSeconds int) verify.AutoVerification {
	auto, err := verify.AfterRun(verify.AfterRunOptions{
		RootDir:        rootDir,
		WorkID:         workID,
		TaskID:         taskID,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return verify.AutoVerification{Attempted: true, Outcome: "blocked", Reason: err.Error()}
	}
	return auto
}

// taskCapsule escreve a cápsula de contexto mínima da task.
func (r *Runner) taskCapsule(args []string) int {
	taskID := ""
	if len(args) > 0 {
		taskID = args[0]
	}
	shown := taskID
	if shown == "" {
		shown = "(task-id)"
	}
	fmt.Fprintf(r.out(), "=== [pwn task capsule] Context Capsule (contrato congelado V4) para %s ===\n\n", shown)
	if taskID == "" {
		fmt.Fprint(r.errOut(), "Uso: pwn task capsule <task-id> [work-id]\n")
		return 1
	}

	rootDir := r.rootDir()
	workID := ""
	if len(args) > 1 {
		workID = args[1]
	}
	if workID == "" {
		workID = work.GetLatestWorkID(rootDir)
	}

	taskContract, err := plan.LoadTaskContract(workID, taskID, rootDir)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ Não foi possível gerar a cápsula: %s\n", err.Error())
		fmt.Fprint(r.errOut(), "  O contrato V4 deve estar congelado em .pwn/work/<id>/<contract_id>.json.\n")
		return 1
	}
	// console.log acrescenta uma quebra de linha ao texto da cápsula.
	fmt.Fprintln(r.out(), plan.GenerateContextCapsule(plan.ContextCapsuleOptions{
		Task: *taskContract,
		Plan: planContextFor(workID, taskID, rootDir),
	}))
	return 0
}

// planContextFor lê os comandos que o plano v3 exige da task. A cápsula é a
// superfície de instrução do agente: mostrar só a allowlist do contrato faria o
// agente usar um comando que o audit recusa.
func planContextFor(workID, taskID, rootDir string) *plan.CapsulePlanContext {
	planPath := plan.TasksMarkdownPath(workID, rootDir)
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil
	}
	planText := string(data)
	task := plan.ParsePlanTask(planText, taskID)
	if task == nil {
		return nil
	}

	context := &plan.CapsulePlanContext{}
	if task.Red != nil {
		context.RedCommand = task.Red.Command
	}
	for _, name := range plan.RequiredAuditChecks(*task) {
		binding := plan.AllowedCheckCommands(planText, *task, name)
		context.Checks = append(context.Checks, plan.CapsuleCheckBinding{
			Name:     name,
			Commands: binding.Commands,
			Error:    binding.Error,
		})
	}
	if gates, _ := plan.ParseGlobalGates(planText); len(gates) > 0 {
		for _, gate := range gates {
			if gate.Command == "" {
				continue
			}
			context.GlobalGates = append(context.GlobalGates, gate.Command)
		}
	}
	return context
}
