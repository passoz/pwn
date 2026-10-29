package run

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/learnings"
	"github.com/passoz/pwn/internal/harness/metrics"
	"github.com/passoz/pwn/internal/harness/policy"
	"github.com/passoz/pwn/internal/harness/queue"
	"github.com/passoz/pwn/internal/platform/jsonx"
	"github.com/passoz/pwn/internal/platform/proc"
	"github.com/passoz/pwn/internal/platform/shellwords"
)

// ExitSuspended é o código de saída de uma run suspensa para revisão humana
// (L4) em vez de executada. Diferente de 0 para que automação não confunda
// "nunca rodou" com sucesso.
const ExitSuspended = 3

// Options descreve a run governada por contrato.
type Options struct {
	WorkID  string
	TaskID  string
	Command []string
	// Timeout é o tempo máximo do comando. Zero desabilita o timeout.
	Timeout time.Duration
	RootDir string
	// Isolated ausente vale true. false executa em RootDir com política, sem
	// sandbox e sem diff guard.
	Isolated *bool
	// Gatekeeper decide a execução de uma task L4 antes do sandbox. nil deixa a
	// decisão para o operador: a task é suspensa e enfileirada.
	Gatekeeper Gatekeeper
	// Log recebe as mensagens de progresso. nil usa os.Stderr.
	Log io.Writer
}

// Result é o desfecho observável da run.
type Result struct {
	Status         int      `json:"status"`
	Stdout         string   `json:"stdout"`
	Stderr         string   `json:"stderr"`
	RunID          string   `json:"runId"`
	DiffViolations []string `json:"diffViolations"`
	Suspended      bool     `json:"suspended"`
}

// GateOutcome é o veredicto do decisor sobre uma execução L4.
type GateOutcome string

const (
	GateApprove  GateOutcome = "approve"
	GateReject   GateOutcome = "reject"
	GateEscalate GateOutcome = "escalate"
)

// GateRequest é o estado entregue ao decisor: os contratos originais e o
// comando que seria executado.
type GateRequest struct {
	RootDir   string
	WorkID    string
	TaskID    string
	Risk      contract.RiskLevel
	Contracts []contract.TaskContractV4
	Command   []string
}

// GateDecision é o veredicto do decisor. Log são as linhas que a run escreve em
// stderr antes de enfileirar; Err interrompe a run (decisor mal configurado).
type GateDecision struct {
	Outcome    GateOutcome
	Reasons    []string
	DecisionID string
	Log        []string
	Err        error
}

// Gatekeeper é o ponto de decisão da fila AFK (L4). O composition root liga o
// decisor; o pacote run não importa o motor de decisão.
type Gatekeeper interface {
	Decide(request GateRequest) GateDecision
}

// VerifyRequest é o contexto pós-run para a verificação de aceitação.
type VerifyRequest struct {
	RootDir  string
	WorkID   string
	TaskID   string
	RunID    string
	Contract contract.TaskContractV4
	Result   Result
}

// VerifyReport é o resultado da verificação de aceitação.
type VerifyReport struct {
	Passed  bool
	Reasons []string
}

// Verifier é o ponto de verificação de aceitação (acceptance-flow). O
// composition root liga a implementação; o pacote run não importa o fluxo.
type Verifier interface {
	Verify(request VerifyRequest) VerifyReport
}

// Run executa um comando sob contrato:
//
//	contrato (V4) → política → sandbox (HEAD + working tree) → budget →
//	diff guard → limpeza → métricas.
func Run(ctx context.Context, options Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	rootDir := options.RootDir
	if rootDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Result{Status: 1, Stderr: "[CONTRACT ERROR] não foi possível obter o diretório atual", RunID: "", DiffViolations: []string{}}
		}
		rootDir = cwd
	}
	logWriter := options.Log
	if logWriter == nil {
		logWriter = os.Stderr
	}

	runID := newRunID()
	startedAt := time.Now()

	if len(options.Command) == 0 {
		return Result{Status: 1, Stderr: "[CONTRACT ERROR] comando de aceitação vazio", RunID: runID, DiffViolations: []string{}}
	}

	contracts, documents, err := loadContracts(options, rootDir)
	if err != nil {
		return Result{
			Status:         1,
			Stderr:         "[CONTRACT ERROR] " + err.Error(),
			RunID:          runID,
			DiffViolations: []string{},
		}
	}

	taskID := options.TaskID
	if taskID == "" {
		taskID = "WORK"
	}
	aggregated, err := aggregateContracts(options.WorkID, taskID, contracts)
	if err != nil {
		return Result{
			Status:         1,
			Stderr:         "[CONTRACT ERROR] " + err.Error(),
			RunID:          runID,
			DiffViolations: []string{},
		}
	}

	if pattern, invalid := contract.InvalidScopePattern(
		aggregated.ScopeContract.WriteAllow,
		aggregated.ScopeContract.WriteDeny,
	); invalid {
		return Result{
			Status: 1,
			Stderr: fmt.Sprintf(
				"[CONTRACT ERROR] padrão de escopo inválido em write_allow/write_deny: %q", pattern,
			),
			RunID:          runID,
			DiffViolations: []string{},
		}
	}

	decision := SelectForRisk(aggregated.Risk.Level, rootDir)
	agentRole := metrics.AgentRole(decision.Role)

	// L4 suspende e enfileira na revisão humana, sem executar — salvo aprovação
	// vigente na fila para ESTE contrato e ESTE comando.
	if aggregated.Risk.Level == contract.RiskL4 {
		binding, err := contractBinding(documents, options.Command)
		if err != nil {
			return Result{
				Status:         1,
				Stderr:         fmt.Sprintf("[CONTRACT ERROR] %v", err),
				RunID:          runID,
				DiffViolations: []string{},
			}
		}
		approved, err := queue.FindApproved(options.WorkID, taskID, binding, rootDir)
		if err != nil {
			fmt.Fprintf(logWriter, "[QUEUE ERROR] %v\n", err)
		}
		if approved != nil {
			fmt.Fprintf(logWriter, "▶  Tarefa L4 aprovada na fila (%s): executando.\n", approved.RunID)
		} else {
			gate := GateDecision{}
			hasGate := options.Gatekeeper != nil
			if hasGate {
				gate = options.Gatekeeper.Decide(GateRequest{
					RootDir:   rootDir,
					WorkID:    options.WorkID,
					TaskID:    taskID,
					Risk:      aggregated.Risk.Level,
					Contracts: cloneContracts(contracts),
					Command:   append([]string(nil), options.Command...),
				})
				if gate.Err != nil {
					return Result{Status: 1, Stderr: gate.Err.Error(), RunID: runID, DiffViolations: []string{}}
				}
				for _, line := range gate.Log {
					fmt.Fprintln(logWriter, line)
				}
			}

			item := queue.Item{
				RunID:        runID,
				WorkID:       options.WorkID,
				TaskID:       taskID,
				Title:        aggregated.Title,
				PausedAtStep: "pre-execution",
				RiskLevel:    string(contract.RiskL4),
				Payload: map[string]any{
					"contract_sha256": binding.ContractSHA256,
					"command":         append([]string(nil), options.Command...),
					"decision_id":     nil,
				},
			}
			if gate.DecisionID != "" {
				item.Payload["decision_id"] = gate.DecisionID
			}
			if hasGate && len(gate.Reasons) > 0 {
				item.Reason = "Tarefa de risco L4: " + strings.Join(gate.Reasons, "; ")
			} else {
				item.Reason = "Tarefa de risco L4 exige aprovação humana na fila AFK"
			}

			switch {
			case hasGate && gate.Outcome == GateReject:
				if _, err := queue.Enqueue(item, rootDir, queue.StatusRejected); err != nil {
					return Result{Status: 1, Stderr: fmt.Sprintf("[QUEUE ERROR] %v", err), RunID: runID, DiffViolations: []string{}}
				}
				return Result{
					Status: 1,
					Stderr: fmt.Sprintf(
						"[DECIDER REJECTED] execução L4 recusada pelo decisor (%s): %s",
						runID, strings.Join(gate.Reasons, "; "),
					),
					RunID:          runID,
					DiffViolations: []string{},
				}
			case hasGate && gate.Outcome == GateApprove:
				if _, err := queue.Enqueue(item, rootDir, queue.StatusApproved); err != nil {
					return Result{Status: 1, Stderr: fmt.Sprintf("[QUEUE ERROR] %v", err), RunID: runID, DiffViolations: []string{}}
				}
			default:
				if _, err := queue.Enqueue(item, rootDir, queue.StatusPendingReview); err != nil {
					return Result{Status: 1, Stderr: fmt.Sprintf("[QUEUE ERROR] %v", err), RunID: runID, DiffViolations: []string{}}
				}
				fmt.Fprintf(logWriter, "⏸  Tarefa L4 suspensa e enviada para a fila de revisão (%s).\n", runID)
				fmt.Fprintf(logWriter, "   Aprove com 'pwn queue approve %s' e rode de novo o mesmo comando (exit code %d).\n", runID, ExitSuspended)
				return Result{
					Status:         ExitSuspended,
					RunID:          runID,
					DiffViolations: []string{},
					Suspended:      true,
				}
			}
		}
	}

	overrides := buildPolicyOverrides(aggregated.AcceptanceContract.Commands, rootDir)

	// Não isolado: a política ainda é aplicada, sem sandbox nem diff guard.
	if options.Isolated != nil && !*options.Isolated {
		policyEngine := policy.NewEngine(aggregated, overrides)
		return runWithoutIsolation(runID, options, policyEngine, agentRole, startedAt, rootDir)
	}

	return runIsolated(ctx, runID, options, aggregated, overrides, agentRole, startedAt, rootDir, logWriter)
}

func runIsolated(
	ctx context.Context,
	runID string,
	options Options,
	aggregated contract.TaskContractV4,
	overrides *policy.Overrides,
	agentRole metrics.AgentRole,
	startedAt time.Time,
	rootDir string,
	logWriter io.Writer,
) Result {
	runCtx, err := InitRunContext(ctx, aggregated, rootDir, runID, overrides)
	if err != nil {
		fmt.Fprintf(logWriter, "[SANDBOX ABORT] %v\n", err)
		fmt.Fprintln(logWriter, "Dica: rode com --no-isolation para executar sem sandbox (decisão explícita do operador).")
		return Result{Status: 1, Stderr: err.Error(), RunID: runID, DiffViolations: []string{}}
	}

	sandboxPath := runCtx.Sandbox.WorktreePath
	injected, err := PrepareSandbox(sandboxPath, rootDir)
	if err != nil {
		FinalizeRun(runCtx, false)
		saveEventsQuietly(runCtx, rootDir, logWriter)
		failedMetrics(runID, options, startedAt, rootDir, agentRole)
		return Result{Status: 1, Stderr: "[SANDBOX ABORT] " + err.Error(), RunID: runID, DiffViolations: []string{}}
	}

	overlay := OverlayWorkingTree(rootDir, sandboxPath, injected)
	if !overlay.OK {
		FinalizeRun(runCtx, false)
		saveEventsQuietly(runCtx, rootDir, logWriter)
		failedMetrics(runID, options, startedAt, rootDir, agentRole)
		return Result{
			Status:         1,
			Stderr:         "[SANDBOX ABORT] " + overlay.Reason,
			RunID:          runID,
			DiffViolations: []string{},
		}
	}

	execResult := runCtx.Tools.Exec(options.Command[0], options.Command[1:], options.Timeout)

	stdout := ""
	stderr := ""
	status := 1
	diffViolations := make([]string, 0)
	success := false

	if execResult.Success {
		output, ok := execResult.Data.(ExecOutput)
		if ok {
			stdout = output.Stdout
			stderr = output.Stderr
			status = output.Status
			success = status == 0
		}
	} else {
		stderr = execResult.Error
		if stderr == "" {
			stderr = "Execução negada pela política ou orçamento."
		}
	}

	// O diff guard roda SEMPRE — inclusive quando o comando falhou, foi negado
	// pela política ou estourou o timeout: o processo já escreveu o que escreveu
	// antes de morrer, e ignorar a árvore transformaria o guard em no-op.
	inventory := ModifiedFiles(sandboxPath, runCtx.Sandbox.GitDir, injected)
	if !inventory.OK {
		diffViolations = append(diffViolations, inventory.Reason)
		status = 1
		success = false
		addLearningQuietly(learnings.NewEntry{
			Category:     learnings.CategoryGotcha,
			Title:        "Diff guard não conseguiu inventariar a árvore do sandbox",
			Description:  fmt.Sprintf("Run %s: %s", runID, inventory.Reason),
			SourceTaskID: options.TaskID,
			Tags:         []string{"diff-guard", "scope"},
		}, rootDir)
	} else {
		report, err := VerifyDiff(runCtx, inventory.Files)
		if err != nil {
			diffViolations = append(diffViolations, err.Error())
			status = 1
			success = false
		} else if !report.Passed {
			for _, violation := range report.Violations {
				reason := violation.Reason
				if reason == "" {
					reason = string(violation.ViolationType)
				}
				diffViolations = append(diffViolations, fmt.Sprintf("%s: %s", violation.File, reason))
			}
			status = 1
			success = false
			addLearningQuietly(learnings.NewEntry{
				Category:     learnings.CategoryGotcha,
				Title:        "Violação de escopo detectada pelo diff guard",
				Description:  fmt.Sprintf("Run %s modificou arquivos fora do write_allow do contrato: %s", runID, strings.Join(diffViolations, "; ")),
				SourceTaskID: options.TaskID,
				Tags:         []string{"diff-guard", "scope"},
			}, rootDir)
		}
	}

	FinalizeRun(runCtx, success)
	saveEventsQuietly(runCtx, rootDir, logWriter)
	recordMetrics(metrics.Entry{
		Timestamp:  nowISO(),
		RunID:      runID,
		WorkID:     options.WorkID,
		TaskID:     options.TaskID,
		AgentRole:  agentRole,
		Model:      "bun",
		DurationMs: time.Since(startedAt).Milliseconds(),
		Status:     metricsStatus(success),
		Attempts:   1,
		Isolated:   true,
	}, rootDir, logWriter)

	return Result{
		Status:         status,
		Stdout:         stdout,
		Stderr:         stderr,
		RunID:          runID,
		DiffViolations: diffViolations,
	}
}

func runWithoutIsolation(
	runID string,
	options Options,
	policyEngine *policy.Engine,
	agentRole metrics.AgentRole,
	startedAt time.Time,
	rootDir string,
) Result {
	command := options.Command
	operation := policy.AgentOperation{Type: policy.OpShellExec, Command: command[0], Args: command[1:]}
	decision := policyEngine.Evaluate(operation)
	if !decision.Allowed {
		failedMetrics(runID, options, startedAt, rootDir, agentRole)
		return Result{Status: 1, Stderr: decision.Reason, RunID: runID, DiffViolations: []string{}}
	}

	results := proc.RunPool(
		[]proc.Job{{ID: runID, Command: command, Dir: rootDir}},
		proc.Options{Concurrency: 1, Timeout: options.Timeout},
	)
	result := results[0]
	status := result.Status
	if result.TimedOut {
		status = 1
	}

	recordMetrics(metrics.Entry{
		Timestamp:  nowISO(),
		RunID:      runID,
		WorkID:     options.WorkID,
		TaskID:     options.TaskID,
		AgentRole:  agentRole,
		Model:      "bun",
		DurationMs: time.Since(startedAt).Milliseconds(),
		Status:     metricsStatus(status == 0),
		Attempts:   1,
		Isolated:   false,
	}, rootDir, nil)

	return Result{
		Status:         status,
		Stdout:         result.Stdout,
		Stderr:         result.Stderr,
		RunID:          runID,
		DiffViolations: []string{},
	}
}

func loadContracts(options Options, rootDir string) ([]contract.TaskContractV4, []any, error) {
	if options.TaskID != "" {
		taskContract, document, err := loadTaskContractWithDocument(options.WorkID, options.TaskID, rootDir)
		if err != nil {
			return nil, nil, err
		}
		return []contract.TaskContractV4{taskContract}, []any{document}, nil
	}
	return loadWorkContractsWithDocuments(options.WorkID, rootDir)
}

func maxRisk(contracts []contract.TaskContractV4) contract.RiskLevel {
	highest := contract.RiskL0
	for _, taskContract := range contracts {
		if taskContract.Risk.Level.Rank() > highest.Rank() {
			highest = taskContract.Risk.Level
		}
	}
	return highest
}

func aggregateContracts(workID, taskID string, contracts []contract.TaskContractV4) (contract.TaskContractV4, error) {
	base, err := contract.CreateDefaultContractV4(
		taskID, workID, fmt.Sprintf("Work %s — execução agregada", workID), maxRisk(contracts), nil,
	)
	if err != nil {
		return contract.TaskContractV4{}, err
	}

	writeAllow := make([]string, 0)
	writeDeny := make([]string, 0)
	commands := make([]string, 0)
	for _, taskContract := range contracts {
		writeAllow = append(writeAllow, taskContract.ScopeContract.WriteAllow...)
		writeDeny = append(writeDeny, taskContract.ScopeContract.WriteDeny...)
		commands = append(commands, taskContract.AcceptanceContract.Commands...)
	}
	base.ScopeContract.WriteAllow = uniqueStrings(writeAllow)
	base.ScopeContract.WriteDeny = uniqueStrings(writeDeny)
	base.AcceptanceContract.Commands = uniqueStrings(commands)
	return base, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, present := seen[value]; present {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

// buildPolicyOverrides resolve a política da run. Sem `.pwn/policy.json`
// (source defaults) o comportamento histórico é preservado: allowlist derivada
// dos comandos de aceitação e denylist default. Com arquivo válido, a política
// declarada substitui a seção.
func buildPolicyOverrides(commands []string, rootDir string) *policy.Overrides {
	resolved, _ := policy.ResolvePolicy(rootDir)
	if resolved.Source == policy.SourceFile {
		return &policy.Overrides{Shell: &resolved.Shell, Network: &resolved.Network}
	}
	shell := buildShellPolicy(commands)
	return &policy.Overrides{Shell: &shell}
}

func buildShellPolicy(commands []string) policy.ShellPolicy {
	allowedCommands := make([]policy.CommandRule, 0, len(commands))
	for _, raw := range commands {
		trimmed := strings.TrimSpace(raw)
		parts, ok := shellwords.Split(trimmed)
		if !ok {
			parts = strings.Fields(trimmed)
		}
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		allowedCommands = append(allowedCommands, policy.CommandRule{
			Command: parts[0],
			Args:    parts[1:],
		})
	}
	return policy.ShellPolicy{
		AllowedCommands: allowedCommands,
		DeniedCommands:  policy.DefaultShellPolicy().DeniedCommands,
		AllowAllShell:   false,
	}
}

// contractBinding calcula o vínculo de aprovação L4: hash canônico dos
// documentos JSON originais e o comando revisado.
func contractBinding(documents []any, command []string) (queue.ReviewBinding, error) {
	canonical, err := jsonx.Canonical(documents)
	if err != nil {
		return queue.ReviewBinding{}, fmt.Errorf("serializar contratos para o vínculo L4: %w", err)
	}
	return queue.ReviewBinding{
		ContractSHA256: jsonx.SHA256Hex(canonical),
		Command:        append([]string(nil), command...),
	}, nil
}

func cloneContracts(contracts []contract.TaskContractV4) []contract.TaskContractV4 {
	cloned := make([]contract.TaskContractV4, len(contracts))
	copy(cloned, contracts)
	return cloned
}

func failedMetrics(runID string, options Options, startedAt time.Time, rootDir string, agentRole metrics.AgentRole) {
	recordMetrics(metrics.Entry{
		Timestamp:  nowISO(),
		RunID:      runID,
		WorkID:     options.WorkID,
		TaskID:     options.TaskID,
		AgentRole:  agentRole,
		Model:      "bun",
		DurationMs: time.Since(startedAt).Milliseconds(),
		Status:     metrics.StatusFailed,
		Attempts:   1,
		Isolated:   options.Isolated == nil || *options.Isolated,
	}, rootDir, nil)
}

func recordMetrics(entry metrics.Entry, rootDir string, logWriter io.Writer) {
	if entry.TaskID == "" {
		entry.TaskID = "WORK"
	}
	if err := metrics.Record(entry, rootDir); err != nil && logWriter != nil {
		fmt.Fprintf(logWriter, "[METRICS ERROR] %v\n", err)
	}
}

func metricsStatus(success bool) metrics.Status {
	if success {
		return metrics.StatusSuccess
	}
	return metrics.StatusFailed
}

func saveEventsQuietly(runCtx *RunContext, rootDir string, logWriter io.Writer) {
	if err := SaveRunEvents(runCtx, filepath.Join(rootDir, ".pwn")); err != nil && logWriter != nil {
		fmt.Fprintf(logWriter, "[EVENTS ERROR] %v\n", err)
	}
}

func addLearningQuietly(entry learnings.NewEntry, rootDir string) {
	_, _ = learnings.Add(entry, rootDir)
}

// newRunID gera um id único por construção: milissegundo em base 36 mais 4
// bytes aleatórios.
func newRunID() string {
	millis := time.Now().UnixMilli()
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "RUN-" + strconv.FormatInt(millis, 36)
	}
	return "RUN-" + strconv.FormatInt(millis, 36) + "-" + hex.EncodeToString(random[:])
}
