package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/policy"
	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// RunStatus é o estado observável de uma run.
type RunStatus string

const (
	StatusPending         RunStatus = "pending"
	StatusRunning         RunStatus = "running"
	StatusSuccess         RunStatus = "success"
	StatusBudgetExceeded  RunStatus = "budget_exceeded"
	StatusPolicyViolation RunStatus = "policy_violation"
	StatusSandboxError    RunStatus = "sandbox_error"
	StatusDiffViolation   RunStatus = "diff_violation"
	StatusAborted         RunStatus = "aborted"
)

// EventType classifica um evento de telemetria da run.
type EventType string

const (
	EventStart       EventType = "start"
	EventStep        EventType = "step"
	EventBudgetCheck EventType = "budget_check"
	EventPolicyCheck EventType = "policy_check"
	EventDiffCheck   EventType = "diff_check"
	EventError       EventType = "error"
	EventEnd         EventType = "end"
)

// Event é uma linha de telemetria da run.
type Event struct {
	Timestamp string    `json:"timestamp"`
	Type      EventType `json:"type"`
	Message   string    `json:"message"`
	Detail    any       `json:"detail,omitempty"`
}

// RunContext reúne contrato, sandbox, budget, política e a Tool API de uma run.
type RunContext struct {
	Contract contract.TaskContractV4
	RootDir  string
	RunID    string
	Sandbox  *sandbox.Session
	Budget   *contract.BudgetController
	Policy   *policy.Engine
	Events   []Event
	Status   RunStatus
	// Tools é o único gateway autorizado do agente.
	Tools *ToolAPI
}

// isoLayout tem a mesma forma de Date.prototype.toISOString.
const isoLayout = "2006-01-02T15:04:05.000Z"

func nowISO() string {
	return time.Now().UTC().Format(isoLayout)
}

func emitEvent(runCtx *RunContext, eventType EventType, message string, detail any) {
	runCtx.Events = append(runCtx.Events, Event{
		Timestamp: nowISO(),
		Type:      eventType,
		Message:   message,
		Detail:    detail,
	})
}

// InitRunContext inicializa contrato → política → sandbox → budget → tools.
//
// Uma falha de sandbox é definitiva: devolve erro e nunca cai de volta para
// rootDir. O ctx é usado na criação do worktree; nil usa context.Background.
func InitRunContext(
	ctx context.Context,
	taskContract contract.TaskContractV4,
	rootDir, runID string,
	overrides *policy.Overrides,
) (*RunContext, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx := &RunContext{
		Contract: taskContract,
		RootDir:  rootDir,
		RunID:    runID,
		Budget:   contract.NewBudgetController(taskContract),
		Policy:   policy.NewEngine(taskContract, overrides),
		Events:   make([]Event, 0),
		Status:   StatusPending,
	}
	emitEvent(runCtx, EventStart, fmt.Sprintf(
		"Run %s inicializado para task %s (risk: %s)",
		runID, taskContract.TaskID, taskContract.Risk.Level,
	), nil)

	session, err := sandbox.CreateGitWorktreeSandbox(ctx, runID, rootDir)
	if err != nil {
		runCtx.Status = StatusSandboxError
		var sandboxErr *sandbox.SandboxError
		if errors.As(err, &sandboxErr) {
			emitEvent(runCtx, EventError, sandboxErr.Message, map[string]string{"reason": sandboxErr.Reason})
		} else {
			emitEvent(runCtx, EventError, err.Error(), nil)
		}
		return nil, err
	}
	runCtx.Sandbox = &session
	emitEvent(runCtx, EventStep, fmt.Sprintf(
		"Sandbox criado: %s (branch: %s)", session.WorktreePath, session.BranchName,
	), nil)

	cwd := rootDir
	if runCtx.Sandbox != nil {
		cwd = runCtx.Sandbox.WorktreePath
	}
	runCtx.Tools = NewToolAPI(ToolAPIOptions{
		Policy: runCtx.Policy,
		Budget: runCtx.Budget,
		Cwd:    cwd,
		RunCtx: runCtx,
	})
	emitEvent(runCtx, EventStep, "Tool API vinculada ao sandbox: "+cwd, nil)

	runCtx.Status = StatusRunning
	return runCtx, nil
}

// VerifyDiff aplica o Diff Guard ao inventário de arquivos modificados.
func VerifyDiff(runCtx *RunContext, modifiedFiles []string) (contract.ContractDiffCheckReport, error) {
	report, err := contract.CheckDiffAgainstContract(
		modifiedFiles,
		runCtx.Contract.ScopeContract.WriteAllow,
		runCtx.Contract.ScopeContract.WriteDeny,
	)
	if err != nil {
		runCtx.Status = StatusDiffViolation
		emitEvent(runCtx, EventError, "DIFF CHECK indisponível: "+err.Error(), nil)
		return contract.ContractDiffCheckReport{}, err
	}

	if !report.Passed {
		runCtx.Status = StatusDiffViolation
		emitEvent(runCtx, EventDiffCheck, fmt.Sprintf(
			"DIFF VIOLATION: %d arquivo(s) fora do escopo", len(report.Violations),
		), report)
	} else {
		emitEvent(runCtx, EventDiffCheck, fmt.Sprintf(
			"DIFF OK: %d arquivo(s) verificado(s)", report.TotalFiles,
		), nil)
	}
	return report, nil
}

// FinalizeRun fecha a run: ajusta o estado, emite o evento final e remove o
// sandbox. A limpeza é best-effort; um erro não altera o estado da run.
func FinalizeRun(runCtx *RunContext, success bool) *RunContext {
	if success {
		runCtx.Status = StatusSuccess
	} else {
		runCtx.Status = StatusAborted
	}
	emitEvent(runCtx, EventEnd, fmt.Sprintf("Run %s finalizado: %s", runCtx.RunID, runCtx.Status), nil)

	if runCtx.Sandbox != nil {
		worktreePath := runCtx.Sandbox.WorktreePath
		err := sandbox.CleanupGitWorktreeSandbox(context.Background(), *runCtx.Sandbox, runCtx.RootDir)
		if err != nil {
			emitEvent(runCtx, EventStep, fmt.Sprintf("Sandbox removido: %s (falha: %v)", worktreePath, err), nil)
		} else {
			emitEvent(runCtx, EventStep, "Sandbox removido: "+worktreePath, nil)
		}
	}
	return runCtx
}

// SaveRunEvents grava os eventos da run em `<metricsDir>/<runID>.jsonl`.
func SaveRunEvents(runCtx *RunContext, metricsDir string) error {
	dir := metricsDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("run: criar %s: %w", dir, err)
	}

	lines := make([]string, 0, len(runCtx.Events))
	for _, event := range runCtx.Events {
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("run: serializar evento: %w", err)
		}
		lines = append(lines, string(data))
	}
	content := ""
	for index, line := range lines {
		if index > 0 {
			content += "\n"
		}
		content += line
	}
	file := filepath.Join(dir, runCtx.RunID+".jsonl")
	return fsx.WriteFileAtomic(file, content)
}
