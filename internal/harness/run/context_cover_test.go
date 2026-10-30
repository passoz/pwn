package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

func TestInitRunContextWithNilContextCreatesSandboxAndFinalizeRemovesIt(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "seed.txt", "x\n")
	commitAll(t, root, "seed")
	taskContract := testContract(t, contract.RiskL1, []string{"src/**"}, nil)

	var ctx context.Context // nil: InitRunContext deve usar Background
	runCtx, err := InitRunContext(ctx, taskContract, root, "RUN-nilctx", nil)
	if err != nil {
		t.Fatalf("InitRunContext: %v", err)
	}
	if runCtx.Status != StatusRunning || runCtx.Sandbox == nil || runCtx.Tools == nil {
		t.Fatalf("contexto incompleto: %+v", runCtx)
	}
	if runCtx.Tools.Cwd() != runCtx.Sandbox.WorktreePath {
		t.Fatalf("tools.Cwd() = %q, esperava o worktree %q", runCtx.Tools.Cwd(), runCtx.Sandbox.WorktreePath)
	}
	if _, err := os.Stat(filepath.Join(runCtx.Sandbox.WorktreePath, "seed.txt")); err != nil {
		t.Fatalf("worktree sem o conteúdo do HEAD: %v", err)
	}
	types := make([]EventType, 0, len(runCtx.Events))
	for _, event := range runCtx.Events {
		types = append(types, event.Type)
	}
	if len(types) != 3 || types[0] != EventStart || types[1] != EventStep || types[2] != EventStep {
		t.Fatalf("eventos = %v, esperava start, step, step", types)
	}

	worktree := runCtx.Sandbox.WorktreePath
	FinalizeRun(runCtx, true)
	if runCtx.Status != StatusSuccess {
		t.Fatalf("status final = %q", runCtx.Status)
	}
	if _, err := os.Stat(worktree); !os.IsNotExist(err) {
		t.Fatalf("worktree não removido: %v", err)
	}
	if !hasEvent(runCtx, EventStep, "Sandbox removido: "+worktree) {
		t.Fatalf("evento de remoção ausente: %+v", runCtx.Events)
	}
}

func TestInitRunContextFailsWhenSandboxDirectoryCannotBeCreated(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "seed.txt", "x\n")
	commitAll(t, root, "seed")
	// ".pwn" como arquivo regular impede criar .pwn/sandboxes.
	writeFile(t, root, ".pwn", "bloqueio")
	taskContract := testContract(t, contract.RiskL1, []string{"src/**"}, nil)

	runCtx, err := InitRunContext(context.Background(), taskContract, root, "RUN-blocked", nil)
	if err == nil || runCtx != nil {
		t.Fatalf("esperava erro sem contexto, obteve %+v / %v", runCtx, err)
	}
	var sandboxErr *sandbox.SandboxError
	if errors.As(err, &sandboxErr) {
		t.Fatalf("falha de infraestrutura não deveria ser SandboxError: %v", err)
	}
	if !strings.Contains(err.Error(), "sandbox: criar") {
		t.Fatalf("erro = %v", err)
	}
}

func TestVerifyDiffReportsUnavailableCheckForMalformedScope(t *testing.T) {
	runCtx := &RunContext{
		Contract: testContract(t, contract.RiskL1, []string{"*.{pem"}, []string{}),
		Status:   StatusRunning,
	}
	report, err := VerifyDiff(runCtx, []string{"a.pem"})
	if err == nil {
		t.Fatal("padrão malformado deveria falhar a verificação")
	}
	if report.Passed || len(report.Violations) != 0 || report.TotalFiles != 0 {
		t.Fatalf("relatório de falha deveria ser vazio: %+v", report)
	}
	if runCtx.Status != StatusDiffViolation {
		t.Fatalf("status = %q, esperava %q", runCtx.Status, StatusDiffViolation)
	}
	if !hasEvent(runCtx, EventError, "DIFF CHECK indisponível: ") {
		t.Fatalf("evento de erro ausente: %+v", runCtx.Events)
	}
}

func TestFinalizeRunRecordsCleanupFailureWithoutChangingStatus(t *testing.T) {
	root := t.TempDir()
	// ".pwn" como arquivo impede o lock da limpeza do worktree.
	writeFile(t, root, ".pwn", "bloqueio")
	runCtx := &RunContext{
		RunID:   "RUN-cleanup",
		RootDir: root,
		Status:  StatusRunning,
		Sandbox: &sandbox.Session{WorktreePath: filepath.Join(root, "wt"), BranchName: "pwn-sandbox-x", Created: true},
	}

	FinalizeRun(runCtx, false)
	if runCtx.Status != StatusAborted {
		t.Fatalf("status = %q, esperava %q", runCtx.Status, StatusAborted)
	}
	if !hasEvent(runCtx, EventEnd, "finalizado: "+string(StatusAborted)) {
		t.Fatalf("evento final ausente: %+v", runCtx.Events)
	}
	if !hasEvent(runCtx, EventStep, "(falha: ") {
		t.Fatalf("falha de limpeza não registrada: %+v", runCtx.Events)
	}
}

func TestSaveRunEventsErrors(t *testing.T) {
	t.Run("diretório de destino impossível", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "arquivo", "x")
		err := SaveRunEvents(&RunContext{RunID: "RUN-a"}, filepath.Join(root, "arquivo", "sub"))
		if err == nil || !strings.Contains(err.Error(), "run: criar") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("evento não serializável", func(t *testing.T) {
		dir := t.TempDir()
		runCtx := &RunContext{RunID: "RUN-b"}
		emitEvent(runCtx, EventStep, "ok", nil)
		emitEvent(runCtx, EventStep, "ruim", make(chan int))
		err := SaveRunEvents(runCtx, dir)
		if err == nil || !strings.Contains(err.Error(), "run: serializar evento") {
			t.Fatalf("erro = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "RUN-b.jsonl")); !os.IsNotExist(statErr) {
			t.Fatalf("arquivo parcial gravado apesar do erro (%v)", statErr)
		}
	})

	t.Run("destino é um diretório", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "RUN-c.jsonl"), 0o755); err != nil {
			t.Fatal(err)
		}
		runCtx := &RunContext{RunID: "RUN-c"}
		emitEvent(runCtx, EventStep, "x", nil)
		if err := SaveRunEvents(runCtx, dir); err == nil {
			t.Fatal("gravar sobre um diretório deveria falhar")
		}
	})

	t.Run("grava uma linha por evento sem linha final vazia", func(t *testing.T) {
		dir := t.TempDir()
		runCtx := &RunContext{RunID: "RUN-d"}
		emitEvent(runCtx, EventStart, "um", nil)
		emitEvent(runCtx, EventEnd, "dois", nil)
		if err := SaveRunEvents(runCtx, dir); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "RUN-d.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) != 2 || !strings.Contains(lines[0], `"um"`) || !strings.Contains(lines[1], `"dois"`) {
			t.Fatalf("conteúdo = %q", data)
		}
	})
}
