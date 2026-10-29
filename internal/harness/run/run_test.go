package run

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/metrics"
	"github.com/passoz/pwn/internal/harness/queue"
)

func writeWork(
	t *testing.T,
	root, acceptance string,
	risk contract.RiskLevel,
	writeAllow, writeDeny []string,
) contract.TaskContractV4 {
	t.Helper()
	workDir := filepath.Join(root, ".pwn", "work", "0001")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{
		"work_id": "0001",
		"title":   "t",
		"tasks": []any{
			map[string]any{"id": "1.1", "contract_id": "CTR-001"},
		},
	}
	planData, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "plan.json"), planData, 0o644); err != nil {
		t.Fatal(err)
	}

	taskContract, err := contract.CreateDefaultContractV4(
		"1.1", "0001", "Task", risk,
		&contract.DefaultOptions{WriteAllow: writeAllow, WriteDeny: writeDeny},
	)
	if err != nil {
		t.Fatal(err)
	}
	taskContract.AcceptanceContract.Commands = []string{acceptance}
	contractData, err := json.MarshalIndent(taskContract, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "CTR-001.json"), contractData, 0o644); err != nil {
		t.Fatal(err)
	}
	return taskContract
}

func commitAll(t *testing.T, root, message string) {
	t.Helper()
	gitCmd(t, root, "add", "-A")
	gitCmd(t, root, "commit", "-qm", message)
}

func baseOptions(root string, command ...string) Options {
	return Options{
		WorkID:  "0001",
		TaskID:  "1.1",
		Command: command,
		Timeout: 10 * time.Second,
		RootDir: root,
		Log:     os.Stderr,
	}
}

func assertSandboxesEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, ".pwn", "sandboxes"))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("sandbox deixado para trás: %v", entries)
	}
}

func TestRunDiffGuardViolationAndSandboxCleanup(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > forbidden.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL2, []string{"allowed.txt"}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "write.sh"))
	if len(result.DiffViolations) == 0 {
		t.Fatal("escrita fora do escopo não foi reportada")
	}
	if !strings.Contains(strings.Join(result.DiffViolations, "\n"), "forbidden.txt") {
		t.Fatalf("violação sem forbidden.txt: %v", result.DiffViolations)
	}
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	if result.Suspended {
		t.Fatal("run isolada não deve suspender")
	}
	assertSandboxesEmpty(t, root)

	entries, err := metrics.Read(root)
	if err != nil {
		t.Fatalf("ler métricas: %v", err)
	}
	if len(entries) != 1 || entries[0].Status != metrics.StatusFailed || !entries[0].Isolated {
		t.Fatalf("métrica inesperada: %+v", entries)
	}
	events, err := os.ReadFile(filepath.Join(root, ".pwn", result.RunID+".jsonl"))
	if err != nil {
		t.Fatalf("eventos da run ausentes: %v", err)
	}
	if !strings.Contains(string(events), `"diff_check"`) || !strings.Contains(string(events), `"end"`) {
		t.Fatalf("eventos incompletos: %s", events)
	}
}

func TestRunPolicyAllowlist(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL2, []string{"allowed.txt"}, []string{})

	result := Run(context.Background(), baseOptions(root, "echo", "hi"))
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	if !strings.Contains(strings.ToLower(result.Stderr), "allowlist") {
		t.Fatalf("stderr sem negação de allowlist: %q", result.Stderr)
	}
	assertSandboxesEmpty(t, root)
}

func TestRunL4SuspendsAndEnqueues(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})

	var log strings.Builder
	options := baseOptions(root, "sh", "write.sh")
	options.Log = &log
	result := Run(context.Background(), options)

	if !result.Suspended || result.Status != ExitSuspended {
		t.Fatalf("resultado = %+v, esperava suspensão", result)
	}
	itemPath := filepath.Join(root, "queue", "review", result.RunID+".json")
	if _, err := os.Stat(itemPath); err != nil {
		t.Fatalf("item da fila ausente: %v", err)
	}
	items, err := queue.List(root)
	if err != nil || len(items) != 1 || items[0].Status != queue.StatusPendingReview {
		t.Fatalf("fila inesperada: %+v (%v)", items, err)
	}
	if !strings.Contains(log.String(), "suspensa") {
		t.Fatalf("aviso de suspensão ausente: %s", log.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".pwn", "sandboxes")); !os.IsNotExist(err) {
		t.Fatal("task L4 suspensa não pode criar sandbox")
	}
}

type captureGatekeeper struct {
	decision GateDecision
	request  GateRequest
}

func (c *captureGatekeeper) Decide(request GateRequest) GateDecision {
	c.request = request
	return c.decision
}

func TestRunL4ApprovedByGatekeeper(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})

	gate := &captureGatekeeper{decision: GateDecision{
		Outcome:    GateApprove,
		Reasons:    []string{"destrutivo=0.0, corresponde=0.9"},
		DecisionID: "DEC-1",
	}}
	options := baseOptions(root, "sh", "write.sh")
	options.Gatekeeper = gate
	result := Run(context.Background(), options)

	if result.Status != 0 {
		t.Fatalf("status = %d, stderr=%s", result.Status, result.Stderr)
	}
	if gate.request.WorkID != "0001" || gate.request.TaskID != "1.1" || len(gate.request.Contracts) != 1 {
		t.Fatalf("pedido do decisor inesperado: %+v", gate.request)
	}
	if !slices.Equal(gate.request.Command, []string{"sh", "write.sh"}) {
		t.Fatalf("comando do decisor inesperado: %v", gate.request.Command)
	}
	items, err := queue.List(root)
	if err != nil || len(items) != 1 || items[0].Status != queue.StatusApproved {
		t.Fatalf("fila inesperada: %+v (%v)", items, err)
	}
	assertSandboxesEmpty(t, root)
}

func TestRunL4RejectedByGatekeeper(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})

	gate := &captureGatekeeper{decision: GateDecision{
		Outcome: GateReject,
		Reasons: []string{"o comando não corresponde à task"},
	}}
	options := baseOptions(root, "sh", "write.sh")
	options.Gatekeeper = gate
	result := Run(context.Background(), options)

	if result.Status != 1 || !strings.Contains(result.Stderr, "[DECIDER REJECTED]") {
		t.Fatalf("resultado = %+v", result)
	}
	items, err := queue.List(root)
	if err != nil || len(items) != 1 || items[0].Status != queue.StatusRejected {
		t.Fatalf("fila inesperada: %+v (%v)", items, err)
	}
	if _, err := os.Stat(filepath.Join(root, "queue", "review", result.RunID+".json")); err != nil {
		t.Fatalf("item rejeitado não gravado: %v", err)
	}
}

func TestRunL4UsesVigentQueueApproval(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL4, []string{"allowed.txt"}, []string{})

	_, documents, err := loadWorkContractsWithDocuments("0001", root)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := contractBinding(documents, []string{"sh", "write.sh"})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := queue.Enqueue(queue.Item{
		RunID:        "RUN-preapproved",
		WorkID:       "0001",
		TaskID:       "1.1",
		Title:        "Task",
		PausedAtStep: "pre-execution",
		Reason:       "revisado",
		RiskLevel:    "L4",
		Payload: map[string]any{
			"contract_sha256": binding.ContractSHA256,
			"command":         binding.Command,
		},
	}, root, queue.StatusApproved)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != queue.StatusApproved {
		t.Fatalf("aprovação não gravada: %+v", approved)
	}

	result := Run(context.Background(), baseOptions(root, "sh", "write.sh"))
	if result.Status != 0 {
		t.Fatalf("status = %d, stderr=%s", result.Status, result.Stderr)
	}
	items, err := queue.List(root)
	if err != nil || len(items) != 1 {
		t.Fatalf("fila inesperada: %+v (%v)", items, err)
	}
}

func TestRunTimeoutKillsCommand(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "slow.sh", "sleep 5\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh slow.sh", contract.RiskL2, []string{}, []string{})

	options := baseOptions(root, "sh", "slow.sh")
	options.Timeout = 200 * time.Millisecond
	started := time.Now()
	result := Run(context.Background(), options)
	elapsed := time.Since(started)

	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	if !strings.Contains(result.Stderr, "timeout") {
		t.Fatalf("stderr sem timeout: %q", result.Stderr)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("timeout demorou %s", elapsed)
	}
	assertSandboxesEmpty(t, root)
}

func TestRunFailsClosedWhenSandboxRepositoryIsDestroyed(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "kill-git.sh", "rm -rf .git\nprintf x > forbidden.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh kill-git.sh", contract.RiskL2, []string{}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "kill-git.sh"))
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	joined := strings.Join(result.DiffViolations, "\n")
	if !strings.Contains(joined, "aponta para") && !strings.Contains(joined, "não resolve para um repositório") {
		t.Fatalf("violação sem âncora do repositório: %v", result.DiffViolations)
	}
}

func TestRunDiffGuardRunsEvenWhenCommandFails(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write-then-fail.sh", "printf x > forbidden.txt\nexit 7\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write-then-fail.sh", contract.RiskL2, []string{}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "write-then-fail.sh"))
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	if len(result.DiffViolations) != 1 {
		t.Fatalf("violações = %v, esperava exatamente forbidden.txt", result.DiffViolations)
	}
	if !strings.Contains(result.DiffViolations[0], "forbidden.txt") {
		t.Fatalf("violação inesperada: %v", result.DiffViolations)
	}
}

func TestRunMalformedScopePatternFailsBeforeSandbox(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "write.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh write.sh", contract.RiskL2, []string{"allowed.txt"}, []string{"*.{pem"})

	result := Run(context.Background(), baseOptions(root, "sh", "write.sh"))
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	if !strings.Contains(result.Stderr, "CONTRACT ERROR") || !strings.Contains(result.Stderr, "padrão de escopo inválido") {
		t.Fatalf("stderr inesperado: %q", result.Stderr)
	}
	if _, err := os.Stat(filepath.Join(root, ".pwn", "sandboxes")); !os.IsNotExist(err) {
		t.Fatal("contrato inválido não pode criar sandbox")
	}
}

func TestRunArtifactIsNotAWorkspaceChange(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, ".gitignore", "node_modules/\n")
	writeFile(t, root, "ok.sh", "printf x > allowed.txt\n")
	commitAll(t, root, "ignore + in-scope script")
	writeFile(t, root, "node_modules/pkg/index.js", "module.exports = 1;\n")
	writeWork(t, root, "sh ok.sh", contract.RiskL2, []string{"allowed.txt"}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "ok.sh"))
	if len(result.DiffViolations) != 0 {
		t.Fatalf("artefato do harness virou violação: %v", result.DiffViolations)
	}
	if result.Status != 0 {
		t.Fatalf("status = %d, stderr=%s", result.Status, result.Stderr)
	}
	assertSandboxesEmpty(t, root)
}

func TestRunUsesUncommittedWorkingTree(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "app.sh", "exit 7\n")
	commitAll(t, root, "app que falha no HEAD")
	writeFile(t, root, "app.sh", "#!/bin/sh\nif grep -q OVERLAY-OK ./app.sh\nthen\n  exit 0\nfi\nexit 7\n")
	writeWork(t, root, "sh app.sh", contract.RiskL2, []string{"app.sh"}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "app.sh"))
	if len(result.DiffViolations) != 0 {
		t.Fatalf("violações inesperadas: %v", result.DiffViolations)
	}
	if result.Status != 0 {
		t.Fatalf("esperava sucesso com a working tree sobreposta; stderr=%s", result.Stderr)
	}
}

func TestRunReportsNewWorkingTreeFileOutsideScope(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "runner.sh", "exit 0\n")
	commitAll(t, root, "runner que passa")
	writeFile(t, root, "intruso.txt", "novo fora do escopo\n")
	writeWork(t, root, "sh runner.sh", contract.RiskL2, []string{"runner.sh"}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "runner.sh"))
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	joined := strings.Join(result.DiffViolations, "\n")
	if !strings.Contains(joined, "intruso.txt") {
		t.Fatalf("violação sem intruso.txt: %v", result.DiffViolations)
	}
}

func TestRunWithoutIsolationStillAppliesPolicy(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "pass.sh", "printf done > out.txt\n")
	commitAll(t, root, "seed")
	writeWork(t, root, "sh pass.sh", contract.RiskL2, []string{"out.txt"}, []string{})

	options := baseOptions(root, "sh", "pass.sh")
	options.Isolated = new(false)
	result := Run(context.Background(), options)
	if result.Status != 0 {
		t.Fatalf("status = %d, stderr=%s", result.Status, result.Stderr)
	}
	if data, err := os.ReadFile(filepath.Join(root, "out.txt")); err != nil || string(data) != "done" {
		t.Fatalf("arquivo não produzido: %q (%v)", data, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pwn", "sandboxes")); !os.IsNotExist(err) {
		t.Fatal("run não isolada não pode criar sandbox")
	}

	entries, err := metrics.Read(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("métricas inesperadas: %+v (%v)", entries, err)
	}
	if entries[0].Isolated {
		t.Fatal("métrica deveria indicar execução não isolada")
	}

	denied := baseOptions(root, "echo", "hi")
	denied.Isolated = new(false)
	deniedResult := Run(context.Background(), denied)
	if deniedResult.Status != 1 || !strings.Contains(strings.ToLower(deniedResult.Stderr), "allowlist") {
		t.Fatalf("política não aplicada sem sandbox: %+v", deniedResult)
	}
}

func TestAggregateContractsUsesMaxRiskAndUniqueScopes(t *testing.T) {
	low := testContract(t, contract.RiskL1, []string{"src/**", "shared/**"}, []string{".git/**"})
	low.AcceptanceContract.Commands = []string{"go test ./..."}
	high := testContract(t, contract.RiskL4, []string{"shared/**", "internal/**"}, []string{"secrets/**"})
	high.AcceptanceContract.Commands = []string{"go test ./...", "go vet ./..."}

	aggregated, err := aggregateContracts("0001", "1.1", []contract.TaskContractV4{low, high})
	if err != nil {
		t.Fatal(err)
	}
	if aggregated.Risk.Level != contract.RiskL4 {
		t.Fatalf("risco agregado = %s", aggregated.Risk.Level)
	}
	if !slices.Equal(aggregated.ScopeContract.WriteAllow, []string{"src/**", "shared/**", "internal/**"}) {
		t.Fatalf("write_allow = %v", aggregated.ScopeContract.WriteAllow)
	}
	if !slices.Equal(aggregated.ScopeContract.WriteDeny, []string{".git/**", "secrets/**"}) {
		t.Fatalf("write_deny = %v", aggregated.ScopeContract.WriteDeny)
	}
	if !slices.Equal(aggregated.AcceptanceContract.Commands, []string{"go test ./...", "go vet ./..."}) {
		t.Fatalf("comandos = %v", aggregated.AcceptanceContract.Commands)
	}
}

func TestRunSandboxErrorAbortsWithoutFallbackToRoot(t *testing.T) {
	root := t.TempDir() // diretório sem repositório Git
	writeWork(t, root, "sh write.sh", contract.RiskL2, []string{}, []string{})

	result := Run(context.Background(), baseOptions(root, "sh", "write.sh"))
	if result.Status != 1 {
		t.Fatalf("status = %d, esperava 1", result.Status)
	}
	if !strings.Contains(result.Stderr, "[SANDBOX ABORT]") {
		t.Fatalf("stderr sem aborto de sandbox: %q", result.Stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "allowed.txt")); !os.IsNotExist(err) {
		t.Fatal("comando foi executado no rootDir apesar da falha do sandbox")
	}
}
