package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/policy"
)

// coverTools monta uma Tool API com RunCtx para observar os eventos. O escopo
// de escrita é o informado; o shell permite os comandos listados.
func coverTools(
	t *testing.T, cwd string, writeAllow []string, isolated bool, commands ...string,
) (*ToolAPI, *RunContext, *contract.BudgetController) {
	t.Helper()
	taskContract := testContract(t, contract.RiskL1, writeAllow, []string{".git/**", "package.json"})
	rules := make([]policy.CommandRule, 0, len(commands))
	for _, command := range commands {
		rules = append(rules, policy.CommandRule{Command: command})
	}
	overrides := &policy.Overrides{
		Shell:   &policy.ShellPolicy{AllowedCommands: rules},
		Network: &policy.NetworkPolicy{AllowedDomains: []string{"example.com"}},
	}
	runCtx := &RunContext{Contract: taskContract, Status: StatusRunning}
	budget := contract.NewBudgetController(taskContract)
	tools := NewToolAPI(ToolAPIOptions{
		Policy:   policy.NewEngine(taskContract, overrides),
		Budget:   budget,
		Cwd:      cwd,
		RunCtx:   runCtx,
		Isolated: &isolated,
	})
	return tools, runCtx, budget
}

func hasEvent(runCtx *RunContext, eventType EventType, messagePart string) bool {
	for _, event := range runCtx.Events {
		if event.Type == eventType && strings.Contains(event.Message, messagePart) {
			return true
		}
	}
	return false
}

func TestToolAPICwd(t *testing.T) {
	dir := t.TempDir()
	tools, _, _ := coverTools(t, dir, []string{"src/**"}, false)
	if tools.Cwd() != dir {
		t.Fatalf("Cwd() = %q, esperava %q", tools.Cwd(), dir)
	}
}

func TestToolAPIBudgetExhaustionBlocksEveryOperation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/existing.txt", "x")
	// Limite zero: a primeira chamada já excede o orçamento.
	taskContract := testContract(t, contract.RiskL1, []string{"src/**"}, nil)
	taskContract.BudgetContract.MaxToolCalls = new(0)
	tools := NewToolAPI(ToolAPIOptions{
		Policy: policy.NewEngine(taskContract, &policy.Overrides{
			Shell: &policy.ShellPolicy{AllowedCommands: []policy.CommandRule{{Command: "echo"}}},
			Network: &policy.NetworkPolicy{
				AllowedDomains: []string{"example.com"},
			},
		}),
		Budget: contract.NewBudgetController(taskContract),
		Cwd:    dir,
	})

	operations := map[string]ToolResult{
		"WriteFile":   tools.WriteFile("src/new.txt", "x"),
		"ReadFile":    tools.ReadFile("src/existing.txt"),
		"DeleteFile":  tools.DeleteFile("src/existing.txt"),
		"CreateDir":   tools.CreateDir("src/newdir"),
		"RenameFile":  tools.RenameFile("src/existing.txt", "src/renamed.txt"),
		"Exec":        tools.Exec("echo", []string{"oi"}, time.Second),
		"HTTPRequest": tools.HTTPRequest("GET", "https://example.com/"),
		"DNSLookup":   tools.DNSLookup("example.com"),
	}
	for name, result := range operations {
		if result.Success {
			t.Fatalf("%s foi aceita com o orçamento esgotado", name)
		}
		if !strings.HasPrefix(result.Error, "BUDGET EXCEEDED: ") {
			t.Fatalf("%s: erro = %q", name, result.Error)
		}
		if result.BudgetViolation == nil || result.BudgetViolation.Reason != contract.BudgetReasonMaxToolCalls {
			t.Fatalf("%s: violação = %+v", name, result.BudgetViolation)
		}
	}
	for _, name := range []string{"new.txt", "newdir", "renamed.txt"} {
		if _, err := os.Stat(filepath.Join(dir, "src", name)); !os.IsNotExist(err) {
			t.Fatalf("src/%s foi criado apesar do bloqueio de orçamento (%v)", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "src", "existing.txt")); err != nil {
		t.Fatalf("arquivo existente foi alterado: %v", err)
	}
}

func TestToolAPIPolicyDenialsAreReportedAndLogged(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "src/a.txt", "a")
	tools, runCtx, budget := coverTools(t, dir, []string{"src/**"}, false, "echo")

	tests := []struct {
		name   string
		result ToolResult
		event  string
	}{
		{name: "deleteFile", result: tools.DeleteFile("package.json"), event: "DENY delete_file package.json"},
		{name: "createDir", result: tools.CreateDir(".git/hooks"), event: "DENY create_dir .git/hooks"},
		{name: "renameFile", result: tools.RenameFile("src/a.txt", "package.json"), event: "DENY rename dest package.json"},
	}
	for _, test := range tests {
		if test.result.Success || test.result.PolicyDecision == nil || test.result.PolicyDecision.Allowed {
			t.Fatalf("%s: resultado = %+v, esperava negação com decisão", test.name, test.result)
		}
		if test.result.Error == "" || test.result.Error != test.result.PolicyDecision.Reason {
			t.Fatalf("%s: erro %q deveria ser o motivo da política %q", test.name, test.result.Error, test.result.PolicyDecision.Reason)
		}
		if !hasEvent(runCtx, EventPolicyCheck, test.event) {
			t.Fatalf("%s: evento %q ausente: %+v", test.name, test.event, runCtx.Events)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err != nil || string(data) != "{}" {
		t.Fatalf("package.json alterado: %q (%v)", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "src", "a.txt")); err != nil {
		t.Fatalf("origem do rename negado sumiu: %v", err)
	}
	if usage := budget.GetUsage(); usage.ToolCalls != 0 {
		t.Fatalf("negativas não devem consumir chamadas: %d", usage.ToolCalls)
	}
}

func TestToolAPIEveryOperationRefusesPathEscape(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "sandbox")
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("segredo"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "src/a.txt", "a")
	// Escopo amplo: a política não é o que barra, só a contenção do sandbox.
	tools, runCtx, budget := coverTools(t, dir, []string{"**"}, false)

	tests := []struct {
		name   string
		result ToolResult
		event  string
	}{
		{name: "readFile", result: tools.ReadFile("../secret.txt"), event: "PATH ESCAPE: "},
		{name: "deleteFile", result: tools.DeleteFile(outsideFile), event: "PATH ESCAPE: "},
		{name: "createDir", result: tools.CreateDir(filepath.Join(base, "novo")), event: "PATH ESCAPE: "},
		{name: "rename com origem fora", result: tools.RenameFile(outsideFile, "src/b.txt"), event: "PATH ESCAPE (source): "},
		{name: "rename com destino fora", result: tools.RenameFile("src/a.txt", filepath.Join(base, "b.txt")), event: "PATH ESCAPE (destination): "},
	}
	for _, test := range tests {
		if test.result.Success {
			t.Fatalf("%s: escape aceito", test.name)
		}
		if !strings.Contains(test.result.Error, "Path escape detectado") {
			t.Fatalf("%s: erro = %q", test.name, test.result.Error)
		}
		if !hasEvent(runCtx, EventError, test.event) {
			t.Fatalf("%s: evento %q ausente: %+v", test.name, test.event, runCtx.Events)
		}
	}
	if data, err := os.ReadFile(outsideFile); err != nil || string(data) != "segredo" {
		t.Fatalf("arquivo externo foi tocado: %q (%v)", data, err)
	}
	for _, name := range []string{"novo", "b.txt"} {
		if _, err := os.Stat(filepath.Join(base, name)); !os.IsNotExist(err) {
			t.Fatalf("%s criado fora do sandbox (%v)", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "src", "a.txt")); err != nil {
		t.Fatalf("origem do rename recusado sumiu: %v", err)
	}
	if usage := budget.GetUsage(); usage.ToolCalls != 0 {
		t.Fatalf("recusas não devem consumir chamadas: %d", usage.ToolCalls)
	}
}

func TestToolAPIFilesystemFailuresAreReportedWithoutBudgetCharge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/blocker", "arquivo comum")
	if err := os.MkdirAll(filepath.Join(dir, "src", "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	tools, _, budget := coverTools(t, dir, []string{"src/**"}, false)

	tests := []struct {
		name   string
		result ToolResult
		want   string
	}{
		{name: "write com pai que é arquivo", result: tools.WriteFile("src/blocker/x.txt", "x"), want: "criar diretório"},
		{name: "write sobre diretório", result: tools.WriteFile("src/adir", "x"), want: "gravar"},
		{name: "read de arquivo ausente", result: tools.ReadFile("src/ausente.txt"), want: "ler"},
		{name: "delete de arquivo ausente", result: tools.DeleteFile("src/ausente.txt"), want: "remover"},
		{name: "mkdir sobre arquivo", result: tools.CreateDir("src/blocker"), want: "criar diretório"},
		{name: "rename de origem ausente", result: tools.RenameFile("src/ausente.txt", "src/novo.txt"), want: "mover"},
	}
	for _, test := range tests {
		if test.result.Success {
			t.Fatalf("%s: falha do filesystem foi reportada como sucesso", test.name)
		}
		if !strings.Contains(test.result.Error, test.want) {
			t.Fatalf("%s: erro = %q, esperava conter %q", test.name, test.result.Error, test.want)
		}
		if test.result.PolicyDecision != nil || test.result.BudgetViolation != nil {
			t.Fatalf("%s: falha de IO não deve trazer decisão de política ou orçamento: %+v", test.name, test.result)
		}
	}
	if usage := budget.GetUsage(); usage.ToolCalls != 0 || usage.Tokens != 0 {
		t.Fatalf("falhas não devem ser cobradas: %+v", usage)
	}
}

func TestToolAPIRefusesBrokenSandboxRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sumiu")
	tools, _, _ := coverTools(t, dir, []string{"src/**"}, false)
	result := tools.WriteFile("src/a.txt", "x")
	if result.Success || !strings.Contains(result.Error, "Symlink quebrado ou não resolvido") {
		t.Fatalf("resultado = %+v", result)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("raiz do sandbox inexistente foi recriada (%v)", err)
	}
}

func TestToolAPIExecStartFailureStatusAndNoTimeout(t *testing.T) {
	dir := t.TempDir()

	t.Run("binário inexistente cobra a execução shell", func(t *testing.T) {
		tools, runCtx, budget := coverTools(t, dir, []string{"src/**"}, false, "pwn-binario-inexistente")
		result := tools.Exec("pwn-binario-inexistente", nil, time.Second)
		if result.Success || !strings.Contains(result.Error, "falha ao iniciar processo") {
			t.Fatalf("resultado = %+v", result)
		}
		if usage := budget.GetUsage(); usage.ShellExecutions != 1 || usage.ToolCalls != 0 {
			t.Fatalf("uso = %+v, esperava 1 shell e 0 chamadas", usage)
		}
		if !hasEvent(runCtx, EventError, "falha ao iniciar processo pwn-binario-inexistente") {
			t.Fatalf("evento de falha ausente: %+v", runCtx.Events)
		}
	})

	t.Run("sem timeout espera o término e devolve o status", func(t *testing.T) {
		tools, runCtx, _ := coverTools(t, dir, []string{"src/**"}, false, "sh")
		writeFile(t, dir, "status3.sh", "echo saida\necho erro >&2\nexit 3\n")
		result := tools.Exec("sh", []string{"status3.sh"}, 0)
		if !result.Success {
			t.Fatalf("processo que terminou com status 3 deve ser sucesso de execução: %+v", result)
		}
		output, ok := result.Data.(ExecOutput)
		if !ok || output.Status != 3 || strings.TrimSpace(output.Stdout) != "saida" || strings.TrimSpace(output.Stderr) != "erro" {
			t.Fatalf("saída = %+v", result.Data)
		}
		if !hasEvent(runCtx, EventStep, "(exit=3)") {
			t.Fatalf("evento com o status ausente: %+v", runCtx.Events)
		}
	})

	t.Run("processo morto por sinal vale status 1", func(t *testing.T) {
		tools, _, _ := coverTools(t, dir, []string{"src/**"}, false, "sh")
		result := tools.Exec("sh", []string{"-c", "kill -9 $$"}, 5*time.Second)
		output, ok := result.Data.(ExecOutput)
		if !result.Success || !ok || output.Status != 1 {
			t.Fatalf("resultado = %+v", result)
		}
	})
}

func TestToolAPIExecRunsInsideBwrapWhenSupported(t *testing.T) {
	dir := t.TempDir()
	tools, _, _ := coverTools(t, dir, []string{"src/**"}, true, "echo")
	result := tools.Exec("echo", []string{"isolado"}, 10*time.Second)
	if !result.Success {
		// bwrap pode existir mas não funcionar no runner (sem user namespaces).
		t.Skipf("execução isolada indisponível neste host: %s", result.Error)
	}
	output, ok := result.Data.(ExecOutput)
	if !ok || strings.TrimSpace(output.Stdout) != "isolado" || output.Status != 0 {
		t.Fatalf("saída = %+v", result.Data)
	}
}

func TestExitStatusAndResolveHelpers(t *testing.T) {
	if got := exitStatus(nil); got != 0 {
		t.Fatalf("exitStatus(nil) = %d", got)
	}
	if got := exitStatus(os.ErrNotExist); got != 1 {
		t.Fatalf("exitStatus(erro genérico) = %d, esperava 1", got)
	}

	base := t.TempDir()
	if !isContained(base, base) || !isContained(base, filepath.Join(base, "a", "b")) {
		t.Fatal("raiz e descendentes devem estar contidos")
	}
	if isContained(base, filepath.Dir(base)) || isContained(base, filepath.Join(base, "..", "irmao")) {
		t.Fatal("pai e irmãos não podem estar contidos")
	}
	// Um prefixo textual comum não é contenção.
	if isContained(base, base+"-vizinho") {
		t.Fatal("diretório vizinho com o mesmo prefixo foi considerado contido")
	}
}

func TestToolAPIUtf16Accounting(t *testing.T) {
	dir := t.TempDir()
	tools, _, budget := coverTools(t, dir, []string{"src/**"}, false)
	// Um caractere fora do plano básico ocupa dois code units UTF-16: 8 units = 2 tokens.
	if result := tools.WriteFile("src/emoji.txt", "😀😀😀😀"); !result.Success {
		t.Fatalf("escrita falhou: %s", result.Error)
	}
	if usage := budget.GetUsage(); usage.Tokens != 2 || usage.ToolCalls != 1 {
		t.Fatalf("uso = %+v, esperava 2 tokens e 1 chamada", usage)
	}
}
