package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/policy"
)

// gitCmd executa git no diretório e falha o teste quando o comando falha.
func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v falhou: %v\n%s", args, err, string(output))
	}
	return string(output)
}

// newRepo cria um repositório Git temporário com identidade configurada.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "test@example.invalid")
	gitCmd(t, dir, "config", "user.name", "Test")
	return dir
}

// writeFile grava um arquivo e falha o teste em erro.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	target := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("criar diretório de %s: %v", name, err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("gravar %s: %v", name, err)
	}
}

// testContract cria um contrato V4 com o escopo informado.
func testContract(t *testing.T, risk contract.RiskLevel, writeAllow, writeDeny []string) contract.TaskContractV4 {
	t.Helper()
	taskContract, err := contract.CreateDefaultContractV4(
		"T-001", "0001", "Tool Test", risk,
		&contract.DefaultOptions{WriteAllow: writeAllow, WriteDeny: writeDeny},
	)
	if err != nil {
		t.Fatalf("criar contrato: %v", err)
	}
	return taskContract
}

func toolTestPolicy(t *testing.T) *policy.Overrides {
	t.Helper()
	return &policy.Overrides{
		Shell: &policy.ShellPolicy{
			AllowedCommands: []policy.CommandRule{
				{Command: "echo"},
				{Command: "sleep"},
				{Command: "git", Args: []string{"status"}},
			},
			DeniedCommands: append(policy.DefaultShellPolicy().DeniedCommands,
				policy.CommandRule{Command: "sh"},
				policy.CommandRule{Command: "bash"},
			),
		},
		Network: &policy.NetworkPolicy{
			AllowedDomains: []string{"example.com"},
			DeniedDomains:  []string{"evil.com"},
		},
	}
}

func makeToolAPI(t *testing.T, cwd string, overrides *policy.Overrides) (*ToolAPI, *contract.BudgetController) {
	t.Helper()
	taskContract := testContract(t, contract.RiskL1,
		[]string{"src/**", "tests/**"},
		[]string{".git/**", "package.json"},
	)
	budget := contract.NewBudgetController(taskContract)
	tools := NewToolAPI(ToolAPIOptions{
		Policy: policy.NewEngine(taskContract, overrides),
		Budget: budget,
		Cwd:    cwd,
	})
	return tools, budget
}
