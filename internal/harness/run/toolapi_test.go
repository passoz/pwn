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

func TestToolAPIFilesystem(t *testing.T) {
	tests := []struct {
		name   string
		action func(t *testing.T, tools *ToolAPI, dir string) ToolResult
		check  func(t *testing.T, dir string, result ToolResult)
	}{
		{
			name: "writeFile grava e conta a chamada",
			action: func(t *testing.T, tools *ToolAPI, dir string) ToolResult {
				return tools.WriteFile("src/test.ts", "export const x = 1;")
			},
			check: func(t *testing.T, dir string, result ToolResult) {
				if !result.Success {
					t.Fatalf("writeFile falhou: %s", result.Error)
				}
				data, err := os.ReadFile(filepath.Join(dir, "src/test.ts"))
				if err != nil || string(data) != "export const x = 1;" {
					t.Fatalf("conteúdo inesperado: %q (%v)", data, err)
				}
			},
		},
		{
			name: "createDir cria o diretório",
			action: func(t *testing.T, tools *ToolAPI, dir string) ToolResult {
				return tools.CreateDir("src/newdir")
			},
			check: func(t *testing.T, dir string, result ToolResult) {
				if !result.Success {
					t.Fatalf("createDir falhou: %s", result.Error)
				}
				info, err := os.Stat(filepath.Join(dir, "src/newdir"))
				if err != nil || !info.IsDir() {
					t.Fatalf("diretório não criado: %v", err)
				}
			},
		},
		{
			name: "deleteFile remove o arquivo",
			action: func(t *testing.T, tools *ToolAPI, dir string) ToolResult {
				writeFile(t, dir, "src/to-delete.ts", "bye")
				return tools.DeleteFile("src/to-delete.ts")
			},
			check: func(t *testing.T, dir string, result ToolResult) {
				if !result.Success {
					t.Fatalf("deleteFile falhou: %s", result.Error)
				}
				if _, err := os.Stat(filepath.Join(dir, "src/to-delete.ts")); !os.IsNotExist(err) {
					t.Fatalf("arquivo ainda existe: %v", err)
				}
			},
		},
		{
			name: "renameFile move dentro do escopo",
			action: func(t *testing.T, tools *ToolAPI, dir string) ToolResult {
				writeFile(t, dir, "src/old.ts", "x")
				return tools.RenameFile("src/old.ts", "src/new.ts")
			},
			check: func(t *testing.T, dir string, result ToolResult) {
				if !result.Success {
					t.Fatalf("renameFile falhou: %s", result.Error)
				}
				if _, err := os.Stat(filepath.Join(dir, "src/new.ts")); err != nil {
					t.Fatalf("destino ausente: %v", err)
				}
				if _, err := os.Stat(filepath.Join(dir, "src/old.ts")); !os.IsNotExist(err) {
					t.Fatalf("origem ainda existe: %v", err)
				}
			},
		},
		{
			name: "writeFile respeita a política de escrita",
			action: func(t *testing.T, tools *ToolAPI, dir string) ToolResult {
				return tools.WriteFile("secret.env", "KEY=VALUE")
			},
			check: func(t *testing.T, dir string, result ToolResult) {
				if result.Success {
					t.Fatal("escrita fora da allowlist foi aceita")
				}
				if result.PolicyDecision == nil {
					t.Fatal("negativa deve trazer a decisão de política")
				}
			},
		},
		{
			name: "readFile lê o conteúdo",
			action: func(t *testing.T, tools *ToolAPI, dir string) ToolResult {
				writeFile(t, dir, "src/hello.ts", "hello")
				return tools.ReadFile("src/hello.ts")
			},
			check: func(t *testing.T, dir string, result ToolResult) {
				if !result.Success {
					t.Fatalf("readFile falhou: %s", result.Error)
				}
				if text, _ := result.Data.(string); text != "hello" {
					t.Fatalf("conteúdo inesperado: %q", result.Data)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			tools, budget := makeToolAPI(t, dir, toolTestPolicy(t))
			result := test.action(t, tools, dir)
			test.check(t, dir, result)
			if result.Success {
				if usage := budget.GetUsage(); usage.ToolCalls != 1 {
					t.Fatalf("toolCalls = %d, esperava 1", usage.ToolCalls)
				}
			}
		})
	}
}

func TestToolAPIShellAndNetwork(t *testing.T) {
	dir := t.TempDir()
	tools, budget := makeToolAPI(t, dir, toolTestPolicy(t))

	ok := tools.Exec("echo", []string{"hello"}, 5*time.Second)
	if !ok.Success {
		t.Fatalf("echo permitido falhou: %s", ok.Error)
	}
	output, isExec := ok.Data.(ExecOutput)
	if !isExec || strings.TrimSpace(output.Stdout) != "hello" || output.Status != 0 {
		t.Fatalf("saída inesperada: %+v", ok.Data)
	}

	deniedExec := tools.Exec("cat", []string{"/etc/passwd"}, 5*time.Second)
	if deniedExec.Success || deniedExec.PolicyDecision == nil {
		t.Fatalf("cat deveria ser negado pela política: %+v", deniedExec)
	}

	allowedHTTP := tools.HTTPRequest("GET", "https://example.com/api")
	if !allowedHTTP.Success {
		t.Fatalf("domínio permitido negado: %s", allowedHTTP.Error)
	}
	deniedHTTP := tools.HTTPRequest("GET", "https://other.com/api")
	if deniedHTTP.Success || deniedHTTP.PolicyDecision == nil {
		t.Fatalf("domínio desconhecido deveria ser negado: %+v", deniedHTTP)
	}
	if bypass := tools.HTTPRequest("GET", "https://example.com.evil.com/exfil"); bypass.Success {
		t.Fatal("bypass de sufixo de domínio foi aceito")
	}
	if deniedDNS := tools.DNSLookup("evil.com"); deniedDNS.Success {
		t.Fatal("DNS para domínio negado foi aceito")
	}
	if allowedDNS := tools.DNSLookup("example.com"); !allowedDNS.Success {
		t.Fatalf("DNS permitido negado: %s", allowedDNS.Error)
	}

	if usage := budget.GetUsage(); usage.ShellExecutions != 1 {
		t.Fatalf("shellExecutions = %d, esperava 1 (a negativa de política não spawna processo)", usage.ShellExecutions)
	}
}

func TestToolAPIRejectsShellInjection(t *testing.T) {
	dir := t.TempDir()
	escape := filepath.Join(t.TempDir(), "injection")
	tests := []struct {
		name string
		args []string
	}{
		{name: "substituição de comando", args: []string{"$(touch " + escape + ")"}},
		{name: "encadeamento com &&", args: []string{"hello", "&&", "touch", escape}},
		{name: "pipe", args: []string{"hello", "|", "touch", escape}},
		{name: "redirecionamento", args: []string{"hello", ">", escape}},
		{name: "crase", args: []string{"`touch " + escape + "`"}},
		{name: "interpolação", args: []string{"${HOME}"}},
	}
	tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := tools.Exec("echo", test.args, 5*time.Second)
			if result.Success {
				t.Fatalf("injeção aceita: %v", test.args)
			}
			if _, err := os.Stat(escape); !os.IsNotExist(err) {
				t.Fatalf("o argumento hostil produziu efeito fora do sandbox: %v", err)
			}
		})
	}
}

func TestToolAPIExecTimeout(t *testing.T) {
	dir := t.TempDir()
	tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))

	started := time.Now()
	result := tools.Exec("sleep", []string{"5"}, 150*time.Millisecond)
	elapsed := time.Since(started)
	if result.Success {
		t.Fatal("comando lento deveria ser morto pelo timeout")
	}
	if !strings.Contains(result.Error, "timeout") {
		t.Fatalf("mensagem sem timeout: %q", result.Error)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("timeout demorou %s", elapsed)
	}
}

func TestToolAPIExecSanitizesVerifierKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PWN_VERIFIER_KEY", "super-secret")
	taskContract := testContract(t, contract.RiskL1, []string{"src/**"}, []string{})
	budget := contract.NewBudgetController(taskContract)
	tools := NewToolAPI(ToolAPIOptions{
		Policy: policy.NewEngine(taskContract, &policy.Overrides{
			Shell: &policy.ShellPolicy{AllowedCommands: []policy.CommandRule{{Command: "sh"}}},
		}),
		Budget: budget,
		Cwd:    dir,
	})

	result := tools.Exec("sh", []string{"-c", `printf %s "$PWN_VERIFIER_KEY"`}, 5*time.Second)
	if !result.Success {
		t.Fatalf("execução falhou: %s", result.Error)
	}
	output := result.Data.(ExecOutput)
	if output.Stdout != "" {
		t.Fatalf("a chave do verificador vazou para o filho: %q", output.Stdout)
	}
}

func TestToolAPIBudget(t *testing.T) {
	taskContract := testContract(t, contract.RiskL0, []string{"src/**"}, []string{})
	budget := contract.NewBudgetController(taskContract)
	dir := t.TempDir()
	tools := NewToolAPI(ToolAPIOptions{
		Policy: policy.NewEngine(taskContract, &policy.Overrides{
			Shell: &policy.ShellPolicy{AllowedCommands: []policy.CommandRule{{Command: "echo"}}},
		}),
		Budget: budget,
		Cwd:    dir,
	})

	// L0 default: max_tool_calls = 20.
	for index := range 20 {
		result := tools.WriteFile("src/fill.ts", strings.Repeat("x", index))
		if !result.Success {
			t.Fatalf("chamada %d bloqueada cedo demais: %s", index, result.Error)
		}
	}
	blocked := tools.WriteFile("src/overflow.ts", "overflow")
	if blocked.Success || blocked.BudgetViolation == nil {
		t.Fatalf("budget excedido não bloqueou: %+v", blocked)
	}
}

func TestToolAPIPathEscapes(t *testing.T) {
	type setup func(t *testing.T, dir, outside string) (tools *ToolAPI, target, relative string)
	tests := []struct {
		name  string
		setup setup
	}{
		{
			name: "path traversal com ../",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
				return tools, filepath.Join(dir, "..", "secret.txt"), "../secret.txt"
			},
		},
		{
			name: "path traversal dentro da allowlist",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				writeFile(t, dir, "src/keep.txt", "x")
				tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
				return tools, filepath.Join(dir, "secret.txt"), "src/../secret.txt"
			},
		},
		{
			name: "caminho absoluto fora do sandbox",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
				target := filepath.Join(outside, "outside.txt")
				return tools, target, target
			},
		},
		{
			name: "caminho absoluto fora com escopo amplo",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				taskContract := testContract(t, contract.RiskL1, []string{"**"}, []string{})
				tools := NewToolAPI(ToolAPIOptions{
					Policy: policy.NewEngine(taskContract, toolTestPolicy(t)),
					Budget: contract.NewBudgetController(taskContract),
					Cwd:    dir,
				})
				target := filepath.Join(outside, "wide-scope.txt")
				return tools, target, target
			},
		},
		{
			name: "symlink de arquivo para fora",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				target := filepath.Join(outside, "preexisting.txt")
				if err := os.WriteFile(target, []byte("safe"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, "src", "existing-link")); err != nil {
					t.Fatal(err)
				}
				tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
				return tools, target, "src/existing-link"
			},
		},
		{
			name: "symlink de diretório para fora",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				if err := os.Symlink(outside, filepath.Join(dir, "src", "link")); err != nil {
					t.Fatal(err)
				}
				tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
				return tools, filepath.Join(outside, "secret.txt"), "src/link/secret.txt"
			},
		},
		{
			name: "diretório-pai symlinkado com arquivo novo",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				if err := os.Symlink(outside, filepath.Join(dir, "src", "linked")); err != nil {
					t.Fatal(err)
				}
				tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
				return tools, filepath.Join(outside, "newfile.txt"), "src/linked/newfile.txt"
			},
		},
		{
			name: "symlink pendente na folha",
			setup: func(t *testing.T, dir, outside string) (*ToolAPI, string, string) {
				target := filepath.Join(outside, "dangling-target.txt")
				if err := os.Symlink(target, filepath.Join(dir, "dangling")); err != nil {
					t.Fatal(err)
				}
				taskContract := testContract(t, contract.RiskL1, []string{"**"}, []string{})
				tools := NewToolAPI(ToolAPIOptions{
					Policy: policy.NewEngine(taskContract, toolTestPolicy(t)),
					Budget: contract.NewBudgetController(taskContract),
					Cwd:    dir,
				})
				return tools, target, "dangling"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			tools, target, relative := test.setup(t, dir, outside)

			result := tools.WriteFile(relative, "owned")
			if result.Success {
				t.Fatalf("escrita aceita para %q", relative)
			}
			if test.name == "symlink de arquivo para fora" {
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "safe" {
					t.Fatalf("alvo externo foi modificado: %q (%v)", data, err)
				}
			} else if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("destino externo foi criado: %v", err)
			}
		})
	}
}

func TestToolAPISymlinkedParentBlocksDirAndRename(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "src", "linked")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "src/orig.txt", "x")

	tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))
	if result := tools.CreateDir("src/linked/newdir"); result.Success {
		t.Fatal("mkdir através de diretório-pai symlinkado foi aceito")
	}
	if result := tools.RenameFile("src/orig.txt", "src/linked/moved.txt"); result.Success {
		t.Fatal("rename para diretório-pai symlinkado foi aceito")
	}
	if _, err := os.Stat(filepath.Join(outside, "newdir")); !os.IsNotExist(err) {
		t.Fatal("diretório externo foi criado")
	}
	if _, err := os.Stat(filepath.Join(outside, "moved.txt")); !os.IsNotExist(err) {
		t.Fatal("arquivo externo foi criado")
	}
}

func TestToolAPIRenameEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "src/move-me.txt", "x")
	tools, _ := makeToolAPI(t, dir, toolTestPolicy(t))

	if result := tools.RenameFile("src/move-me.txt", "../escaped.txt"); result.Success {
		t.Fatal("rename para fora do sandbox foi aceito")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "escaped.txt")); !os.IsNotExist(err) {
		t.Fatal("arquivo escapou do sandbox")
	}
}

func TestToolAPILogsRunEvents(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	taskContract := testContract(t, contract.RiskL1, []string{"src/**"}, []string{})
	runCtx := &RunContext{Contract: taskContract, Status: StatusRunning}
	tools := NewToolAPI(ToolAPIOptions{
		Policy: policy.NewEngine(taskContract, nil),
		Budget: contract.NewBudgetController(taskContract),
		Cwd:    dir,
		RunCtx: runCtx,
	})

	if result := tools.WriteFile("src/ok.ts", "ok"); !result.Success {
		t.Fatalf("escrita falhou: %s", result.Error)
	}
	types := make(map[EventType]bool)
	for _, event := range runCtx.Events {
		types[event.Type] = true
	}
	for _, expected := range []EventType{EventPolicyCheck, EventStep} {
		if !types[expected] {
			t.Fatalf("evento %q ausente: %+v", expected, runCtx.Events)
		}
	}
}
