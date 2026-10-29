package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/config"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv(config.OperatorEnv, "")
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "sem argumentos", args: nil},
		{name: "--help", args: []string{"--help"}},
		{name: "-h", args: []string{"-h"}},
		{name: "help antes do separador", args: []string{"work", "--help"}},
		{name: "apenas separador", args: []string{"--"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, test.args...)
			if code != 0 {
				t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
			}
			if !strings.Contains(stdout, "PWN — Policy Work Norms CLI (pwn)") {
				t.Fatalf("stdout sem o título da ajuda: %q", stdout)
			}
			if !strings.Contains(stdout, "COMANDOS DISPONÍVEIS:") {
				t.Fatalf("stdout sem a lista de comandos: %q", stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, quer vazio", stderr)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "--version", args: []string{"--version"}},
		{name: "-v", args: []string{"-v"}},
		{name: "version antes do comando", args: []string{"work", "run", "--version"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, test.args...)
			if code != 0 {
				t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
			}
			if want := "pwn v" + Version + "\n"; stdout != want {
				t.Fatalf("stdout = %q, quer %q", stdout, want)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, quer vazio", stderr)
			}
		})
	}
}

func TestUnknownCommandShowsHelp(t *testing.T) {
	code, stdout, stderr := runCLI(t, "nope")
	if code != 1 {
		t.Fatalf("código = %d, quer 1", code)
	}
	if !strings.Contains(stderr, "Comando desconhecido: 'nope'") {
		t.Fatalf("stderr = %q, quer o comando desconhecido", stderr)
	}
	if !strings.Contains(stdout, "COMANDOS DISPONÍVEIS:") {
		t.Fatalf("stdout = %q, quer a ajuda", stdout)
	}

	t.Run("PWN_OPERATOR inválido não impede a ajuda", func(t *testing.T) {
		t.Setenv(config.OperatorEnv, "auto")
		var stdout, stderr bytes.Buffer
		code := Run([]string{"nope"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr.String(), "Comando desconhecido: 'nope'") {
			t.Fatalf("stderr = %q, quer o comando desconhecido", stderr.String())
		}
		if !strings.Contains(stdout.String(), "COMANDOS DISPONÍVEIS:") {
			t.Fatalf("stdout = %q, quer a ajuda", stdout.String())
		}
	})
}

func TestGlobalFlagsBeforeSeparatorOnly(t *testing.T) {
	t.Run("--version do operador não é interceptado", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "audit", "check", "--", "bun", "--version")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if strings.Contains(stdout, "pwn v") || strings.Contains(stderr, "pwn v") {
			t.Fatalf("stdout = %q, stderr = %q, não podem conter a versão do pwn", stdout, stderr)
		}
		if !strings.Contains(stderr, "FAIL: missing required option: --work") {
			t.Fatalf("stderr = %q, quer o diagnóstico do audit", stderr)
		}
	})

	t.Run("--help do operador não é interceptado", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "run", "--", "--help")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if strings.Contains(stdout, "COMANDOS DISPONÍVEIS:") {
			t.Fatalf("stdout = %q, não pode conter a ajuda", stdout)
		}
		if !strings.Contains(stderr, "[GATE BLOCKED] Work 0001 não existe em ") {
			t.Fatalf("stderr = %q, quer o diagnóstico do handler", stderr)
		}
	})

	t.Run("--operator do operador não é interpretado", func(t *testing.T) {
		inTempDir(t)
		code, stdout, stderr := runCLI(t, "work", "run", "--", "--operator", "bogus")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if strings.Contains(stderr, "--operator inválido") {
			t.Fatalf("stderr = %q, não pode validar o --operator do operador", stderr)
		}
		if strings.Contains(stdout, "COMANDOS DISPONÍVEIS:") {
			t.Fatalf("stdout = %q, não pode conter a ajuda", stdout)
		}
		if !strings.Contains(stderr, "[GATE BLOCKED] Work 0001 não existe em ") {
			t.Fatalf("stderr = %q, quer o diagnóstico do handler", stderr)
		}
	})

	t.Run("separador sozinho mostra ajuda", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "--", "--version")
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
		}
		if !strings.Contains(stdout, "COMANDOS DISPONÍVEIS:") {
			t.Fatalf("stdout = %q, quer a ajuda", stdout)
		}
	})
}

func TestOperator(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "forma inline", args: []string{"--operator=human", "work", "status"}},
		{name: "forma separada", args: []string{"--operator", "decider", "work", "status"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inTempDir(t)
			code, stdout, stderr := runCLI(t, test.args...)
			if code != 0 {
				t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr)
			}
			if !strings.Contains(stdout, "=== [pwn work status] Relatório de Status do Work ===") {
				t.Fatalf("stdout = %q, quer o relatório de status", stdout)
			}
			if strings.Contains(stderr, "ainda não portado") {
				t.Fatalf("stderr = %q, o comando já está portado", stderr)
			}
		})
	}

	t.Run("valor inválido", func(t *testing.T) {
		for _, args := range [][]string{
			{"--operator=auto", "work"},
			{"--operator", "auto", "work"},
		} {
			code, _, stderr := runCLI(t, args...)
			if code != 1 {
				t.Fatalf("args %v: código = %d, quer 1", args, code)
			}
			if !strings.Contains(stderr, "--operator inválido: 'auto' (use human ou decider)") {
				t.Fatalf("args %v: stderr = %q", args, stderr)
			}
		}
	})

	t.Run("valor ausente", func(t *testing.T) {
		code, _, stderr := runCLI(t, "--operator")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr, "--operator inválido: '' (use human ou decider)") {
			t.Fatalf("stderr = %q", stderr)
		}
	})

	t.Run("valor inline vazio", func(t *testing.T) {
		code, _, stderr := runCLI(t, "--operator=", "work")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr, "--operator inválido: '' (use human ou decider)") {
			t.Fatalf("stderr = %q", stderr)
		}
	})
}

func TestOperatorEnvironment(t *testing.T) {
	t.Run("PWN_OPERATOR inválido falha", func(t *testing.T) {
		t.Setenv(config.OperatorEnv, "auto")
		var stdout, stderr bytes.Buffer
		code := Run([]string{"work", "status"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr.String(), "PWN_OPERATOR inválido: 'auto' (use human ou decider)") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("--operator substitui o ambiente inválido", func(t *testing.T) {
		inTempDir(t)
		t.Setenv(config.OperatorEnv, "auto")
		var stdout, stderr bytes.Buffer
		code := Run([]string{"--operator", "human", "work", "status"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr.String())
		}
		if strings.Contains(stderr.String(), "PWN_OPERATOR inválido") {
			t.Fatalf("stderr = %q, não pode validar o ambiente", stderr.String())
		}
		if !strings.Contains(stdout.String(), "=== [pwn work status] Relatório de Status do Work ===") {
			t.Fatalf("stdout = %q, quer o relatório de status", stdout.String())
		}
	})

	t.Run("espaços são ignorados no ambiente", func(t *testing.T) {
		inTempDir(t)
		t.Setenv(config.OperatorEnv, "  decider  ")
		var stdout, stderr bytes.Buffer
		code := Run([]string{"work", "status"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("código = %d, quer 0 (stderr: %q)", code, stderr.String())
		}
		if strings.Contains(stderr.String(), "PWN_OPERATOR inválido") {
			t.Fatalf("stderr = %q, não pode rejeitar o valor com espaços", stderr.String())
		}
	})
}

func TestSubcommandDispatch(t *testing.T) {
	t.Run("comandos conhecidos chegam aos handlers portados", func(t *testing.T) {
		// Cada linha usa um subcomando sem efeito colateral no diretório
		// temporário. O texto "ainda não portado" é exclusivo do stub.
		tests := []struct {
			name string
			args []string
		}{
			{name: "init", args: []string{"init"}},
			{name: "decider", args: []string{"decider", "show"}},
			{name: "work", args: []string{"work", "sync", "--work", "0001"}},
			{name: "task", args: []string{"task", "capsule"}},
			{name: "verify", args: []string{"verify", "show", "--work", "0001"}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				inTempDir(t)
				isolatedVerifier(t)
				_, stdout, stderr := runCLI(t, test.args...)
				if strings.Contains(stdout, "ainda não portado") || strings.Contains(stderr, "ainda não portado") {
					t.Fatalf("%v: comando ainda no stub", test.args)
				}
			})
		}
	})

	t.Run("subcomando desconhecido mostra o uso", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "work", "nope")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr, "Subcomando desconhecido para 'pwn work': nope") {
			t.Fatalf("stderr = %q", stderr)
		}
		if !strings.Contains(stdout, "Uso:") {
			t.Fatalf("stdout = %q, quer o uso", stdout)
		}
	})

	t.Run("subcomando vazio mostra o uso", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "work")
		if code != 1 {
			t.Fatalf("código = %d, quer 1", code)
		}
		if !strings.Contains(stderr, "(vazio)") {
			t.Fatalf("stderr = %q, quer (vazio)", stderr)
		}
		if !strings.Contains(stdout, "Uso:") {
			t.Fatalf("stdout = %q, quer o uso", stdout)
		}
	})
}

func TestRunContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := RunContext(ctx, []string{"--help"}, &stdout, &stderr)
	if code != 130 {
		t.Fatalf("código = %d, quer 130", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, quer vazio", stdout.String())
	}
	if !strings.Contains(stderr.String(), "interrompida") {
		t.Fatalf("stderr = %q, quer o aviso de interrupção", stderr.String())
	}
}
