package work_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/passoz/pwn/internal/platform/gitx"
)

// repoRoot devolve a raiz do repositório a partir deste arquivo de teste.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller falhou")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// writeFile cria o diretório e grava content.
func writeFile(t *testing.T, root, relative, content string) {
	t.Helper()
	target := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("criar diretório de %s: %v", relative, err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("gravar %s: %v", relative, err)
	}
}

// readFile lê relative a partir de root.
func readFile(t *testing.T, root, relative string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatalf("ler %s: %v", relative, err)
	}
	return string(data)
}

// git executa um comando git no repositório e exige sucesso.
func git(t *testing.T, root string, args ...string) string {
	t.Helper()
	result, err := gitx.New(root).Run(t.Context(), args, gitx.Options{})
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	if !result.OK() {
		t.Fatalf("git %v falhou: %s", args, result.Stderr)
	}
	return string(result.Stdout)
}

// initRepo cria um repositório git com identidade local.
func initRepo(t *testing.T, root string) {
	t.Helper()
	git(t, root, "init", "-q")
	git(t, root, "config", "user.email", "fixture@example.invalid")
	git(t, root, "config", "user.name", "Fixture")
}

// commitAll adiciona tudo e cria um commit.
func commitAll(t *testing.T, root, message string) string {
	t.Helper()
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", message)
	return trimSpace(git(t, root, "rev-parse", "HEAD"))
}

// trimSpace remove os espaços das pontas.
func trimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}

// neutralVerifier aponta a raiz do verificador para um diretório vazio, de modo
// que a aceitação nunca use o verificador real do operador.
func neutralVerifier(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("PWN_VERIFIER_HOME", root)
	return root
}
