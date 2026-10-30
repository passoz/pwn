package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/config"
	"github.com/passoz/pwn/internal/harness/verify"
)

// outcome é o resultado de um handler: código de saída e os dois fluxos.
type outcome struct {
	code   int
	stdout string
	stderr string
}

// env é um repositório Git temporário com verificador isolado. Cada teste tem o
// seu: nada toca o repositório real nem a raiz protegida do operador.
type env struct {
	t        *testing.T
	dir      string
	verifier string
}

// newEnv cria o repositório com um commit vazio e aponta o verificador para um
// diretório temporário. O diretório de trabalho do teste passa a ser o repositório.
func newEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "Teste")
	t.Setenv("GIT_AUTHOR_EMAIL", "teste@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "Teste")
	t.Setenv("GIT_COMMITTER_EMAIL", "teste@example.com")
	t.Setenv(config.OperatorEnv, "")
	verifierRoot := filepath.Join(t.TempDir(), "verifier")
	t.Setenv(verify.HomeEnv, verifierRoot)

	dir := t.TempDir()
	e := &env{t: t, dir: dir, verifier: verifierRoot}
	e.git("init", "-q", dir)
	e.git("commit", "-q", "--allow-empty", "-m", "inicial")
	t.Chdir(dir)
	return e
}

// git executa o git no repositório e falha o teste se o comando falhar.
func (e *env) git(args ...string) string {
	e.t.Helper()
	command := exec.Command("git", args...)
	command.Dir = e.dir
	output, err := command.CombinedOutput()
	if err != nil {
		e.t.Fatalf("git %s: %v (%s)", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

// write grava o arquivo relativo ao repositório.
func (e *env) write(rel, content string) {
	e.t.Helper()
	writeTestFile(e.t, filepath.Join(e.dir, rel), content)
}

// read lê o arquivo relativo ao repositório.
func (e *env) read(rel string) string {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.dir, rel))
	if err != nil {
		e.t.Fatalf("ler %s: %v", rel, err)
	}
	return string(data)
}

// exists informa se o caminho relativo existe no repositório.
func (e *env) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(e.dir, rel))
	return err == nil
}

// commit adiciona tudo e cria um commit.
func (e *env) commit(message string) {
	e.t.Helper()
	e.git("add", "-A")
	e.git("commit", "-q", "-m", message)
}

// call executa um handler com a raiz no repositório.
func (e *env) call(handler func(*Runner) int) outcome {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	runner := &Runner{Stdout: &stdout, Stderr: &stderr, RootDir: e.dir}
	code := handler(runner)
	return outcome{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func (e *env) work(sub string, args ...string) outcome {
	e.t.Helper()
	return e.call(func(r *Runner) int { return r.Work(sub, args) })
}

func (e *env) verify(sub string, args ...string) outcome {
	e.t.Helper()
	return e.call(func(r *Runner) int { return r.Verify(sub, args) })
}

func (e *env) queue(sub string, args ...string) outcome {
	e.t.Helper()
	return e.call(func(r *Runner) int { return r.Queue(sub, args) })
}

func (e *env) metrics(sub string, args ...string) outcome {
	e.t.Helper()
	return e.call(func(r *Runner) int { return r.Metrics(sub, args) })
}

func (e *env) target(sub string, args ...string) outcome {
	e.t.Helper()
	return e.call(func(r *Runner) int { return r.Target(sub, args) })
}

func (e *env) init(args ...string) outcome {
	e.t.Helper()
	return e.call(func(r *Runner) int { return r.Init(args) })
}

// mustOK falha o teste se o handler não saiu com 0.
func (o outcome) mustOK(t *testing.T, what string) outcome {
	t.Helper()
	if o.code != 0 {
		t.Fatalf("%s: código = %d, quer 0\nstdout: %s\nstderr: %s", what, o.code, o.stdout, o.stderr)
	}
	return o
}

// expect confere o código e os trechos de cada fluxo.
func (o outcome) expect(t *testing.T, code int, stdout []string, stderr []string) {
	t.Helper()
	if o.code != code {
		t.Fatalf("código = %d, quer %d\nstdout: %s\nstderr: %s", o.code, code, o.stdout, o.stderr)
	}
	for _, want := range stdout {
		if !strings.Contains(o.stdout, want) {
			t.Fatalf("stdout sem %q:\n%s\n(stderr: %s)", want, o.stdout, o.stderr)
		}
	}
	for _, want := range stderr {
		if !strings.Contains(o.stderr, want) {
			t.Fatalf("stderr sem %q:\n%s\n(stdout: %s)", want, o.stderr, o.stdout)
		}
	}
}

// scaffold cria o Work completo e o deixa pronto para execução com `sh`: os
// comandos do plano e do contrato trocam `bun` por scripts de shell, que o
// teste controla.
func (e *env) scaffold(workID string) {
	e.t.Helper()
	e.work("scaffold", "--title", "Add widget", "--work", workID).mustOK(e.t, "scaffold")
	for _, rel := range []string{
		".todo/" + workID + "-tasks.md",
		".pwn/work/" + workID + "/plan.json",
		".pwn/work/" + workID + "/CTR-001.json",
	} {
		text := e.read(rel)
		text = strings.ReplaceAll(text, "bun test tests/add-widget.test.ts", "sh tests/add-widget.test.ts")
		text = strings.ReplaceAll(text, "bun run check", "sh tests/check.sh")
		text = strings.ReplaceAll(text, "bun test", "sh tests/reg.sh")
		e.write(rel, text)
	}
	e.mutateJSON(".pwn/work/"+workID+"/CTR-001.json", func(document map[string]any) {
		document["acceptance_contract"].(map[string]any)["commands"] = []any{
			"sh tests/add-widget.test.ts", "sh tests/reg.sh", "sh tests/check.sh",
		}
	})
	e.write("tests/add-widget.test.ts", "test -f src/add-widget.ts\n")
	e.write("tests/check.sh", "echo checado\n")
	e.write("tests/reg.sh", "true\n")
	e.commit("scaffold " + workID)
}

// fakeBwrap grava um bwrap de teste: ignora o isolamento e executa o comando
// depois de `--` no diretório de `--chdir`. Assim o verificador roda sem
// depender de bubblewrap na máquina.
func fakeBwrap(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bwrap")
	script := "#!/bin/sh\ndir=.\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --chdir) dir=$2; shift 2;;\n    --) shift; break;;\n    *) shift;;\n  esac\ndone\ncd \"$dir\" && exec \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("escrever bwrap de teste: %v", err)
	}
	return path
}

// configureVerifier inicializa a raiz protegida e troca o runtime e o bwrap
// pelos caminhos dados. bwrap vazio remove o isolamento da configuração.
func (e *env) configureVerifier(bwrap string) {
	e.t.Helper()
	if _, err := verify.InitializeVerifierHome(e.verifier); err != nil {
		e.t.Fatalf("inicializar verificador: %v", err)
	}
	file := verify.ConfigFile(e.verifier)
	data, err := os.ReadFile(file)
	if err != nil {
		e.t.Fatalf("ler config do verificador: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		e.t.Fatalf("decodificar config do verificador: %v", err)
	}
	document["runtime"] = map[string]any{"bun": "/bin/sh"}
	isolation := document["isolation"].(map[string]any)
	if bwrap == "" {
		isolation["bwrap"] = nil
	} else {
		isolation["bwrap"] = bwrap
	}
	updated, err := json.Marshal(document)
	if err != nil {
		e.t.Fatalf("codificar config do verificador: %v", err)
	}
	if err := os.WriteFile(file, updated, 0o600); err != nil {
		e.t.Fatalf("gravar config do verificador: %v", err)
	}
}

// freezeAndApprove congela o teste de aceitação da task 1.1, commita e aprova.
func (e *env) freezeAndApprove(workID string) {
	e.t.Helper()
	e.work("contract", "--work", workID, "--task", "1.1", "--freeze-tests", "tests/add-widget.test.ts").mustOK(e.t, "freeze")
	e.commit("congela testes " + workID)
	e.verify("approve", "--work", workID, "--task", "1.1", "--by", "operador").mustOK(e.t, "approve")
}

// mutateJSON lê o JSON relativo ao repositório, aplica a mudança e regrava.
func (e *env) mutateJSON(rel string, mutate func(document map[string]any)) {
	e.t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(e.read(rel)), &document); err != nil {
		e.t.Fatalf("decodificar %s: %v", rel, err)
	}
	mutate(document)
	updated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		e.t.Fatalf("codificar %s: %v", rel, err)
	}
	e.write(rel, string(updated)+"\n")
}
