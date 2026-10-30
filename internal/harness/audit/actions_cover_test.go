package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/cryptox"
)

// step executa uma fase e exige o código de saída esperado.
func step(t *testing.T, dir string, want int, args ...string) (string, string) {
	t.Helper()
	code, stdout, stderr := runAudit(t, dir, args...)
	mustCode(t, want, args, code, stdout, stderr)
	return stdout, stderr
}

func expectIn(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("a saída deveria conter %q:\n%s", needle, haystack)
	}
}

// newFlow cria o fixture padrão da task 1.1 com o baseline já capturado.
func newFlow(t *testing.T) string {
	t.Helper()
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.1", title: "Implement value", implementation: "app.value", test: "app.test.sh", assertion: "VALUE-NEW",
	}})
	commit(t, dir, "baseline")
	step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
	return dir
}

func redStep(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, dir, "app.test.sh", testScript("app.value", "VALUE-NEW"))
	step(t, dir, ExitOK, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
}

func greenStep(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, dir, "app.value", "new\n")
	step(t, dir, ExitOK, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
}

// newGreenFlow leva a task 1.1 até o GREEN.
func newGreenFlow(t *testing.T) string {
	t.Helper()
	dir := newFlow(t)
	redStep(t, dir)
	greenStep(t, dir)
	return dir
}

func TestParseArgs(t *testing.T) {
	errorCases := []struct {
		name string
		argv []string
		want string
	}{
		{"sem argumentos", nil, "unknown or missing action"},
		{"ação desconhecida", []string{"candidate", "--work", "0001"}, "unknown or missing action"},
		{"sem --work", []string{"baseline"}, "missing required option: --work"},
		{"sem --task", []string{"baseline", "--work", "0001"}, "missing required option: --task"},
		{"--work sem valor", []string{"baseline", "--work"}, "missing value for --work"},
		{"--work seguido de flag", []string{"baseline", "--work", "--task", "1.1"}, "missing value for --work"},
		{"--work vazio", []string{"baseline", "--work", "", "--task", "1.1"}, "missing value for --work"},
		{"Work inválido", []string{"baseline", "--work", "12", "--task", "1.1"}, "invalid Work ID: 12"},
		{"baseline com argumento solto", []string{"baseline", "--work", "0001", "--task", "1.1", "--bogus"}, "unexpected arguments: --bogus"},
		{"red sem --expect", []string{"red", "--work", "0001", "--task", "1.1", "--", "sh"}, "missing required option: --expect"},
		{"red sem comando", []string{"red", "--work", "0001", "--task", "1.1", "--expect", "x"}, "RED command is required after --"},
		{"red com argumento solto", []string{"red", "--work", "0001", "--task", "1.1", "--expect", "x", "--extra", "--", "sh"}, "unexpected arguments: --extra"},
		{"red --expect sem valor", []string{"red", "--work", "0001", "--task", "1.1", "--expect"}, "missing value for --expect"},
		{"green sem comando", []string{"green", "--work", "0001", "--task", "1.1"}, "GREEN command is required after --"},
		{"green com argumento solto", []string{"green", "--work", "0001", "--task", "1.1", "--extra", "--", "sh"}, "unexpected arguments: --extra"},
		{"check sem --name", []string{"check", "--work", "0001", "--task", "1.1", "--", "sh"}, "missing required option: --name"},
		{"check com argumento solto", []string{"check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--extra"}, "unexpected arguments: --extra"},
		{"check --name sem valor", []string{"check", "--work", "0001", "--task", "1.1", "--name"}, "missing value for --name"},
		{"verify sem comando", []string{"verify", "--work", "0001", "--task", "1.1"}, "VERIFY command is required after --"},
		{"verify com argumento solto", []string{"verify", "--work", "0001", "--task", "1.1", "--bogus", "--", "sh"}, "unexpected arguments: --bogus"},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseArgs(tc.argv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseArgs(%v) = %+v, %v; quer erro com %q", tc.argv, parsed, err, tc.want)
			}
		})
	}

	t.Run("baseline com listas", func(t *testing.T) {
		parsed, err := parseArgs([]string{"baseline", "--work", "0001", "--task", "1.1", "--implementation", "a.go", "b.go", "--tests", "a_test.go"})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.action != "baseline" || parsed.work != "0001" || parsed.task != "1.1" {
			t.Errorf("cabeçalho = %+v", parsed)
		}
		if !reflect.DeepEqual(parsed.implementation, []string{"a.go", "b.go"}) || !reflect.DeepEqual(parsed.tests, []string{"a_test.go"}) {
			t.Errorf("listas = %v %v", parsed.implementation, parsed.tests)
		}
		if parsed.paths.logDir != filepath.Join(".todo", "evidence", "0001") || parsed.paths.stateDir != filepath.Join(".todo", "evidence", "0001", "state") {
			t.Errorf("caminhos = %+v", parsed.paths)
		}
	})

	t.Run("red com flag literal e comando com --", func(t *testing.T) {
		parsed, err := parseArgs([]string{"red", "--work", "legacy", "--task", "2", "--expect-literal", "--expect", "texto livre", "--", "sh", "-c", "x", "--", "y"})
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.expectLiteral || !parsed.expectSet || parsed.expect != "texto livre" {
			t.Errorf("expect = %+v", parsed)
		}
		if !reflect.DeepEqual(parsed.command, []string{"sh", "-c", "x", "--", "y"}) {
			t.Errorf("comando = %v", parsed.command)
		}
		if parsed.paths.logDir != filepath.Join(".todo", "evidence") || parsed.paths.stateDir != filepath.Join(".todo", "evidence", "state") {
			t.Errorf("caminhos do legacy = %+v", parsed.paths)
		}
	})

	t.Run("green com e sem expect", func(t *testing.T) {
		with, err := parseArgs([]string{"green", "--work", "0001", "--task", "1.1", "--expect", "ok", "--", "sh"})
		if err != nil || !with.expectSet || with.expect != "ok" {
			t.Fatalf("com expect = %+v, %v", with, err)
		}
		without, err := parseArgs([]string{"green", "--work", "0001", "--task", "1.1", "--", "sh"})
		if err != nil || without.expectSet {
			t.Fatalf("sem expect = %+v, %v", without, err)
		}
	})

	t.Run("check completo", func(t *testing.T) {
		parsed, err := parseArgs([]string{"check", "--work", "0001", "--task", "1.1", "--name", "AC-2", "--expect-literal", "--expect", "ok", "--", "sh"})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.name != "AC-2" || !parsed.expectLiteral || !parsed.expectSet || parsed.expect != "ok" {
			t.Errorf("check = %+v", parsed)
		}
	})
}

func TestMainWithoutArgumentsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main(nil, &stdout, &stderr)
	if code != ExitViolation || stdout.Len() != 0 {
		t.Fatalf("código = %d, stdout = %q", code, stdout.String())
	}
	for _, want := range []string{
		"usage: task_evidence.js baseline", "red --work", "green --work", "verify --work", "check --work",
		"FAIL: unknown or missing action",
	} {
		expectIn(t, stderr.String(), want)
	}
}

func TestIncompleteWhenPlanOrTaskIsMissing(t *testing.T) {
	t.Run("plano ausente", func(t *testing.T) {
		dir := newRepo(t)
		_, stderr := step(t, dir, ExitIncomplete, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "INCOMPLETO: faltam 1 evidência(s)")
		expectIn(t, stderr, "plan not found: "+filepath.Join(".todo", "0001-tasks.md"))
	})

	t.Run("task ausente do plano", func(t *testing.T) {
		dir := newFlow(t)
		_, stderr := step(t, dir, ExitIncomplete, "baseline", "--work", "0001", "--task", "9.9")
		expectIn(t, stderr, "task 9.9 no plano")
	})

	t.Run("plano legacy usa .todo/tasks.md", func(t *testing.T) {
		dir := newRepo(t)
		_, stderr := step(t, dir, ExitIncomplete, "baseline", "--work", "legacy", "--task", "1.1")
		expectIn(t, stderr, "plan not found: "+filepath.Join(".todo", "tasks.md"))
	})

	t.Run("fases sem baseline", func(t *testing.T) {
		dir := newRepo(t)
		for _, args := range [][]string{
			{"green", "--work", "0001", "--task", "1.1", "--", "sh"},
			{"verify", "--work", "0001", "--task", "1.1", "--", "sh"},
			{"check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh"},
		} {
			_, stderr := step(t, dir, ExitIncomplete, args...)
			expectIn(t, stderr, "baseline not found for task 1.1; run baseline first")
		}
	})

	t.Run("estado ilegível", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"), "{ quebrado")
		_, stderr := step(t, dir, ExitIncomplete, "green", "--work", "0001", "--task", "1.1", "--", "sh")
		expectIn(t, stderr, "state unreadable for task 1.1")

		if err := os.MkdirAll(filepath.Join(dir, ".todo", "evidence", "0001", "state", "2.1.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, stderr = step(t, dir, ExitIncomplete, "green", "--work", "0001", "--task", "2.1", "--", "sh")
		expectIn(t, stderr, "state unreadable for task 2.1")
	})

	t.Run("estado anterior ao amarramento", func(t *testing.T) {
		dir := newFlow(t)
		path := filepath.Join(dir, ".todo", "evidence", "0001", "state", "1.1.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		old := strings.Replace(string(data), `"state_version": 2`, `"state_version": 1`, 1)
		if old == string(data) {
			t.Fatal("o estado deveria declarar state_version 2")
		}
		writeFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"), old)
		_, stderr := step(t, dir, ExitIncomplete, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "refaça o baseline")
	})
}

func TestBaselineViolations(t *testing.T) {
	t.Run("task sem arquivos declarados", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), `**Contract version:** 3
**Work ID:** 0001

### [ ] [1.1] Sem arquivos

**RED:**
- `+"`sh app.test.sh`"+` — a asserção X falha.

**ACs:**
- [ ] `+"`sh app.test.sh`"+` — a asserção X passa.
`)
		commit(t, dir, "plano")
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "FAIL: 2 violação(ões):")
		expectIn(t, stderr, "não declara **Implementation files:** no plano")
		expectIn(t, stderr, "não declara **Test files:** no plano")
	})

	t.Run("implementação e teste são o mesmo arquivo", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "mesmo.sh", "")
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Sobreposição", implementation: "mesmo.sh", test: "mesmo.sh", assertion: "X"}})
		commit(t, dir, "plano")
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "implementation/test files overlap: mesmo.sh")
	})

	t.Run("sem repositório git", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Sem git", implementation: "app.value", test: "app.test.sh", assertion: "X"}})
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "git repository required to prove implementation removal")
	})

	t.Run("git corrompido", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Git quebrado", implementation: "app.value", test: "app.test.sh", assertion: "X"}})
		if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "git status failed")
	})

	t.Run("repositório sem commit em HEAD", func(t *testing.T) {
		dir := newRepo(t)
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Sem commit", implementation: "app.value", test: "app.test.sh", assertion: "X"}})
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "baseline exige um commit em HEAD")
	})

	t.Run("implementação existe mas não é versionada", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, ".gitignore", "app.value\n")
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Ignorado", implementation: "app.value", test: "app.test.sh", assertion: "X"}})
		commit(t, dir, "plano")
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "arquivo de implementação existe mas não está versionado: app.value")
	})

	t.Run("operador repete os arquivos do plano", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Igual", implementation: "app.value", test: "app.test.sh", assertion: "X"}})
		commit(t, dir, "plano")
		stdout, _ := step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1", "--implementation", "app.value", "--tests", "app.test.sh")
		expectIn(t, stdout, "PASS: baseline captured for 1.1")
	})

	t.Run("implementação nova ainda não existe", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "app.test.sh", "")
		planFor(t, dir, []fixtureTask{{id: "1.1", title: "Novo", implementation: "novo.value", test: "app.test.sh", assertion: "X"}})
		commit(t, dir, "plano")
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
		var state State
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		if entry := state.BaselineImplementation["novo.value"]; entry.Exists || entry.SHA256 != nil {
			t.Errorf("baseline da implementação nova = %+v", entry)
		}
		if state.Contract != nil || len(state.FrozenTests) != 0 {
			t.Errorf("sem plan.json não há contrato: %+v %+v", state.Contract, state.FrozenTests)
		}
	})
}

func TestBaselineContractErrors(t *testing.T) {
	setup := func(t *testing.T, frozen []contract.FrozenTest) string {
		t.Helper()
		dir := newRepo(t)
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		writeFile(t, dir, "acceptance.test.sh", "")
		canonicalPlan(t, dir, "sh app.test.sh", "sh app.test.sh", frozen)
		commit(t, dir, "plano")
		return dir
	}
	contractPath := filepath.Join(".pwn", "work", "0001", "CTR-001.json")

	t.Run("teste congelado declarado como implementação", func(t *testing.T) {
		dir := setup(t, []contract.FrozenTest{{Path: "app.value", SHA256: cryptox.SHA256Hex([]byte("old\n"))}})
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "teste congelado declarado como implementação: app.value")
	})

	t.Run("contrato registrado no estado", func(t *testing.T) {
		dir := setup(t, []contract.FrozenTest{{Path: "acceptance.test.sh", SHA256: cryptox.SHA256Hex(nil)}})
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		var state State
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		if state.Contract == nil || state.Contract.ID != "CTR-001" || len(state.Contract.SHA256) != 64 {
			t.Errorf("contrato = %+v", state.Contract)
		}
		if len(state.FrozenTests) != 1 || state.FrozenTests[0].Path != "acceptance.test.sh" {
			t.Errorf("frozen_tests = %+v", state.FrozenTests)
		}
	})

	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"JSON ilegível", "{ quebrado", "contrato CTR-001 ilegível"},
		{"frozen_tests nulo", `{"acceptance_contract":{"frozen_tests":null}}`, "frozen_tests deve ser uma lista"},
		{"frozen_tests não é lista", `{"acceptance_contract":{"frozen_tests":"x"}}`, "frozen_tests deve ser uma lista"},
		{"entrada sem sha256", `{"acceptance_contract":{"frozen_tests":[{"path":"a.sh"}]}}`, `frozen_tests com entrada inválida ({"path":"a.sh"})`},
		{"sha256 malformado", `{"acceptance_contract":{"frozen_tests":[{"path":"a.sh","sha256":"ABC"}]}}`, "frozen_tests com entrada inválida"},
		{"entrada que não é objeto", `{"acceptance_contract":{"frozen_tests":[7]}}`, "frozen_tests com entrada inválida (7)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setup(t, nil)
			writeFile(t, dir, contractPath, tc.content)
			_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
			expectIn(t, stderr, tc.want)
		})
	}

	t.Run("contrato ausente", func(t *testing.T) {
		dir := setup(t, nil)
		if err := os.Remove(filepath.Join(dir, contractPath)); err != nil {
			t.Fatal(err)
		}
		_, stderr := step(t, dir, ExitViolation, "baseline", "--work", "0001", "--task", "1.1")
		expectIn(t, stderr, "contrato CTR-001 da task 1.1 não encontrado")
	})

	t.Run("contrato sem acceptance_contract", func(t *testing.T) {
		dir := setup(t, nil)
		writeFile(t, dir, contractPath, `{}`)
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
	})
}

func TestLegacyWorkFlow(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, filepath.Join(".todo", "tasks.md"), `**Contract version:** 2

### [ ] [1.1] Legacy task

**Implementation files:** `+"`app.value`"+`

**Test files:** `+"`app.test.sh`"+`

**RED:**
- `+"`sh app.test.sh`"+` — a asserção falha antes da implementação.

**ACs:**
- [ ] `+"`sh app.test.sh`"+` — a asserção passa com a implementação.
`)
	commit(t, dir, "baseline")

	step(t, dir, ExitOK, "baseline", "--work", "legacy", "--task", "1.1")
	statePath := filepath.Join(dir, ".todo", "evidence", "state", "1.1.json")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("o estado do legacy deveria ficar em .todo/evidence/state: %v", err)
	}

	// Contrato v2: um --expect genérico é aceito com aviso.
	writeFile(t, dir, "app.test.sh", testScript("app.value", "fail"))
	stdout, stderr := step(t, dir, ExitOK, "red", "--work", "legacy", "--task", "1.1", "--expect", "fail", "--", "sh", "app.test.sh")
	expectIn(t, stderr, "WARNING: --expect genérico aceito pelo contrato legado v2")
	expectIn(t, stdout, "PASS: RED captured and tests frozen")
	if _, err := os.Stat(filepath.Join(dir, ".todo", "evidence", "1.1-red.log")); err != nil {
		t.Errorf("o log do legacy deveria ficar em .todo/evidence: %v", err)
	}

	writeFile(t, dir, "app.value", "new\n")
	step(t, dir, ExitOK, "green", "--work", "legacy", "--task", "1.1", "--", "sh", "app.test.sh")
}

func TestRedViolations(t *testing.T) {
	t.Run("comando diverge do plano", func(t *testing.T) {
		dir := newFlow(t)
		writeFile(t, dir, "app.test.sh", testScript("app.value", "VALUE-NEW"))
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "gate.sh")
		expectIn(t, stderr, "RED invalid: comando diverge do plano (plano: `sh app.test.sh`; operador: `sh gate.sh`)")
	})

	t.Run("comando passa mas a saída não tem o esperado", func(t *testing.T) {
		dir := newFlow(t)
		writeFile(t, dir, "app.test.sh", "# VALUE-NEW\necho outra-coisa >&2\nexit 1\n")
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		expectIn(t, stderr, `FAIL: RED needs non-zero exit and output containing "VALUE-NEW"; evidence: `)
		log := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-red.log"))
		expectIn(t, log, "VERDICT: FAIL")
		var state State
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		if state.RedTests != nil {
			t.Error("um RED recusado não pode congelar os testes")
		}
	})

	t.Run("exit zero não é RED", func(t *testing.T) {
		dir := newFlow(t)
		writeFile(t, dir, "app.test.sh", "# VALUE-NEW\necho VALUE-NEW\nexit 0\n")
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "FAIL: RED needs non-zero exit")
	})

	t.Run("arquivo de teste vira diretório", func(t *testing.T) {
		dir := newFlow(t)
		if err := os.Remove(filepath.Join(dir, "app.test.sh")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "app.test.sh"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "not a regular file: app.test.sh")
	})

	t.Run("expect literal exigido fora do contrato v3", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), `**Contract version:** 2

### [ ] [1.1] Task

**Implementation files:** `+"`app.value`"+`

**Test files:** `+"`app.test.sh`"+`

**RED:**
- `+"`sh app.test.sh`"+` — a asserção falha antes da implementação.

**ACs:**
- [ ] `+"`sh app.test.sh`"+` — a asserção passa.
`)
		commit(t, dir, "plano")
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
		writeFile(t, dir, "app.test.sh", "echo texto-especifico-no-script-1 >&2\nexit 1\n")
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "texto-que-nao-esta-no-teste", "--expect-literal", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "FAIL: --expect não é literal nos arquivos de teste congelados")
	})

	t.Run("task sem comando RED no plano", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), `**Contract version:** 3

### [ ] [1.1] Sem RED

**Implementation files:** `+"`app.value`"+`

**Test files:** `+"`app.test.sh`"+`

**ACs:**
- [ ] `+"`sh app.test.sh`"+` — a asserção passa.
`)
		commit(t, dir, "plano")
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
		writeFile(t, dir, "app.test.sh", "echo X >&2\nexit 1\n")
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "X-especifico", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "a task 1.1 não declara comando em **RED:** no plano")
	})

	t.Run("plano troca o binário depois do baseline", func(t *testing.T) {
		dir := newFlow(t)
		writeFile(t, dir, "app.test.sh", testScript("app.value", "VALUE-NEW"))
		// O plano dita o comando; trocar o binário no plano exige refazer o baseline.
		rewritten := strings.ReplaceAll(readFile(t, dir, filepath.Join(".todo", "0001-tasks.md")), "sh app.test.sh", "comando-que-nao-existe app.test.sh")
		writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), rewritten)
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "comando-que-nao-existe", "app.test.sh")
		expectIn(t, stderr, "a definição da task 1.1 no plano mudou depois do baseline")
	})
}

func TestPlanAndContractChangesAfterBaseline(t *testing.T) {
	t.Run("definição da task mudou", func(t *testing.T) {
		dir := newFlow(t)
		redStep(t, dir)
		text := readFile(t, dir, filepath.Join(".todo", "0001-tasks.md"))
		writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), strings.Replace(text, "passa.", "passa de outro jeito.", 1))
		_, stderr := step(t, dir, ExitViolation, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "a definição da task 1.1 no plano mudou depois do baseline")
	})

	t.Run("contrato mudou", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		canonicalPlan(t, dir, "sh app.test.sh", "sh app.test.sh", nil)
		commit(t, dir, "plano")
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
		contractPath := filepath.Join(".pwn", "work", "0001", "CTR-001.json")
		writeFile(t, dir, contractPath, readFile(t, dir, contractPath)+"\n")
		writeFile(t, dir, "app.test.sh", testScript("app.value", "CANONICAL-RED-001"))
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "CANONICAL-RED-001", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "o contrato da task 1.1 mudou depois do baseline")
	})

	t.Run("contrato removido depois do baseline", func(t *testing.T) {
		dir := newRepo(t)
		writeFile(t, dir, "app.value", "old\n")
		writeFile(t, dir, "app.test.sh", "")
		canonicalPlan(t, dir, "sh app.test.sh", "sh app.test.sh", nil)
		commit(t, dir, "plano")
		step(t, dir, ExitOK, "baseline", "--work", "0001", "--task", "1.1")
		if err := os.Remove(filepath.Join(dir, ".pwn", "work", "0001", "CTR-001.json")); err != nil {
			t.Fatal(err)
		}
		_, stderr := step(t, dir, ExitViolation, "red", "--work", "0001", "--task", "1.1", "--expect", "CANONICAL-RED-001", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "contrato CTR-001 da task 1.1 não encontrado")
	})
}

func TestGreenViolations(t *testing.T) {
	t.Run("sem evidência de RED", func(t *testing.T) {
		dir := newFlow(t)
		_, stderr := step(t, dir, ExitIncomplete, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "RED (RED evidence not found for task 1.1)")
	})

	t.Run("implementação não mudou", func(t *testing.T) {
		dir := newFlow(t)
		redStep(t, dir)
		_, stderr := step(t, dir, ExitViolation, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "GREEN invalid: no implementation file changed since baseline")
	})

	t.Run("comando passa a falhar", func(t *testing.T) {
		dir := newFlow(t)
		redStep(t, dir)
		writeFile(t, dir, "app.value", "ainda-errado\n")
		_, stderr := step(t, dir, ExitViolation, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "FAIL: GREEN command did not pass expected output; evidence: ")
		expectIn(t, readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-green.log")), "VERDICT: FAIL")
		var state State
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		if state.GreenImplementation != nil {
			t.Error("um GREEN recusado não pode gravar o snapshot")
		}
	})

	t.Run("expect do GREEN fica registrado", func(t *testing.T) {
		dir := newFlow(t)
		writeFile(t, dir, "app.test.sh", "echo marcador-verde\n"+testScript("app.value", "VALUE-NEW"))
		step(t, dir, ExitOK, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		writeFile(t, dir, "app.value", "new\n")
		step(t, dir, ExitOK, "green", "--work", "0001", "--task", "1.1", "--expect", "marcador-verde", "--", "sh", "app.test.sh")
		var state State
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		if state.GreenExpect == nil || *state.GreenExpect != "marcador-verde" {
			t.Errorf("green_expect = %v", state.GreenExpect)
		}
		// O VERIFY herda o expect do GREEN.
		step(t, dir, ExitOK, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	})

	t.Run("mutation check: teste passa sem a implementação", func(t *testing.T) {
		dir := newFlow(t)
		// O primeiro run falha (RED); os seguintes passam, também sem a implementação.
		writeFile(t, dir, "app.test.sh", "if [ ! -f .ja-rodou ]; then touch .ja-rodou; echo VALUE-NEW >&2; exit 1; fi\n")
		step(t, dir, ExitOK, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		writeFile(t, dir, "app.value", "new\n")
		_, stderr := step(t, dir, ExitViolation, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "mutation check failed")
		if got := readFile(t, dir, "app.value"); got != "new\n" {
			t.Errorf("a implementação não foi restaurada: %q", got)
		}
	})
}

func TestVerifyViolations(t *testing.T) {
	t.Run("sem evidência de GREEN", func(t *testing.T) {
		dir := newFlow(t)
		redStep(t, dir)
		_, stderr := step(t, dir, ExitIncomplete, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "GREEN (GREEN evidence not found for task 1.1)")
	})

	t.Run("comando do operador diverge do RED", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "-c", "echo 'oi mundo'")
		expectIn(t, stderr, `verification invalidated: command differs from RED command (estado: 'sh app.test.sh'; operador: 'sh -c echo '"'"'oi mundo'"'"'')`)
	})

	t.Run("implementação removida depois do GREEN", func(t *testing.T) {
		dir := newGreenFlow(t)
		// O VERIFY compara o snapshot do GREEN com a árvore atual antes de rodar.
		writeFile(t, dir, "app.test.sh", testScript("app.value", "VALUE-NEW"))
		if err := os.Remove(filepath.Join(dir, "app.value")); err != nil {
			t.Fatal(err)
		}
		_, stderr := step(t, dir, ExitViolation, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "verification invalidated: implementation changed: app.value")
	})

	t.Run("expect do GREEN some da saída", func(t *testing.T) {
		dir := newFlow(t)
		writeFile(t, dir, "app.test.sh", "if [ -f .mudo ]; then exit 0; fi\necho marcador-verde\n"+testScript("app.value", "VALUE-NEW"))
		step(t, dir, ExitOK, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
		writeFile(t, dir, "app.value", "new\n")
		step(t, dir, ExitOK, "green", "--work", "0001", "--task", "1.1", "--expect", "marcador-verde", "--", "sh", "app.test.sh")
		writeFile(t, dir, ".mudo", "")
		_, stderr := step(t, dir, ExitViolation, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "FAIL: current focused test no longer passes; evidence: ")
		expectIn(t, readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-verify.log")), "VERDICT: FAIL")
	})

	t.Run("RED sem comando registrado", func(t *testing.T) {
		dir := newGreenFlow(t)
		path := filepath.Join(".todo", "evidence", "0001", "state", "1.1.json")
		var raw map[string]any
		if err := json.Unmarshal([]byte(readFile(t, dir, path)), &raw); err != nil {
			t.Fatal(err)
		}
		raw["red_command"] = []string{}
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, path, string(data))
		_, stderr := step(t, dir, ExitIncomplete, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "RED (comando RED não registrado no estado da task 1.1)")
	})
}

func TestCheckViolations(t *testing.T) {
	t.Run("nome inválido", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "AC-0", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "invalid audit check name: AC-0")
	})

	t.Run("sem comando", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1")
		expectIn(t, stderr, "audit check command is required after --")
	})

	t.Run("--expect-literal exige --expect", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--expect-literal", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "--expect-literal requires --expect")
	})

	t.Run("antes do GREEN", func(t *testing.T) {
		dir := newFlow(t)
		_, stderr := step(t, dir, ExitIncomplete, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "GREEN (o check AC-1 roda sobre o snapshot do GREEN da task 1.1)")
	})

	t.Run("arquivos mudaram depois do GREEN", func(t *testing.T) {
		dir := newGreenFlow(t)
		writeFile(t, dir, "app.value", "mudou-depois\n")
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "check invalidated: arquivos mudaram depois do GREEN (app.value); refaça o GREEN")
	})

	t.Run("AC inexistente no plano", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "AC-7", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "AC-7 não existe no plano")
	})

	t.Run("VISUAL não exigido pelo plano", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "VISUAL", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "a task 1.1 não exige VISUAL")
	})

	t.Run("comando diverge do plano", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "REGRESSION: comando diverge do plano (plano: `sh gate.sh`; operador: `sh app.test.sh`)")
	})

	t.Run("REGRESSION que falha grava o veredito FAIL", func(t *testing.T) {
		dir := newGreenFlow(t)
		writeFile(t, dir, "gate.sh", "echo gate-quebrado >&2\nexit 1\n")
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "gate.sh")
		expectIn(t, stderr, "FAIL: REGRESSION did not produce the expected successful result; evidence: ")
		var state State
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		record, ok := state.AuditChecks["REGRESSION"]
		if !ok || record.Verdict != "FAIL" || record.ExitCode != 1 || record.Vacuity != nil {
			t.Fatalf("registro = %+v (ok = %v)", record, ok)
		}
		if record.LogSHA256 == nil || len(*record.LogSHA256) != 64 || record.GreenSHA256 == "" {
			t.Errorf("registro sem digests: %+v", record)
		}
	})

	t.Run("expect e repetição mantêm a ordem dos checks", func(t *testing.T) {
		dir := newGreenFlow(t)
		step(t, dir, ExitOK, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "gate.sh")
		// REGRESSION roda `sh gate.sh`, que chama o teste focado e não imprime o expect.
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--expect", "texto-ausente", "--", "sh", "gate.sh")
		expectIn(t, stderr, "FAIL: REGRESSION did not produce the expected successful result")
		step(t, dir, ExitOK, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")

		var state State
		data := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			t.Fatal(err)
		}
		if len(state.AuditChecks) != 2 {
			t.Fatalf("checks = %v", state.AuditChecks)
		}
		if state.AuditChecks["REGRESSION"].Verdict != "FAIL" || state.AuditChecks["REGRESSION"].Expect == nil || *state.AuditChecks["REGRESSION"].Expect != "texto-ausente" {
			t.Errorf("REGRESSION = %+v", state.AuditChecks["REGRESSION"])
		}
		ac := state.AuditChecks["AC-1"]
		if ac.Verdict != "PASS" || ac.Vacuity == nil || ac.Vacuity.Verdict != "PASS" || ac.Vacuity.ExitCode == 0 {
			t.Errorf("AC-1 = %+v", ac)
		}
		reloaded, reason := tryLoadState(workPaths{logDir: filepath.Join(dir, ".todo", "evidence", "0001"), stateDir: filepath.Join(dir, ".todo", "evidence", "0001", "state")}, "1.1")
		if reloaded == nil {
			t.Fatalf("estado: %s", reason)
		}
		if !reflect.DeepEqual(reloaded.AuditCheckOrder, []string{"REGRESSION", "AC-1"}) {
			t.Errorf("ordem dos checks = %v", reloaded.AuditCheckOrder)
		}
	})

	t.Run("AC com expect ausente da saída", func(t *testing.T) {
		dir := newGreenFlow(t)
		_, stderr := step(t, dir, ExitViolation, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--expect", "texto-ausente", "--", "sh", "app.test.sh")
		expectIn(t, stderr, "FAIL: AC-1 did not produce the expected successful result")
		if strings.Contains(readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-ac-1.log")), "MUTATION_EXIT") {
			t.Error("só um AC que passa roda o mutation check")
		}
	})
}

func TestEvidenceChainSurvivesCorruptedLine(t *testing.T) {
	dir := t.TempDir()
	paths := workPaths{logDir: filepath.Join(dir, "logs"), stateDir: filepath.Join(dir, "logs", "state")}
	first, err := appendEvidenceChain(paths, "1.1", "RED", []string{"sh", "x"}, 1, "saída")
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || first.PrevHash != genesisHash || len(first.EntryHash) != 64 {
		t.Fatalf("primeira entrada = %+v", first)
	}
	chain := filepath.Join(paths.logDir, "1.1-chain.jsonl")
	file, err := os.OpenFile(chain, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("linha corrompida\n\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := appendEvidenceChain(paths, "1.1", "GREEN", []string{"sh", "x"}, 0, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != 2 || second.PrevHash != first.EntryHash {
		t.Errorf("a linha corrompida não pode reiniciar a cadeia: %+v", second)
	}
	if first.EntryHash == second.EntryHash {
		t.Error("entradas distintas têm hashes distintos")
	}
}

func TestWriteLogErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "arquivo")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := workPaths{logDir: filepath.Join(blocker, "logs"), stateDir: filepath.Join(blocker, "logs", "state")}
	if _, err := writeLog(paths, "1.1", "RED", []string{"sh"}, 1, "x", "FAIL", ""); err == nil {
		t.Error("writeLog sob um arquivo deveria falhar")
	}
	if _, err := appendEvidenceChain(paths, "1.1", "RED", []string{"sh"}, 1, "x"); err == nil {
		t.Error("appendEvidenceChain sob um arquivo deveria falhar")
	}

	// O log do check é um diretório: a escrita atômica do log falha.
	good := workPaths{logDir: filepath.Join(dir, "ok"), stateDir: filepath.Join(dir, "ok", "state")}
	if err := os.MkdirAll(filepath.Join(good.logDir, "1.1-red.log", "ocupado"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := writeLog(good, "1.1", "RED", []string{"sh"}, 1, "x", "FAIL", ""); err == nil {
		t.Error("log bloqueado por diretório deveria falhar")
	}
}

func TestWithoutImplementationRestoresFiles(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "src/outro.value", "outro-antigo\n")
	commit(t, dir, "baseline")
	head := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	t.Chdir(dir)

	files := []string{"app.value", "src/outro.value", "novo.value"}
	baseline, err := snapshot(files)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{BaselineCommit: head, ImplementationFiles: files, BaselineImplementation: baseline}

	writeFile(t, dir, "app.value", "new\n")
	if err := os.Chmod(filepath.Join(dir, "app.value"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "novo.value", "criado\n")
	if err := os.Remove(filepath.Join(dir, "src", "outro.value")); err != nil {
		t.Fatal(err)
	}

	var seen map[string]string
	got, err := withoutImplementation(state, func() (string, error) {
		seen = map[string]string{}
		for _, name := range files {
			data, readErr := os.ReadFile(name)
			if readErr != nil {
				seen[name] = "<ausente>"
				continue
			}
			seen[name] = string(data)
		}
		return "resultado", nil
	})
	if err != nil || got != "resultado" {
		t.Fatalf("resultado = %q, erro = %v", got, err)
	}
	want := map[string]string{"app.value": "old\n", "src/outro.value": "outro-antigo\n", "novo.value": "<ausente>"}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("durante o mutation check = %v, quer %v", seen, want)
	}
	if readFile(t, dir, "app.value") != "new\n" || readFile(t, dir, "novo.value") != "criado\n" {
		t.Error("os arquivos atuais não foram restaurados")
	}
	if info, err := os.Stat(filepath.Join(dir, "app.value")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("modo restaurado = %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "src", "outro.value")); !os.IsNotExist(err) {
		t.Errorf("arquivo que não existia antes deve continuar ausente: %v", err)
	}

	t.Run("erro da função propaga e restaura", func(t *testing.T) {
		_, err := withoutImplementation(state, func() (int, error) {
			return 0, os.ErrInvalid
		})
		if err != os.ErrInvalid {
			t.Errorf("erro = %v", err)
		}
		if readFile(t, dir, "app.value") != "new\n" {
			t.Error("a implementação não foi restaurada depois do erro")
		}
	})

	t.Run("sem baseline_commit", func(t *testing.T) {
		_, err := withoutImplementation(&State{ImplementationFiles: files}, func() (int, error) { return 1, nil })
		if err == nil || !strings.Contains(err.Error(), "exige baseline_commit") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("arquivo não versionado no baseline", func(t *testing.T) {
		missing := Snapshot{"fantasma.value": FileDigest{Exists: true, SHA256: new("abc")}}
		_, err := withoutImplementation(&State{BaselineCommit: head, ImplementationFiles: []string{"fantasma.value"}, BaselineImplementation: missing}, func() (int, error) { return 1, nil })
		if err == nil || !strings.Contains(err.Error(), "fantasma.value não está versionado em "+head[:12]) {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("conteúdo do commit diverge do snapshot", func(t *testing.T) {
		diverging := Snapshot{"app.value": FileDigest{Exists: true, SHA256: new(strings.Repeat("0", 64))}}
		_, err := withoutImplementation(&State{BaselineCommit: head, ImplementationFiles: []string{"app.value"}, BaselineImplementation: diverging}, func() (int, error) { return 1, nil })
		if err == nil || !strings.Contains(err.Error(), "não corresponde ao snapshot do baseline") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("snapshot sem hash", func(t *testing.T) {
		noHash := Snapshot{"app.value": FileDigest{Exists: true}}
		_, err := withoutImplementation(&State{BaselineCommit: head, ImplementationFiles: []string{"app.value"}, BaselineImplementation: noHash}, func() (int, error) { return 1, nil })
		if err == nil || !strings.Contains(err.Error(), "não corresponde ao snapshot do baseline") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("falha ao restaurar é perda de dados sinalizada", func(t *testing.T) {
		result, err := withoutImplementation(state, func() (string, error) {
			// A função deixa um diretório onde havia o arquivo: restaurar falha.
			if removeErr := os.Remove("app.value"); removeErr != nil {
				return "", removeErr
			}
			if mkErr := os.Mkdir("app.value", 0o755); mkErr != nil {
				return "", mkErr
			}
			return "não deve vazar", nil
		})
		if err == nil || !strings.Contains(err.Error(), "DATA SAFETY: failed to restore implementation after mutation check: app.value") {
			t.Errorf("erro = %v", err)
		}
		if result != "" {
			t.Errorf("o resultado deve ser descartado quando a restauração falha: %q", result)
		}
	})
}

func TestRestoreFilesFailures(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "arquivo")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(dir, "cheio")
	if err := os.MkdirAll(filepath.Join(occupied, "filho"), 0o755); err != nil {
		t.Fatal(err)
	}
	failures := restoreFiles([]savedFile{
		{path: filepath.Join(blocker, "sub", "x"), exists: true, content: []byte("c"), mode: 0o644},
		{path: occupied},
		{path: filepath.Join(dir, "ausente")},
	})
	if len(failures) != 2 {
		t.Fatalf("falhas = %v", failures)
	}
	expectIn(t, failures[0], filepath.Join(blocker, "sub", "x"))
	expectIn(t, failures[1], occupied)
	if joined := joinFailures(failures); !strings.Contains(joined, "; ") {
		t.Errorf("joinFailures = %q", joined)
	}
}

func TestGitPathIsRelativeToWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	relative, err := gitPath(filepath.Join("src", "..", "src", "a.go"))
	if err != nil || relative != "src/a.go" {
		t.Errorf("gitPath = %q, %v", relative, err)
	}
	absolute, err := gitPath(filepath.Join(dir, "b", "c.go"))
	if err != nil || absolute != "b/c.go" {
		t.Errorf("gitPath absoluto = %q, %v", absolute, err)
	}
}

func TestRunAndSanitize(t *testing.T) {
	t.Run("comando vazio", func(t *testing.T) {
		if _, err := run(nil); err == nil || !strings.Contains(err.Error(), "comando vazio") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("binário inexistente", func(t *testing.T) {
		if _, err := run([]string{"binario-que-nao-existe-xyz"}); err == nil {
			t.Error("binário inexistente deveria falhar na execução")
		}
	})

	t.Run("saída e código de saída", func(t *testing.T) {
		result, err := run([]string{"sh", "-c", "echo fora; echo erro >&2; exit 7"})
		if err != nil || result.exitCode != 7 || result.output != "fora\nerro\n" {
			t.Errorf("resultado = %+v, %v", result, err)
		}
	})

	t.Run("processo morto por sinal vira exit 1", func(t *testing.T) {
		result, err := run([]string{"sh", "-c", "kill -9 $$"})
		if err != nil || result.exitCode != 1 {
			t.Errorf("resultado = %+v, %v", result, err)
		}
	})

	t.Run("credenciais são redigidas no resultado", func(t *testing.T) {
		result, err := run([]string{"sh", "-c", "echo 'Authorization: Bearer abc'; echo 'apikey=semdoispontos'; echo normal"})
		if err != nil {
			t.Fatal(err)
		}
		want := "Authorization: " + redacted + "\nsensitive: " + redacted + "\nnormal\n"
		if result.output != want {
			t.Errorf("saída = %q, quer %q", result.output, want)
		}
	})

	t.Run("ambiente sem a chave do verificador", func(t *testing.T) {
		t.Setenv("PWN_VERIFIER_KEY", "segredo")
		t.Setenv("PWN_OUTRA_VARIAVEL", "mantida")
		for _, entry := range childEnv() {
			if strings.HasPrefix(entry, "PWN_VERIFIER_KEY=") {
				t.Errorf("a chave do verificador vazou para o filho: %s", entry)
			}
		}
		found := false
		for _, entry := range childEnv() {
			if entry == "PWN_OUTRA_VARIAVEL=mantida" {
				found = true
			}
		}
		if !found {
			t.Error("o ambiente comum deve ser herdado")
		}
	})
}

func TestToolchainErrorDetection(t *testing.T) {
	cases := []struct {
		name   string
		output string
		expect string
		want   bool
	}{
		{"asserção que cita o texto", "FAIL: expected NEW\nerror: could not compile", "expected new", false},
		{"só erro de ferramenta", "package x is not in std\nexit 1", "package x", true},
		{"nenhuma linha de ferramenta", "assertion failed: VALUE", "value", false},
		{"erro de ferramenta sem o texto esperado", "build failed", "outro", true},
		{"make", "make: *** [all] Error 2", "all", true},
		{"typescript", "src/a.ts: error TS2304: Cannot find name", "ts2304", true},
	}
	for _, tc := range cases {
		if got := IsToolchainError(tc.output, tc.expect); got != tc.want {
			t.Errorf("%s: IsToolchainError = %v, quer %v", tc.name, got, tc.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"sh":             "sh",
		"a/b-c.d:e=1":    "a/b-c.d:e=1",
		"com espaço":     "'com espaço'",
		"it's":           `'it'"'"'s'`,
		"":               "''",
		"$(rm -rf /)":    "'$(rm -rf /)'",
		"a;b":            "'a;b'",
		"--flag=valor x": "'--flag=valor x'",
	}
	for input, want := range cases {
		if got := shellQuote(input); got != want {
			t.Errorf("shellQuote(%q) = %q, quer %q", input, got, want)
		}
		// O shell reconstrói o token original.
		output, err := exec.Command("sh", "-c", "printf %s "+shellQuote(input)).Output()
		if err != nil || string(output) != input {
			t.Errorf("sh reconstruiu %q como %q (%v)", input, output, err)
		}
	}
}

func TestHelpersAndStateUtilities(t *testing.T) {
	if got := uniqueSorted([]string{"b", "a", "b", "c", "a"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("uniqueSorted = %v", got)
	}
	if got := shortHash("0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("shortHash longo = %q", got)
	}
	if got := shortHash("curto"); got != "curto" {
		t.Errorf("shortHash curto = %q", got)
	}
	if got := jsonQuote("a \"b\"\n"); got != `"a \"b\"\n"` {
		t.Errorf("jsonQuote = %s", got)
	}
	if got := joinOrDash(nil); got != "—" {
		t.Errorf("joinOrDash(nil) = %q", got)
	}
	if got := joinOrDash([]string{"a", "b"}); got != "a, b" {
		t.Errorf("joinOrDash = %q", got)
	}
	if !contains([]string{"a", "b"}, "b") || contains([]string{"a"}, "z") {
		t.Error("contains")
	}
	if !sameSet([]string{"a", "b", "a"}, []string{"b", "a"}) || sameSet([]string{"a"}, []string{"a", "b"}) || sameSet([]string{"a", "c"}, []string{"a", "b"}) {
		t.Error("sameSet")
	}
	if nonNilStrings(nil) == nil || nonNilFrozen(nil) == nil {
		t.Error("as listas nulas devem virar listas vazias")
	}
	if got := contractVersionOf("sem versão"); got != 1 {
		t.Errorf("plano sem versão = %d, quer 1", got)
	}
	if got := contractVersionOf("x\n**Contract version:** 12\n"); got != 12 {
		t.Errorf("versão = %d, quer 12", got)
	}
	if got := compactJSON([]byte(`{ "a" : 1 }`)); got != `{"a":1}` {
		t.Errorf("compactJSON = %q", got)
	}
	if got := compactJSON([]byte(`{ quebrado`)); got != `{ quebrado` {
		t.Errorf("compactJSON de entrada inválida = %q", got)
	}
	err := &incompleteError{items: []string{"a", "b"}}
	if err.Error() != "a; b" {
		t.Errorf("incompleteError = %q", err.Error())
	}
	if planPathFor("legacy") != filepath.Join(".todo", "tasks.md") || planPathFor("0007") != filepath.Join(".todo", "0007-tasks.md") {
		t.Errorf("planPathFor = %q %q", planPathFor("legacy"), planPathFor("0007"))
	}

	one, two := "1", "2"
	if len(changed(Snapshot{"a": {Exists: true, SHA256: &one}}, Snapshot{"a": {Exists: true, SHA256: &one}})) != 0 {
		t.Error("digests iguais não mudaram")
	}
	if got := changed(Snapshot{"a": {Exists: true, SHA256: &one}, "b": {}}, Snapshot{"a": {Exists: true, SHA256: &two}, "c": {}}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("changed = %v", got)
	}
	if !sameDigest(FileDigest{}, FileDigest{}) || sameDigest(FileDigest{Exists: true, SHA256: &one}, FileDigest{Exists: true}) || sameDigest(FileDigest{Exists: true}, FileDigest{}) {
		t.Error("sameDigest")
	}

	state := &State{GreenImplementation: Snapshot{"a": {Exists: true, SHA256: &one}}, GreenTests: Snapshot{}}
	first := greenDigest(state)
	if len(first) != 64 || first != greenDigest(state) {
		t.Errorf("greenDigest = %q", first)
	}
	state.GreenTests = Snapshot{"t": {Exists: true, SHA256: &two}}
	if greenDigest(state) == first {
		t.Error("o digest deve mudar com o snapshot")
	}
}

func TestConfigureWorkAndDigest(t *testing.T) {
	if _, err := configureWork("abc"); err == nil || !strings.Contains(err.Error(), "invalid Work ID: abc") {
		t.Errorf("erro = %v", err)
	}
	if _, err := configureWork("00001"); err == nil {
		t.Error("cinco dígitos não são um Work válido")
	}
	paths, err := configureWork("0042")
	if err != nil || paths.logDir != filepath.Join(".todo", "evidence", "0042") {
		t.Errorf("paths = %+v, %v", paths, err)
	}

	dir := t.TempDir()
	missing, err := digest(filepath.Join(dir, "ausente"))
	if err != nil || missing.Exists || missing.SHA256 != nil {
		t.Errorf("digest ausente = %+v, %v", missing, err)
	}
	if _, err := digest(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("digest de diretório: erro = %v", err)
	}
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	present, err := digest(file)
	if err != nil || !present.Exists || present.SHA256 == nil || *present.SHA256 != cryptox.SHA256Hex([]byte("abc")) {
		t.Errorf("digest = %+v, %v", present, err)
	}
	if _, err := snapshot([]string{file, dir}); err == nil {
		t.Error("snapshot com diretório deveria falhar")
	}
	if _, err := snapshotChanges(Snapshot{}, []string{dir}); err == nil {
		t.Error("snapshotChanges com diretório deveria falhar")
	}
}

func TestFrozenTestViolations(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("congelado.sh", []byte("conteúdo"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := cryptox.SHA256Hex([]byte("conteúdo"))
	violations, err := frozenTestViolations([]FrozenTest{
		{Path: "congelado.sh", SHA256: good},
		{Path: "congelado.sh", SHA256: strings.Repeat("0", 64)},
		{Path: "ausente.sh", SHA256: good},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"teste de aceitação congelado alterado ou ausente: congelado.sh",
		"teste de aceitação congelado alterado ou ausente: ausente.sh",
	}
	if !reflect.DeepEqual(violations, want) {
		t.Errorf("violações = %v", violations)
	}
	if err := os.Mkdir("pasta", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := frozenTestViolations([]FrozenTest{{Path: "pasta", SHA256: good}}); err == nil {
		t.Error("um teste congelado que é diretório deveria falhar")
	}
}

func TestPlanDrift(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if drift, err := planDrift("legacy", "qualquer"); err != nil || drift != "" {
		t.Errorf("legacy = %q, %v", drift, err)
	}
	if drift, err := planDrift("0001", "qualquer"); err != nil || drift != "" {
		t.Errorf("sem plan.json = %q, %v", drift, err)
	}
	if err := os.MkdirAll(filepath.Join(".pwn", "work", "0001"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(".pwn", "work", "0001", "plan.json"), []byte("{ quebrado"), 0o644); err != nil {
		t.Fatal(err)
	}
	drift, err := planDrift("0001", "qualquer")
	if err != nil || !strings.Contains(drift, "DRIFT: .pwn/work/0001/plan.json está ilegível ou inválido") {
		t.Errorf("plan.json ilegível = %q, %v", drift, err)
	}
	if err := os.WriteFile(filepath.Join(".pwn", "work", "0001", "plan.json"), []byte(`{"work_id":"0001","tasks":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	drift, err = planDrift("0001", "texto diferente do plano")
	if err != nil || !strings.Contains(drift, "DRIFT: "+filepath.Join(".todo", "0001-tasks.md")+" diverge de .pwn/work/0001/plan.json") ||
		!strings.Contains(drift, "pwn work plan --work 0001 --force") {
		t.Errorf("divergência = %q, %v", drift, err)
	}
}
