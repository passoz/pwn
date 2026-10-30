package plan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
)

// secondTask devolve o bloco da task 1.1 de validTasks renumerado para id e com
// um Requirement próprio, para montar planos com mais de uma task.
func secondTask(id, requirement string) string {
	text := validTasks()
	block := text[strings.Index(text, "### [ ] [1.1]"):]
	block = strings.Replace(block, "[1.1]", "["+id+"]", 1)
	return strings.Replace(block, "**Requirement:** FR-001", "**Requirement:** "+requirement, 1)
}

func TestAnalyzeTasksStructuralErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{
			name: "versão declarada duas vezes",
			mutate: func(text string) string {
				return strings.Replace(text, "**Work ID:** 0001", "**Contract version:** 3\n**Work ID:** 0001", 1)
			},
			want: "duplicate task contract version declaration",
		},
		{
			name: "versão ilegível",
			mutate: func(text string) string {
				return strings.Replace(text, "**Contract version:** 3", "**Contract version:** três", 1)
			},
			want: "line 2: invalid task contract version declaration",
		},
		{
			name: "versão não suportada",
			mutate: func(text string) string {
				return strings.Replace(text, "**Contract version:** 3", "**Contract version:** 9", 1)
			},
			want: "unsupported task contract version: 9; supported versions are 1, 2, and 3",
		},
		{
			name: "Work ID duplicado",
			mutate: func(text string) string {
				return strings.Replace(text, "**Work ID:** 0001", "**Work ID:** 0001\n**Work ID:** 0001", 1)
			},
			want: "duplicate Work ID declaration",
		},
		{
			name:   "Work ID ausente",
			mutate: func(text string) string { return strings.Replace(text, "**Work ID:** 0001\n", "", 1) },
			want:   "missing declaration: **Work ID:** NNNN",
		},
		{
			name:   "Work ID com formato inválido",
			mutate: func(text string) string { return strings.Replace(text, "**Work ID:** 0001", "**Work ID:** 12", 1) },
			want:   "line 3: invalid Work ID declaration; expected four digits",
		},
		{
			name:   "seção Execution contract ausente",
			mutate: func(text string) string { return strings.Replace(text, "## Execution contract", "## Contrato", 1) },
			want:   "missing section: ## Execution contract",
		},
		{
			name:   "seção Global gates ausente",
			mutate: func(text string) string { return strings.Replace(text, "## Global gates", "## Gates", 1) },
			want:   "missing section: ## Global gates",
		},
		{
			name: "contrato sem componentes",
			mutate: func(text string) string {
				return strings.Replace(text, "| backend-go | §.§ | §go test ./...§ | §N/A§ | §go build ./...§ | §N/A§ | §N/A§ | §N/A§ |\n", "", 1)
			},
			want: "execution contract has no components",
		},
		{
			name:   "task duplicada",
			mutate: func(text string) string { return text + "\n" + text[strings.Index(text, "### [ ] [1.1]"):] },
			want:   "task 1.1: duplicate ID",
		},
		{
			name: "ordem decrescente",
			mutate: func(text string) string {
				return text + "\n" + strings.Replace(secondTask("1.1", "FR-002"), "[1.1]", "[1.0]", 1)
			},
			want: "task 1.0: IDs are not strictly increasing",
		},
		{
			name:   "task bloqueada sem motivo",
			mutate: func(text string) string { return text + "\n### [!] [1.2] Aguardando\n" },
			want:   "task 1.2: blocked task must include a concrete reason",
		},
		{
			name: "depends on vazio",
			mutate: func(text string) string {
				return strings.Replace(text, "**Depends on:** none", "**Depends on:** ,", 1)
			},
			want: "Depends on must be none, previous local task IDs, or qualified NNNN/task IDs",
		},
		{
			name: "dependência de si mesma",
			mutate: func(text string) string {
				return strings.Replace(text, "**Depends on:** none", "**Depends on:** 1.1", 1)
			},
			want: "task 1.1: task cannot depend on itself",
		},
		{
			name: "dependência local futura",
			mutate: func(text string) string {
				return strings.Replace(text, "**Depends on:** none", "**Depends on:** 5.5", 1)
			},
			want: "local dependency must reference an earlier task: 5.5",
		},
		{
			name: "dependência com formato inválido",
			mutate: func(text string) string {
				return strings.Replace(text, "**Depends on:** none", "**Depends on:** abc", 1)
			},
			want: "task 1.1: invalid dependency ID: abc",
		},
		{
			name: "dependência qualificada do mesmo Work apontando para o futuro",
			mutate: func(text string) string {
				return strings.Replace(text, "**Depends on:** none", "**Depends on:** 0001/9.9", 1)
			},
			want: "same-work dependency must reference an earlier task: 0001/9.9",
		},
		{
			name: "dependência qualificada do mesmo Work em si mesma",
			mutate: func(text string) string {
				return strings.Replace(text, "**Depends on:** none", "**Depends on:** 0001/1.1", 1)
			},
			want: "task 1.1: task cannot depend on itself",
		},
		{
			name: "RED sem comando concreto",
			mutate: func(text string) string {
				return strings.Replace(text, "- §go test -run TestInvalidLogin ./internal/...§ — exit non-zero and failure names the test.\n\n**Implementation", "- nada concreto\n\n**Implementation", 1)
			},
			want: "task 1.1: RED needs a concrete command and expected failure",
		},
		{
			name: "ACs sem comando concreto",
			mutate: func(text string) string {
				return strings.Replace(text, "- [ ] §go test -run TestInvalidLogin ./internal/...§ — exit 0.", "- [ ] nada concreto", 1)
			},
			want: "task 1.1: ACs need at least one concrete command and expected result",
		},
		{
			name:   "Visual inválido",
			mutate: func(text string) string { return strings.Replace(text, "**Visual:** N/A", "**Visual:** TALVEZ", 1) },
			want:   "task 1.1: Visual must be N/A or REQUIRED",
		},
		{
			name: "Visual exigido sem detalhes",
			mutate: func(text string) string {
				return strings.Replace(text, "**Visual:** N/A", "**Visual:** REQUIRED\n- **Route:** /login", 1)
			},
			want: "task 1.1: visual validation missing Selector",
		},
		{
			name: "Documentation inválido",
			mutate: func(text string) string {
				return strings.Replace(text, "**Documentation:** N/A", "**Documentation:** TALVEZ", 1)
			},
			want: "task 1.1: Documentation must be N/A or REQUIRED",
		},
		{
			name: "migração declarada duas vezes",
			mutate: func(text string) string {
				return strings.Replace(text, "**Work ID:** 0001", "**Migrated from task contract:** 1\n**Migrated from task contract:** 1\n**Work ID:** 0001", 1)
			},
			want: "duplicate task contract migration source declaration",
		},
		{
			name: "origem de migração ilegível",
			mutate: func(text string) string {
				return strings.Replace(text, "**Work ID:** 0001", "**Migrated from task contract:** x\n**Work ID:** 0001", 1)
			},
			want: "line 3: invalid task contract migration source declaration",
		},
		{
			name: "origem de migração não suportada",
			mutate: func(text string) string {
				return strings.Replace(text, "**Work ID:** 0001", "**Migrated from task contract:** 3\n**Work ID:** 0001", 1)
			},
			want: "unsupported task contract migration source: v3 -> v3",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text := strings.ReplaceAll(testCase.mutate(strings.ReplaceAll(validTasks(), "`", "§")), "§", "`")
			result := plan.AnalyzeTasks(text, plan.AnalyzeOptions{})
			mustContain(t, result.Errors, testCase.want)
		})
	}
}

// Regressão: Visual REQUIRED depois de Documentation estourava o limite do
// slice do bloco visual e derrubava o validador com panic.
func TestAnalyzeTasksVisualRequiredAfterDocumentation(t *testing.T) {
	text := strings.Replace(validTasks(), "**Visual:** N/A\n\n**Documentation:** N/A\n", "**Documentation:** N/A\n\n**Visual:** REQUIRED\n- **Route:** /login\n", 1)
	result := plan.AnalyzeTasks(text, plan.AnalyzeOptions{})
	for _, name := range []string{"Route", "Selector", "Playwright", "Expected"} {
		mustContain(t, result.Errors, "task 1.1: visual validation missing "+name)
	}
}

func TestAnalyzeTasksBlockedTaskWithReasonIsSkipped(t *testing.T) {
	text := validTasks() + "\n### [!] [1.2] Bloqueada: aguarda credencial externa\n"
	result := plan.AnalyzeTasks(text, plan.AnalyzeOptions{})
	if len(result.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", result.Errors)
	}
	if len(result.Tasks) != 2 {
		t.Fatalf("tasks=%d; want=2", len(result.Tasks))
	}
}

func TestAnalyzeTasksAcceptsTasksAcrossMajorNumbers(t *testing.T) {
	text := validTasks() + "\n" + secondTask("2.1", "FR-002")
	result := plan.AnalyzeTasks(text, plan.AnalyzeOptions{})
	if len(result.Errors) != 0 {
		t.Fatalf("erros inesperados: %q", result.Errors)
	}
	wrongOrder := validTasks()
	wrongOrder = strings.Replace(wrongOrder, "[1.1]", "[2.1]", 1) + "\n" + secondTask("1.9", "FR-002")
	mustContain(t, plan.AnalyzeTasks(wrongOrder, plan.AnalyzeOptions{}).Errors, "task 1.9: IDs are not strictly increasing")
}

func TestAnalyzeTasksLegacyAllowanceDeclarations(t *testing.T) {
	migrated := strings.Replace(validTasks(), "**Work ID:** 0001", "**Migrated from task contract:** 1\n**Work ID:** 0001", 1)
	cases := []struct {
		name      string
		allowance string
		want      string
	}{
		{name: "vazio", allowance: "", want: "task 1.1: Legacy allowances cannot be empty"},
		{name: "chave desconhecida", allowance: "files=4", want: "task 1.1: invalid legacy allowance: files=4"},
		{name: "formato inválido", allowance: "implementation-files", want: "task 1.1: invalid legacy allowance: implementation-files"},
		{name: "repetido", allowance: "implementation-files=4, implementation-files=4", want: "task 1.1: duplicate legacy allowance: implementation-files"},
		{name: "sem uso na task", allowance: "ac-commands=9", want: "task 1.1: stale legacy allowance ac-commands=9"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text := strings.Replace(migrated, "**Depends on:** none", "**Depends on:** none\n**Legacy allowances:** "+testCase.allowance, 1)
			mustContain(t, plan.AnalyzeTasks(text, plan.AnalyzeOptions{}).Errors, testCase.want)
		})
	}
}

// depsPlan devolve um plano com uma instalação de dependência declarada.
func depsPlan(entry string) string {
	section := "**Dependency installations:**"
	if entry != "" {
		section += "\n" + entry
	}
	return strings.ReplaceAll(strings.Replace(validTasks(), "**Depends on:** none", "**Depends on:** none\n"+section, 1), "§", "`")
}

func TestDependencyInstallationDiagnostics(t *testing.T) {
	specAllowing := func(names ...string) string {
		return "# System spec\n\n**Dependencies:** `" + strings.Join(names, "`, `") + "`\n"
	}
	cases := []struct {
		name  string
		entry string
		spec  string
		want  string // vazio: nenhum erro esperado
	}{
		{name: "lista vazia", entry: "", want: "Dependency installations needs at least one command and governing spec path"},
		{name: "linhas em branco são ignoradas", entry: "\n- §npm install fastify@4§ — declared in §.specs/system.md§.", spec: specAllowing("fastify")},
		{name: "declaração malformada", entry: "- instalar fastify", spec: specAllowing("fastify"), want: "invalid dependency installation declaration"},
		{name: "fora do repositório", entry: "- §npm install fastify@4§ — declared in §../fora.md§.", spec: specAllowing("fastify"), want: "governing spec path escapes repository root: ../fora.md"},
		{name: "spec inexistente", entry: "- §npm install fastify@4§ — declared in §.specs/outra.md§.", spec: specAllowing("fastify"), want: "governing spec not found: .specs/outra.md"},
		{name: "apt-get com flag", entry: "- §apt-get install -y curl§ — declared in §.specs/system.md§.", spec: specAllowing("curl")},
		{name: "brew", entry: "- §brew install jq§ — declared in §.specs/system.md§.", spec: specAllowing("jq")},
		{name: "pacote npm com escopo sem versão", entry: "- §npm install @fastify/cors§ — declared in §.specs/system.md§.", spec: specAllowing("@fastify/cors")},
		{name: "flag de desenvolvimento é ignorada", entry: "- §npm install --save-dev vitest@1§ — declared in §.specs/system.md§.", spec: specAllowing("vitest")},
		{name: "pip com operador de versão", entry: "- §pip install requests>=2§ — declared in §.specs/system.md§.", spec: specAllowing("requests")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := writePlanWithSpec(t, t.TempDir(), depsPlan(testCase.entry), testCase.spec)
			errors := plan.ValidateTasks(path, plan.AnalyzeOptions{})
			if testCase.want == "" {
				if len(errors) != 0 {
					t.Fatalf("erros inesperados: %q", errors)
				}
				return
			}
			mustContain(t, errors, testCase.want)
		})
	}
}

func TestDependencyInstallationAcceptsAbsoluteSpecInsideRepository(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, ".specs", "system.md")
	entry := "- §npm install fastify@4§ — declared in §" + spec + "§."
	path := writePlanWithSpec(t, dir, depsPlan(entry), "# System spec\n\n**Dependencies:** `fastify`\n")
	if errors := plan.ValidateTasks(path, plan.AnalyzeOptions{}); len(errors) != 0 {
		t.Fatalf("erros inesperados: %q", errors)
	}
}

func TestDependencyInstallationRequiresPlanPath(t *testing.T) {
	result := plan.AnalyzeTasks(depsPlan("- §npm install fastify@4§ — declared in §.specs/system.md§."), plan.AnalyzeOptions{})
	mustContain(t, result.Errors, "dependency installation validation requires a plan file path")
}

func TestValidateTasksDetailedFileAccessErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nao-existe.md")
	for _, path := range []string{missing, dir} {
		result := plan.ValidateTasksDetailed(path, plan.AnalyzeOptions{})
		if len(result.Errors) != 1 || result.Errors[0] != "file not found: "+path {
			t.Errorf("%s: erros=%q", path, result.Errors)
		}
		if result.ContractVersion != nil || result.ContractVersionSource != "absent" {
			t.Errorf("%s: versão=%v origem=%q", path, result.ContractVersion, result.ContractVersionSource)
		}
		if len(result.Tasks) != 0 || len(result.Warnings) != 0 || len(result.Exceptions) != 0 {
			t.Errorf("%s: resultado deveria ser vazio: %#v", path, result)
		}
	}
	if errors := plan.ValidateTasks(missing, plan.AnalyzeOptions{}); len(errors) != 1 {
		t.Errorf("ValidateTasks: erros=%q", errors)
	}
}

func legacyPlan() string {
	legacy := validTasks()
	legacy = strings.Replace(legacy, "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy, "**Requirement:** FR-001\n", "", 1)
	return strings.Replace(legacy, "**Depends on:** none\n", "", 1)
}

func TestMigrateTasksContentRefusals(t *testing.T) {
	t.Run("plano com erros não é migrado", func(t *testing.T) {
		broken := strings.Replace(legacyPlan(), "go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin", 1)
		result := plan.MigrateTasksContent(broken, plan.MigrateOptions{WorkID: "0001"})
		mustContain(t, result.Errors, "unsafe command")
		if result.Content != broken || len(result.Changes) != 0 {
			t.Errorf("conteúdo ou mudanças alterados: %#v", result.Changes)
		}
		if result.FromVersion == nil || *result.FromVersion != plan.LegacyTaskContractVersion || result.ToVersion != plan.CurrentTaskContractVersion {
			t.Errorf("versões: %v -> %d", result.FromVersion, result.ToVersion)
		}
	})
	t.Run("plano já migrado não muda", func(t *testing.T) {
		result := plan.MigrateTasksContent(validTasks(), plan.MigrateOptions{WorkID: "0001"})
		if len(result.Errors) != 0 || len(result.Changes) != 0 || result.Content != validTasks() {
			t.Errorf("resultado=%#v", result)
		}
	})
	t.Run("Work ID inválido", func(t *testing.T) {
		result := plan.MigrateTasksContent(legacyPlan(), plan.MigrateOptions{WorkID: "12"})
		mustContain(t, result.Errors, "migration to task contract v3 requires a four-digit Work ID")
		if result.Content != legacyPlan() {
			t.Error("conteúdo não deveria mudar")
		}
	})
	t.Run("título ausente", func(t *testing.T) {
		text := strings.Replace(legacyPlan(), "# Tasks: auth", "# Plano auth", 1)
		result := plan.MigrateTasksContent(text, plan.MigrateOptions{WorkID: "0001"})
		mustContain(t, result.Errors, "migration requires a canonical # Tasks: title")
	})
	t.Run("Work ID em conflito", func(t *testing.T) {
		text := strings.Replace(legacyPlan(), "# Tasks: auth\n", "# Tasks: auth\n**Work ID:** 0002\n", 1)
		result := plan.MigrateTasksContent(text, plan.MigrateOptions{WorkID: "0001"})
		mustContain(t, result.Errors, "migration Work ID conflicts with existing declaration: **Work ID:** 0002")
	})
}

func TestMigrateTasksContentRecordsAllowancesAndSerialDependencies(t *testing.T) {
	legacy := legacyPlan()
	legacy = strings.Replace(legacy, "**Contract version:** 3\n", "", 1)
	legacy = strings.Replace(legacy, "# Tasks: auth\n", "# Tasks: auth\n**Work ID:** 0001\n", 1)
	// A segunda task é bloqueada (não migra) e a terceira herda a dependência da primeira.
	legacy += "\n### [!] [1.2] Bloqueada: aguarda credencial externa\n\n" + strings.Replace(secondTask("1.3", "FR-003"),
		"**Depends on:** none\n", "", 1)
	legacy = strings.Replace(legacy, "**Requirement:** FR-003\n", "", 1)
	result := plan.MigrateTasksContent(legacy, plan.MigrateOptions{WorkID: "0001"})
	mustContain(t, result.Changes, "task 1.3: made the legacy serial dependency explicit")
	mustContain(t, result.Changes, "task 1.3: added a SOURCE-* requirement")
	mustContain(t, result.Changes, "set task contract version to 3 with migration provenance from v1")
	for _, change := range result.Changes {
		if strings.Contains(change, "assigned Work ID") {
			t.Errorf("o Work ID já declarado não deveria ser atribuído de novo: %q", change)
		}
	}
	mustContain(t, []string{result.Content}, "### [!] [1.2] Bloqueada: aguarda credencial externa\n")
	mustContain(t, []string{result.Content}, "**Depends on:** 1.2")
}

func TestMigrateTasksContentAllowancesForEachLimit(t *testing.T) {
	legacy := legacyPlan()
	legacy = strings.Replace(legacy,
		"- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.",
		"- `go test -run TestInvalidLogin ./internal/...` — exit non-zero and failure names the test.\n- `go test -run TestSecond ./internal/...` — exit non-zero too.", 1)
	legacy = strings.Replace(legacy,
		"- [ ] `go test -run TestInvalidLogin ./internal/...` — exit 0.",
		"- [ ] `go test -run TestA ./internal/...` — exit 0.\n- [ ] `go test -run TestB ./internal/...` — exit 0.\n- [ ] `go test -run TestC ./internal/...` — exit 0.\n- [ ] `go test -run TestD ./internal/...` — exit 0.", 1)
	legacy = strings.Replace(legacy, "1. Return unauthorized for an invalid password.", "1. Primeiro.\n2. Segundo.\n3. Terceiro.", 1)
	result := plan.MigrateTasksContent(legacy, plan.MigrateOptions{WorkID: "0001"})
	mustContain(t, result.Changes, "task 1.1: recorded exact legacy atomicity allowances (red-commands=2, ac-commands=4, implementation-steps=3)")
	mustContain(t, []string{result.Content}, "**Legacy allowances:** red-commands=2, ac-commands=4, implementation-steps=3")
}

func runTasksMain(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = plan.ValidateTasksMain(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestValidateTasksMainUsageErrors(t *testing.T) {
	const usage = "usage: validate_tasks.js [--strict] PATH | --migrate --work NNNN [--write] PATH\n"
	cases := []struct {
		name string
		args []string
	}{
		{name: "sem argumentos", args: nil},
		{name: "dois caminhos", args: []string{"a.md", "b.md"}},
		{name: "opção desconhecida", args: []string{"--verbose", "a.md"}},
		{name: "write sem migrate", args: []string{"--write", "a.md"}},
		{name: "strict com migrate", args: []string{"--strict", "--migrate", "--work", "0001", "a.md"}},
		{name: "migrate sem work", args: []string{"--migrate", "a.md"}},
		{name: "migrate com work inválido", args: []string{"--migrate", "--work", "12", "a.md"}},
		{name: "work sem valor", args: []string{"--migrate", "a.md", "--work"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			code, stdout, stderr := runTasksMain(testCase.args...)
			if code != 2 || stdout != "" || stderr != usage {
				t.Errorf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestValidateTasksMainPassCurrent(t *testing.T) {
	path := writePlan(t, t.TempDir(), validTasks())
	code, stdout, stderr := runTasksMain(path)
	if code != 0 || stderr != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, stderr, stdout)
	}
	if want := "PASS: " + path + " is executable under task contract v3 (current)\n"; stdout != want {
		t.Errorf("stdout=%q; want=%q", stdout, want)
	}
}

func TestValidateTasksMainPassLegacyListsWarnings(t *testing.T) {
	path := writePlan(t, t.TempDir(), legacyPlan())
	code, stdout, _ := runTasksMain(path)
	if code != 0 {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	for _, want := range []string{
		"PASS: " + path + " is executable under task contract v1 (legacy compatibility)\n",
		"Compatibility warnings (3):\n- task contract version is missing; assuming legacy version 1\n",
		"Migration is optional: preview with --migrate, then apply with --migrate --write.\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout sem %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Preserved legacy exceptions") {
		t.Errorf("plano sem exceções não deveria listá-las:\n%s", stdout)
	}
}

func TestValidateTasksMainListsPreservedLegacyExceptions(t *testing.T) {
	legacy := legacyPlan()
	legacy = strings.Replace(legacy, "**Files:** internal/auth.go, internal/auth_test.go",
		"**Files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go, internal/auth_test.go", 1)
	legacy = strings.Replace(legacy, "**Implementation files:** internal/auth.go", "**Implementation files:** internal/auth.go, internal/a.go, internal/b.go, internal/c.go", 1)
	migrated := plan.MigrateTasksContent(legacy, plan.MigrateOptions{WorkID: "0001"})
	if len(migrated.Errors) != 0 {
		t.Fatalf("erros de migração: %q", migrated.Errors)
	}
	path := writePlan(t, t.TempDir(), migrated.Content)
	code, stdout, _ := runTasksMain(path)
	if code != 0 {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	want := "Preserved legacy exceptions (1):\n- task 1.1: preserved legacy allowance implementation-files=4\n"
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout sem %q:\n%s", want, stdout)
	}
}

func TestValidateTasksMainFailures(t *testing.T) {
	t.Run("erros de validação", func(t *testing.T) {
		path := writePlan(t, t.TempDir(), strings.Replace(validTasks(), "go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin", 1))
		code, stdout, _ := runTasksMain(path)
		if code != 1 {
			t.Fatalf("code=%d", code)
		}
		if !strings.HasPrefix(stdout, "FAIL: "+path+"\nBlocking issues (") || !strings.Contains(stdout, "unsafe command (sudo)") {
			t.Errorf("stdout=%q", stdout)
		}
	})
	t.Run("arquivo ausente", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nao-existe.md")
		code, stdout, _ := runTasksMain(missing)
		if want := "FAIL: " + missing + "\nBlocking issues (1):\n- file not found: " + missing + "\n"; code != 1 || stdout != want {
			t.Errorf("code=%d stdout=%q", code, stdout)
		}
	})
	t.Run("caminho fora de .todo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "plan.md")
		if err := os.WriteFile(path, []byte(validTasks()), 0o644); err != nil {
			t.Fatal(err)
		}
		code, stdout, _ := runTasksMain(path)
		want := "current task contract requires canonical path .todo/NNNN-tasks.md: " + path
		if code != 1 || !strings.Contains(stdout, want) {
			t.Errorf("code=%d stdout=%q", code, stdout)
		}
	})
	t.Run("Work ID diferente do nome do arquivo", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".todo", "0002-tasks.md")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(validTasks()), 0o644); err != nil {
			t.Fatal(err)
		}
		code, stdout, _ := runTasksMain(path)
		want := "plan filename Work ID 0002 does not match declaration 0001"
		if code != 1 || !strings.Contains(stdout, want) {
			t.Errorf("code=%d stdout=%q", code, stdout)
		}
	})
	t.Run("Work ID ausente no plano", func(t *testing.T) {
		dir := t.TempDir()
		path := writePlan(t, dir, strings.Replace(validTasks(), "**Work ID:** 0001\n", "", 1))
		code, stdout, _ := runTasksMain(path)
		if code != 1 || !strings.Contains(stdout, "plan filename Work ID 0001 does not match declaration missing") {
			t.Errorf("code=%d stdout=%q", code, stdout)
		}
	})
}

func TestValidateTasksMainMigrationOutcomes(t *testing.T) {
	t.Run("arquivo ausente", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nao-existe.md")
		code, stdout, _ := runTasksMain("--migrate", "--work", "0001", missing)
		want := "MIGRATION FAIL: " + missing + "\n- file not found: " + missing + "\n"
		if code != 1 || stdout != want {
			t.Errorf("code=%d stdout=%q", code, stdout)
		}
	})
	t.Run("plano atual com erros", func(t *testing.T) {
		broken := strings.Replace(validTasks(), "go test -run TestInvalidLogin", "sudo go test -run TestInvalidLogin", 1)
		path := writePlan(t, t.TempDir(), broken)
		code, stdout, _ := runTasksMain("--migrate", "--work", "0001", path)
		if code != 1 || !strings.HasPrefix(stdout, "MIGRATION BLOCKED: "+path+"\nBlocking issues (") {
			t.Errorf("code=%d stdout=%q", code, stdout)
		}
		if after, _ := os.ReadFile(path); string(after) != broken {
			t.Error("plano não deveria ser alterado")
		}
	})
	t.Run("migração bloqueada lista avisos de compatibilidade", func(t *testing.T) {
		text := strings.Replace(legacyPlan(), "# Tasks: auth\n", "# Tasks: auth\n**Work ID:** 0002\n", 1)
		path := writePlan(t, t.TempDir(), text)
		code, stdout, _ := runTasksMain("--migrate", "--work", "0001", path)
		if code != 1 {
			t.Fatalf("code=%d stdout=%q", code, stdout)
		}
		for _, want := range []string{
			"MIGRATION BLOCKED: " + path + "\n",
			"Blocking issues (1):\n- migration Work ID conflicts with existing declaration: **Work ID:** 0002\n",
			"Compatibility warnings (",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout sem %q:\n%s", want, stdout)
			}
		}
	})
	t.Run("prévia mostra o conteúdo migrado sem gravar", func(t *testing.T) {
		path := writePlan(t, t.TempDir(), legacyPlan())
		code, stdout, _ := runTasksMain("--migrate", "--work", "0001", path)
		if code != 0 {
			t.Fatalf("code=%d stdout=%q", code, stdout)
		}
		for _, want := range []string{
			"MIGRATION PREVIEW: " + path + " (v1 -> v3)\nChanges (",
			"No file was changed. Migrated content follows:\n--- BEGIN MIGRATED FILE ---\n# Tasks: auth\n**Contract version:** 3\n",
			"--- END MIGRATED FILE ---\nApply by re-running the loaded validator with --migrate --write for the same file.\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout sem %q:\n%s", want, stdout)
			}
		}
	})
	t.Run("gravação em arquivo somente leitura falha", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignora permissões de arquivo")
		}
		path := writePlan(t, t.TempDir(), legacyPlan())
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runTasksMain("--migrate", "--work", "0001", "--write", path)
		if code != 1 || !strings.Contains(stderr, "permission denied") {
			t.Errorf("code=%d stderr=%q", code, stderr)
		}
		if after, _ := os.ReadFile(path); string(after) != legacyPlan() {
			t.Error("plano não deveria ser alterado")
		}
	})
}
