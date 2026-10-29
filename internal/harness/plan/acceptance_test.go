package plan_test

import (
	"reflect"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
)

// fixturePlan é o plano v3 completo do teste de referência: contrato de
// execução, gates globais e duas tasks.
const fixturePlan = `## Execution contract

| Component | Regression | Lint | Build | Security |
| --- | --- | --- | --- | --- |
| core | ` + "`bun test tests/core.test.ts`" + ` | ` + "`bun run lint`" + ` | ` + "`bun run build`" + ` | N/A |

## Global gates

- [ ] ` + "`bun run typecheck`" + ` — verificação de tipos

## Tasks

### [ ] [1.1] Tokenizar linha de comando

**Implementation files:** ` + "`src/core/acceptance.ts`, `src/core/cli.ts`" + `

**Test files:** ` + "`tests/acceptance.test.ts`" + `

**Components:** ` + "`core`" + `

**RED:**
- ` + "`bun test tests/acceptance.test.ts`" + ` — falha porque a tokenização ainda não existe

**ACs:**
- [ ] ` + "`bun test tests/acceptance-split.test.ts`" + ` — tokeniza aspas simples
- [ ] ` + "`bun test tests/acceptance-quote.test.ts`" + ` — tokeniza aspas duplas

**Visual:** N/A
**Documentation:** N/A

### [ ] [1.2] Interface visual do relatório

**Implementation files:** ` + "`src/core/report.ts`" + `

**Test files:** ` + "`tests/report.test.ts`" + `

**Components:** ` + "`core`" + `

**RED:**
- ` + "`bun test tests/report.test.ts`" + ` — o relatório ainda não existe

**ACs:**
- [ ] ` + "`bun test tests/report-render.test.ts`" + ` — renderiza o card

**Visual:** REQUIRED
**Playwright:** ` + "`bun run e2e`" + `
**Documentation:** REQUIRED
- **Evidence:** ` + "`bun run docs`" + `
`

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
		ok      bool
	}{
		{name: "aspas simples", command: "bun test 'a b.test.mjs'", want: []string{"bun", "test", "a b.test.mjs"}, ok: true},
		{name: "aspas duplas com escape", command: `"valor com \"aspas\""`, want: []string{`valor com "aspas"`}, ok: true},
		{name: "barra invertida fora de aspas", command: `echo a\ b`, want: []string{"echo", "a b"}, ok: true},
		{name: "aspas duplas não fechadas", command: `echo "aspas`, ok: false},
		{name: "aspas simples não fechadas", command: `echo 'aspas`, ok: false},
		{name: "string vazia", command: "", want: []string{}, ok: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := plan.SplitCommandLine(testCase.command)
			if ok != testCase.ok {
				t.Fatalf("ok=%v; want=%v", ok, testCase.ok)
			}
			if ok && !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("tokens=%q; want=%q", got, testCase.want)
			}
		})
	}
}

func TestCommandMatches(t *testing.T) {
	const planned = "bun test tests/x.test.ts"
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{name: "mesmos tokens", argv: []string{"bun", "test", "tests/x.test.ts"}, want: true},
		{name: "texto exato via bash -c", argv: []string{"bash", "-c", planned}, want: true},
		{name: "sh -c divergente", argv: []string{"sh", "-c", "bun test tests/outro.test.ts"}, want: false},
		{name: "programa diferente", argv: []string{"node", "test", "tests/x.test.ts"}, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := plan.CommandMatches(planned, testCase.argv); got != testCase.want {
				t.Errorf("Match=%v; want=%v", got, testCase.want)
			}
		})
	}
}

func TestVacuousCommandReason(t *testing.T) {
	for _, command := range []string{"true", ":", "echo ok", "sh -c 'true'"} {
		if got := plan.VacuousCommandReason(command); got == "" {
			t.Errorf("%q deveria ter motivo de vacuidade", command)
		}
	}
	if got := plan.VacuousCommandReason("bun test tests/x.test.ts"); got != "" {
		t.Errorf("comando real não deveria ter motivo; got %q", got)
	}
}

func TestIsWholeSuiteCommand(t *testing.T) {
	whole := []string{"bun test", "bun run test", "npm test", "npx vitest run", "pytest", "go test ./...", "node --test", "bun test --timeout 5000"}
	for _, command := range whole {
		if !plan.IsWholeSuiteCommand(command) {
			t.Errorf("%q deveria ser suíte inteira", command)
		}
	}
	focused := []string{"bun test tests/x.test.ts", "bun test -t 'nome do caso'", "pytest tests/test_x.py", "go test ./internal/auth"}
	for _, command := range focused {
		if plan.IsWholeSuiteCommand(command) {
			t.Errorf("%q não deveria ser suíte inteira", command)
		}
	}
}

func TestGenericCommandReason(t *testing.T) {
	cases := []struct {
		name    string
		command string
		gates   []string
		substr  string
	}{
		{name: "vácuo", command: "true", substr: "não exercita comportamento"},
		{name: "repete gate", command: "bun test", gates: []string{"bun test"}, substr: "repete um gate"},
		{name: "suíte inteira", command: "bun test", substr: "suíte inteira"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reason := plan.GenericCommandReason(testCase.command, testCase.gates)
			if !contains(reason, testCase.substr) {
				t.Errorf("motivo=%q; deveria conter %q", reason, testCase.substr)
			}
		})
	}
	if got := plan.GenericCommandReason("bun test tests/x.test.ts", nil); got != "" {
		t.Errorf("comando focado não deveria ter motivo; got %q", got)
	}
}

func TestGenericExpectReason(t *testing.T) {
	for _, marker := range []string{"fail", "(fail)", "Error", "expected"} {
		if got := plan.GenericExpectReason(marker); got == "" {
			t.Errorf("%q deveria ser genérico", marker)
		}
	}
	if got := plan.GenericExpectReason("abc"); !contains(got, "3 caractere") {
		t.Errorf("texto curto deveria ser recusado; got %q", got)
	}
	if got := plan.GenericExpectReason("VALUE-NEW-001"); got != "" {
		t.Errorf("identificador específico deveria ser aceito; got %q", got)
	}
}

func TestPlaceholderPathReason(t *testing.T) {
	cases := []struct {
		path   string
		substr string
	}{
		{path: "src/", substr: "diretório"},
		{path: ".", substr: "diretório"},
		{path: "src/**", substr: "glob"},
		{path: "*.ts", substr: "glob"},
		{path: "<arquivo>.ts", substr: "placeholder"},
		{path: "TODO.ts", substr: "placeholder"},
		{path: "src/app.ts", substr: ""},
	}
	for _, testCase := range cases {
		reason := plan.PlaceholderPathReason(testCase.path)
		if testCase.substr == "" {
			if reason != "" {
				t.Errorf("%q deveria ser aceito; got %q", testCase.path, reason)
			}
			continue
		}
		if !contains(reason, testCase.substr) {
			t.Errorf("%q: motivo=%q; deveria conter %q", testCase.path, reason, testCase.substr)
		}
	}
}

func TestParsePlanTask(t *testing.T) {
	task := plan.ParsePlanTask(fixturePlan, "1.1")
	if task == nil {
		t.Fatal("task 1.1 não encontrada")
	}
	if task.ID != "1.1" || task.Marker != " " || task.Title != "Tokenizar linha de comando" {
		t.Fatalf("cabeçalho lido errado: %#v", task)
	}
	if want := "### [ ] [1.1] Tokenizar linha de comando"; task.Lines[0] != want {
		t.Errorf("primeira linha=%q; want=%q", task.Lines[0], want)
	}
	if want := []string{"src/core/acceptance.ts", "src/core/cli.ts"}; !reflect.DeepEqual(task.ImplementationFiles, want) {
		t.Errorf("implementation files=%q; want=%q", task.ImplementationFiles, want)
	}
	if want := []string{"tests/acceptance.test.ts"}; !reflect.DeepEqual(task.TestFiles, want) {
		t.Errorf("test files=%q; want=%q", task.TestFiles, want)
	}
	if want := []string{"core"}; !reflect.DeepEqual(task.Components, want) {
		t.Errorf("components=%q; want=%q", task.Components, want)
	}
	wantRed := plan.PlanCommand{Command: "bun test tests/acceptance.test.ts", Description: "falha porque a tokenização ainda não existe"}
	if task.Red == nil || *task.Red != wantRed {
		t.Errorf("red=%#v; want=%#v", task.Red, wantRed)
	}
	wantACs := []plan.PlanCommand{
		{Command: "bun test tests/acceptance-split.test.ts", Description: "tokeniza aspas simples"},
		{Command: "bun test tests/acceptance-quote.test.ts", Description: "tokeniza aspas duplas"},
	}
	if !reflect.DeepEqual(task.ACs, wantACs) {
		t.Errorf("acs=%#v; want=%#v", task.ACs, wantACs)
	}
	if task.Visual != (plan.PlanRequirement{}) || task.Documentation != (plan.PlanRequirement{}) {
		t.Errorf("visual/documentation deveriam estar ausentes: %#v %#v", task.Visual, task.Documentation)
	}

	if got := plan.ParsePlanTask(fixturePlan, "9.9"); got != nil {
		t.Errorf("id inexistente deveria devolver nil; got %#v", got)
	}
	if got := plan.ParsePlanTask(fixturePlan, "01.01"); got == nil || got.ID != "1.1" {
		t.Errorf("id com zeros à esquerda deveria casar; got %#v", got)
	}
}

func TestParsePlanTasks(t *testing.T) {
	tasks := plan.ParsePlanTasks(fixturePlan)
	if len(tasks) != 2 {
		t.Fatalf("tasks=%d; want=2", len(tasks))
	}
	if tasks[0].ID != "1.1" || tasks[1].ID != "1.2" {
		t.Errorf("ids=%q,%q", tasks[0].ID, tasks[1].ID)
	}
	if tasks[1].Title != "Interface visual do relatório" {
		t.Errorf("título=%q", tasks[1].Title)
	}
}

func TestParseGlobalGates(t *testing.T) {
	if gates, found := plan.ParseGlobalGates("# Plano\n\n### [ ] [1.1] X\n"); found || gates != nil {
		t.Errorf("seção ausente deveria devolver nil,false; got %#v,%v", gates, found)
	}
	gates, found := plan.ParseGlobalGates("# Plano\n\n## Global gates\n\nN/A\n")
	if !found || len(gates) != 0 {
		t.Errorf("seção N/A deveria devolver lista vazia; got %#v,%v", gates, found)
	}
	gates, found = plan.ParseGlobalGates("## Global gates\n- [ ] `bun test` — roda tudo\n- [!] revisar lint manualmente\n")
	want := []plan.PlanGlobalGate{
		{Marker: " ", Command: "bun test", Text: "`bun test` — roda tudo"},
		{Marker: "!", Command: "", Text: "revisar lint manualmente"},
	}
	if !found || !reflect.DeepEqual(gates, want) {
		t.Errorf("gates=%#v,%v; want=%#v", gates, found, want)
	}
}

func TestRequiredAuditChecks(t *testing.T) {
	cases := []struct {
		taskID string
		want   []string
	}{
		{taskID: "1.1", want: []string{"AC-1", "AC-2", "REGRESSION"}},
		{taskID: "1.2", want: []string{"AC-1", "VISUAL", "DOCUMENTATION", "REGRESSION"}},
	}
	for _, testCase := range cases {
		task := plan.ParsePlanTask(fixturePlan, testCase.taskID)
		if task == nil {
			t.Fatalf("task %s ausente", testCase.taskID)
		}
		if got := plan.RequiredAuditChecks(*task); !reflect.DeepEqual(got, testCase.want) {
			t.Errorf("task %s: checks=%q; want=%q", testCase.taskID, got, testCase.want)
		}
	}
}

func TestAllowedCheckCommands(t *testing.T) {
	taskOne := plan.ParsePlanTask(fixturePlan, "1.1")
	taskTwo := plan.ParsePlanTask(fixturePlan, "1.2")
	if taskOne == nil || taskTwo == nil {
		t.Fatal("fixture sem as tasks esperadas")
	}

	cases := []struct {
		name     string
		task     *plan.PlanTaskDefinition
		check    string
		commands []string
		errText  string
	}{
		{name: "AC fora do range", task: taskOne, check: "AC-3", commands: []string{}, errText: "AC-3 não existe no plano: a task 1.1 declara 2 AC(s)"},
		{name: "AC válido", task: taskOne, check: "AC-1", commands: []string{"bun test tests/acceptance-split.test.ts"}},
		{name: "VISUAL ausente", task: taskOne, check: "VISUAL", commands: []string{}, errText: "a task 1.1 não exige VISUAL"},
		{name: "VISUAL exigido", task: taskTwo, check: "VISUAL", commands: []string{"bun run e2e"}},
		{name: "DOCUMENTATION exigido", task: taskTwo, check: "DOCUMENTATION", commands: []string{"bun run docs"}},
		{name: "REGRESSION", task: taskOne, check: "REGRESSION", commands: []string{"bun test tests/core.test.ts", "bun run typecheck"}},
		{name: "check desconhecido", task: taskOne, check: "BOGUS", commands: []string{}, errText: "check desconhecido: BOGUS"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := plan.AllowedCheckCommands(fixturePlan, *testCase.task, testCase.check)
			if !reflect.DeepEqual(got.Commands, testCase.commands) {
				t.Errorf("commands=%q; want=%q", got.Commands, testCase.commands)
			}
			if testCase.errText == "" {
				if got.Error != "" {
					t.Errorf("erro inesperado: %q", got.Error)
				}
				return
			}
			if got.Error != testCase.errText {
				t.Errorf("erro=%q; want=%q", got.Error, testCase.errText)
			}
		})
	}
}

func TestTaskDefinitionDigest(t *testing.T) {
	digestFor := func(text string) string {
		task := plan.ParsePlanTask(text, "1.1")
		if task == nil {
			t.Fatal("task 1.1 ausente")
		}
		return plan.TaskDefinitionDigest(text, *task)
	}
	base := digestFor(fixturePlan)

	toggled := replaceAll(fixturePlan, "[ ]", "[x]")
	if got := digestFor(toggled); got != base {
		t.Error("estado dos checkboxes não deveria mudar o digest")
	}
	changedAC := replaceFirst(fixturePlan, "bun test tests/acceptance-split.test.ts", "bun test tests/acceptance-split-v2.test.ts")
	if got := digestFor(changedAC); got == base {
		t.Error("mudança no comando de AC deveria mudar o digest")
	}
	changedRed := replaceFirst(fixturePlan, "bun test tests/acceptance.test.ts", "bun test tests/acceptance-red-v2.test.ts")
	if got := digestFor(changedRed); got == base {
		t.Error("mudança no comando de RED deveria mudar o digest")
	}
}

func TestNormalizeCommand(t *testing.T) {
	if got, want := plan.NormalizeCommand("bun    test   tests/x.test.ts"), "bun test tests/x.test.ts"; got != want {
		t.Errorf("normalizado=%q; want=%q", got, want)
	}
}

func contains(text, substr string) bool {
	for index := 0; index+len(substr) <= len(text); index++ {
		if text[index:index+len(substr)] == substr {
			return true
		}
	}
	return false
}

func replaceAll(text, old, replacement string) string {
	for {
		next := replaceFirst(text, old, replacement)
		if next == text {
			return text
		}
		text = next
	}
}

// TestTaskDefinitionDigestMatchesReference fixa o digest calculado pelo
// TypeScript para o plano do Work 0002.
func TestTaskDefinitionDigestMatchesReference(t *testing.T) {
	planText := readTestdata(t, "0002-tasks.rendered.md")
	cases := map[string]string{
		"1.1": "a92b16c09720b1afbb95b7a75a462f48df4c8ffa3d2d5cb7bc3f8fcc8ea19901",
		"1.5": "1b2fc9aff06b7cb3e7dc0fe3ab1da157770d5c7334dc8e3a51866a0f9b3ab197",
	}
	for taskID, want := range cases {
		task := plan.ParsePlanTask(planText, taskID)
		if task == nil {
			t.Fatalf("task %s ausente", taskID)
		}
		if got := plan.TaskDefinitionDigest(planText, *task); got != want {
			t.Errorf("task %s: digest=%q; want=%q", taskID, got, want)
		}
	}
}
