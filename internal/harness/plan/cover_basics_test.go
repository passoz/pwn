package plan_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
)

func TestDisplayCommandQuotesOnlyWhenNeeded(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "vazio", argv: nil, want: ""},
		{name: "tokens simples", argv: []string{"go", "test", "./..."}, want: "go test ./..."},
		{name: "espaço exige aspas", argv: []string{"echo", "a b"}, want: "echo 'a b'"},
		{name: "aspa simples é escapada", argv: []string{"echo", "it's"}, want: `echo 'it'"'"'s'`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := plan.DisplayCommand(testCase.argv); got != testCase.want {
				t.Errorf("DisplayCommand(%q)=%q; want=%q", testCase.argv, got, testCase.want)
			}
		})
	}
}

func TestDisplayCommandRoundTripsThroughSplit(t *testing.T) {
	argv := []string{"sh", "-c", "echo 'x y'", "it's"}
	tokens, ok := plan.SplitCommandLine(plan.DisplayCommand(argv))
	if !ok || !reflect.DeepEqual(tokens, argv) {
		t.Errorf("tokens=%q ok=%v; want=%q", tokens, ok, argv)
	}
}

func TestFirstInlineCommand(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		want   string
		wantOK bool
	}{
		{name: "primeiro trecho em crase", text: "rode `go test ./...` e depois `go vet`", want: "go test ./...", wantOK: true},
		{name: "crase com espaços internos", text: "`  go build  `", want: "go build", wantOK: true},
		{name: "sem crase devolve o texto aparado", text: "  make check  ", want: "make check", wantOK: true},
		{name: "texto vazio", text: "", want: "", wantOK: false},
		{name: "só espaços", text: " \t ", want: "", wantOK: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := plan.FirstInlineCommand(testCase.text)
			if got != testCase.want || ok != testCase.wantOK {
				t.Errorf("FirstInlineCommand(%q)=(%q,%v); want=(%q,%v)", testCase.text, got, ok, testCase.want, testCase.wantOK)
			}
		})
	}
}

func TestVacuousAndWholeSuiteRejectEmptyCommands(t *testing.T) {
	if reason := plan.VacuousCommandReason("   "); !strings.Contains(reason, "vazio") {
		t.Errorf("comando em branco: motivo=%q", reason)
	}
	if reason := plan.VacuousCommandReason(`go test "./...`); !strings.Contains(reason, "aspas desbalanceadas") {
		t.Errorf("aspas abertas: motivo=%q", reason)
	}
	if plan.IsWholeSuiteCommand("") {
		t.Error("comando vazio não é suíte inteira")
	}
	if plan.IsWholeSuiteCommand(`go test "./...`) {
		t.Error("comando com aspas abertas não é suíte inteira")
	}
}

func TestIsWholeSuiteCommandSkipsDoubleDash(t *testing.T) {
	if !plan.IsWholeSuiteCommand("bun test --") {
		t.Error("`--` sem alvo continua sendo suíte inteira")
	}
	if plan.IsWholeSuiteCommand("bun test -- tests/a.test.ts") {
		t.Error("alvo depois de `--` seleciona arquivo")
	}
}

func TestPlaceholderPathReasonEmpty(t *testing.T) {
	if reason := plan.PlaceholderPathReason("  "); reason != "caminho vazio" {
		t.Errorf("motivo=%q", reason)
	}
}

func TestParsePlanTasksStopsBlockAtNextSection(t *testing.T) {
	text := "## Tasks\n\n" +
		"### [ ] [1.1] Primeira\n\n**Test files:** `a_test.go`\n\n### Notas soltas\n\n**Test files:** `ignorado_test.go`\n\n" +
		"### [x] [2.3] Segunda\n\n**Test files:** `b_test.go`\n\n## Apêndice\n\n**Test files:** `fim_test.go`\n"
	tasks := plan.ParsePlanTasks(text)
	if len(tasks) != 2 {
		t.Fatalf("tasks=%d; want=2", len(tasks))
	}
	if want := []string{"a_test.go"}; !reflect.DeepEqual(tasks[0].TestFiles, want) {
		t.Errorf("task 1.1: test files=%q; want=%q", tasks[0].TestFiles, want)
	}
	if want := []string{"b_test.go"}; !reflect.DeepEqual(tasks[1].TestFiles, want) {
		t.Errorf("task 2.3: test files=%q; want=%q", tasks[1].TestFiles, want)
	}
	if tasks[1].Marker != "x" || tasks[1].ID != "2.3" {
		t.Errorf("cabeçalho da segunda task: %#v", tasks[1])
	}
	for _, task := range tasks {
		for _, line := range task.Lines {
			if strings.HasPrefix(line, "## ") || strings.Contains(line, "ignorado_test") || strings.Contains(line, "fim_test") {
				t.Errorf("task %s inclui linha de outra seção: %q", task.ID, line)
			}
		}
	}
}

func TestParsePlanTaskUnknownIDFormat(t *testing.T) {
	if got := plan.ParsePlanTask(fixturePlan, "um.ponto-um"); got != nil {
		t.Errorf("id fora do padrão N.M deveria devolver nil; got %#v", got)
	}
}

func TestParsePlanTaskOmittedFields(t *testing.T) {
	text := "### [!] [3.1] Sem campos\n\n**Visual:** N/A\n"
	task := plan.ParsePlanTask(text, "3.1")
	if task == nil {
		t.Fatal("task 3.1 ausente")
	}
	if task.Marker != "!" {
		t.Errorf("marker=%q", task.Marker)
	}
	if task.Red != nil {
		t.Errorf("sem seção RED, Red deveria ser nil; got %#v", task.Red)
	}
	if task.ImplementationFiles != nil || task.TestFiles != nil || task.Components != nil {
		t.Errorf("campos ausentes deveriam ser nil: %#v", task)
	}
	if len(task.ACs) != 0 {
		t.Errorf("acs=%#v", task.ACs)
	}
}

func TestParsePlanTaskListValuesDeduplicates(t *testing.T) {
	text := "### [ ] [1.1] Lista\n\n**Implementation files:** `a.go`, `a.go`, N/A, , `b.go`\n"
	task := plan.ParsePlanTask(text, "1.1")
	if task == nil {
		t.Fatal("task 1.1 ausente")
	}
	if want := []string{"a.go", "b.go"}; !reflect.DeepEqual(task.ImplementationFiles, want) {
		t.Errorf("implementation files=%q; want=%q", task.ImplementationFiles, want)
	}
}

func TestParsePlanTaskVisualRequiresPlaywrightCommand(t *testing.T) {
	text := "### [ ] [1.1] Visual\n\n**Visual:** REQUIRED\n**Documentation:** REQUIRED\n"
	task := plan.ParsePlanTask(text, "1.1")
	if task == nil {
		t.Fatal("task 1.1 ausente")
	}
	if !task.Visual.Required || task.Visual.Command != "" {
		t.Errorf("visual=%#v", task.Visual)
	}
	if !task.Documentation.Required || task.Documentation.Command != "" {
		t.Errorf("documentation=%#v", task.Documentation)
	}
}

func TestAllowedCheckCommandsMissingDeclarations(t *testing.T) {
	const noGates = "## Execution contract\n\n| Component | Regression |\n| --- | --- |\n| core | N/A |\n\n" +
		"### [ ] [1.1] Sem comandos\n\n**Components:** `core`\n\n**ACs:**\n- [ ] `go test ./a` — ok\n\n" +
		"**Visual:** REQUIRED\n**Documentation:** REQUIRED\n\n" +
		"### [ ] [1.2] Sem exigências\n\n**Components:** `core`\n\n**Visual:** N/A\n**Documentation:** N/A\n"
	required := plan.ParsePlanTask(noGates, "1.1")
	optional := plan.ParsePlanTask(noGates, "1.2")
	if required == nil || optional == nil {
		t.Fatal("tasks da fixture ausentes")
	}
	cases := []struct {
		name  string
		task  *plan.PlanTaskDefinition
		check string
		want  string
	}{
		{name: "VISUAL sem Playwright", task: required, check: "VISUAL", want: "a task 1.1 exige VISUAL mas não declara o comando em **Playwright:**"},
		{name: "DOCUMENTATION não exigida", task: optional, check: "DOCUMENTATION", want: "a task 1.2 não exige DOCUMENTATION"},
		{name: "DOCUMENTATION sem Evidence", task: required, check: "DOCUMENTATION", want: "a task 1.1 exige DOCUMENTATION mas não declara o comando em **Evidence:**"},
		{name: "REGRESSION sem comando", task: required, check: "REGRESSION", want: "o plano não declara comando de regressão (coluna Regression ou itens de ## Global gates)"},
		{name: "LOCAL-GATES sem comando", task: required, check: "LOCAL-GATES", want: "o plano não declara gates locais (colunas de garantia ou ## Global gates)"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := plan.AllowedCheckCommands(noGates, *testCase.task, testCase.check)
			if got.Error != testCase.want {
				t.Errorf("erro=%q; want=%q", got.Error, testCase.want)
			}
			if len(got.Commands) != 0 || got.Commands == nil {
				t.Errorf("commands=%#v; want slice vazio não nulo", got.Commands)
			}
		})
	}
}

func TestAllowedCheckCommandsLocalGates(t *testing.T) {
	task := plan.ParsePlanTask(fixturePlan, "1.1")
	if task == nil {
		t.Fatal("task 1.1 ausente")
	}
	got := plan.AllowedCheckCommands(fixturePlan, *task, "LOCAL-GATES")
	want := []string{"bun test tests/core.test.ts", "bun run lint", "bun run build", "bun run typecheck"}
	if got.Error != "" || !reflect.DeepEqual(got.Commands, want) {
		t.Errorf("gates=%q erro=%q; want=%q", got.Commands, got.Error, want)
	}
}

func TestAssuranceCommandsIgnoreMalformedTables(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "sem seção de contrato de execução",
			text: "## Global gates\n- [ ] `make check`\n",
			want: []string{"make check"},
		},
		{
			name: "tabela só com cabeçalho",
			text: "## Execution contract\n\n| Component | Regression |\n\n## Global gates\n- [ ] `make check`\n",
			want: []string{"make check"},
		},
		{
			name: "linha com menos células que o cabeçalho",
			text: "## Execution contract\n\n| Component | Regression | Lint |\n| --- | --- | --- |\n| core | `go test ./...` |\n",
			want: []string{"go test ./..."},
		},
		{
			name: "comando repetido na tabela e nos gates é único",
			text: "## Execution contract\n\n| Component | Regression |\n| --- | --- |\n| core | `go  test ./...` |\n\n## Global gates\n- [ ] `go test ./...`\n",
			want: []string{"go  test ./..."},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := plan.AssuranceCommands(testCase.text, nil); !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("AssuranceCommands=%q; want=%q", got, testCase.want)
			}
		})
	}
}

func TestRegressionCommandsFiltersByComponent(t *testing.T) {
	text := "## Execution contract\n\n| Component | Regression |\n| --- | --- |\n| api | `go test ./api` |\n| web | `bun test` |\n"
	if got, want := plan.RegressionCommands(text, []string{"web"}), []string{"bun test"}; !reflect.DeepEqual(got, want) {
		t.Errorf("web: %q; want=%q", got, want)
	}
	if got, want := plan.RegressionCommands(text, nil), []string{"go test ./api", "bun test"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sem filtro: %q; want=%q", got, want)
	}
}

// writeWorkFile grava <root>/.pwn/work/<work>/<name> com o conteúdo dado.
func writeWorkFile(t *testing.T, root, work, name, content string) string {
	t.Helper()
	path := filepath.Join(root, ".pwn", "work", work, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPlanRejectsUnreadableShapes(t *testing.T) {
	root := t.TempDir()
	writeWorkFile(t, root, "0001", "plan.json", "{ isto não é json")
	writeWorkFile(t, root, "0002", "plan.json", `{"work_id": "0002", "title": "sem tasks"}`)
	writeWorkFile(t, root, "0003", "plan.json", `{"work_id": "0003", "title": "vazio", "tasks": []}`)
	for _, work := range []string{"0001", "0002", "9999"} {
		if got := plan.LoadPlan(work, root); got != nil {
			t.Errorf("Work %s: LoadPlan deveria devolver nil; got %#v", work, got)
		}
	}
	got := plan.LoadPlan("0003", root)
	if got == nil || got.WorkID != "0003" || len(got.Tasks) != 0 {
		t.Errorf("lista vazia de tasks é um plano válido; got %#v", got)
	}
}

func TestLoadPlanAndTasksMarkdownPathDefaultToCurrentDirectory(t *testing.T) {
	root := t.TempDir()
	writeWorkFile(t, root, "0007", "plan.json", `{"work_id": "0007", "title": "cwd", "tasks": []}`)
	t.Chdir(root)
	got := plan.LoadPlan("0007", "")
	if got == nil || got.Title != "cwd" {
		t.Errorf("LoadPlan com rootDir vazio deveria ler do diretório atual; got %#v", got)
	}
	if want := filepath.Join(".todo", "0007-tasks.md"); plan.TasksMarkdownPath("0007", "") != want {
		t.Errorf("TasksMarkdownPath=%q; want=%q", plan.TasksMarkdownPath("0007", ""), want)
	}
}

func TestRenderTasksMarkdownMarksDoneAndBlockedTasks(t *testing.T) {
	base := samplePlan()
	done := base.Tasks[0]
	done.ID, done.Status = "1.1", "done"
	blocked := base.Tasks[0]
	blocked.ID, blocked.Status = "1.2", "blocked"
	pending := base.Tasks[0]
	pending.ID = "1.3"
	base.Tasks = []plan.PlanTask{done, blocked, pending}
	rendered := plan.RenderTasksMarkdown(base)
	for _, heading := range []string{"### [x] [1.1] ", "### [!] [1.2] ", "### [ ] [1.3] "} {
		if !strings.Contains(rendered, heading) {
			t.Errorf("markdown sem o heading %q", heading)
		}
	}
	if !plan.PlanMatchesMarkdown(base, strings.ReplaceAll(rendered, "### [x]", "### [ ]")) {
		t.Error("o estado do checkbox não deveria contar como divergência")
	}
}

func capsuleTask() contract.TaskContractV4 {
	return contract.TaskContractV4{
		ContractVersion:    contract.ContractVersionV4,
		TaskID:             "2.1",
		WorkID:             "0009",
		Title:              "Cápsula completa",
		Risk:               contract.RiskContract{Level: contract.RiskL2, Reasons: []string{"a", "b"}},
		ValidationStrategy: contract.StrategyRegressionGuarded,
		BehavioralContract: contract.BehavioralContract{Scenarios: []contract.Scenario{
			{ID: "S1", Given: "g1", When: "w1", Then: "t1"},
			{ID: "S2", Given: "g2", When: "w2", Then: "t2"},
		}},
		AcceptanceContract: contract.AcceptanceContract{
			Commands:    []string{"go test ./a"},
			FrozenTests: []contract.FrozenTest{{Path: "a_test.go", SHA256: "x"}},
		},
		ScopeContract: contract.ScopeContract{
			WriteAllow: []string{"a.go"},
			WriteDeny:  []string{"b.go"},
			OutOfScope: []string{"Migração de dados"},
		},
		BudgetContract: contract.BudgetContract{
			MaxAgentAttempts:   3,
			MaxLLMCalls:        new(10),
			MaxToolCalls:       new(20),
			MaxShellExecutions: new(30),
			MaxDurationMinutes: new(45),
			MaxCostUSD:         new(12.5),
		},
		EscalationContract: contract.EscalationContract{
			OnWriteViolation: "block_and_escalate",
			OnBudgetExceeded: "human_review",
			OnAttemptFailed:  "retry",
		},
	}
}

func TestGenerateContextCapsuleRendersDeclaredLimitsAndScope(t *testing.T) {
	got := plan.GenerateContextCapsule(plan.ContextCapsuleOptions{Task: capsuleTask()})
	for _, want := range []string{
		"TASK ID:    2.1 (Work: 0009)",
		"RISK LEVEL: " + string(contract.RiskL2) + " (a; b)",
		"[S1]\nGiven: g1\nWhen:  w1\nThen:  t1\n\n[S2]\nGiven: g2",
		"  + a.go",
		"  - b.go",
		"OUT OF SCOPE:\n  ! Migração de dados",
		"  $ go test ./a",
		"  = a_test.go",
		"Max Agent Attempts:   3",
		"Max LLM Calls:        10",
		"Max Tool Calls:       20",
		"Max Shell Executions: 30",
		"Max Duration:         45 mins",
		"Max USD:              $12.5",
		"On Attempt Failed:   retry",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("cápsula sem %q\n%s", want, got)
		}
	}
	for _, absent := range []string{"(não declarado)", "(nenhum)", "N/A"} {
		if strings.Contains(got, absent) {
			t.Errorf("cápsula não deveria conter %q", absent)
		}
	}
}

func TestGenerateContextCapsuleUsesPlaceholdersForMissingData(t *testing.T) {
	task := capsuleTask()
	task.ScopeContract.OutOfScope = nil
	task.AcceptanceContract.FrozenTests = nil
	task.BudgetContract = contract.BudgetContract{MaxAgentAttempts: 1}
	got := plan.GenerateContextCapsule(plan.ContextCapsuleOptions{Task: task})
	for _, want := range []string{
		"OUT OF SCOPE:\n  (não declarado)",
		"FROZEN ACCEPTANCE TESTS (não editar — o audit recusa a atestação se mudarem):\n  (nenhum)",
		"Max LLM Calls:        N/A",
		"Max Tool Calls:       N/A",
		"Max Shell Executions: N/A",
		"Max Duration:         N/A mins",
		"Max USD:              $N/A",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("cápsula sem %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "PLANO (o audit exige") {
		t.Error("sem contexto de plano, a seção PLANO não deve aparecer")
	}
}

func TestGenerateContextCapsulePlanSection(t *testing.T) {
	t.Run("plano sem RED, checks nem gates", func(t *testing.T) {
		got := plan.GenerateContextCapsule(plan.ContextCapsuleOptions{Task: capsuleTask(), Plan: &plan.CapsulePlanContext{}})
		for _, want := range []string{
			"PLANO (o audit exige EXATAMENTE estes comandos):",
			"  RED:        (o plano não declara RED)",
			"  (o plano não declara checks de aceitação)",
			"  GATES GLOBAIS: (N/A)",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("cápsula sem %q\n%s", want, got)
			}
		}
	})
	t.Run("nomes longos não são truncados nem alinhados", func(t *testing.T) {
		got := plan.GenerateContextCapsule(plan.ContextCapsuleOptions{Task: capsuleTask(), Plan: &plan.CapsulePlanContext{
			RedCommand: "go test ./red",
			Checks: []plan.CapsuleCheckBinding{
				{Name: "AC-1", Commands: []string{"go test ./a", "go test ./b"}},
				{Name: "DOCUMENTATION", Commands: []string{"make docs"}},
				{Name: "VISUAL", Error: "a task não exige VISUAL"},
			},
			GlobalGates: []string{"make check"},
		}})
		for _, want := range []string{
			"  RED:        go test ./red",
			"  AC-1        `go test ./a` | `go test ./b`",
			"  DOCUMENTATION `make docs`",
			"  VISUAL      [a task não exige VISUAL]",
			"  GATES GLOBAIS: `make check`",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("cápsula sem %q\n%s", want, got)
			}
		}
	})
}

// writeContractWork monta um Work 0010 cuja task 1.1 aponta para o contrato
// indicado e grava o conteúdo do contrato, quando não vazio.
func writeContractWork(t *testing.T, root, contractID, contractContent string) {
	t.Helper()
	planJSON := `{"work_id":"0010","title":"t","components":[],"global_gates":[],"tasks":[` +
		`{"id":"1.1","title":"a","contract_id":"` + contractID + `","implementation_files":[],"test_files":[]},` +
		`{"id":"1.2","title":"sem contrato","contract_id":""}]}`
	writeWorkFile(t, root, "0010", "plan.json", planJSON)
	if contractContent != "" {
		writeWorkFile(t, root, "0010", contractID+".json", contractContent)
	}
}

func TestLoadTaskContractFailureModes(t *testing.T) {
	cases := []struct {
		name     string
		contract string
		task     string
		want     string
	}{
		{name: "task sem contract_id", task: "1.2", want: "Task 1.2 não vincula contract_id no plano do Work 0010"},
		{name: "arquivo do contrato ausente", task: "1.1", want: "Contrato CTR-404 não encontrado em"},
		{name: "JSON inválido", contract: "{ quebrado", task: "1.1", want: "Erro ao ler o contrato CTR-404"},
		{name: "versão antiga", contract: `{"contract_version": "3.0"}`, task: "1.1", want: "Contrato CTR-404 não é V4 (contract_version: 3.0)"},
		{name: "versão ausente", contract: `{"task_id": "1.1"}`, task: "1.1", want: "Contrato CTR-404 não é V4 (contract_version: ausente)"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			writeContractWork(t, root, "CTR-404", testCase.contract)
			loaded, err := plan.LoadTaskContract("0010", testCase.task, root)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("erro=%v; want contendo %q", err, testCase.want)
			}
			if loaded != nil {
				t.Errorf("contrato deveria ser nil em caso de erro; got %#v", loaded)
			}
		})
	}
}

func TestLoadTaskContractDefaultsToCurrentDirectory(t *testing.T) {
	root := t.TempDir()
	writeContractWork(t, root, "CTR-001", freezeContract)
	t.Chdir(root)
	loaded, err := plan.LoadTaskContract("0010", "1.1", "")
	if err != nil {
		t.Fatalf("carregar: %v", err)
	}
	if loaded.TaskID != "1.1" || loaded.ContractVersion != contract.ContractVersionV4 {
		t.Errorf("contrato=%#v", loaded)
	}
}

func TestLoadWorkContractsFailureModes(t *testing.T) {
	t.Run("work sem plan.json", func(t *testing.T) {
		contracts, err := plan.LoadWorkContracts("0010", t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "plan.json não encontrado para o Work 0010") {
			t.Fatalf("erro=%v", err)
		}
		if contracts != nil {
			t.Errorf("contratos=%#v", contracts)
		}
	})
	t.Run("erro de uma task interrompe a carga", func(t *testing.T) {
		root := t.TempDir()
		writeContractWork(t, root, "CTR-001", freezeContract)
		contracts, err := plan.LoadWorkContracts("0010", root)
		if err == nil || !strings.Contains(err.Error(), "Task 1.2 não vincula contract_id") {
			t.Fatalf("erro=%v", err)
		}
		if contracts != nil {
			t.Errorf("contratos=%#v", contracts)
		}
	})
}

func freezeOptions(dir string, paths ...string) plan.FreezeOptions {
	return plan.FreezeOptions{WorkID: "0005", TaskID: "1.1", Paths: paths, RootDir: dir}
}

func TestFreezeAcceptanceTestsMoreRejections(t *testing.T) {
	t.Run("task inexistente", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		options := freezeOptions(dir, "tests/acceptance_test.go")
		options.TaskID = "9.9"
		_, err := plan.FreezeAcceptanceTests(context.Background(), options)
		if err == nil || !strings.Contains(err.Error(), "Task 9.9 não encontrada no plan.json do Work 0005") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("work sem plano", func(t *testing.T) {
		_, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(t.TempDir(), "x_test.go"))
		if err == nil || !strings.Contains(err.Error(), "não encontrada no plan.json do Work 0005") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("task sem contract_id", func(t *testing.T) {
		root := t.TempDir()
		writeContractWork(t, root, "CTR-001", freezeContract)
		options := plan.FreezeOptions{WorkID: "0010", TaskID: "1.2", Paths: []string{"x_test.go"}, RootDir: root}
		_, err := plan.FreezeAcceptanceTests(context.Background(), options)
		if err == nil || !strings.Contains(err.Error(), "Task 1.2 não vincula contract_id") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("arquivo inexistente", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		_, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(dir, "tests/nao_existe_test.go"))
		if err == nil || !strings.Contains(err.Error(), "teste de aceitação não encontrado: tests/nao_existe_test.go") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("diretório não é teste", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		_, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(dir, "tests"))
		if err == nil || !strings.Contains(err.Error(), "teste de aceitação não encontrado: tests") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("arquivo versionado com alteração pendente", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		path := filepath.Join(dir, "tests", "acceptance_test.go")
		if err := os.WriteFile(path, []byte("package tests\n\n// editado\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(dir, "tests/acceptance_test.go"))
		if err == nil || !strings.Contains(err.Error(), "precisa estar commitado e sem alterações") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("contrato ausente não é gravado", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		if err := os.Remove(filepath.Join(dir, ".pwn", "work", "0005", "CTR-001.json")); err != nil {
			t.Fatal(err)
		}
		_, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(dir, "tests/acceptance_test.go"))
		if err == nil || !strings.Contains(err.Error(), "Contrato CTR-001 não encontrado") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("contrato somente leitura", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignora permissões de arquivo")
		}
		dir := setupFreezeRepo(t)
		contractPath := filepath.Join(dir, ".pwn", "work", "0005", "CTR-001.json")
		if err := os.Chmod(contractPath, 0o444); err != nil {
			t.Fatal(err)
		}
		_, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(dir, "tests/acceptance_test.go"))
		if err == nil || !os.IsPermission(err) && !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("erro=%v; want permissão negada", err)
		}
		data, readErr := os.ReadFile(contractPath)
		if readErr != nil || string(data) != freezeContract {
			t.Errorf("contrato não deveria mudar: err=%v", readErr)
		}
	})
}

func TestFreezeAcceptanceTestsDefaultsToCurrentDirectory(t *testing.T) {
	dir := setupFreezeRepo(t)
	t.Chdir(dir)
	result, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
		WorkID: "0005", TaskID: "1.1", Paths: []string{"tests/acceptance_test.go"},
	})
	if err != nil {
		t.Fatalf("congelar: %v", err)
	}
	if result.ContractID != "CTR-001" || len(result.Frozen) != 1 || result.Frozen[0].Path != "tests/acceptance_test.go" {
		t.Errorf("resultado=%#v", result)
	}
}

func TestFreezeAcceptanceTestsKeepsContractFieldsAndNoHTMLEscape(t *testing.T) {
	dir := setupFreezeRepo(t)
	contractPath := filepath.Join(dir, ".pwn", "work", "0005", "CTR-001.json")
	withHTML := strings.Replace(freezeContract, `"Freeze target"`, `"A <b> & C"`, 1)
	if err := os.WriteFile(contractPath, []byte(withHTML), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := plan.FreezeAcceptanceTests(context.Background(), freezeOptions(dir, "tests/acceptance_test.go")); err != nil {
		t.Fatalf("congelar: %v", err)
	}
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"title": "A <b> & C"`) {
		t.Errorf("o JSON gravado deveria manter <, > e & sem escape; got:\n%s", data)
	}
	if !strings.HasPrefix(string(data), "{\n  \"contract_version\": \"4.0\",\n") {
		t.Errorf("indentação de dois espaços ausente:\n%s", data)
	}
}
