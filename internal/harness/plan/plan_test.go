package plan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
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

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("ler testdata/%s: %v", name, err)
	}
	return string(data)
}

// samplePlan reproduz o plano fixo do teste de referência do TypeScript.
func samplePlan() plan.Plan {
	return plan.Plan{
		WorkID: "0001",
		Title:  "pwn-ledger",
		Components: []plan.PlanComponent{
			{Name: "core-domain", Purpose: "Dominio e validacao dos lancamentos"},
			{Name: "cli", Purpose: "Interface de linha de comando"},
		},
		GlobalGates: []string{"`bun test` — a suíte completa permanece verde"},
		Tasks: []plan.PlanTask{
			{
				ID:                  "1.1",
				Title:               "Dominio de lancamentos",
				RequirementID:       "FR-001",
				DependsOn:           []string{},
				Behavior:            "Valida descricao, valor e tipo e calcula o saldo",
				Components:          []string{"core-domain"},
				Files:               []string{"src/ledger.ts", "tests/ledger.test.ts"},
				ImplementationFiles: []string{"src/ledger.ts"},
				TestFiles:           []string{"tests/ledger.test.ts"},
				Red: plan.PlanRed{
					Command:     "bun test tests/ledger.test.ts",
					Description: "a assercao de saldo consolidado falha antes da implementacao",
				},
				ImplementationSteps: []string{"Implementar addEntry com validacao", "Implementar computeBalance"},
				AcceptanceCriteria: []plan.PlanAC{
					{Command: "bun test tests/ledger.test.ts", Description: "a suite focada do dominio passa"},
					{Command: "bun test tests/ledger.test.ts -t 'saldo consolidado'", Description: "a assercao de saldo consolidado e observada"},
				},
				SpecReference: "CAP-001",
				ContractID:    "CTR-001",
				Complexity:    "medium",
			},
		},
	}
}

func TestRenderTasksMarkdownGolden(t *testing.T) {
	cases := []struct {
		name string
		plan plan.Plan
		want string
	}{
		{name: "sample", plan: samplePlan(), want: readTestdata(t, "sample-plan.md")},
		{
			name: "extended",
			plan: plan.Plan{
				WorkID: "0007",
				Title:  "extended plan",
				Components: []plan.PlanComponent{
					{Name: "backend-go", Purpose: "ignored", Root: new("."), Regression: new("go test ./..."), Lint: new("N/A"), Build: new("go build ./..."), Security: new("N/A"), Dev: new("N/A"), Health: new("N/A")},
					{Name: "docs", Purpose: "ignored"},
				},
				GlobalGates: []string{},
				Tasks: []plan.PlanTask{
					{
						ID:                  "2.1",
						Title:               "Extended",
						RequirementID:       "FR-002",
						DependsOn:           []string{"1.1"},
						Behavior:            "Renders the extended table",
						Components:          []string{"backend-go", "docs"},
						Files:               []string{"a.go"},
						ImplementationFiles: []string{"a.go"},
						TestFiles:           []string{},
						Red:                 plan.PlanRed{Command: "go test ./...", Description: "fails"},
						ImplementationSteps: []string{"Do it"},
						AcceptanceCriteria:  []plan.PlanAC{{Command: "go test ./...", Description: "passes"}},
						Visual:              "REQUIRED",
						Documentation:       "REQUIRED",
						SpecReference:       "CAP-002",
						ContractID:          "CTR-007",
						Complexity:          "standard",
						Status:              "blocked",
					},
				},
			},
			want: readTestdata(t, "extended-plan.md"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := plan.RenderTasksMarkdown(testCase.plan); got != testCase.want {
				t.Errorf("markdown divergente\n--- got ---\n%s\n--- want ---\n%s", got, testCase.want)
			}
		})
	}
}

// TestRenderWork0002 prova a paridade do renderizador com o plano do Work 0002 e
// com o markdown real do repositório.
func TestRenderWork0002(t *testing.T) {
	root := repoRoot(t)
	workPlan := plan.LoadPlan("0002", root)
	if workPlan == nil {
		t.Fatal("plan.json do Work 0002 não foi lido")
	}

	rendered := plan.RenderTasksMarkdown(*workPlan)
	if want := readTestdata(t, "0002-tasks.rendered.md"); rendered != want {
		t.Fatalf("render do Work 0002 diverge do golden do TypeScript")
	}

	existingPath := filepath.Join(root, ".todo", "0002-tasks.md")
	existing, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatalf("ler %s: %v", existingPath, err)
	}
	if !plan.PlanMatchesMarkdown(*workPlan, string(existing)) {
		t.Fatalf("plano renderizado não corresponde ao markdown existente")
	}
	if got, want := plan.NormalizeMarkers(rendered), plan.NormalizeMarkers(string(existing)); got != want {
		t.Fatalf("markdown normalizado diverge do arquivo .todo/0002-tasks.md")
	}

	tasks := plan.ParsePlanTasks(rendered)
	wantIDs := []string{"1.1", "1.2", "1.3", "1.4", "1.5"}
	if len(tasks) != len(wantIDs) {
		t.Fatalf("idas=%d tasks; want=%d", len(tasks), len(wantIDs))
	}
	for index, want := range wantIDs {
		if tasks[index].ID != want {
			t.Errorf("task %d: id=%q; want=%q", index, tasks[index].ID, want)
		}
		if tasks[index].Red == nil {
			t.Errorf("task %s sem RED", want)
		}
		if len(tasks[index].ACs) == 0 {
			t.Errorf("task %s sem AC", want)
		}
	}
}

func TestNormalizeMarkersIgnoresCheckboxState(t *testing.T) {
	clean := plan.RenderTasksMarkdown(samplePlan())
	if plan.NormalizeMarkers(clean) != clean {
		t.Fatal("normalização não é idempotente")
	}
	// Estado marcado em heading e gate não é divergência.
	toggled := replaceFirst(clean, "### [ ] [1.1]", "### [x] [1.1]")
	toggled = replaceFirst(toggled, "- [ ] `bun test`", "- [x] `bun test`")
	if plan.NormalizeMarkers(toggled) != plan.NormalizeMarkers(clean) {
		t.Fatal("normalização deveria ignorar o estado dos checkboxes")
	}
}

func TestPlanMatchesMarkdownDetectsDrift(t *testing.T) {
	planValue := samplePlan()
	markdown := plan.RenderTasksMarkdown(planValue)

	marked := replaceFirst(markdown, "### [ ] [1.1]", "### [x] [1.1]")
	if !plan.PlanMatchesMarkdown(planValue, marked) {
		t.Error("marcador de estado não deve contar como drift")
	}
	drifted := replaceFirst(markdown, "**Behavior:** Valida descricao", "**Behavior:** Alterado manualmente")
	if plan.PlanMatchesMarkdown(planValue, drifted) {
		t.Error("mudança estrutural deve ser detectada como drift")
	}
	if !plan.PlanMatchesMarkdown(planValue, markdown+"\n\n") {
		t.Error("espaço em branco no fim do arquivo não deve contar como drift")
	}
}

func replaceFirst(text, old, replacement string) string {
	for index := 0; index+len(old) <= len(text); index++ {
		if text[index:index+len(old)] == old {
			return text[:index] + replacement + text[index+len(old):]
		}
	}
	return text
}

func TestTasksMarkdownPath(t *testing.T) {
	if got, want := plan.TasksMarkdownPath("0002", "/repo"), filepath.Join("/repo", ".todo", "0002-tasks.md"); got != want {
		t.Errorf("path=%q; want=%q", got, want)
	}
}

func TestLoadPlanMissing(t *testing.T) {
	if got := plan.LoadPlan("9999", t.TempDir()); got != nil {
		t.Errorf("plano ausente deveria devolver nil; got %#v", got)
	}
}

func TestLoadPlanRejectsTasksMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pwn", "work", "0003")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "plan.json"), []byte(`{"work_id":"0003"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := plan.LoadPlan("0003", dir); got != nil {
		t.Errorf("plano sem tasks deveria devolver nil; got %#v", got)
	}
}

func TestValidatesRealPlan0002(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, ".todo", "0002-tasks.md")
	if errors := plan.ValidateTasks(path, plan.AnalyzeOptions{}); len(errors) != 0 {
		t.Fatalf("plano do Work 0002 deveria passar: %q", errors)
	}
	detailed := plan.ValidateTasksDetailed(path, plan.AnalyzeOptions{})
	if detailed.ContractVersion == nil || *detailed.ContractVersion != plan.CurrentTaskContractVersion {
		t.Fatalf("contractVersion=%v", detailed.ContractVersion)
	}
	if detailed.WorkID == nil || *detailed.WorkID != "0002" {
		t.Fatalf("workId=%v", detailed.WorkID)
	}

	var stdout, stderr bytes.Buffer
	if code := plan.ValidateTasksMain([]string{path}, &stdout, &stderr); code != 0 {
		t.Fatalf("CLI falhou: code=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS:") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
