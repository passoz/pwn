package work_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/work"
)

func TestScaffoldWorkCreatesCompleteValidChain(t *testing.T) {
	root := t.TempDir()
	result, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo de Pagamentos PIX"})
	if err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	if result.WorkID != "0001" {
		t.Fatalf("WorkID = %s", result.WorkID)
	}
	for _, file := range []string{
		"discovery.json", "requirements.json", "prd.json", "spec.json", "plan.json",
		"CTR-001.json", "traceability-matrix.json",
	} {
		if _, err := os.Stat(filepath.Join(root, ".pwn", "work", "0001", file)); err != nil {
			t.Fatalf("faltou %s: %v", file, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".todo", "0001-tasks.md")); err != nil {
		t.Fatalf("faltou o markdown derivado: %v", err)
	}

	validation := assets.ValidateWorkDocuments("0001", root)
	if len(validation) != 2 {
		t.Fatalf("documentos validados = %d, quer 2", len(validation))
	}
	for _, entry := range validation {
		if len(entry.Errors) != 0 {
			t.Fatalf("%s: %v", entry.File, entry.Errors)
		}
	}
}

func TestScaffoldWorkPassesFiveGatesAndValidator(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo de Pagamentos PIX"}); err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	workDir := filepath.Join(root, ".pwn", "work", "0001")
	for _, output := range []gates.GateOutput{
		gates.EvaluateGateDiscReq("0001", workDir),
		gates.EvaluateGateReqPrd("0001", workDir),
		gates.EvaluateGatePrdSpec("0001", workDir),
		gates.EvaluateGateSpecPlan("0001", workDir),
		gates.EvaluateGatePlanContract("0001", workDir),
	} {
		if output.Result == gates.ResultBlocked {
			t.Fatalf("%s bloqueou: %+v", output.Gate, output.Findings)
		}
	}
	markdownPath := filepath.Join(root, ".todo", "0001-tasks.md")
	if errors := plan.ValidateTasks(markdownPath, plan.AnalyzeOptions{}); len(errors) != 0 {
		t.Fatalf("validador v3: %v", errors)
	}
}

func TestScaffoldWorkRoundTripsMarkdown(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo de Pagamentos PIX"}); err != nil {
		t.Fatal(err)
	}
	loaded := plan.LoadPlan("0001", root)
	if loaded == nil {
		t.Fatal("plan.json não carregou")
	}
	markdown := readFile(t, root, filepath.Join(".todo", "0001-tasks.md"))
	rendered := plan.RenderTasksMarkdown(*loaded)
	if plan.NormalizeMarkers(markdown) != plan.NormalizeMarkers(rendered) {
		t.Fatalf("round-trip divergente:\n--- markdown\n%s\n--- render\n%s", markdown, rendered)
	}
}

func TestScaffoldWorkFreezesLoadableContract(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo de Pagamentos PIX", Risk: contract.RiskL3}); err != nil {
		t.Fatal(err)
	}
	taskContract, err := plan.LoadTaskContract("0001", "1.1", root)
	if err != nil {
		t.Fatalf("LoadTaskContract: %v", err)
	}
	if taskContract.ContractVersion != contract.ContractVersionV4 {
		t.Fatalf("versão = %s", taskContract.ContractVersion)
	}
	if taskContract.Risk.Level != contract.RiskL3 {
		t.Fatalf("risco = %s", taskContract.Risk.Level)
	}
	if taskContract.ValidationStrategy != contract.StrategyTDDStrict {
		t.Fatalf("estratégia = %s", taskContract.ValidationStrategy)
	}
	if len(taskContract.AcceptanceContract.Commands) != 2 ||
		taskContract.AcceptanceContract.Commands[0] != work.DefaultAcceptance {
		t.Fatalf("comandos = %v", taskContract.AcceptanceContract.Commands)
	}
	if len(taskContract.ScopeContract.WriteAllow) == 0 {
		t.Fatal("write_allow vazio")
	}
}

func TestScaffoldWorkAutoIncrementAndPreservation(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Primeiro módulo"}); err != nil {
		t.Fatal(err)
	}
	if got := work.GetNextWorkID(root); got != "0002" {
		t.Fatalf("próximo = %s", got)
	}
	second, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Segundo módulo", WorkID: "0001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Generated) != 0 || len(second.Skipped) == 0 {
		t.Fatalf("segundo scaffold não preservou: generated=%v skipped=%v", second.Generated, second.Skipped)
	}
	for _, entry := range second.Skipped {
		if entry.Reason != "já existe (use --force para sobrescrever)" {
			t.Fatalf("motivo = %q", entry.Reason)
		}
	}
	forced, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Segundo módulo", WorkID: "0001", Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(forced.Generated) == 0 {
		t.Fatal("--force não regenerou nada")
	}
}

func TestScaffoldWorkRejectsInvalidInput(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "abc"}); err == nil {
		t.Fatal("título curto devia falhar")
	}
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Título válido", WorkID: "1"}); err == nil {
		t.Fatal("Work ID inválido devia falhar")
	}
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Título válido", Risk: contract.RiskLevel("L9")}); err == nil {
		t.Fatal("risco inválido devia falhar")
	}
}

func TestScaffoldContractBuildsShellAllowlist(t *testing.T) {
	taskContract, err := work.ScaffoldContract("0001", "1.1", "Tarefa", contract.RiskL2, nil)
	if err != nil {
		t.Fatalf("ScaffoldContract: %v", err)
	}
	if len(taskContract.AcceptanceContract.Commands) != 2 ||
		taskContract.AcceptanceContract.Commands[0] != "bun test" ||
		taskContract.AcceptanceContract.Commands[1] != "bun run check" {
		t.Fatalf("comandos = %v", taskContract.AcceptanceContract.Commands)
	}
	if taskContract.Risk.Level != contract.RiskL2 {
		t.Fatalf("risco = %s", taskContract.Risk.Level)
	}
	scoped, err := work.ScaffoldContract("0001", "1.1", "Tarefa", contract.RiskL2, &work.ScaffoldScope{
		WriteAllow: []string{"src/add.ts"},
		WriteDeny:  []string{"package.json"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped.ScopeContract.WriteAllow) != 1 || scoped.ScopeContract.WriteAllow[0] != "src/add.ts" {
		t.Fatalf("write_allow = %v", scoped.ScopeContract.WriteAllow)
	}
}

func TestScaffoldWorkDeclaresConcreteFocusedFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo de Pagamentos PIX"}); err != nil {
		t.Fatal(err)
	}
	loaded := plan.LoadPlan("0001", root)
	if loaded == nil || len(loaded.Tasks) != 1 {
		t.Fatalf("plano = %+v", loaded)
	}
	task := loaded.Tasks[0]
	implementationFile := "src/modulo-de-pagamentos-pix.ts"
	testFile := "tests/modulo-de-pagamentos-pix.test.ts"
	if len(task.ImplementationFiles) != 1 || task.ImplementationFiles[0] != implementationFile {
		t.Fatalf("implementation_files = %v", task.ImplementationFiles)
	}
	if len(task.TestFiles) != 1 || task.TestFiles[0] != testFile {
		t.Fatalf("test_files = %v", task.TestFiles)
	}
	for _, file := range append(append([]string{}, task.ImplementationFiles...), task.TestFiles...) {
		if reason := plan.PlaceholderPathReason(file); reason != "" {
			t.Fatalf("caminho não concreto %s: %s", file, reason)
		}
	}
	focused := "bun test " + testFile
	if plan.NormalizeCommand(task.Red.Command) != plan.NormalizeCommand(focused) {
		t.Fatalf("RED = %q", task.Red.Command)
	}
	if plan.NormalizeCommand(task.AcceptanceCriteria[0].Command) != plan.NormalizeCommand(focused) {
		t.Fatalf("AC = %q", task.AcceptanceCriteria[0].Command)
	}
	if plan.IsWholeSuiteCommand(task.AcceptanceCriteria[0].Command) {
		t.Fatal("a AC focada não pode ser a suíte inteira")
	}
	if reason := plan.GenericCommandReason(task.AcceptanceCriteria[0].Command, []string{"bun test", "bun run check"}); reason != "" {
		t.Fatalf("AC genérica: %s", reason)
	}
}

func TestScaffoldAtL3AsksToFreezeTests(t *testing.T) {
	root := t.TempDir()
	result, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo de Pagamentos PIX", Risk: contract.RiskL3})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range result.Review {
		if contains(line, "--freeze-tests") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("review sem --freeze-tests: %v", result.Review)
	}
}

func TestScaffoldWorkCopiesSourceSnapshot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "spec.md", "# Spec antiga\n")
	result, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Módulo legado", SourcePath: "spec.md"})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, root, filepath.Join(".pwn", "work", "0001", "legacy-spec.md")) != "# Spec antiga\n" {
		t.Fatal("snapshot da fonte divergente")
	}
	if len(result.Generated) == 0 {
		t.Fatal("nenhum arquivo gerado")
	}
}
