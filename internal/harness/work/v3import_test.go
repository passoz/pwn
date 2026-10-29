package work_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/work"
)

// readTestdata lê um fixture de testdata/v3.
func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "v3", name))
	if err != nil {
		t.Fatalf("ler testdata/v3/%s: %v", name, err)
	}
	return string(data)
}

// v3Fixture cria o layout v3 de um Work.
func v3Fixture(t *testing.T, planMarkdown string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, ".work/0004.json", `{"version":1,"work_id":"0004","state":"planned"}`)
	writeFile(t, root, ".todo/0004-tasks.md", planMarkdown)
	writeFile(t, root, ".prompts/0004-change.md", readTestdata(t, "prompt.md"))
	writeFile(t, root, ".sources/0004-local.md", "# Origem\n\nPedido original.\n")
	writeFile(t, root, ".specs/system.md", readTestdata(t, "system.md"))
	return root
}

func TestParseV3PlanMarkdown(t *testing.T) {
	planValue := work.ParseV3PlanMarkdown(readTestdata(t, "plan.md"), "0004")
	if planValue.Title != "Migração de Autenticação" || planValue.WorkID != "0004" {
		t.Fatalf("plano = %+v", planValue)
	}
	if len(planValue.Tasks) != 2 || len(planValue.GlobalGates) != 2 {
		t.Fatalf("tasks=%d gates=%d", len(planValue.Tasks), len(planValue.GlobalGates))
	}
	component := planValue.Components[0]
	if component.Name != "jachegai-bun" {
		t.Fatalf("componente = %+v", component)
	}
	if component.Regression == nil || *component.Regression != "bun test" {
		t.Fatalf("regression = %v", component.Regression)
	}
	if component.Health == nil || *component.Health != "N/A" {
		t.Fatalf("health = %v", component.Health)
	}
	first, second := planValue.Tasks[0], planValue.Tasks[1]
	if first.ID != "4.1" || first.RequirementID != "FR-001" || len(first.DependsOn) != 0 {
		t.Fatalf("task 0 = %+v", first)
	}
	if len(first.ImplementationFiles) != 1 || first.ImplementationFiles[0] != "src/auth/index.ts" {
		t.Fatalf("implementation_files = %v", first.ImplementationFiles)
	}
	if len(first.TestFiles) != 1 || first.TestFiles[0] != "tests/auth/init.test.ts" {
		t.Fatalf("test_files = %v", first.TestFiles)
	}
	if first.Red.Command != "bun test tests/auth/init.test.ts" {
		t.Fatalf("RED = %q", first.Red.Command)
	}
	if len(first.AcceptanceCriteria) != 1 || first.AcceptanceCriteria[0].Command != "bun test tests/auth/init.test.ts" {
		t.Fatalf("ACs = %+v", first.AcceptanceCriteria)
	}
	if len(first.ImplementationSteps) != 2 || first.Status != "done" || first.ContractID != "CTR-001" {
		t.Fatalf("task 0 = %+v", first)
	}
	if len(second.DependsOn) != 1 || second.DependsOn[0] != "4.1" || second.ContractID != "CTR-002" {
		t.Fatalf("task 1 = %+v", second)
	}
}

func TestV3PlanMarkdownRoundTripIsByteIdentical(t *testing.T) {
	markdown := readTestdata(t, "plan.md")
	planValue := work.ParseV3PlanMarkdown(markdown, "0004")
	rendered := plan.RenderTasksMarkdown(planValue)
	if got, want := plan.NormalizeMarkers(rendered), plan.NormalizeMarkers(markdown); got != want {
		t.Fatalf("render(parse(md)) divergiu:\n--- render\n%s\n--- original\n%s", got, want)
	}
}

func TestParsePromptDigest(t *testing.T) {
	digest := work.ParsePromptDigest(readTestdata(t, "prompt.md"))
	if !contains(digest.Problem, "gerenciamento manual de sessões") {
		t.Fatalf("problema = %q", digest.Problem)
	}
	if !contains(digest.Solution, "motor de autenticação padronizado") {
		t.Fatalf("solução = %q", digest.Solution)
	}
	if len(digest.Actors) != 2 || digest.Actors[0] != "Cliente" || digest.Actors[1] != "Administrador" {
		t.Fatalf("atores = %v", digest.Actors)
	}
	if len(digest.InScope) != 2 || digest.InScope[0] != "`src/auth/` — motor de autenticação." {
		t.Fatalf("inScope = %v", digest.InScope)
	}
	if len(digest.OutOfScope) != 1 || digest.OutOfScope[0] != "Migração de dados históricos." {
		t.Fatalf("outOfScope = %v", digest.OutOfScope)
	}
	found := false
	for _, requirement := range digest.Requirements {
		if requirement.ID == "FR-001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("requirements = %+v", digest.Requirements)
	}
	if len(digest.Constraints) != 1 || !contains(digest.Constraints[0], "QR-001") {
		t.Fatalf("constraints = %v", digest.Constraints)
	}
}

func TestParseCapabilityMap(t *testing.T) {
	capabilityMap := work.ParseCapabilityMap(readTestdata(t, "system.md"))
	if len(capabilityMap.Capabilities) != 4 {
		t.Fatalf("capabilities = %+v", capabilityMap.Capabilities)
	}
	if capabilityMap.Capabilities[1].Name != "Identity and Access" || capabilityMap.Capabilities[1].ID != "CAP-002" {
		t.Fatalf("capability 1 = %+v", capabilityMap.Capabilities[1])
	}
	if len(capabilityMap.Rules) != 2 || capabilityMap.Rules[0].ID != "BR-001" {
		t.Fatalf("rules = %+v", capabilityMap.Rules)
	}
}

func TestDeriveContractUsesTaskDeclarations(t *testing.T) {
	planValue := work.ParseV3PlanMarkdown(readTestdata(t, "plan.md"), "0004")
	taskContract, err := work.DeriveContract(planValue, planValue.Tasks[0], "0004", contract.RiskL2)
	if err != nil {
		t.Fatalf("DeriveContract: %v", err)
	}
	if taskContract.ContractVersion != "4.0" || taskContract.Risk.Level != contract.RiskL2 {
		t.Fatalf("contrato = %+v", taskContract)
	}
	if taskContract.ValidationStrategy != contract.StrategyTDDStrict {
		t.Fatalf("estratégia = %s", taskContract.ValidationStrategy)
	}
	if !containsSlice(taskContract.AcceptanceContract.Commands, "bun test tests/auth/init.test.ts") ||
		!containsSlice(taskContract.AcceptanceContract.Commands, "bun run check") {
		t.Fatalf("comandos = %v", taskContract.AcceptanceContract.Commands)
	}
	if len(taskContract.ScopeContract.WriteAllow) != 2 ||
		taskContract.ScopeContract.WriteAllow[0] != "src/auth/index.ts" ||
		taskContract.ScopeContract.WriteAllow[1] != "tests/auth/init.test.ts" {
		t.Fatalf("write_allow = %v", taskContract.ScopeContract.WriteAllow)
	}
	if !containsSlice(taskContract.ScopeContract.WriteDeny, "package.json") {
		t.Fatalf("write_deny = %v", taskContract.ScopeContract.WriteDeny)
	}
	if len(taskContract.BehavioralContract.Scenarios) == 0 {
		t.Fatal("contrato sem cenários")
	}
}

func TestFindV3WorkAndListWorkIDs(t *testing.T) {
	root := v3Fixture(t, readTestdata(t, "plan.md"))
	ids := work.ListV3WorkIDs(root)
	if len(ids) != 1 || ids[0] != "0004" {
		t.Fatalf("ids = %v", ids)
	}
	files, err := work.FindV3Work(root, "0004")
	if err != nil || files == nil {
		t.Fatalf("FindV3Work: %v", err)
	}
	if filepath.Base(files.PlanPath) != "0004-tasks.md" {
		t.Fatalf("plan = %s", files.PlanPath)
	}
	if files.PromptPath == nil || filepath.Base(*files.PromptPath) != "0004-change.md" {
		t.Fatalf("prompt = %v", files.PromptPath)
	}
	if files.SystemSpecPath == nil || files.SourcePath == nil || files.ManifestPath == nil {
		t.Fatalf("artefatos v3 = %+v", files)
	}
	if files, err := work.FindV3Work(root, "9999"); err != nil || files != nil {
		t.Fatalf("Work ausente = %+v, err=%v", files, err)
	}
}

func TestImportV3WorkWritesCanonicalArtifactsWithoutTouchingV3(t *testing.T) {
	markdown := readTestdata(t, "plan.md")
	root := v3Fixture(t, markdown)
	result, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	workDir := filepath.Join(root, ".pwn", "work", "0004")
	for _, file := range []string{"plan.json", "CTR-001.json", "CTR-002.json"} {
		if _, err := os.Stat(filepath.Join(workDir, file)); err != nil {
			t.Fatalf("faltou %s: %v", file, err)
		}
	}
	if !containsSlice(result.Generated, "plan.json") {
		t.Fatalf("generated = %v", result.Generated)
	}
	imported := readFile(t, root, filepath.Join(".pwn", "work", "0004", "plan.json"))
	if !contains(imported, `"tasks"`) {
		t.Fatalf("plan.json = %s", imported)
	}
	for _, task := range result.Plan.Tasks {
		if task.SpecReference == "" || !contains(task.SpecReference, "CAP-") {
			t.Fatalf("spec_reference = %q", task.SpecReference)
		}
	}

	again, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"})
	if err != nil {
		t.Fatalf("segunda importação: %v", err)
	}
	if len(again.Generated) != 0 {
		t.Fatalf("generated = %v", again.Generated)
	}
	for _, entry := range again.Skipped {
		if !contains(entry.Reason, "já existe") {
			t.Fatalf("motivo = %q", entry.Reason)
		}
	}
	if readFile(t, root, ".todo/0004-tasks.md") != markdown {
		t.Fatal("a importação alterou o markdown v3")
	}
}

func TestImportV3WorkGateChainPassesFiveGates(t *testing.T) {
	root := v3Fixture(t, readTestdata(t, "plan.md"))
	result, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004", GateChain: true, Force: true})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	for _, name := range []string{"discovery.json", "requirements.json", "prd.json", "spec.json", "traceability-matrix.json"} {
		if !containsSlice(result.Generated, name) {
			t.Fatalf("faltou %s em generated=%v", name, result.Generated)
		}
	}
	workDir := filepath.Join(root, ".pwn", "work", "0004")
	for _, validation := range assets.ValidateWorkDocuments("0004", root) {
		if len(validation.Errors) != 0 {
			t.Fatalf("%s: %v", validation.File, validation.Errors)
		}
	}
	for _, output := range []gates.GateOutput{
		gates.EvaluateGateDiscReq("0004", workDir),
		gates.EvaluateGateReqPrd("0004", workDir),
		gates.EvaluateGatePrdSpec("0004", workDir),
		gates.EvaluateGateSpecPlan("0004", workDir),
		gates.EvaluateGatePlanContract("0004", workDir),
	} {
		if output.Result == gates.ResultBlocked {
			t.Fatalf("%s bloqueou: %+v", output.Gate, output.Findings)
		}
	}
}

func TestDeriveTaskRisk(t *testing.T) {
	base := work.ParseV3PlanMarkdown(readTestdata(t, "plan.md"), "0004").Tasks[0]
	cases := []struct {
		name string
		task func() plan.PlanTask
		want contract.RiskLevel
	}{
		{
			name: "sessão e credenciais são L3",
			task: func() plan.PlanTask {
				task := base
				task.Title = "Validar sessão e credenciais de login"
				return task
			},
			want: contract.RiskL3,
		},
		{
			name: "HMAC de webhook é L3",
			task: func() plan.PlanTask {
				task := base
				task.Title = "Verificação de assinatura HMAC em webhooks de pagamento"
				return task
			},
			want: contract.RiskL3,
		},
		{
			name: "documentação é L1",
			task: func() plan.PlanTask {
				task := base
				task.Title = "Atualizar README e documentação do módulo"
				task.Behavior = "descreve o formato do changelog"
				task.Files = []string{"README.md", "docs/modulo.md"}
				task.Red = plan.PlanRed{Command: "bun test", Description: "validação de documentação"}
				task.AcceptanceCriteria = []plan.PlanAC{{Command: "bun test", Description: "documentação publicada"}}
				return task
			},
			want: contract.RiskL1,
		},
		{
			name: "domínio é L2",
			task: func() plan.PlanTask {
				task := base
				task.Title = "Refatorar cálculo de saldo do domínio"
				task.Behavior = "consolida lançamentos e valida o saldo"
				task.Files = []string{"src/domain/money.ts"}
				task.Red = plan.PlanRed{Command: "bun test tests/domain/money.test.ts", Description: "saldo incorreto antes da implementação"}
				task.AcceptanceCriteria = []plan.PlanAC{{Command: "bun test tests/domain/money.test.ts", Description: "saldo consolidado correto"}}
				return task
			},
			want: contract.RiskL2,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := work.DeriveTaskRisk(test.task()); got != test.want {
				t.Fatalf("risco = %s, quer %s", got, test.want)
			}
		})
	}
	if work.DeriveTaskRisk(base) == contract.RiskL4 {
		t.Fatal("L4 nunca é automático")
	}
}

func TestMapTaskToCapability(t *testing.T) {
	capabilityMap := work.ParseCapabilityMap(readTestdata(t, "system.md"))
	planValue := work.ParseV3PlanMarkdown(readTestdata(t, "plan.md"), "0004")
	id, score := work.MapTaskToCapability(planValue.Tasks[0], capabilityMap)
	if id != "CAP-002" || score == 0 {
		t.Fatalf("identity = %s (%d)", id, score)
	}
	customer := planValue.Tasks[0]
	customer.Title = "Exportação de dados e endereços do titular (LGPD)"
	customer.Behavior = ""
	customer.Files = []string{}
	customer.Red = plan.PlanRed{Command: "bun test", Description: ""}
	customer.AcceptanceCriteria = []plan.PlanAC{{Command: "bun test", Description: ""}}
	id, score = work.MapTaskToCapability(customer, capabilityMap)
	if score == 0 || id != "CAP-003" {
		t.Fatalf("customer = %s (%d)", id, score)
	}
}

func TestImportV3WorkRiskAutoFreezesRiskPerTask(t *testing.T) {
	root := v3Fixture(t, readTestdata(t, "plan.md"))
	result, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004", Risk: "auto", Force: true})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	if len(result.RiskMapping) != 2 {
		t.Fatalf("riskMapping = %+v", result.RiskMapping)
	}
	for _, entry := range result.RiskMapping {
		if entry.Risk != contract.RiskL3 {
			t.Fatalf("risco de %s = %s", entry.Task, entry.Risk)
		}
	}
	taskContract, err := plan.LoadTaskContract("0004", "4.1", root)
	if err != nil {
		t.Fatal(err)
	}
	if taskContract.Risk.Level != contract.RiskL3 {
		t.Fatalf("contrato = %s", taskContract.Risk.Level)
	}
}

// fakeDecider é um RiskDecider controlado pelo teste.
type fakeDecider struct {
	decision work.RiskDecision
	err      error
}

func (d fakeDecider) RaiseRisk(_ context.Context, _ string, _ []work.RiskCandidate) (work.RiskDecision, error) {
	return d.decision, d.err
}

func TestImportRiskDeciderCanRaiseButNeverLowerOrL4(t *testing.T) {
	markdown := readTestdata(t, "plan.md")
	root := v3Fixture(t, markdown)
	result, err := work.ImportV3Work(work.V3ImportOptions{
		RootDir: root, WorkID: "0004", Risk: "auto", Force: true,
		Decider: fakeDecider{decision: work.RiskDecision{Raises: []work.RiskRaise{
			{Task: "4.1", From: contract.RiskL3, To: contract.RiskL4, Confidence: 0.99, DecisionID: "DEC-R1"},
			{Task: "inexistente", From: contract.RiskL2, To: contract.RiskL3, Confidence: 0.8, DecisionID: "DEC-R2"},
			{Task: "4.2", From: contract.RiskL3, To: contract.RiskL2, Confidence: 0.8, DecisionID: "DEC-R3"},
		}}},
	})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	for _, entry := range result.RiskMapping {
		if entry.Risk != contract.RiskL3 {
			t.Fatalf("risco de %s = %s (o decisor rebaixou ou elevou a L4)", entry.Task, entry.Risk)
		}
	}
	if !containsWarning(result.Warnings, "L4 exige decisão humana") ||
		!containsWarning(result.Warnings, "task inexistente") ||
		!containsWarning(result.Warnings, "nunca rebaixa") {
		t.Fatalf("warnings = %v", result.Warnings)
	}
}

func TestImportRiskDeciderRaisesDeterministicRisk(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0005-tasks.md", statusPlanMarkdown([]string{
		statusTaskBlock("1.1", " ", "FR-001", "none", "Refatorar saldo do dominio"),
	}, "N/A", "0005"))
	result, err := work.ImportV3Work(work.V3ImportOptions{
		RootDir: root, WorkID: "0005", Risk: "auto",
		Decider: fakeDecider{decision: work.RiskDecision{Raises: []work.RiskRaise{
			{Task: "1.1", From: contract.RiskL2, To: contract.RiskL3, Confidence: 0.91, DecisionID: "DEC-R4"},
		}}},
	})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	if result.RiskMapping[0].Risk != contract.RiskL3 {
		t.Fatalf("risco = %s", result.RiskMapping[0].Risk)
	}
	if !containsWarning(result.Warnings, "elevado pelo decisor de L2 para L3") {
		t.Fatalf("warnings = %v", result.Warnings)
	}
	taskContract, err := plan.LoadTaskContract("0005", "1.1", root)
	if err != nil {
		t.Fatal(err)
	}
	if taskContract.Risk.Level != contract.RiskL3 {
		t.Fatalf("contrato = %s", taskContract.Risk.Level)
	}
}

func TestImportRiskDeciderErrorFallsBackToHeuristic(t *testing.T) {
	root := v3Fixture(t, readTestdata(t, "plan.md"))
	result, err := work.ImportV3Work(work.V3ImportOptions{
		RootDir: root, WorkID: "0004", Risk: "auto", Force: true,
		Decider: fakeDecider{err: errors.New("decisor indisponível")},
	})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	if !containsWarning(result.Warnings, "decisor indisponível") {
		t.Fatalf("warnings = %v", result.Warnings)
	}
	if result.RiskMapping[0].Risk != contract.RiskL3 {
		t.Fatalf("heurística não foi mantida: %s", result.RiskMapping[0].Risk)
	}
}

func TestImportV3WorkRejectsMissingWork(t *testing.T) {
	root := t.TempDir()
	if _, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "9999"}); err == nil {
		t.Fatal("Work ausente devia falhar")
	}
}

func containsWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if contains(warning, fragment) {
			return true
		}
	}
	return false
}
