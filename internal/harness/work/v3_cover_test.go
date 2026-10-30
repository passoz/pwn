package work_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/work"
)

// jsonUnmarshalFile lê um JSON do Work para uma estrutura de teste.
func jsonUnmarshalFile(t *testing.T, root, relative string, target any) error {
	t.Helper()
	return json.Unmarshal([]byte(readFile(t, root, relative)), target)
}

func TestParseV3PlanMarkdownWithoutTasksUsesFallbackTitle(t *testing.T) {
	parsed := work.ParseV3PlanMarkdown("sem nada de útil\n", "0009")
	if parsed.WorkID != "0009" || parsed.Title != "Work 0009" {
		t.Fatalf("plano = %+v", parsed)
	}
	if parsed.Components == nil || parsed.GlobalGates == nil || parsed.Tasks == nil {
		t.Fatalf("listas do plano não podem ser nil: %+v", parsed)
	}
	if len(parsed.Components)+len(parsed.GlobalGates)+len(parsed.Tasks) != 0 {
		t.Fatalf("plano deveria estar vazio: %+v", parsed)
	}
}

func TestParseV3PlanMarkdownMarkersDefaultsAndDuplicateFields(t *testing.T) {
	markdown := strings.Join([]string{
		"# Tasks: Plano com CRLF",
		"",
		"## Execution contract",
		"",
		"| Component | Purpose | Root | Lint | Build |",
		"|-----------|---------|------|------|-------|",
		"| `api` | Serviço HTTP | `services/api` |  | `go build` |",
		"",
		"## Global gates",
		"- [ ] `go test ./...` — suíte completa",
		"- [x] `go vet ./...` — análise estática",
		"outra linha ignorada",
		"",
		"### [x] [1.1] Primeira feita",
		"",
		"**Depends on:** none",
		"**Behavior:** primeiro comportamento",
		"**Behavior:** comportamento duplicado ignorado",
		"**Components:** api, `core`, N/A",
		"**Files:** src/a.go, `src/a_test.go`",
		"**Implementation files:** src/a.go",
		"**Test files:** src/a_test.go",
		"**Visual:** REQUIRED",
		"**Documentation:** REQUIRED",
		"",
		"### [!] [1.2] Segunda bloqueada",
		"",
		"**Requirement:** `US-004`",
		"**Depends on:** `1.1`, N/A, 0002/3.1",
		"**RED:**",
		"- `go test ./a` — falha com a nova asserção",
		"- `go test ./b` — segunda linha não vira RED",
		"",
		"**Implementation:**",
		"1. Primeiro passo",
		"2. Segundo passo",
		"",
		"3. Terceiro depois do vazio não entra",
		"",
		"**ACs:**",
		"- [ ] `go test ./a` — passa",
		"- [x] `go test ./b`",
		"",
		"### [ ] [1.3] Terceira pendente",
		"",
	}, "\r\n")

	parsed := work.ParseV3PlanMarkdown(markdown, "0004")
	if parsed.Title != "Plano com CRLF" {
		t.Fatalf("título = %q", parsed.Title)
	}
	if len(parsed.Components) != 1 {
		t.Fatalf("components = %+v", parsed.Components)
	}
	component := parsed.Components[0]
	if component.Name != "api" || component.Purpose != "Serviço HTTP" ||
		component.Root == nil || *component.Root != "services/api" ||
		component.Lint == nil || *component.Lint != "N/A" ||
		component.Build == nil || *component.Build != "go build" ||
		component.Security != nil || component.Dev != nil {
		t.Fatalf("component = %+v", component)
	}
	if strings.Join(parsed.GlobalGates, "|") != "`go test ./...` — suíte completa|`go vet ./...` — análise estática" {
		t.Fatalf("gates = %v", parsed.GlobalGates)
	}
	if len(parsed.Tasks) != 3 {
		t.Fatalf("tasks = %+v", parsed.Tasks)
	}

	first := parsed.Tasks[0]
	if first.Status != "done" || first.RequirementID != "FR-001" || first.ContractID != "CTR-001" ||
		first.Behavior != "primeiro comportamento" || first.Visual != "REQUIRED" || first.Documentation != "REQUIRED" {
		t.Fatalf("task 1.1 = %+v", first)
	}
	if strings.Join(first.Components, ",") != "api,core" || strings.Join(first.Files, ",") != "src/a.go,src/a_test.go" {
		t.Fatalf("listas 1.1 = %v / %v", first.Components, first.Files)
	}
	if len(first.DependsOn) != 0 || first.DependsOn == nil {
		t.Fatalf("depends 1.1 = %#v", first.DependsOn)
	}
	if first.Red.Command != "bun test" || first.Red.Description != "RED de 1.1" {
		t.Fatalf("RED padrão = %+v", first.Red)
	}
	if len(first.AcceptanceCriteria) != 1 || first.AcceptanceCriteria[0].Command != "bun test" ||
		first.AcceptanceCriteria[0].Description != "Aceitação de 1.1" {
		t.Fatalf("ACs padrão = %+v", first.AcceptanceCriteria)
	}
	if len(first.ImplementationSteps) != 1 || first.ImplementationSteps[0] != "Implementar o comportamento declarado" {
		t.Fatalf("passos padrão = %v", first.ImplementationSteps)
	}

	second := parsed.Tasks[1]
	if second.Status != "blocked" || second.RequirementID != "US-004" || second.ContractID != "CTR-002" {
		t.Fatalf("task 1.2 = %+v", second)
	}
	if strings.Join(second.DependsOn, ",") != "1.1,0002/3.1" {
		t.Fatalf("depends 1.2 = %v", second.DependsOn)
	}
	if second.Red.Command != "go test ./a" || second.Red.Description != "falha com a nova asserção" {
		t.Fatalf("RED = %+v", second.Red)
	}
	if strings.Join(second.ImplementationSteps, "|") != "Primeiro passo|Segundo passo" {
		t.Fatalf("passos = %v", second.ImplementationSteps)
	}
	if len(second.AcceptanceCriteria) != 2 || second.AcceptanceCriteria[1].Command != "go test ./b" || second.AcceptanceCriteria[1].Description != "" {
		t.Fatalf("ACs = %+v", second.AcceptanceCriteria)
	}
	if parsed.Tasks[2].Status != "pending" || parsed.Tasks[2].RequirementID != "FR-003" {
		t.Fatalf("task 1.3 = %+v", parsed.Tasks[2])
	}
}

func TestParseV3ExecutionContractWithoutComponentColumn(t *testing.T) {
	markdown := "## Execution contract\n\n| Nome | Purpose |\n|---|---|\n| `solto` | descrição |\n\n## Outro\n"
	parsed := work.ParseV3PlanMarkdown(markdown, "0001")
	if len(parsed.Components) != 1 || parsed.Components[0].Name != "solto" || parsed.Components[0].Purpose != "descrição" {
		t.Fatalf("components = %+v", parsed.Components)
	}

	// Tabela depois de outro heading `##` não pertence ao contrato.
	detached := "## Execution contract\n\ntexto\n## Outro\n\n| Component | Purpose |\n|---|---|\n| `x` | y |\n"
	if got := work.ParseV3PlanMarkdown(detached, "0001").Components; len(got) != 0 {
		t.Fatalf("tabela de outra seção virou componente: %+v", got)
	}
	// Heading sem nenhuma tabela depois.
	if got := work.ParseV3PlanMarkdown("## Execution contract\n\nsó texto\n", "0001").Components; len(got) != 0 {
		t.Fatalf("components = %+v", got)
	}
}

func TestParsePromptDigestExtractsAuthoredContent(t *testing.T) {
	prompt := strings.Join([]string{
		"# Prompt",
		"**Problema:** O checkout perde pedidos quando o pagamento demora",
		"**Resultado esperado:** Pedidos nunca se perdem",
		"",
		"## Atores e valor",
		"- **Comprador:** quer pagar",
		"- **Lojista:** quer receber",
		"- sem negrito",
		"",
		"## Requisitos",
		"- **FR-001:** Registrar o pedido",
		"- **QR-002:** Responder em 2s",
		"- **SC-003:** Zero pedidos perdidos",
		"- **A-004:** Premissa",
		"",
		"### Inclui",
		"- checkout",
		"- pagamento",
		"### Não inclui",
		"- entrega",
	}, "\n")
	digest := work.ParsePromptDigest(prompt)
	if digest.Problem != "O checkout perde pedidos quando o pagamento demora" || digest.Solution != "Pedidos nunca se perdem" {
		t.Fatalf("digest = %+v", digest)
	}
	if strings.Join(digest.Actors, ",") != "Comprador,Lojista" {
		t.Fatalf("atores = %v", digest.Actors)
	}
	if len(digest.Requirements) != 4 || digest.Requirements[1].ID != "QR-002" || digest.Requirements[1].Statement != "Responder em 2s" {
		t.Fatalf("requisitos = %+v", digest.Requirements)
	}
	if strings.Join(digest.SuccessCriteria, "|") != "SC-003: Zero pedidos perdidos" ||
		strings.Join(digest.Constraints, "|") != "QR-002: Responder em 2s" {
		t.Fatalf("sc=%v qr=%v", digest.SuccessCriteria, digest.Constraints)
	}
	if strings.Join(digest.InScope, ",") != "checkout,pagamento" || strings.Join(digest.OutOfScope, ",") != "entrega" {
		t.Fatalf("escopo = %v / %v", digest.InScope, digest.OutOfScope)
	}

	empty := work.ParsePromptDigest("")
	if empty.Problem != "" || empty.Requirements == nil || empty.InScope == nil || empty.Actors == nil ||
		empty.SuccessCriteria == nil || empty.Constraints == nil || empty.OutOfScope == nil {
		t.Fatalf("digest vazio deve ter listas não nil: %+v", empty)
	}
}

func TestParseCapabilityMapVariants(t *testing.T) {
	spec := strings.Join([]string{
		"# Spec",
		"## 3. Capability Map",
		"",
		"```",
		"Identity and Access",
		"",
		"Catalog",
		"```",
		"### 3.1 Capability dependency rules",
		"- Catalog depende de Identity",
		"texto solto",
		"- Pedido exige Catalog",
		"### 3.2 Outra",
		"- fora das regras",
	}, "\r\n")
	parsed := work.ParseCapabilityMap(spec)
	if len(parsed.Capabilities) != 2 || parsed.Capabilities[0].ID != "CAP-001" || parsed.Capabilities[1].Name != "Catalog" {
		t.Fatalf("capabilities = %+v", parsed.Capabilities)
	}
	if len(parsed.Rules) != 2 || parsed.Rules[0].ID != "BR-001" || parsed.Rules[1].Statement != "Pedido exige Catalog" {
		t.Fatalf("regras = %+v", parsed.Rules)
	}

	none := work.ParseCapabilityMap("# sem mapa\n")
	if len(none.Capabilities) != 0 || len(none.Rules) != 0 || none.Capabilities == nil || none.Rules == nil {
		t.Fatalf("mapa vazio = %+v", none)
	}
}

func TestFindV3WorkReportsUnreadableLayout(t *testing.T) {
	t.Run("plano bloqueado por arquivo", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo", "arquivo no lugar do diretório")
		files, err := work.FindV3Work(root, "0004")
		if err == nil || files != nil {
			t.Fatalf("files=%+v err=%v", files, err)
		}
	})
	t.Run("diretório de prompts bloqueado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo/0004-tasks.md", "# Tasks: x\n")
		writeFile(t, root, ".prompts", "arquivo no lugar do diretório")
		if _, err := work.FindV3Work(root, "0004"); err == nil || !strings.Contains(err.Error(), ".prompts") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("diretório de fontes bloqueado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo/0004-tasks.md", "# Tasks: x\n")
		writeFile(t, root, ".sources", "arquivo no lugar do diretório")
		if _, err := work.FindV3Work(root, "0004"); err == nil || !strings.Contains(err.Error(), ".sources") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("só o plano existe", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo/0004-tasks.md", "# Tasks: x\n")
		files, err := work.FindV3Work(root, "0004")
		if err != nil || files == nil {
			t.Fatalf("files=%+v err=%v", files, err)
		}
		if files.ManifestPath != nil || files.PromptPath != nil || files.SourcePath != nil || files.SystemSpecPath != nil {
			t.Fatalf("artefatos opcionais não deviam existir: %+v", files)
		}
	})
	t.Run("ListV3WorkIDs sem .todo", func(t *testing.T) {
		ids := work.ListV3WorkIDs(t.TempDir())
		if ids == nil || len(ids) != 0 {
			t.Fatalf("ids = %#v", ids)
		}
	})
}

func TestImportV3WorkErrors(t *testing.T) {
	t.Run("Work v3 ausente", func(t *testing.T) {
		_, err := work.ImportV3Work(work.V3ImportOptions{RootDir: t.TempDir(), WorkID: "0004"})
		if err == nil || !strings.Contains(err.Error(), "Work v3 0004 não encontrado: falta .todo/0004-tasks.md") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("layout ilegível", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo", "arquivo")
		if _, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"}); err == nil {
			t.Fatal("layout ilegível devia falhar")
		}
	})
	t.Run("plano sem tasks", func(t *testing.T) {
		root := v3Fixture(t, "# Tasks: vazio\n")
		_, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"})
		if err == nil || !strings.Contains(err.Error(), "Nenhuma task canônica encontrada") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("risco inválido", func(t *testing.T) {
		root := v3Fixture(t, readTestdata(t, "plan.md"))
		_, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004", Risk: "L9"})
		if err == nil || !strings.Contains(err.Error(), "--risk") {
			t.Fatalf("erro = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(root, ".pwn")); !os.IsNotExist(statErr) {
			t.Fatal("falha de risco não pode criar artefatos")
		}
	})
	t.Run("diretório canônico bloqueado", func(t *testing.T) {
		root := v3Fixture(t, readTestdata(t, "plan.md"))
		writeFile(t, root, ".pwn", "arquivo no lugar do diretório")
		if _, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"}); err == nil ||
			!strings.Contains(err.Error(), "criar") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("plan.json é diretório com --force", func(t *testing.T) {
		root := v3Fixture(t, readTestdata(t, "plan.md"))
		if err := os.MkdirAll(filepath.Join(root, ".pwn", "work", "0004", "plan.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004", Force: true}); err == nil {
			t.Fatal("gravar plan.json sobre diretório devia falhar")
		}
	})
	t.Run("contrato é diretório com --force", func(t *testing.T) {
		root := v3Fixture(t, readTestdata(t, "plan.md"))
		if err := os.MkdirAll(filepath.Join(root, ".pwn", "work", "0004", "CTR-001.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004", Force: true}); err == nil {
			t.Fatal("gravar contrato sobre diretório devia falhar")
		}
	})
	t.Run("prompt ilegível", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lê qualquer arquivo")
		}
		root := v3Fixture(t, readTestdata(t, "plan.md"))
		prompt := filepath.Join(root, ".prompts", "0004-change.md")
		if err := os.Chmod(prompt, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(prompt, 0o644) })
		if _, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"}); err == nil ||
			!strings.Contains(err.Error(), "0004-change.md") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestImportV3WorkGateChainWithoutOptionalArtifacts(t *testing.T) {
	markdown := strings.Join([]string{
		"# Tasks: Importação mínima",
		"",
		"## Global gates",
		"- [ ] `go test ./...` — suíte completa",
		"",
		"### [x] [1.1] Primeira",
		"",
		"**Requirement:** `US-004`",
		"**Files:** src/a.go, src/a_test.go",
		"**Implementation files:** src/a.go",
		"**Test files:** src/a_test.go",
		"",
		"### [x] [1.2] Segunda",
		"",
		"**Requirement:** SC-009",
		"**Files:** src/b.go",
		"",
	}, "\n")
	root := t.TempDir()
	writeFile(t, root, ".todo/0007-tasks.md", markdown)

	result, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0007", Risk: "auto", GateChain: true})
	if err != nil {
		t.Fatalf("ImportV3Work: %v", err)
	}
	if len(result.Plan.Tasks) != 2 || len(result.RiskMapping) != 2 {
		t.Fatalf("resultado = %+v", result)
	}
	for _, entry := range result.CapabilityMapping {
		if entry.Capability != "CAP-001" || entry.Score != 0 {
			t.Fatalf("sem system spec toda task cai em CAP-001: %+v", entry)
		}
	}
	joined := strings.Join(result.Warnings, "\n")
	if !strings.Contains(joined, "Task 1.1: nenhuma capability casou") ||
		!strings.Contains(joined, "Nenhum .sources/NNNN-*.md encontrado") {
		t.Fatalf("warnings = %v", result.Warnings)
	}

	var prd struct {
		Status       string `json:"status"`
		Requirements []struct {
			ID string `json:"id"`
		} `json:"requirements"`
		Stakeholders []struct {
			Name string `json:"name"`
		} `json:"stakeholders"`
	}
	if err := jsonUnmarshalFile(t, root, ".pwn/work/0007/prd.json", &prd); err != nil {
		t.Fatal(err)
	}
	if prd.Status != "approved" {
		t.Fatalf("todas as tasks feitas devem aprovar o PRD, veio %q", prd.Status)
	}
	if len(prd.Requirements) != 2 || prd.Requirements[0].ID != "FR-004" || prd.Requirements[1].ID != "SC-009" {
		t.Fatalf("requisitos do PRD = %+v", prd.Requirements)
	}
	if len(prd.Stakeholders) != 1 || prd.Stakeholders[0].Name != "Operador humano" {
		t.Fatalf("stakeholders = %+v", prd.Stakeholders)
	}
	var spec struct {
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
	}
	if err := jsonUnmarshalFile(t, root, ".pwn/work/0007/spec.json", &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Rules) != 1 || spec.Rules[0].ID != "BR-001" {
		t.Fatalf("regras do spec = %+v", spec.Rules)
	}
	var trace struct {
		Matrix []struct {
			Status string `json:"status"`
		} `json:"matrix"`
	}
	if err := jsonUnmarshalFile(t, root, ".pwn/work/0007/traceability-matrix.json", &trace); err != nil {
		t.Fatal(err)
	}
	if len(trace.Matrix) != 2 || trace.Matrix[0].Status != "done" {
		t.Fatalf("matriz = %+v", trace.Matrix)
	}
}

func TestImportV3WorkForceOverwritesAndDefaultRiskIsL2(t *testing.T) {
	root := v3Fixture(t, readTestdata(t, "plan.md"))
	writeFile(t, root, ".pwn/work/0004/plan.json", `{"manual":true}`)
	skipped, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004"})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, root, ".pwn/work/0004/plan.json") != `{"manual":true}` {
		t.Fatal("plan.json existente foi sobrescrito sem --force")
	}
	foundSkip := false
	for _, entry := range skipped.Skipped {
		if entry.File == "plan.json" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("skipped = %+v", skipped.Skipped)
	}
	for _, entry := range skipped.RiskMapping {
		if entry.Risk != contract.RiskL2 {
			t.Fatalf("risco padrão = %s, quer L2", entry.Risk)
		}
	}

	forced, err := work.ImportV3Work(work.V3ImportOptions{RootDir: root, WorkID: "0004", Force: true, Risk: "L3"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsSlice(forced.Generated, "plan.json") {
		t.Fatalf("generated = %v", forced.Generated)
	}
	if strings.Contains(readFile(t, root, ".pwn/work/0004/plan.json"), `"manual"`) {
		t.Fatal("--force devia sobrescrever plan.json")
	}
	loaded, err := plan.LoadTaskContract("0004", "4.1", root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Risk.Level != contract.RiskL3 {
		t.Fatalf("risco congelado = %s", loaded.Risk.Level)
	}
}

func TestDeriveContractFallsBackWithoutDeclaredFiles(t *testing.T) {
	planValue := plan.Plan{GlobalGates: []string{"`go vet ./...` — estático", "sem comando"}}
	task := plan.PlanTask{
		ID:    "1.1",
		Title: "Tarefa sem arquivos",
		AcceptanceCriteria: []plan.PlanAC{
			{Command: "go test ./x", Description: ""},
			{Command: "", Description: "sem comando"},
		},
	}
	derived, err := work.DeriveContract(planValue, task, "0001", contract.RiskL2)
	if err != nil {
		t.Fatalf("DeriveContract: %v", err)
	}
	if got := strings.Join(derived.ScopeContract.WriteAllow, ","); got != "src/**,tests/**" {
		t.Fatalf("write_allow = %s", got)
	}
	if got := strings.Join(derived.AcceptanceContract.Commands, ","); got != "go test ./x,go vet ./..." {
		t.Fatalf("comandos = %s", got)
	}
	if len(derived.BehavioralContract.Scenarios) != 2 ||
		!strings.Contains(derived.BehavioralContract.Scenarios[0].Then, "a aceitação é satisfeita") ||
		!strings.Contains(derived.BehavioralContract.Scenarios[0].Given, "Tarefa sem arquivos") {
		t.Fatalf("cenários = %+v", derived.BehavioralContract.Scenarios)
	}
	if strings.Join(derived.ChangeContract.AffectedComponents, ",") != "jachegai-bun" {
		t.Fatalf("componentes = %v", derived.ChangeContract.AffectedComponents)
	}
	if len(derived.ScopeContract.OutOfScope) != 0 && strings.Contains(derived.ScopeContract.OutOfScope[0], "Arquivos fora de") {
		t.Fatalf("sem arquivos declarados não há escopo negativo: %v", derived.ScopeContract.OutOfScope)
	}

	empty, err := work.DeriveContract(plan.Plan{}, plan.PlanTask{ID: "1.1", Title: "Sem aceitação"}, "0001", contract.RiskL2)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(empty.AcceptanceContract.Commands, ","); got != "bun test" {
		t.Fatalf("comando padrão = %s", got)
	}
}
