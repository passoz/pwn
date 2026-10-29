package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/platform/cryptox"
)

// newRepo cria um repositório git temporário com identidade configurada.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	git(t, dir, "config", "user.email", "test@example.invalid")
	git(t, dir, "config", "user.name", "Test")
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v falhou: %v\n%s", args, err, output)
	}
	return string(output)
}

func commit(t *testing.T, dir, message string) {
	t.Helper()
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-qm", message)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	target := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("criar diretório de %s: %v", name, err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("gravar %s: %v", name, err)
	}
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("ler %s: %v", name, err)
	}
	return string(data)
}

// runAudit executa uma fase do audit no diretório do fixture.
func runAudit(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func mustCode(t *testing.T, want int, args []string, code int, stdout, stderr string) {
	t.Helper()
	if code != want {
		t.Fatalf("%v: código %d, quer %d\nstdout: %s\nstderr: %s", args, code, want, stdout, stderr)
	}
}

type fixtureTask struct {
	id             string
	title          string
	implementation string
	test           string
	assertion      string
	acs            []string
}

// planFor escreve o plano v3 do fixture. A definição da task sai do plano,
// nunca da linha de comando do operador.
func planFor(t *testing.T, dir string, tasks []fixtureTask) string {
	t.Helper()
	var builder strings.Builder
	builder.WriteString("# Tasks: fixture do audit\n\n**Contract version:** 3\n**Work ID:** 0001\n\n")
	builder.WriteString("## Global gates\n- [ ] `sh gate.sh` — a suíte completa permanece verde.\n\n")
	for _, task := range tasks {
		acs := task.acs
		if len(acs) == 0 {
			acs = []string{"sh " + task.test}
		}
		builder.WriteString(fmt.Sprintf(`
### [ ] [%s] %s

**Implementation files:** `+"`%s`"+`

**Test files:** `+"`%s`"+`

**RED:**
- `+"`sh %s`"+` — a asserção %s falha antes da implementação.

**ACs:**
`, task.id, task.title, task.implementation, task.test, task.test, task.assertion))
		for _, command := range acs {
			builder.WriteString(fmt.Sprintf("- [ ] `%s` — a asserção %s passa.\n", command, task.assertion))
		}
		builder.WriteString("\n**Visual:** N/A\n\n**Documentation:** N/A\n")
	}
	text := builder.String()
	writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), text)
	return text
}

// testScript devolve um teste shell que exige o valor novo da implementação.
func testScript(implementation, assertion string) string {
	return fmt.Sprintf(`value=$(cat %s 2>/dev/null || true)
if [ "$value" != "new" ]; then
  echo %q >&2
  exit 1
fi
`, implementation, assertion)
}

func TestEnforcesImmutableRedGreenEvidence(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.1", title: "Implement value", implementation: "app.value", test: "app.test.sh", assertion: "VALUE-NEW",
	}})
	commit(t, dir, "baseline")

	// baseline recusa arquivo declarado já sujo
	writeFile(t, dir, "app.value", "dirty\n")
	code, _, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 1, []string{"baseline sujo"}, code, "", stderr)
	if !strings.Contains(stderr, "declared files already have changes") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	writeFile(t, dir, "app.value", "old\n")

	// baseline é amarrado ao plano: arquivos divergentes são violação
	code, _, stderr = runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1", "--implementation", "app.value", "--tests", "other.test.sh")
	mustCode(t, 1, []string{"baseline divergente"}, code, "", stderr)
	if !strings.Contains(stderr, "--tests diverge do plano") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	// sem baseline, a auditoria está incompleta
	code, _, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
	mustCode(t, 2, []string{"red sem baseline"}, code, "", stderr)
	if !strings.Contains(stderr, "INCOMPLETO") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	// RED exige teste alterado desde o baseline
	code, _, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"red sem teste alterado"}, code, "", stderr)
	if !strings.Contains(stderr, "no test file changed since baseline") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	writeFile(t, dir, "app.value", "premature\n")
	writeFile(t, dir, "app.test.sh", testScript("app.value", "VALUE-NEW"))
	code, _, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"red prematuro"}, code, "", stderr)
	if !strings.Contains(stderr, "implementation changed before RED") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	writeFile(t, dir, "app.value", "old\n")
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red"}, code, stdout, stderr)
	if !strings.Contains(stdout, "PASS: RED captured and tests frozen") {
		t.Fatalf("stdout inesperado: %s", stdout)
	}

	// GREEN exige os testes congelados pelo RED
	writeFile(t, dir, "app.test.sh", "// weakened after RED\n")
	writeFile(t, dir, "app.value", "new\n")
	code, _, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"green com teste alterado"}, code, "", stderr)
	if !strings.Contains(stderr, "test files changed after RED") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	writeFile(t, dir, "app.test.sh", testScript("app.value", "VALUE-NEW"))
	code, _, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--", "sh", "gate.sh")
	mustCode(t, 1, []string{"green com comando divergente"}, code, "", stderr)
	if !strings.Contains(stderr, "command differs from RED command") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	code, _, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--expect", "NOT-IN-SUCCESS-OUTPUT-001", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"green sem expect na saída"}, code, "", stderr)
	if !strings.Contains(stderr, "GREEN command did not pass expected output") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	code, stdout, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"green"}, code, stdout, stderr)
	greenLog := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-green.log"))
	if !strings.Contains(greenLog, "MUTATION_EXIT:") || !strings.Contains(greenLog, "MUTATION_VERDICT: PASS") {
		t.Fatalf("log do green sem mutation check: %s", greenLog)
	}
	if got := readFile(t, dir, "app.value"); got != "new\n" {
		t.Fatalf("implementação não foi restaurada: %q", got)
	}

	code, stdout, stderr = runAudit(t, dir, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"verify"}, code, stdout, stderr)
	verifyLog := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-verify.log"))
	if !strings.Contains(verifyLog, "VERDICT: PASS") {
		t.Fatalf("log do verify sem veredito: %s", verifyLog)
	}

	// checks exigem os comandos declarados no plano
	code, _, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "true")
	mustCode(t, 1, []string{"check com comando divergente"}, code, "", stderr)
	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"check AC-1"}, code, stdout, stderr)
	code, _, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"regression divergente"}, code, "", stderr)
	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "gate.sh")
	mustCode(t, 0, []string{"regression"}, code, stdout, stderr)

	// As ações candidate e gate foram removidas: uso inválido, sem atestação.
	code, _, stderr = runAudit(t, dir, "candidate", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"candidate removida"}, code, "", stderr)
	if !strings.Contains(stderr, "unknown or missing action") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".todo", "attestations")); !os.IsNotExist(err) {
		t.Fatalf("a ação removida não pode gravar atestação")
	}

	writeFile(t, dir, "app.value", "broken-after-green\n")
	code, _, stderr = runAudit(t, dir, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"verify com implementação alterada"}, code, "", stderr)
	if !strings.Contains(stderr, "implementation changed") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	writeFile(t, dir, "app.value", "new\n")
	code, stdout, stderr = runAudit(t, dir, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"verify restaurado"}, code, stdout, stderr)
	writeFile(t, dir, "app.test.sh", "// changed after green\n")
	code, _, stderr = runAudit(t, dir, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"verify com teste alterado"}, code, "", stderr)

	// O estado preserva comando e expect do RED e o snapshot GREEN.
	stateData := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"))
	var state State
	if err := json.Unmarshal([]byte(stateData), &state); err != nil {
		t.Fatalf("estado ilegível: %v", err)
	}
	if state.StateVersion != 2 || state.RedExpect != "VALUE-NEW" {
		t.Fatalf("estado inesperado: %+v", state)
	}
	if len(state.RedCommand) == 0 || state.GreenImplementation == nil || state.GreenTests == nil {
		t.Fatalf("estado sem o ciclo RED/GREEN: %+v", state)
	}
	if _, ok := state.AuditChecks["AC-1"]; !ok {
		t.Fatalf("estado sem o check AC-1: %+v", state.AuditChecks)
	}
	if !strings.Contains(readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-chain.jsonl")), `"entry_hash"`) {
		t.Fatalf("cadeia de evidência ausente")
	}
}

func TestSupportsNewImplementationFileDuringMutationCheck(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "feature.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh feature.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.3", title: "Create feature", implementation: "feature.value", test: "feature.test.sh", assertion: "new-file-behavior",
	}})
	commit(t, dir, "baseline")

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.3")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	writeFile(t, dir, "feature.test.sh", `value=$(cat feature.value 2>/dev/null || true)
if [ "$value" != "created" ]; then
  echo "new-file-behavior" >&2
  exit 1
fi
`)
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.3", "--expect", "new-file-behavior", "--", "sh", "feature.test.sh")
	mustCode(t, 0, []string{"red"}, code, stdout, stderr)

	writeFile(t, dir, "feature.value", "created\n")
	code, stdout, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.3", "--", "sh", "feature.test.sh")
	mustCode(t, 0, []string{"green"}, code, stdout, stderr)
	if got := readFile(t, dir, "feature.value"); got != "created\n" {
		t.Fatalf("arquivo novo não foi restaurado: %q", got)
	}
}

func TestRejectsToolchainErrorRed(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.1", title: "Implement value", implementation: "app.value", test: "app.test.sh", assertion: "assertion-new-behavior",
	}})
	commit(t, dir, "baseline")

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	writeFile(t, dir, "app.test.sh", "echo 'cannot find main module' >&2\nexit 1\n")
	code, _, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "cannot find main module", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"red de toolchain"}, code, "", stderr)
	if !strings.Contains(strings.ToLower(stderr), "toolchain") && !strings.Contains(strings.ToLower(stderr), "incidental") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	writeFile(t, dir, "app.test.sh", "echo 'assertion-new-behavior: value should be X not Y' >&2\nexit 1\n")
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "assertion-new-behavior", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red de asserção"}, code, stdout, stderr)
}

func TestRejectsGenericAndNonLiteralExpect(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.1", title: "Implement value", implementation: "app.value", test: "app.test.sh", assertion: "VALUE-NEW",
	}})
	commit(t, dir, "baseline")

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	writeFile(t, dir, "app.test.sh", "echo 'VALUE-NEW: value should change' >&2\nexit 1\n")
	code, _, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "fail", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"expect genérico"}, code, "", stderr)
	if !strings.Contains(stderr, "--expect genérico") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	code, _, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "outra-assercao-qualquer", "--", "sh", "app.test.sh")
	mustCode(t, 1, []string{"expect não literal"}, code, "", stderr)
	if !strings.Contains(stderr, "não é literal") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}

	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "VALUE-NEW", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"expect literal"}, code, stdout, stderr)
}

func TestAllowsIncidentalRedInLegacyPlanWithWarning(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), `**Contract version:** 2
**Work ID:** 0001

### [ ] [1.1] Legacy task

**Implementation files:** `+"`app.value`"+`

**Test files:** `+"`app.test.sh`"+`

**RED:**
- `+"`sh app.test.sh`"+` — a asserção falha antes da implementação.

**ACs:**
- [ ] `+"`sh app.test.sh`"+` — a asserção passa com a implementação.
`)
	commit(t, dir, "baseline")

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	writeFile(t, dir, "app.test.sh", "echo 'cannot find main module' >&2\nexit 1\n")
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "cannot find main module", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red legado incidental"}, code, stdout, stderr)
	if !strings.Contains(stderr, "WARNING: RED accepted due to legacy contract") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
}

func TestRejectsVacuousAcceptanceCriterion(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.1", title: "Implement value", implementation: "app.value", test: "app.test.sh", assertion: "VALUE-NEW",
		acs: []string{"sh app.test.sh", "true"},
	}})
	commit(t, dir, "baseline")

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)
	writeFile(t, dir, "app.test.sh", testScript("app.value", "vacuous-check-001"))
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "vacuous-check-001", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red"}, code, stdout, stderr)
	writeFile(t, dir, "app.value", "new\n")
	code, stdout, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"green"}, code, stdout, stderr)

	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"check AC-1"}, code, stdout, stderr)
	code, _, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "AC-2", "--", "true")
	mustCode(t, 1, []string{"check AC-2 vácuo"}, code, "", stderr)
	if !strings.Contains(stderr, "AC-2 é vácuo") || !strings.Contains(stderr, "implementação removida") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	log := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-ac-2.log"))
	if !strings.Contains(log, "MUTATION_VERDICT: FAIL") {
		t.Fatalf("log sem mutation check: %s", log)
	}
}

// canonicalPlan escreve plan.json e o markdown canônico do fixture.
func canonicalPlan(t *testing.T, dir string, redCommand, acCommand string, frozen []contract.FrozenTest) plan.Plan {
	t.Helper()
	model := plan.Plan{
		WorkID:     "0001",
		Title:      "Audit canônico",
		Components: []plan.PlanComponent{{Name: "core", Purpose: "núcleo do fixture"}},
		GlobalGates: []string{
			"`sh gate.sh` — a suíte completa permanece verde.",
		},
		Tasks: []plan.PlanTask{{
			ID:                  "1.1",
			Title:               "Implement value",
			RequirementID:       "FR-001",
			DependsOn:           []string{},
			Behavior:            "entrega o valor novo",
			Components:          []string{"core"},
			Files:               []string{"app.value", "app.test.sh", "acceptance.test.sh"},
			ImplementationFiles: []string{"app.value"},
			TestFiles:           []string{"app.test.sh"},
			Red:                 plan.PlanRed{Command: redCommand, Description: "a asserção CANONICAL-RED-001 falha antes da implementação"},
			ImplementationSteps: []string{"Escrever o teste focado", "Implementar o valor novo"},
			AcceptanceCriteria:  []plan.PlanAC{{Command: acCommand, Description: "a asserção CANONICAL-RED-001 passa"}},
			Visual:              "N/A",
			Documentation:       "N/A",
			SpecReference:       "CAP-001",
			ContractID:          "CTR-001",
			Complexity:          "standard",
			Status:              "pending",
		}},
	}
	workDir := filepath.Join(dir, ".pwn", "work", "0001")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("criar work dir: %v", err)
	}
	planJSON, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		t.Fatalf("serializar plano: %v", err)
	}
	writeFile(t, dir, filepath.Join(".pwn", "work", "0001", "plan.json"), string(planJSON)+"\n")

	contractModel, err := contract.CreateDefaultContractV4("1.1", "0001", "Implement value", contract.RiskL3, nil)
	if err != nil {
		t.Fatalf("criar contrato: %v", err)
	}
	contractModel.AcceptanceContract.FrozenTests = frozen
	contractJSON, err := json.MarshalIndent(contractModel, "", "  ")
	if err != nil {
		t.Fatalf("serializar contrato: %v", err)
	}
	writeFile(t, dir, filepath.Join(".pwn", "work", "0001", "CTR-001.json"), string(contractJSON)+"\n")

	writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), plan.RenderTasksMarkdown(model))
	return model
}

func TestRequiresFrozenAcceptanceTests(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "acceptance.test.sh", `value=$(cat app.value 2>/dev/null || true)
if [ "$value" != "new" ]; then
  echo "ACCEPTANCE-001 missing" >&2
  exit 1
fi
`)
	writeFile(t, dir, "gate.sh", "sh app.test.sh && sh acceptance.test.sh\n")

	acceptance := readFile(t, dir, "acceptance.test.sh")
	frozenSHA := cryptox.SHA256Hex([]byte(acceptance))
	canonicalPlan(t, dir, "sh app.test.sh", "sh acceptance.test.sh", []contract.FrozenTest{{Path: "acceptance.test.sh", SHA256: frozenSHA}})
	commit(t, dir, "teste de aceitação aprovado")

	// Baseline recusa teste congelado alterado, mesmo fora das listas da task.
	writeFile(t, dir, "acceptance.test.sh", "// alterado depois de congelado\n")
	code, _, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 1, []string{"baseline com congelado alterado"}, code, "", stderr)
	if !strings.Contains(stderr, "teste de aceitação congelado alterado ou ausente: acceptance.test.sh") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
	writeFile(t, dir, "acceptance.test.sh", acceptance)

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline congelado"}, code, stdout, stderr)
	writeFile(t, dir, "app.test.sh", testScript("app.value", "focused-red-001"))
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "focused-red-001", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red"}, code, stdout, stderr)
	writeFile(t, dir, "app.value", "new\n")
	code, stdout, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"green"}, code, stdout, stderr)

	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "acceptance.test.sh")
	mustCode(t, 0, []string{"check AC-1"}, code, stdout, stderr)
	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "gate.sh")
	mustCode(t, 0, []string{"check REGRESSION"}, code, stdout, stderr)
}

func TestDriftAndUnreadablePlanRejectBeforeExecuting(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "acceptance.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	writeFile(t, dir, "marker.txt", "")
	model := canonicalPlan(t, dir, "sh app.test.sh", "sh app.test.sh", nil)

	markdown := readFile(t, dir, filepath.Join(".todo", "0001-tasks.md"))
	canonical := readFile(t, dir, filepath.Join(".pwn", "work", "0001", "plan.json"))
	marker := filepath.Join(dir, "COMMAND-RAN")

	changedModel := model
	changedModel.Tasks = append([]plan.PlanTask{}, model.Tasks...)
	changedModel.Tasks[0].AcceptanceCriteria = []plan.PlanAC{{
		Command: "sh app.test.sh", Description: "critério canônico alterado",
	}}
	changedJSON, err := json.MarshalIndent(changedModel, "", "  ")
	if err != nil {
		t.Fatalf("serializar plano alterado: %v", err)
	}

	corruptions := []func(){
		func() {
			writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), strings.Replace(
				markdown, "a asserção CANONICAL-RED-001 passa", "critério markdown alterado", 1,
			))
		},
		func() {
			writeFile(t, dir, filepath.Join(".pwn", "work", "0001", "plan.json"), string(changedJSON))
		},
		func() {
			writeFile(t, dir, filepath.Join(".pwn", "work", "0001", "plan.json"), "{ invalid JSON\n")
		},
	}

	snapshotEvidence := func() map[string]string {
		result := make(map[string]string)
		root := filepath.Join(dir, ".todo", "evidence", "0001")
		entries, err := os.ReadDir(root)
		if err != nil {
			return result
		}
		for _, entry := range entries {
			if entry.IsDir() {
				subEntries, subErr := os.ReadDir(filepath.Join(root, entry.Name()))
				if subErr != nil {
					continue
				}
				for _, sub := range subEntries {
					data, readErr := os.ReadFile(filepath.Join(root, entry.Name(), sub.Name()))
					if readErr == nil {
						result[entry.Name()+"/"+sub.Name()] = string(data)
					}
				}
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
			if readErr == nil {
				result[entry.Name()] = string(data)
			}
		}
		return result
	}

	refuse := func(args ...string) {
		t.Helper()
		for _, corrupt := range corruptions {
			_ = os.Remove(marker)
			before := snapshotEvidence()
			corrupt()
			code, stdout, stderr := runAudit(t, dir, args...)
			if code != 1 {
				t.Fatalf("%v: código %d, quer 1\nstderr: %s", args, code, stderr)
			}
			if !strings.Contains(stderr, "DRIFT") {
				t.Fatalf("%v: sem DRIFT em %s", args, stderr)
			}
			if strings.Contains(stdout, "PASS:") {
				t.Fatalf("%v: PASS antes de recusar: %s", args, stdout)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("%v: comando foi executado", args)
			}
			after := snapshotEvidence()
			if len(before) != len(after) {
				t.Fatalf("%v: evidência gravada antes de recusar", args)
			}
			for key, value := range before {
				if after[key] != value {
					t.Fatalf("%v: evidência %s mudou antes de recusar", args, key)
				}
			}
			writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), markdown)
			writeFile(t, dir, filepath.Join(".pwn", "work", "0001", "plan.json"), canonical)
		}
	}

	commit(t, dir, "baseline canônico")
	refuse("baseline", "--work", "0001", "--task", "1.1")
	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	writeFile(t, dir, "app.test.sh", `touch COMMAND-RAN
value=$(cat app.value 2>/dev/null || true)
if [ "$value" != "new" ]; then
  echo "CANONICAL-RED-001" >&2
  exit 1
fi
`)
	refuse("red", "--work", "0001", "--task", "1.1", "--expect", "CANONICAL-RED-001", "--", "sh", "app.test.sh")
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "CANONICAL-RED-001", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red"}, code, stdout, stderr)
	writeFile(t, dir, "app.value", "new\n")
	refuse("green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	code, stdout, stderr = runAudit(t, dir, "green", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"green"}, code, stdout, stderr)

	refuse("verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	code, stdout, stderr = runAudit(t, dir, "verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"verify"}, code, stdout, stderr)
	refuse("check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")

	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"check AC-1"}, code, stdout, stderr)
	code, stdout, stderr = runAudit(t, dir, "check", "--work", "0001", "--task", "1.1", "--name", "REGRESSION", "--", "sh", "gate.sh")
	mustCode(t, 0, []string{"check REGRESSION"}, code, stdout, stderr)

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("o fixture legítimo deveria executar o comando com marcador")
	}
	refuse("verify", "--work", "0001", "--task", "1.1", "--", "sh", "app.test.sh")
	refuse("check", "--work", "0001", "--task", "1.1", "--name", "AC-1", "--", "sh", "app.test.sh")
}

func TestForgedStateNeverExecutesCommand(t *testing.T) {
	dir := newRepo(t)
	marker := filepath.Join(dir, "PWNED.txt")
	payload := fmt.Sprintf("touch %s", marker)
	writeFile(t, dir, filepath.Join(".todo", "evidence", "0001", "state", "1.1.json"), `{
  "task": "1.1",
  "test_files": [],
  "implementation_files": [],
  "green_implementation": {},
  "green_tests": {},
  "red_command": ["sh", "-c", `+fmt.Sprintf("%q", payload)+`],
  "red_expect": "never-present-string-xyz",
  "green_expect": null
}
`)

	// Sem comando do operador: uso inválido, nada executa.
	code, _, stderr := runAudit(t, dir, "verify", "--work", "0001", "--task", "1.1")
	mustCode(t, 1, []string{"verify sem comando"}, code, "", stderr)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("o comando gravado no estado não pode ser executado sozinho")
	}

	for _, command := range [][]string{{"sh", "-c", "true"}, {"sh", "-c", payload}} {
		args := append([]string{"verify", "--work", "0001", "--task", "1.1", "--"}, command...)
		code, _, stderr = runAudit(t, dir, args...)
		mustCode(t, 2, args, code, "", stderr)
		if !strings.Contains(stderr, "baseline amarrado ao plano") {
			t.Fatalf("mensagem inesperada: %s", stderr)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("nenhum comando executa sem definição válida")
		}
	}
}

func TestAuditedCommandDoesNotInheritVerifierKey(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, "app.test.sh", "")
	writeFile(t, dir, "gate.sh", "sh app.test.sh\n")
	planFor(t, dir, []fixtureTask{{
		id: "1.1", title: "Implement value", implementation: "app.value", test: "app.test.sh", assertion: "ENV-RED-001",
	}})
	commit(t, dir, "baseline")

	t.Setenv("PWN_VERIFIER_KEY", "subprocess-only-secret-001")
	t.Setenv("PWN_AUDIT_ENV_CONTROL", "explicit-control")

	code, stdout, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 0, []string{"baseline"}, code, stdout, stderr)

	writeFile(t, dir, "app.test.sh", `if [ "$PWN_AUDIT_ENV_CONTROL" != "explicit-control" ]; then
  echo "CONTROL-MISSING" >&2
  exit 2
fi
if [ -n "$PWN_VERIFIER_KEY" ]; then
  echo "KEY-LEAK" >&2
  exit 3
fi
echo "ENV-RED-001" >&2
exit 1
`)
	code, stdout, stderr = runAudit(t, dir, "red", "--work", "0001", "--task", "1.1", "--expect", "ENV-RED-001", "--", "sh", "app.test.sh")
	mustCode(t, 0, []string{"red com ambiente"}, code, stdout, stderr)
	log := readFile(t, dir, filepath.Join(".todo", "evidence", "0001", "1.1-red.log"))
	if !strings.Contains(log, "VERDICT: PASS") {
		t.Fatalf("log sem veredito: %s", log)
	}
	if strings.Contains(log, "subprocess-only-secret-001") {
		t.Fatalf("log vazou a chave do verificador: %s", log)
	}
}

func TestBaselineRejectsPlaceholderPaths(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "app.value", "old\n")
	writeFile(t, dir, filepath.Join(".todo", "0001-tasks.md"), `# Tasks: fixture

**Contract version:** 3
**Work ID:** 0001

## Global gates
- [ ] `+"`sh gate.sh`"+` — a suíte completa permanece verde.

### [ ] [1.1] Placeholder

**Implementation files:** `+"`src/*.value`"+`

**Test files:** `+"`app.test.sh`"+`

**RED:**
- `+"`sh app.test.sh`"+` — a asserção X falha.

**ACs:**
- [ ] `+"`sh app.test.sh`"+` — a asserção X passa.
`)
	commit(t, dir, "baseline")

	code, _, stderr := runAudit(t, dir, "baseline", "--work", "0001", "--task", "1.1")
	mustCode(t, 1, []string{"baseline com glob"}, code, "", stderr)
	if !strings.Contains(stderr, "declare arquivos concretos no plano") {
		t.Fatalf("mensagem inesperada: %s", stderr)
	}
}
