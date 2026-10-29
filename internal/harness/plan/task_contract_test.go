package plan_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/platform/cryptox"
)

func TestGenerateContextCapsuleMatchesReference(t *testing.T) {
	root := repoRoot(t)
	task, err := plan.LoadTaskContract("0002", "1.1", root)
	if err != nil {
		t.Fatalf("carregar contrato: %v", err)
	}
	if got, want := plan.GenerateContextCapsule(plan.ContextCapsuleOptions{Task: *task}), readTestdata(t, "capsule-ctr001.txt"); got != want {
		t.Errorf("cápsula divergente\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	withPlan := plan.ContextCapsuleOptions{
		Task:               *task,
		RelevantInterfaces: []string{"Interface X"},
		Plan: &plan.CapsulePlanContext{
			RedCommand: "bun test tests/parity/normative.test.ts",
			Checks: []plan.CapsuleCheckBinding{
				{Name: "AC-1", Commands: []string{"bun test tests/parity/acceptance.test.ts"}},
				{Name: "REGRESSION", Error: "o plano não declara comando de regressão"},
			},
			GlobalGates: []string{"bun test tests/parity", "bun run typecheck"},
		},
	}
	if got, want := plan.GenerateContextCapsule(withPlan), readTestdata(t, "capsule-ctr001-plan.txt"); got != want {
		t.Errorf("cápsula com plano divergente\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestLoadTaskContractErrors(t *testing.T) {
	root := repoRoot(t)
	if _, err := plan.LoadTaskContract("9999", "1.1", root); err == nil {
		t.Error("Work inexistente deveria falhar")
	}
	if _, err := plan.LoadTaskContract("0002", "9.9", root); err == nil {
		t.Error("task inexistente deveria falhar")
	}
}

func TestLoadWorkContractsKeepsPlanOrder(t *testing.T) {
	contracts, err := plan.LoadWorkContracts("0002", repoRoot(t))
	if err != nil {
		t.Fatalf("carregar contratos: %v", err)
	}
	want := []string{"1.1", "1.2", "1.3", "1.4", "1.5"}
	if len(contracts) != len(want) {
		t.Fatalf("contratos=%d; want=%d", len(contracts), len(want))
	}
	for index, id := range want {
		if contracts[index].TaskID != id {
			t.Errorf("contrato %d: task=%q; want=%q", index, contracts[index].TaskID, id)
		}
		if contracts[index].ContractVersion != contract.ContractVersionV4 {
			t.Errorf("contrato %s: versão=%q", id, contracts[index].ContractVersion)
		}
	}
}

const freezeContract = `{
  "contract_version": "4.0",
  "task_id": "1.1",
  "work_id": "0005",
  "title": "Freeze target",
  "risk": {"level": "L1", "reasons": ["teste"]},
  "validation_strategy": "tdd-strict",
  "behavioral_contract": {"scenarios": []},
  "change_contract": {"target_files": [], "affected_components": []},
  "architecture_contract": {"invariants": []},
  "acceptance_contract": {"commands": [], "required_evidence": []},
  "scope_contract": {"write_allow": [], "write_deny": []},
  "budget_contract": {"max_agent_attempts": 1},
  "escalation_contract": {"on_write_violation": "block_and_escalate", "on_budget_exceeded": "human_review", "on_attempt_failed": "human_review"}
}
`

// setupFreezeRepo cria um Work 0005 em um repositório git temporário com um
// teste de aceitação commitado.
func setupFreezeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	workDir := filepath.Join(dir, ".pwn", "work", "0005")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workPlan := `{
  "work_id": "0005",
  "title": "freeze",
  "components": [],
  "global_gates": [],
  "tasks": [
    {
      "id": "1.1",
      "title": "Freeze target",
      "requirement_id": "FR-001",
      "depends_on": [],
      "behavior": "b",
      "components": [],
      "files": ["tests/acceptance_test.go"],
      "implementation_files": ["internal/impl.go"],
      "test_files": ["tests/acceptance_test.go"],
      "red": {"command": "go test ./tests", "description": "d"},
      "implementation_steps": ["s"],
      "acceptance_criteria": [{"command": "go test ./tests", "description": "d"}],
      "spec_reference": "CAP-001",
      "contract_id": "CTR-001",
      "complexity": "standard"
    }
  ]
}
`
	if err := os.WriteFile(filepath.Join(workDir, "plan.json"), []byte(workPlan), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "CTR-001.json"), []byte(freezeContract), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "acceptance_test.go"), []byte("package tests\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal", "impl.go"), []byte("package internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runGit(t, dir, "init", "-q")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-q", "-m", "init")
	return dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func TestFreezeAcceptanceTests(t *testing.T) {
	dir := setupFreezeRepo(t)
	result, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
		WorkID:  "0005",
		TaskID:  "1.1",
		Paths:   []string{"tests/acceptance_test.go", "tests/acceptance_test.go"},
		RootDir: dir,
	})
	if err != nil {
		t.Fatalf("congelar: %v", err)
	}
	if result.ContractID != "CTR-001" {
		t.Errorf("contractId=%q", result.ContractID)
	}
	if len(result.Frozen) != 1 {
		t.Fatalf("frozen=%d; want=1", len(result.Frozen))
	}
	content, err := os.ReadFile(filepath.Join(dir, "tests", "acceptance_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if want := cryptox.SHA256Hex(content); result.Frozen[0].SHA256 != want {
		t.Errorf("hash=%q; want=%q", result.Frozen[0].SHA256, want)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".pwn", "work", "0005", "CTR-001.json"))
	if err != nil {
		t.Fatal(err)
	}
	var written map[string]any
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("contrato gravado não é JSON: %v", err)
	}
	acceptance, ok := written["acceptance_contract"].(map[string]any)
	if !ok {
		t.Fatalf("acceptance_contract ausente: %s", data)
	}
	frozen, ok := acceptance["frozen_tests"].([]any)
	if !ok || len(frozen) != 1 {
		t.Fatalf("frozen_tests=%v", acceptance["frozen_tests"])
	}
	entry := frozen[0].(map[string]any)
	if entry["path"] != "tests/acceptance_test.go" {
		t.Errorf("path=%v", entry["path"])
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("contrato deveria terminar em newline")
	}
}

func TestFreezeAcceptanceTestsRejections(t *testing.T) {
	t.Run("baseline existente", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		stateDir := filepath.Join(dir, ".todo", "evidence", "0005", "state")
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stateDir, "1.1.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
			WorkID: "0005", TaskID: "1.1", Paths: []string{"tests/acceptance_test.go"}, RootDir: dir,
		})
		if err == nil || !strings.Contains(err.Error(), "já tem baseline") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("implementação não é teste", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		_, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
			WorkID: "0005", TaskID: "1.1", Paths: []string{"internal/impl.go"}, RootDir: dir,
		})
		if err == nil || !strings.Contains(err.Error(), "arquivo de implementação") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("placeholder", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		_, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
			WorkID: "0005", TaskID: "1.1", Paths: []string{"tests/"}, RootDir: dir,
		})
		if err == nil || !strings.Contains(err.Error(), "diretório") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("arquivo não commitado", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		if err := os.WriteFile(filepath.Join(dir, "tests", "novo_test.go"), []byte("package tests\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
			WorkID: "0005", TaskID: "1.1", Paths: []string{"tests/novo_test.go"}, RootDir: dir,
		})
		if err == nil || !strings.Contains(err.Error(), "commitado") {
			t.Fatalf("erro=%v", err)
		}
	})
	t.Run("lista vazia", func(t *testing.T) {
		dir := setupFreezeRepo(t)
		_, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
			WorkID: "0005", TaskID: "1.1", RootDir: dir,
		})
		if err == nil || !strings.Contains(err.Error(), "ao menos um arquivo") {
			t.Fatalf("erro=%v", err)
		}
	})
}
