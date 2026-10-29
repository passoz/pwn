package batch_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/batch"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
)

const workID = "0001"

type spec struct {
	id        string
	key       string
	contract  string
	component string
	depends   []string
}

var specs = []spec{
	{id: "1.1", key: "a", contract: "CTR-001", component: "alpha"},
	{id: "1.2", key: "b", contract: "CTR-002", component: "beta"},
	{id: "1.3", key: "c", contract: "CTR-003", component: "alpha", depends: []string{"1.1"}},
}

type fixture struct {
	root         string
	verifierRoot string
	baseline     string
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func writeFile(t *testing.T, root, relative, content string) {
	t.Helper()
	target := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
		t.Fatalf("criar %s: %v", filepath.Dir(target), err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("gravar %s: %v", target, err)
	}
}

func sha256hex(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

func acceptanceTest(key string) string {
	return fmt.Sprintf("import { expect, test } from \"bun:test\";\nimport { %s } from \"../src/%s.js\";\ntest(\"%s aceito\", () => { expect(%s).toBe(2); });\n", key, key, key, key)
}

const regressionScript = `#!/bin/sh
if [ "$(cat src/a.js 2>/dev/null)" = 'export const a = 2;' ] && [ "$(cat src/b.js 2>/dev/null)" = 'export const b = 2;' ]; then
  exit 1
fi
exit 0
`

// newFixture monta um Work 0001 com três tasks L3: testes de aceitação
// congelados e aprovações feitas ANTES de qualquer implementação.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	verifierRoot := t.TempDir()

	writeFile(t, root, ".gitignore", "node_modules/\n")
	writeFile(t, root, "node_modules/.keep", "")
	writeFile(t, root, "bin/regression", regressionScript)
	if err := os.Chmod(filepath.Join(root, "bin", "regression"), 0o755); err != nil {
		t.Fatalf("tornar a regressão executável: %v", err)
	}

	components := []plan.PlanComponent{
		{Name: "alpha", Purpose: "componente alpha", Regression: new("./bin/regression")},
		{Name: "beta", Purpose: "componente beta", Regression: new("./bin/regression")},
	}
	tasks := make([]plan.PlanTask, 0, len(specs))
	contracts := make(map[string]string, len(specs))
	for index, entry := range specs {
		implementation := fmt.Sprintf("export const %s = 1;\n", entry.key)
		acceptance := acceptanceTest(entry.key)
		writeFile(t, root, "src/"+entry.key+".js", implementation)
		writeFile(t, root, "tests/"+entry.key+".test.js", "// teste focado: escrito pelo agente depois do baseline\n")
		writeFile(t, root, "tests/"+entry.key+".acceptance.test.js", acceptance)
		tasks = append(tasks, plan.PlanTask{
			ID:                  entry.id,
			Title:               fmt.Sprintf("Entrega %s", entry.key),
			RequirementID:       fmt.Sprintf("FR-00%d", index+1),
			DependsOn:           entry.depends,
			Behavior:            fmt.Sprintf("%s passa a valer 2.", entry.key),
			Components:          []string{entry.component},
			Files:               []string{"src/" + entry.key + ".js", "tests/" + entry.key + ".test.js"},
			ImplementationFiles: []string{"src/" + entry.key + ".js"},
			TestFiles:           []string{"tests/" + entry.key + ".test.js"},
			Red: plan.PlanRed{
				Command:     "./bin/regression",
				Description: fmt.Sprintf("a asserção %s-RED-001 falha antes da implementação", strings.ToUpper(entry.key)),
			},
			ImplementationSteps: []string{"Implementar só o resultado observável declarado."},
			AcceptanceCriteria: []plan.PlanAC{{
				Command:     "go version",
				Description: fmt.Sprintf("%s vale 2", entry.key),
			}},
			Visual:        "N/A",
			Documentation: "N/A",
			SpecReference: "CAP-001",
			ContractID:    entry.contract,
			Complexity:    "standard",
			Status:        "pending",
		})
		contracts[entry.id] = acceptance

		taskContract, err := contract.CreateDefaultContractV4(entry.id, workID, fmt.Sprintf("Entrega %s", entry.key), contract.RiskL3, nil)
		if err != nil {
			t.Fatalf("criar o contrato de %s: %v", entry.id, err)
		}
		taskContract.ScopeContract.WriteAllow = []string{"src/" + entry.key + ".js"}
		taskContract.AcceptanceContract.FrozenTests = []contract.FrozenTest{{
			Path:   "tests/" + entry.key + ".acceptance.test.js",
			SHA256: sha256hex(contracts[entry.id]),
		}}
		data, err := json.MarshalIndent(taskContract, "", "  ")
		if err != nil {
			t.Fatalf("serializar o contrato de %s: %v", entry.id, err)
		}
		writeFile(t, root, ".pwn/work/"+workID+"/"+entry.contract+".json", string(data)+"\n")
	}

	workPlan := plan.Plan{
		WorkID:      workID,
		Title:       "Lote paralelo",
		Components:  components,
		GlobalGates: []string{"`./bin/regression` — a regressão responde."},
		Tasks:       tasks,
	}
	planJSON, err := json.MarshalIndent(workPlan, "", "  ")
	if err != nil {
		t.Fatalf("serializar o plano: %v", err)
	}
	writeFile(t, root, ".pwn/work/"+workID+"/plan.json", string(planJSON)+"\n")
	writeFile(t, root, ".todo/"+workID+"-tasks.md", plan.RenderTasksMarkdown(workPlan))

	git(t, root, "init", "-q")
	git(t, root, "config", "user.email", "batch@example.invalid")
	git(t, root, "config", "user.name", "Batch")
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "baseline")
	baseline := strings.TrimSpace(git(t, root, "rev-parse", "HEAD"))

	for _, entry := range specs {
		if _, err := verify.CreateApproval(verify.CreateApprovalOptions{
			RootDir:         root,
			WorkID:          workID,
			TaskID:          entry.id,
			ApprovedBy:      "operador",
			VerifierRootDir: verifierRoot,
		}); err != nil {
			t.Fatalf("aprovar %s: %v", entry.id, err)
		}
	}
	t.Setenv(verify.HomeEnv, verifierRoot)
	return &fixture{root: root, verifierRoot: verifierRoot, baseline: baseline}
}

// deliver reproduz o que o agente faz no worktree: implementação + estado local
// VERIFIED com verify PASS, ancorado em baseline.
func deliver(t *testing.T, fx *fixture, worktree string, entry spec, baseline string) {
	t.Helper()
	implementation := fmt.Sprintf("export const %s = 2;\n", entry.key)
	writeFile(t, worktree, "src/"+entry.key+".js", implementation)
	state := map[string]any{
		"baseline_implementation": map[string]any{},
		"baseline_tests":          map[string]any{},
		"red_tests":               map[string]any{},
		"green_implementation": map[string]any{
			"src/" + entry.key + ".js": map[string]any{"exists": true, "sha256": sha256hex(implementation)},
		},
		"green_tests":     map[string]any{},
		"baseline_commit": baseline,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("serializar o estado de %s: %v", entry.id, err)
	}
	writeFile(t, worktree, ".todo/evidence/"+workID+"/state/"+entry.id+".json", string(data)+"\n")
	writeFile(t, worktree, ".todo/evidence/"+workID+"/"+entry.id+"-verify.log", "VERDICT: PASS\n")
}

func mainStatus(t *testing.T, fx *fixture) work.ProjectStatus {
	t.Helper()
	status, err := work.CollectProjectStatus(filepath.Join(fx.root, ".todo", workID+"-tasks.md"))
	if err != nil {
		t.Fatalf("coletar o status: %v", err)
	}
	return status
}

func evidenceOf(t *testing.T, fx *fixture, id string) work.EvidenceState {
	t.Helper()
	for _, task := range mainStatus(t, fx).Tasks {
		if task.ID == id {
			return task.Evidence
		}
	}
	t.Fatalf("task %s ausente do status", id)
	return work.EvidenceState{}
}

func taskOf(t *testing.T, manifest *batch.BatchManifest, id string) batch.BatchTask {
	t.Helper()
	if manifest == nil {
		t.Fatalf("manifesto ausente; queria a task %s", id)
	}
	for _, task := range manifest.Tasks {
		if task.ID == id {
			return task
		}
	}
	t.Fatalf("task %s ausente do lote: %v", id, idsOf(manifest))
	return batch.BatchTask{}
}

func idsOf(manifest *batch.BatchManifest) []string {
	if manifest == nil {
		return nil
	}
	ids := make([]string, 0, len(manifest.Tasks))
	for _, task := range manifest.Tasks {
		ids = append(ids, task.ID)
	}
	return ids
}

func findDeferral(schedule batch.Schedule, id string) string {
	for _, entry := range schedule.Deferred {
		if entry.ID == id {
			return entry.Reason
		}
	}
	return ""
}

func worktreeCount(t *testing.T, root string) int {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(git(t, root, "worktree", "list")), "\n")
	return len(lines)
}

func writeManifestRaw(t *testing.T, root string, manifest *batch.BatchManifest) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("serializar o manifesto: %v", err)
	}
	writeFile(t, root, ".pwn/batch.json", string(data)+"\n")
}
