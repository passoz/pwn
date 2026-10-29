package verify_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/verify"
)

const (
	workID   = "0001"
	taskID   = "1.1"
	acPath   = "tests/acceptance.test.ts"
	implPath = "src/lib.ts"
)

const (
	newImplementation   = "export function value() { return \"NEW\"; }\n"
	oldImplementation   = "export function value() { return \"OLD\"; }\n"
	wrongImplementation = "export function value() { return \"WRONG\"; }\n"
	acceptanceImport    = "import { expect, test } from \"bun:test\";\nimport { value } from \"../src/lib.ts\";\n"
	trivialAcceptance   = "import { expect, test } from \"bun:test\";\ntest(\"trivial\", () => { expect(1).toBe(1); });\n"
)

func acceptanceAsserting(expected string) string {
	return acceptanceImport + "test(\"value\", () => { expect(value()).toBe(" + quote(expected) + "); });\n"
}

func quote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func writeFile(t *testing.T, rootDir, relative, content string) {
	t.Helper()
	absolute := filepath.Join(rootDir, relative)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o777); err != nil {
		t.Fatalf("criar %s: %v", filepath.Dir(absolute), err)
	}
	if err := os.WriteFile(absolute, []byte(content), 0o644); err != nil {
		t.Fatalf("gravar %s: %v", absolute, err)
	}
}

func readText(rootDir, relative string) (string, error) {
	data, err := os.ReadFile(filepath.Join(rootDir, relative))
	return string(data), err
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func newVerifier(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if _, err := verify.InitializeVerifierHome(root); err != nil {
		t.Fatalf("inicializar o verificador: %v", err)
	}
	return root
}

func configureVerifier(t *testing.T, root, runtime, bwrap string) {
	t.Helper()
	config := verify.ReadConfig(root)
	if config == nil {
		t.Fatalf("config.json ausente em %s", root)
	}
	config.Runtime.Bun = runtime
	config.Isolation.Bwrap = new(bwrap)
	if err := verify.WriteJSONAtomic(verify.ConfigFile(root), config); err != nil {
		t.Fatalf("gravar a configuração: %v", err)
	}
}

type repoFixture struct {
	rootDir         string
	verifierRoot    string
	acceptedContent string
}

type repoOptions struct {
	acceptanceTest string
	candidate      string
	baseline       string
	omitFrozen     bool
	frozenSHA      string
	acCommand      string
	regression     string
	verifierRoot   string
	globalGates    []string
}

func buildRepo(t *testing.T, options repoOptions) repoFixture {
	t.Helper()
	rootDir := t.TempDir()
	acceptanceTest := options.acceptanceTest
	if acceptanceTest == "" {
		acceptanceTest = acceptanceAsserting("NEW")
	}
	candidate := options.candidate
	if candidate == "" {
		candidate = newImplementation
	}
	baseline := options.baseline
	if baseline == "" {
		baseline = candidate
	}
	acCommand := options.acCommand
	if acCommand == "" {
		acCommand = "/usr/bin/true"
	}
	regression := options.regression
	if regression == "" {
		regression = acCommand
	}

	workPlan := plan.Plan{
		WorkID: workID,
		Title:  "Aceitação independente",
		Components: []plan.PlanComponent{
			{Name: "core", Purpose: "núcleo", Regression: new(regression)},
		},
		GlobalGates: options.globalGates,
		Tasks: []plan.PlanTask{{
			ID:                  taskID,
			Title:               "Implementar valor",
			RequirementID:       "FR-001",
			DependsOn:           []string{},
			Behavior:            "value() devolve o valor implementado",
			Components:          []string{"core"},
			Files:               []string{implPath, acPath},
			ImplementationFiles: []string{implPath},
			TestFiles:           []string{acPath},
			Red:                 plan.PlanRed{Command: acCommand, Description: "falha antes da implementação"},
			ImplementationSteps: []string{"implementar value()"},
			AcceptanceCriteria:  []plan.PlanAC{{Command: acCommand, Description: "value() satisfaz o AC"}},
			Visual:              "N/A",
			Documentation:       "N/A",
			SpecReference:       "SPEC-001",
			ContractID:          "CTR-001",
			Complexity:          "L1",
		}},
	}
	rendered, err := json.MarshalIndent(workPlan, "", "  ")
	if err != nil {
		t.Fatalf("serializar o plano: %v", err)
	}
	writeFile(t, rootDir, ".pwn/work/"+workID+"/plan.json", string(rendered)+"\n")
	writeFile(t, rootDir, ".todo/"+workID+"-tasks.md", plan.RenderTasksMarkdown(workPlan))
	writeFile(t, rootDir, implPath, baseline)
	writeFile(t, rootDir, acPath, acceptanceTest)

	contract := map[string]any{
		"contract_version": "4.0",
		"task_id":          taskID,
		"work_id":          workID,
		"title":            "Implementar valor",
		"acceptance_contract": map[string]any{
			"commands":          []string{acCommand},
			"required_evidence": []string{"evidence.json"},
		},
	}
	if !options.omitFrozen {
		digest := verify.DigestOfText(acceptanceTest)
		if options.frozenSHA != "" {
			digest = options.frozenSHA
		}
		contract["acceptance_contract"].(map[string]any)["frozen_tests"] = []map[string]any{
			{"path": acPath, "sha256": digest},
		}
	}
	contractJSON, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		t.Fatalf("serializar o contrato: %v", err)
	}
	writeFile(t, rootDir, ".pwn/work/"+workID+"/CTR-001.json", string(contractJSON)+"\n")

	runGit(t, rootDir, "init", "-q")
	runGit(t, rootDir, "config", "user.email", "test@example.com")
	runGit(t, rootDir, "config", "user.name", "Test")
	runGit(t, rootDir, "add", "-A")
	runGit(t, rootDir, "commit", "-q", "-m", "baseline")

	if candidate != baseline {
		writeFile(t, rootDir, implPath, candidate)
	}

	verifierRoot := options.verifierRoot
	if verifierRoot == "" {
		verifierRoot = newVerifier(t)
	}

	return repoFixture{
		rootDir:         rootDir,
		verifierRoot:    verifierRoot,
		acceptedContent: acceptanceTest,
	}
}

func approve(t *testing.T, fixture repoFixture) verify.Approval {
	t.Helper()
	approval, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		ApprovedBy:      "operator",
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("criar a aprovação: %v", err)
	}
	return approval
}

func passingResult(t *testing.T, rootDir string) verify.VerificationRunResult {
	t.Helper()
	snapshot, err := verify.CaptureSnapshot(rootDir)
	if err != nil {
		t.Fatalf("capturar o snapshot: %v", err)
	}
	dependency, err := verify.CaptureDependencyDigest(rootDir)
	if err != nil {
		t.Fatalf("capturar as dependências: %v", err)
	}
	return verify.VerificationRunResult{
		Checks: []verify.CheckObservation{{
			ID:           "AC-1",
			Command:      []string{"/usr/bin/true"},
			Outcome:      "pass",
			ExitCode:     0,
			OutputDigest: verify.DigestOfText("ok"),
			OutputTail:   "ok",
		}},
		SnapshotDigest:   snapshot.Digest,
		DependencyDigest: dependency.Digest,
		SandboxDigest:    verify.DigestOfText("policy"),
	}
}

func findCheck(t *testing.T, result verify.VerificationRunResult, id string) verify.CheckObservation {
	t.Helper()
	for _, check := range result.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("check %s ausente no resultado", id)
	return verify.CheckObservation{}
}
