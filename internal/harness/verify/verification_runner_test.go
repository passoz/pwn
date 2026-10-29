package verify_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// bwrapEnvironment devolve os caminhos de bun e bwrap. Sem eles os testes de
// execução são pulados: bwrap é pré-requisito da aceitação independente.
func bwrapEnvironment(t *testing.T) (string, string) {
	t.Helper()
	if !sandbox.IsBwrapSupported() {
		t.Skip("bwrap indisponível: execução no sandbox pulada")
	}
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("bun indisponível: execução no sandbox pulada")
	}
	bwrap, ok := verify.FindExecutable("bwrap")
	if !ok {
		t.Skip("bwrap indisponível: execução no sandbox pulada")
	}
	return bun, bwrap
}

func runFixture(t *testing.T, fixture repoFixture, approval verify.Approval) verify.VerificationRunResult {
	t.Helper()
	result, err := verify.RunVerification(verify.RunVerificationOptions{
		RootDir:         fixture.rootDir,
		Approval:        approval,
		TimeoutSeconds:  120,
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("executar a verificação: %v", err)
	}
	return result
}

func TestRunVerificationRequiresCausality(t *testing.T) {
	bun, bwrap := bwrapEnvironment(t)
	command := bun + " test " + acPath
	fixture := buildRepo(t, repoOptions{
		acceptanceTest: acceptanceAsserting("NEW"),
		candidate:      newImplementation,
		baseline:       oldImplementation,
		acCommand:      command,
		regression:     command,
	})
	configureVerifier(t, fixture.verifierRoot, bun, bwrap)
	approval := approve(t, fixture)

	result := runFixture(t, fixture, approval)
	if result.SandboxPolicy.Engine != "bwrap" || result.SandboxPolicy.Home != "/nonexistent" || result.SandboxPolicy.Network {
		t.Errorf("política do sandbox inesperada: %+v", result.SandboxPolicy)
	}
	if len(result.SandboxDigest) != 64 || len(result.SnapshotDigest) != 64 || len(result.DependencyDigest) != 64 {
		t.Errorf("digests inesperados: %+v", result)
	}

	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "pass" {
		t.Fatalf("AC-1 = %s: %s\n%s", ac.Outcome, ac.Reason, ac.OutputTail)
	}
	if ac.ExitCode != 0 {
		t.Errorf("exit do candidato = %d", ac.ExitCode)
	}
	if ac.Baseline == nil || ac.Baseline.ExitCode == 0 || ac.Baseline.SuspectEnvironmental {
		t.Errorf("baseline inesperado: %+v", ac.Baseline)
	}

	regression := findCheck(t, result, "REGRESSION")
	if regression.Outcome != "pass" || regression.Baseline != nil {
		t.Errorf("REGRESSION inesperado: %+v", regression)
	}
}

func TestRunVerificationRejectsVacuousAcceptance(t *testing.T) {
	bun, bwrap := bwrapEnvironment(t)
	command := bun + " test " + acPath
	fixture := buildRepo(t, repoOptions{
		acceptanceTest: trivialAcceptance,
		candidate:      newImplementation,
		baseline:       oldImplementation,
		acCommand:      command,
		regression:     command,
	})
	configureVerifier(t, fixture.verifierRoot, bun, bwrap)
	approval := approve(t, fixture)

	result := runFixture(t, fixture, approval)
	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "fail" {
		t.Fatalf("AC-1 = %s, quer fail: %s", ac.Outcome, ac.Reason)
	}
	if !strings.Contains(ac.Reason, "sem a implementação") {
		t.Errorf("motivo = %q", ac.Reason)
	}
	if ac.Baseline == nil || ac.Baseline.ExitCode != 0 {
		t.Errorf("baseline inesperado: %+v", ac.Baseline)
	}
}

func TestRunVerificationUsesApprovedAcceptanceFile(t *testing.T) {
	bun, bwrap := bwrapEnvironment(t)
	command := bun + " test " + acPath
	fixture := buildRepo(t, repoOptions{
		acceptanceTest: acceptanceAsserting("NEW"),
		candidate:      newImplementation,
		baseline:       oldImplementation,
		acCommand:      command,
		regression:     command,
	})
	configureVerifier(t, fixture.verifierRoot, bun, bwrap)
	approval := approve(t, fixture)

	// Enfraquece no repositório: agora afirmaria "OLD", que FALHA contra o
	// candidato "NEW". Se o runner usasse o arquivo do repositório, o candidato
	// falharia.
	writeFile(t, fixture.rootDir, acPath, acceptanceAsserting("OLD"))

	result := runFixture(t, fixture, approval)
	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "pass" {
		t.Fatalf("AC-1 = %s: %s\n%s", ac.Outcome, ac.Reason, ac.OutputTail)
	}
	if ac.Baseline == nil || ac.Baseline.ExitCode == 0 {
		t.Errorf("baseline inesperado: %+v", ac.Baseline)
	}
}

// As dependências são montadas DEPOIS de `--bind workDir`. Se a ordem regredir,
// `node_modules` desaparece e o teste falha por import.
func TestRunVerificationMountsDependencies(t *testing.T) {
	bun, bwrap := bwrapEnvironment(t)
	command := bun + " test " + acPath
	root := newVerifier(t)
	keyPath := verify.PrivateKeyFile(root)
	acceptance := "import { expect, test } from \"bun:test\";\n" +
		"import { readFileSync } from \"node:fs\";\n" +
		"import { value } from \"../src/lib.ts\";\n" +
		"test(\"value\", () => {\n" +
		"  expect(value()).toBe(\"NEW\");\n" +
		"  expect(readFileSync(\"node_modules/marker.txt\", \"utf8\").trim()).toBe(\"marker-ok\");\n" +
		"  let keyVisible = false;\n" +
		"  try { readFileSync(" + quote(keyPath) + ", \"utf8\"); keyVisible = true; } catch {}\n" +
		"  expect(keyVisible).toBe(false);\n" +
		"});\n"
	fixture := buildRepo(t, repoOptions{
		acceptanceTest: acceptance,
		candidate:      newImplementation,
		baseline:       oldImplementation,
		acCommand:      command,
		regression:     command,
		verifierRoot:   root,
	})
	configureVerifier(t, fixture.verifierRoot, bun, bwrap)
	approval := approve(t, fixture)
	// node_modules não entra no snapshot; a árvore é montada read-only dentro
	// da cópia avaliada.
	writeFile(t, fixture.rootDir, "node_modules/marker.txt", "marker-ok\n")

	result := runFixture(t, fixture, approval)
	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "pass" {
		t.Fatalf("AC-1 = %s: %s\n%s", ac.Outcome, ac.Reason, ac.OutputTail)
	}
	if ac.Baseline == nil || ac.Baseline.ExitCode == 0 {
		t.Errorf("baseline inesperado: %+v", ac.Baseline)
	}
}
