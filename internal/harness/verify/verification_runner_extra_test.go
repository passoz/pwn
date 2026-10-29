package verify_test

import (
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

func TestRunVerificationEnforcesExpectOutput(t *testing.T) {
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
	approval.Checks[0].ExpectOutput = new("texto que o check não produz")

	result := runFixture(t, fixture, approval)
	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "fail" || ac.ExitCode != 0 {
		t.Fatalf("AC-1 = %+v", ac)
	}
	if !strings.Contains(ac.Reason, `"texto que o check não produz"`) {
		t.Errorf("motivo = %q", ac.Reason)
	}
}

func TestRunVerificationBlocksOnTimeout(t *testing.T) {
	_, bwrap := bwrapEnvironment(t)
	command := "/usr/bin/true"
	fixture := buildRepo(t, repoOptions{acCommand: command, regression: command})
	configureVerifier(t, fixture.verifierRoot, verify.DefaultRuntime(), bwrap)
	approval := approve(t, fixture)
	approval.Checks[0].Command = []string{"/usr/bin/sleep", "5"}

	result, err := verify.RunVerification(verify.RunVerificationOptions{
		RootDir:         fixture.rootDir,
		Approval:        approval,
		TimeoutSeconds:  1,
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("executar a verificação: %v", err)
	}
	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "blocked" || !strings.Contains(ac.Reason, "excedeu 1s") {
		t.Fatalf("AC-1 = %+v", ac)
	}
	if outcome := verify.ReceiptOutcome(result); outcome != "blocked" {
		t.Errorf("outcome = %q, quer blocked", outcome)
	}
}
