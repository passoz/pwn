package verify_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

func TestAfterRunWithoutApproval(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	verification, err := verify.AfterRun(verify.AfterRunOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("verificação automática: %v", err)
	}
	if verification.Attempted {
		t.Error("sem aprovação a avaliação não pode ser tentada")
	}
	if !strings.Contains(verification.Reason, "sem aprovação") || !strings.Contains(verification.Reason, taskID) {
		t.Errorf("motivo = %q", verification.Reason)
	}
	var stdout, stderr bytes.Buffer
	verify.ReportAutoVerification(verification, &stdout, &stderr)
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "⚠") {
		t.Errorf("relatório: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAfterRunBlockedWhenBwrapMissing(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	approve(t, fixture)
	configureVerifier(t, fixture.verifierRoot, verify.DefaultRuntime(), "/nonexistent/bwrap")

	verification, err := verify.AfterRun(verify.AfterRunOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("verificação automática: %v", err)
	}
	if !verification.Attempted || verification.Outcome != "blocked" {
		t.Errorf("verificação = %+v", verification)
	}
	if !strings.Contains(verification.Reason, "isolamento indisponível") {
		t.Errorf("motivo = %q", verification.Reason)
	}
	entries, err := os.ReadDir(verify.ReceiptDir(fixture.verifierRoot))
	if err != nil {
		t.Fatalf("listar os recibos: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Errorf("não deveria existir recibo: %s", entry.Name())
		}
	}

	var stdout, stderr bytes.Buffer
	verify.ReportAutoVerification(verification, &stdout, &stderr)
	if !strings.Contains(stderr.String(), "BLOQUEADA") {
		t.Errorf("relatório: %q", stderr.String())
	}
}

func TestReportAutoVerification(t *testing.T) {
	var stdout, stderr bytes.Buffer
	verify.ReportAutoVerification(verify.AutoVerification{Attempted: true, Outcome: "pass", ReceiptID: "abc"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "PASS (recibo abc)") || stderr.Len() != 0 {
		t.Errorf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	verify.ReportAutoVerification(verify.AutoVerification{Attempted: true, Outcome: "fail", ReceiptID: "def"}, &stdout, &stderr)
	if !strings.Contains(stderr.String(), "FAIL (recibo def)") {
		t.Errorf("stderr=%q", stderr.String())
	}
}
