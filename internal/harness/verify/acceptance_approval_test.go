package verify_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

func TestCreateApproval(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	approval := approve(t, fixture)

	if approval.Version != 1 || approval.Kind != "task" || approval.ApprovedBy != "operator" {
		t.Errorf("cabeçalho inesperado: %+v", approval.ApprovalContent)
	}
	if approval.WorkID != workID || approval.TaskID != taskID {
		t.Errorf("par Work/task inesperado: %s/%s", approval.WorkID, approval.TaskID)
	}
	if len(approval.ApprovalID) != 64 {
		t.Errorf("approval_id = %q", approval.ApprovalID)
	}
	if len(approval.BaselineCommit) != 40 {
		t.Errorf("baseline_commit = %q", approval.BaselineCommit)
	}
	if approval.ContractID == nil || *approval.ContractID != "CTR-001" {
		t.Errorf("contract_id = %v", approval.ContractID)
	}
	if approval.ContractSHA256 == nil || len(*approval.ContractSHA256) != 64 {
		t.Errorf("contract_sha256 = %v", approval.ContractSHA256)
	}
	if len(approval.ImplementationFiles) != 1 || approval.ImplementationFiles[0] != implPath {
		t.Errorf("implementation_files = %v", approval.ImplementationFiles)
	}

	if len(approval.Checks) != 2 {
		t.Fatalf("checks = %+v", approval.Checks)
	}
	ac := approval.Checks[0]
	if ac.ID != "AC-1" || !ac.RequireBaselineFailure || ac.ExpectOutput != nil {
		t.Errorf("AC-1 inesperado: %+v", ac)
	}
	if len(ac.Command) != 1 || ac.Command[0] != "/usr/bin/true" {
		t.Errorf("comando do AC-1 = %v", ac.Command)
	}
	if approval.Checks[1].ID != "REGRESSION" || approval.Checks[1].RequireBaselineFailure {
		t.Errorf("REGRESSION inesperado: %+v", approval.Checks[1])
	}

	if len(approval.ApprovedFiles) != 1 {
		t.Fatalf("approved_files = %+v", approval.ApprovedFiles)
	}
	file := approval.ApprovedFiles[0]
	if file.Path != acPath || file.SHA256 != verify.DigestOfText(fixture.acceptedContent) {
		t.Errorf("arquivo aprovado inesperado: %+v", file)
	}

	// O conteúdo aprovado sobrevive à alteração do repositório.
	writeFile(t, fixture.rootDir, acPath, "// enfraquecido depois da aprovação\n")
	content, ok := verify.ApprovedFileContent(approval, acPath, fixture.verifierRoot)
	if !ok || content != fixture.acceptedContent {
		t.Errorf("conteúdo aprovado = %q, ok = %v", content, ok)
	}

	current := verify.CurrentApproval(workID, taskID, fixture.verifierRoot)
	if current == nil || current.ApprovalID != approval.ApprovalID {
		t.Errorf("aprovação vigente = %+v", current)
	}
	if approvals := verify.ListApprovals(fixture.verifierRoot); len(approvals) != 1 {
		t.Errorf("listApprovals = %+v", approvals)
	}

	// O JSON gravado precisa reproduzir o approval_id: canonicalizar o conteúdo
	// relido do disco tem de dar o mesmo digest.
	data, err := os.ReadFile(verify.ApprovalPath(approval.ApprovalID, fixture.verifierRoot))
	if err != nil {
		t.Fatalf("ler a aprovação gravada: %v", err)
	}
	var reloaded verify.Approval
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("decodificar a aprovação gravada: %v", err)
	}
	canonical, err := jsonx.Canonical(reloaded.ApprovalContent)
	if err != nil {
		t.Fatalf("canonicalizar a aprovação relida: %v", err)
	}
	if digest := verify.DigestOfText(string(canonical)); digest != approval.ApprovalID {
		t.Errorf("approval_id relido = %s, quer %s", digest, approval.ApprovalID)
	}
}

func TestCreateApprovalGlobalGate(t *testing.T) {
	fixture := buildRepo(t, repoOptions{globalGates: []string{"G-1 `bun test`"}})
	approval, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		Global:          "G-1",
		ApprovedBy:      "operator",
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("criar a aprovação global: %v", err)
	}
	if approval.Kind != "global" || approval.TaskID != "G-1" {
		t.Errorf("cabeçalho inesperado: %+v", approval.ApprovalContent)
	}
	if approval.ContractID != nil || approval.ContractSHA256 != nil {
		t.Errorf("aprovação global não deveria ter contrato: %v %v", approval.ContractID, approval.ContractSHA256)
	}
	if len(approval.ImplementationFiles) != 0 || len(approval.ApprovedFiles) != 0 {
		t.Errorf("aprovação global não deveria ter arquivos: %+v", approval.ApprovalContent)
	}
	if len(approval.Checks) != 1 || approval.Checks[0].ID != "G-1" ||
		len(approval.Checks[0].Command) != 2 || approval.Checks[0].RequireBaselineFailure {
		t.Errorf("checks globais inesperados: %+v", approval.Checks)
	}
	if current := verify.CurrentApproval(workID, "G-1", fixture.verifierRoot); current == nil || current.ApprovalID != approval.ApprovalID {
		t.Errorf("aprovação global não está vigente: %+v", current)
	}

	if _, err := verify.CreateApproval(verify.CreateApprovalOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		Global:          "G-9",
		ApprovedBy:      "operator",
		VerifierRootDir: fixture.verifierRoot,
	}); err == nil || !strings.Contains(err.Error(), "não existe no plano") {
		t.Errorf("erro = %v, quer gate inexistente", err)
	}
}

func TestCreateApprovalRequiresFrozenTests(t *testing.T) {
	t.Run("contrato sem frozen_tests", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{omitFrozen: true})
		_, err := verify.CreateApproval(verify.CreateApprovalOptions{
			RootDir:         fixture.rootDir,
			WorkID:          workID,
			TaskID:          taskID,
			ApprovedBy:      "operator",
			VerifierRootDir: fixture.verifierRoot,
		})
		if err == nil || !strings.Contains(err.Error(), "congelados") {
			t.Fatalf("erro = %v, quer testes congelados ausentes", err)
		}
	})

	t.Run("sha256 divergente do congelado", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{frozenSHA: verify.DigestOfText("conteúdo que não está no repositório")})
		_, err := verify.CreateApproval(verify.CreateApprovalOptions{
			RootDir:         fixture.rootDir,
			WorkID:          workID,
			TaskID:          taskID,
			ApprovedBy:      "operator",
			VerifierRootDir: fixture.verifierRoot,
		})
		if err == nil || !strings.Contains(err.Error(), "diverge do congelado") {
			t.Fatalf("erro = %v, quer divergência do congelado", err)
		}
	})

	t.Run("aprovação exige responsável", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		_, err := verify.CreateApproval(verify.CreateApprovalOptions{
			RootDir:         fixture.rootDir,
			WorkID:          workID,
			TaskID:          taskID,
			VerifierRootDir: fixture.verifierRoot,
		})
		if err == nil || !strings.Contains(err.Error(), "--by") {
			t.Fatalf("erro = %v, quer exigência de --by", err)
		}
	})
}
