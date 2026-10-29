package verify_test

import (
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

func storeApproval(t *testing.T, root string, approval verify.Approval) {
	t.Helper()
	if err := verify.WriteJSONAtomic(verify.ApprovalPath(approval.ApprovalID, root), approval); err != nil {
		t.Fatalf("gravar a aprovação: %v", err)
	}
	index := verify.ApprovalIndex{Version: 1, Current: map[string]string{
		approval.WorkID + ":" + approval.TaskID: approval.ApprovalID,
	}}
	if err := verify.WriteJSONAtomic(verify.ApprovalsDir(root)+"/index.json", index); err != nil {
		t.Fatalf("gravar o índice: %v", err)
	}
}

func TestReceiptSignatureAndEvaluation(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	approval := approve(t, fixture)
	result := passingResult(t, fixture.rootDir)
	receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{
		Approval:        approval,
		Result:          result,
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("montar o recibo: %v", err)
	}

	if receipt.Version != 1 || receipt.Kind != "independent-acceptance" || receipt.Outcome != "pass" {
		t.Errorf("cabeçalho inesperado: %+v", receipt.ReceiptBase)
	}
	if len(receipt.ReceiptID) != 64 || len(receipt.Signature) != 88 {
		t.Errorf("receipt_id/assinatura inesperados: %q %q", receipt.ReceiptID, receipt.Signature)
	}
	if receipt.ApprovalID != approval.ApprovalID || receipt.WorkID != workID || receipt.TaskID != taskID {
		t.Errorf("vínculo inesperado: %+v", receipt.ReceiptBase)
	}
	if !verify.SignatureIsValid(receipt, fixture.verifierRoot) {
		t.Fatal("a assinatura do recibo não verifica")
	}
	fingerprint, _ := verify.PublicKeyFingerprint(fixture.verifierRoot)
	if receipt.Verifier.PublicKeyFingerprint != fingerprint {
		t.Errorf("fingerprint do recibo = %q, quer %q", receipt.Verifier.PublicKeyFingerprint, fingerprint)
	}

	paths, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot)
	if err != nil {
		t.Fatalf("gravar o recibo: %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("caminhos gravados = %v", paths)
	}

	evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: fixture.verifierRoot,
	})
	if !evaluation.Accepted {
		t.Fatalf("não aceitou: %s", evaluation.Reason)
	}
	if evaluation.Receipt == nil || evaluation.Receipt.ReceiptID != receipt.ReceiptID {
		t.Errorf("recibo da avaliação = %+v", evaluation.Receipt)
	}
	latest := verify.LatestReceipt(workID, taskID, fixture.verifierRoot)
	if latest == nil || latest.ReceiptID != receipt.ReceiptID {
		t.Fatalf("latestReceipt = %+v", latest)
	}
	if !verify.SignatureIsValid(*latest, fixture.verifierRoot) {
		t.Error("o recibo relido do disco não verifica")
	}
}

func TestReceiptTamperingIsRejected(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	approval := approve(t, fixture)
	result := passingResult(t, fixture.rootDir)
	valid, err := verify.BuildReceipt(verify.BuildReceiptOptions{Approval: approval, Result: result, VerifierRootDir: fixture.verifierRoot})
	if err != nil {
		t.Fatalf("montar o recibo: %v", err)
	}
	if !verify.SignatureIsValid(valid, fixture.verifierRoot) {
		t.Fatal("o recibo original deveria verificar")
	}

	tampers := map[string]func(*verify.VerificationReceipt){
		"outcome": func(receipt *verify.VerificationReceipt) { receipt.Outcome = "fail" },
		"checks":  func(receipt *verify.VerificationReceipt) { receipt.Checks = []verify.ReceiptCheckSummary{} },
		"snapshot": func(receipt *verify.VerificationReceipt) {
			receipt.CandidateSnapshotDigest = verify.DigestOfText("outra árvore")
		},
	}
	for label, tamper := range tampers {
		t.Run(label, func(t *testing.T) {
			forged := valid
			tamper(&forged)
			if verify.SignatureIsValid(forged, fixture.verifierRoot) {
				t.Fatal("recibo adulterado não pode verificar")
			}
			if err := verify.WriteJSONAtomic(verify.ReceiptDir(fixture.verifierRoot)+"/"+workID+"-"+taskID+".json", forged); err != nil {
				t.Fatalf("gravar o recibo forjado: %v", err)
			}
			evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
				RootDir:         fixture.rootDir,
				WorkID:          workID,
				TaskID:          taskID,
				VerifierRootDir: fixture.verifierRoot,
			})
			if evaluation.Accepted || !strings.Contains(evaluation.Reason, "assinatura") {
				t.Errorf("avaliação = %+v, quer recusa por assinatura", evaluation)
			}
		})
	}
}

func TestEvaluateAcceptanceRejectsTreeAndApprovalChanges(t *testing.T) {
	t.Run("árvore mudou", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{
			Approval:        approval,
			Result:          passingResult(t, fixture.rootDir),
			VerifierRootDir: fixture.verifierRoot,
		})
		if err != nil {
			t.Fatalf("montar o recibo: %v", err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err != nil {
			t.Fatalf("gravar o recibo: %v", err)
		}

		writeFile(t, fixture.rootDir, "src/indireto.ts", "export const mudou = true;\n")
		evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
			RootDir:         fixture.rootDir,
			WorkID:          workID,
			TaskID:          taskID,
			VerifierRootDir: fixture.verifierRoot,
		})
		if evaluation.Accepted || !strings.Contains(evaluation.Reason, "árvore mudou") {
			t.Errorf("avaliação = %+v", evaluation)
		}
	})

	t.Run("nova aprovação substitui a vigente", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		first := approve(t, fixture)
		receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{
			Approval:        first,
			Result:          passingResult(t, fixture.rootDir),
			VerifierRootDir: fixture.verifierRoot,
		})
		if err != nil {
			t.Fatalf("montar o recibo: %v", err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err != nil {
			t.Fatalf("gravar o recibo: %v", err)
		}

		contractPath := ".pwn/work/" + workID + "/CTR-001.json"
		contract, err := readText(fixture.rootDir, contractPath)
		if err != nil {
			t.Fatalf("ler o contrato: %v", err)
		}
		writeFile(t, fixture.rootDir, contractPath, strings.Replace(contract, "\"title\": \"Implementar valor\"", "\"title\": \"Contrato alterado\"", 1))
		second := approve(t, fixture)
		if second.ApprovalID == first.ApprovalID {
			t.Fatal("a nova aprovação deveria ter outro id")
		}

		evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
			RootDir:         fixture.rootDir,
			WorkID:          workID,
			TaskID:          taskID,
			VerifierRootDir: fixture.verifierRoot,
		})
		if evaluation.Accepted || !strings.Contains(evaluation.Reason, "aprovação anterior") {
			t.Errorf("avaliação = %+v", evaluation)
		}
	})
}

func TestEvaluateAcceptanceRejectsOtherVerifier(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	approval := approve(t, fixture)
	receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{
		Approval:        approval,
		Result:          passingResult(t, fixture.rootDir),
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("montar o recibo: %v", err)
	}

	other := newVerifier(t)
	if verify.SignatureIsValid(receipt, other) {
		t.Fatal("o recibo não pode verificar com outra chave")
	}
	// A MESMA aprovação existe no outro verificador, mas o recibo foi assinado
	// pelo primeiro.
	storeApproval(t, other, approval)
	if err := verify.WriteJSONAtomic(verify.ReceiptDir(other)+"/"+workID+"-"+taskID+".json", receipt); err != nil {
		t.Fatalf("gravar o recibo: %v", err)
	}
	evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: other,
	})
	if evaluation.Accepted || !strings.Contains(evaluation.Reason, "verificador desconhecido") {
		t.Errorf("avaliação = %+v", evaluation)
	}
}

func TestEvaluateAcceptanceWithoutApprovalOrReceipt(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: fixture.verifierRoot,
	})
	if evaluation.Accepted || !strings.Contains(evaluation.Reason, "sem aprovação") {
		t.Errorf("avaliação = %+v", evaluation)
	}

	approval := approve(t, fixture)
	evaluation = verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: fixture.verifierRoot,
	})
	if evaluation.Accepted || !strings.Contains(evaluation.Reason, "sem recibo") {
		t.Errorf("avaliação = %+v", evaluation)
	}
	if evaluation.Approval == nil || evaluation.Approval.ApprovalID != approval.ApprovalID {
		t.Errorf("aprovação da avaliação = %+v", evaluation.Approval)
	}
}

func TestCurrentTreeDigest(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	first, err := verify.CurrentTreeDigest(fixture.rootDir)
	if err != nil {
		t.Fatalf("digest da árvore: %v", err)
	}
	if len(first) != 16 {
		t.Errorf("digest = %q, quer 16 caracteres", first)
	}
	writeFile(t, fixture.rootDir, "src/outro.ts", "export const outro = 1;\n")
	second, err := verify.CurrentTreeDigest(fixture.rootDir)
	if err != nil {
		t.Fatalf("digest da árvore: %v", err)
	}
	if first == second {
		t.Error("o digest deveria mudar com a árvore")
	}
}
