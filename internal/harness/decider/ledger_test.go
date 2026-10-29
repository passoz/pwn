package decider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordDecisionSignsAndCopies(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	model := "jev-test-1"
	digest := "abc"
	content := DecisionContent{
		Point:    PointApprove,
		Project:  repo,
		WorkID:   "0001",
		TaskID:   "1.1",
		Decider:  "jev:jev-latest",
		Model:    &model,
		StateSHA: &digest,
		Questions: map[string]Question{
			"ok": {Type: QuestionNoul, Instructions: "tudo certo?", Criteria: NoulCriteria{True: "sim", False: "não"}},
		},
		Answers:    map[string]Answer{"ok": {Type: QuestionNoul, Noul: new(0.9)}},
		Usage:      &Usage{InputTokens: 10, OutputTokens: 2},
		Thresholds: map[string]any{"min": 0.8},
		Outcome:    OutcomeApprove,
		Reasons:    []string{"ok=0.90"},
	}
	record, err := RecordDecision(content, repo, verifier)
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if len(record.DecisionID) != 24 {
		t.Fatalf("decision_id = %q", record.DecisionID)
	}
	if !DecisionSignatureValid(record, verifier) {
		t.Fatal("assinatura deveria ser válida")
	}
	tampered := record
	tampered.Outcome = OutcomeReject
	if DecisionSignatureValid(tampered, verifier) {
		t.Fatal("assinatura deveria invalidar com outcome alterado")
	}
	tampered = record
	tampered.Answers = map[string]Answer{"ok": {Type: QuestionNoul, Noul: new(0.1)}}
	if DecisionSignatureValid(tampered, verifier) {
		t.Fatal("assinatura deveria invalidar com respostas alteradas")
	}

	authority := filepath.Join(verifier, "decisions", record.DecisionID+".json")
	if _, err := os.Stat(authority); err != nil {
		t.Fatalf("registro de autoridade ausente: %v", err)
	}
	copyPath := DecisionRepoCopy(repo, "0001", record.DecisionID)
	if _, err := os.Stat(copyPath); err != nil {
		t.Fatalf("cópia no repositório ausente: %v", err)
	}

	read, err := ReadDecision(record.DecisionID, verifier)
	if err != nil || read == nil {
		t.Fatalf("ReadDecision = %+v, %v", read, err)
	}
	if !DecisionSignatureValid(*read, verifier) {
		t.Fatal("assinatura não sobreviveu à releitura (ordem canônica das perguntas)")
	}
	if read.Model == nil || *read.Model != model || read.Outcome != OutcomeApprove {
		t.Fatalf("registro relido = %+v", read)
	}

	missing, err := ReadDecision("000000000000000000000000", verifier)
	if err != nil || missing != nil {
		t.Fatalf("ReadDecision ausente = %+v, %v", missing, err)
	}

	list, err := ListDecisions(repo, verifier)
	if err != nil || len(list) != 1 || list[0].DecisionID != record.DecisionID {
		t.Fatalf("ListDecisions = %+v, %v", list, err)
	}
	other, err := ListDecisions("outro", verifier)
	if err != nil || len(other) != 0 {
		t.Fatalf("ListDecisions outro = %+v, %v", other, err)
	}
}

func TestRuleDecisionReferenceAndDescription(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	record, err := RecordRuleDecision(RuleDecisionOptions{
		RootDir: repo,
		WorkID:  "0001",
		TaskID:  "1.1",
		Point:   PointApprove,
		Action:  "baseline",
		Reasons: []string{"regra fixa"},
	}, verifier)
	if err != nil {
		t.Fatalf("RecordRuleDecision: %v", err)
	}
	if record.Decider != "rule" || record.Model != nil || record.Outcome != OutcomeApprove {
		t.Fatalf("registro de regra = %+v", record)
	}
	if got := DecisionReference(record); got != "decider:rule#"+record.DecisionID {
		t.Fatalf("DecisionReference = %q", got)
	}
	lines := DescribeDecision(record)
	if len(lines) != 2 || lines[0] != "[DECISOR] APROVADO (baseline) — rule, registro "+record.DecisionID {
		t.Fatalf("DescribeDecision = %q", lines)
	}
	if lines[1] != "  · regra fixa" {
		t.Fatalf("linha de motivo = %q", lines[1])
	}
	if !DecisionSignatureValid(record, verifier) {
		t.Fatal("assinatura da decisão por regra inválida")
	}
}
