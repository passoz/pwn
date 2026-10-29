package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/passoz/pwn/internal/platform/cryptox"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// ReceiptCheckSummary é o resumo assinado de um check observado.
type ReceiptCheckSummary struct {
	ID                           string `json:"id"`
	Outcome                      string `json:"outcome"`
	ExitCode                     int    `json:"exit_code"`
	OutputDigest                 string `json:"output_digest"`
	BaselineExitCode             *int   `json:"baseline_exit_code"`
	BaselineSuspectEnvironmental bool   `json:"baseline_suspect_environmental"`
}

// ReceiptVerifier identifica quem assinou o recibo.
type ReceiptVerifier struct {
	ID                   string `json:"id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// ReceiptBase são os campos do recibo antes do identificador calculado.
type ReceiptBase struct {
	Version                 int                   `json:"version"`
	Kind                    string                `json:"kind"`
	WorkID                  string                `json:"work_id"`
	TaskID                  string                `json:"task_id"`
	ApprovalID              string                `json:"approval_id"`
	CandidateSnapshotDigest string                `json:"candidate_snapshot_digest"`
	DependencyDigest        string                `json:"dependency_digest"`
	SandboxDigest           string                `json:"sandbox_digest"`
	Outcome                 string                `json:"outcome"`
	Checks                  []ReceiptCheckSummary `json:"checks"`
	Verifier                ReceiptVerifier       `json:"verifier"`
	CreatedAt               string                `json:"created_at"`
}

// ReceiptSubject é o payload assinado: ReceiptBase mais o receipt_id.
type ReceiptSubject struct {
	ReceiptID string `json:"receipt_id"`
	ReceiptBase
}

// VerificationReceipt é o único documento que autoriza conclusão.
//
// Ele é assinado com a chave privada do verificador — que o código avaliado
// nunca alcança — e vincula a aprovação vigente, a entrega exata que foi
// executada e o resultado observado.
type VerificationReceipt struct {
	ReceiptSubject
	Signature string `json:"signature"`
}

func summarizeObservation(observation CheckObservation) ReceiptCheckSummary {
	summary := ReceiptCheckSummary{
		ID:           observation.ID,
		Outcome:      observation.Outcome,
		ExitCode:     observation.ExitCode,
		OutputDigest: observation.OutputDigest,
	}
	if observation.Baseline != nil {
		summary.BaselineExitCode = new(observation.Baseline.ExitCode)
		summary.BaselineSuspectEnvironmental = observation.Baseline.SuspectEnvironmental
	}
	return summary
}

// ReceiptOutcome agrega o resultado dos checks.
func ReceiptOutcome(result VerificationRunResult) string {
	for _, check := range result.Checks {
		if check.Outcome == "blocked" {
			return "blocked"
		}
	}
	for _, check := range result.Checks {
		if check.Outcome == "fail" {
			return "fail"
		}
	}
	if len(result.Checks) == 0 {
		return "blocked"
	}
	return "pass"
}

// BuildReceiptOptions são as entradas de BuildReceipt.
type BuildReceiptOptions struct {
	Approval Approval
	Result   VerificationRunResult
	// VerifierRootDir é a raiz protegida. Vazio usa Root.
	VerifierRootDir string
}

// BuildReceipt monta e assina o recibo de aceitação.
func BuildReceipt(options BuildReceiptOptions) (VerificationReceipt, error) {
	root, err := resolveRoot(options.VerifierRootDir)
	if err != nil {
		return VerificationReceipt{}, err
	}
	fingerprint, ok := PublicKeyFingerprint(root)
	privateKey, hasKey := LoadPrivateKey(root)
	config := ReadConfig(root)
	if !hasKey || !ok || config == nil {
		return VerificationReceipt{}, fmt.Errorf("verificador não inicializado: não há chave privada para assinar o recibo")
	}
	checks := make([]ReceiptCheckSummary, 0, len(options.Result.Checks))
	for _, observation := range options.Result.Checks {
		checks = append(checks, summarizeObservation(observation))
	}
	base := ReceiptBase{
		Version:                 1,
		Kind:                    "independent-acceptance",
		WorkID:                  options.Approval.WorkID,
		TaskID:                  options.Approval.TaskID,
		ApprovalID:              options.Approval.ApprovalID,
		CandidateSnapshotDigest: options.Result.SnapshotDigest,
		DependencyDigest:        options.Result.DependencyDigest,
		SandboxDigest:           options.Result.SandboxDigest,
		Outcome:                 ReceiptOutcome(options.Result),
		Checks:                  checks,
		Verifier: ReceiptVerifier{
			ID:                   config.VerifierID,
			PublicKeyFingerprint: fingerprint,
		},
		CreatedAt: isoNow(),
	}
	canonicalBase, err := jsonx.Canonical(base)
	if err != nil {
		return VerificationReceipt{}, fmt.Errorf("verifier: serializar o recibo: %w", err)
	}
	subject := ReceiptSubject{ReceiptID: digestBytes(canonicalBase), ReceiptBase: base}
	// O receipt_id entra no payload assinado: a conferência reconstrói o sujeito
	// removendo apenas `signature`, então assinar sem ele invalidaria todo recibo.
	canonicalSubject, err := jsonx.Canonical(subject)
	if err != nil {
		return VerificationReceipt{}, fmt.Errorf("verifier: serializar o recibo: %w", err)
	}
	signature, err := cryptox.SignBase64(privateKey, canonicalSubject)
	if err != nil {
		return VerificationReceipt{}, fmt.Errorf("verifier: assinar o recibo: %w", err)
	}
	return VerificationReceipt{ReceiptSubject: subject, Signature: signature}, nil
}

// SignatureIsValid confere a assinatura do recibo contra a chave pública da
// raiz protegida.
func SignatureIsValid(receipt VerificationReceipt, root string) bool {
	publicKey, ok := LoadPublicKey(root)
	if !ok {
		return false
	}
	canonical, err := jsonx.Canonical(receipt.ReceiptSubject)
	if err != nil {
		return false
	}
	return cryptox.VerifyBase64(publicKey, canonical, receipt.Signature)
}

// ReceiptRepoCopy é a rota da cópia no repositório: revisão humana, nunca fonte
// de autoridade.
func ReceiptRepoCopy(rootDir, workID, taskID string) string {
	path, err := filepath.Abs(filepath.Join(rootDir, ".todo", "verification", fmt.Sprintf("%s-%s-receipt.json", workID, taskID)))
	if err != nil {
		return filepath.Join(rootDir, ".todo", "verification", fmt.Sprintf("%s-%s-receipt.json", workID, taskID))
	}
	return path
}

func receiptCurrentPath(workID, taskID, root string) string {
	return filepath.Join(ReceiptDir(root), fmt.Sprintf("%s-%s.json", workID, taskID))
}

// LatestReceipt lê o recibo mais recente de um par Work/task.
func LatestReceipt(workID, taskID, root string) *VerificationReceipt {
	data, err := os.ReadFile(receiptCurrentPath(workID, taskID, root))
	if err != nil {
		return nil
	}
	return parseReceipt(data)
}

// parseReceipt decodifica um recibo. Devolve nil quando inválido ou de tipo
// diferente de independent-acceptance.
func parseReceipt(data []byte) *VerificationReceipt {
	var receipt VerificationReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil
	}
	if receipt.Version != 1 || receipt.Kind != "independent-acceptance" {
		return nil
	}
	return &receipt
}

// StoreReceipt grava o recibo no histórico, na rota corrente e na cópia do
// repositório. Devolve os caminhos do histórico e da cópia.
func StoreReceipt(receipt VerificationReceipt, rootDir, root string) ([]string, error) {
	history := filepath.Join(ReceiptDir(root), "history", receipt.ReceiptID+".json")
	if err := WriteJSONAtomic(history, receipt); err != nil {
		return nil, err
	}
	if err := WriteJSONAtomic(receiptCurrentPath(receipt.WorkID, receipt.TaskID, root), receipt); err != nil {
		return nil, err
	}
	repoCopy := ReceiptRepoCopy(rootDir, receipt.WorkID, receipt.TaskID)
	if err := os.MkdirAll(filepath.Dir(repoCopy), 0o777); err != nil {
		return nil, fmt.Errorf("verifier: criar %s: %w", filepath.Dir(repoCopy), err)
	}
	if err := WriteJSONAtomic(repoCopy, receipt); err != nil {
		return nil, err
	}
	return []string{history, repoCopy}, nil
}

// AcceptanceEvaluation é o veredicto de EvaluateAcceptance.
type AcceptanceEvaluation struct {
	Accepted bool
	Reason   string
	Receipt  *VerificationReceipt
	Approval *Approval
}

// EvaluateAcceptanceOptions são as entradas de EvaluateAcceptance.
type EvaluateAcceptanceOptions struct {
	RootDir         string
	WorkID          string
	TaskID          string
	VerifierRootDir string
}

// EvaluateAcceptance decide se a task está aceita AGORA.
//
// Aceito exige: aprovação vigente, recibo assinado por chave confiável para essa
// aprovação, resultado `pass` e a árvore atual idêntica à que foi avaliada.
// Qualquer divergência invalida a autorização anterior — o recibo continua sendo
// histórico, não permissão.
func EvaluateAcceptance(options EvaluateAcceptanceOptions) AcceptanceEvaluation {
	root, err := resolveRoot(options.VerifierRootDir)
	if err != nil {
		return AcceptanceEvaluation{Accepted: false, Reason: err.Error()}
	}
	approval := CurrentApproval(options.WorkID, options.TaskID, root)
	if approval == nil {
		return AcceptanceEvaluation{Accepted: false, Approval: nil, Reason: "sem aprovação de aceitação independente"}
	}
	receipt := LatestReceipt(options.WorkID, options.TaskID, root)
	if receipt == nil {
		copyPath := ReceiptRepoCopy(options.RootDir, options.WorkID, options.TaskID)
		if data, err := os.ReadFile(copyPath); err == nil {
			receipt = parseReceipt(data)
		}
	}
	if receipt == nil {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Reason: "sem recibo de verificação independente"}
	}
	if receipt.ApprovalID != approval.ApprovalID {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: "recibo pertence a uma aprovação anterior"}
	}
	fingerprint, ok := PublicKeyFingerprint(root)
	if !ok || receipt.Verifier.PublicKeyFingerprint != fingerprint {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: "recibo assinado por verificador desconhecido"}
	}
	if !SignatureIsValid(*receipt, root) {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: "assinatura do recibo inválida"}
	}
	if receipt.Outcome != "pass" {
		return AcceptanceEvaluation{
			Accepted: false,
			Approval: approval,
			Receipt:  receipt,
			Reason:   fmt.Sprintf("última verificação independente: %s", receipt.Outcome),
		}
	}
	snapshot, err := CaptureSnapshot(options.RootDir)
	if err != nil {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: err.Error()}
	}
	if snapshot.Digest != receipt.CandidateSnapshotDigest {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: "a árvore mudou depois da verificação independente"}
	}
	dependency, err := CaptureDependencyDigest(options.RootDir)
	if err != nil {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: err.Error()}
	}
	if dependency.Digest != receipt.DependencyDigest {
		return AcceptanceEvaluation{Accepted: false, Approval: approval, Receipt: receipt, Reason: "as dependências mudaram depois da verificação independente"}
	}
	return AcceptanceEvaluation{Accepted: true, Approval: approval, Receipt: receipt}
}

// CurrentTreeDigest devolve 16 caracteres do digest da árvore atual, para o
// operador comparar com o recibo.
func CurrentTreeDigest(rootDir string) (string, error) {
	snapshot, err := CaptureSnapshot(rootDir)
	if err != nil {
		return "", err
	}
	return digestBytes([]byte(snapshot.Digest))[:16], nil
}
