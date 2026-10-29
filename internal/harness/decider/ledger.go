package decider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/cryptox"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// Registro de cada decisão tomada no lugar do operador.
//
// Fonte de autoridade: `<raiz do verificador>/decisions/<id>.json`, assinado com
// a chave Ed25519 do verificador (a mesma dos recibos). Cópia para revisão
// humana em `.pwn/decisions/<work>/<id>.json`. Guarda perguntas, respostas
// brutas, limiares e modelo exato: a política pode ser recalculada sem chamar o
// modelo de novo.

// Outcome é o resultado de uma decisão.
type Outcome string

const (
	// OutcomeApprove aceita a ação.
	OutcomeApprove Outcome = "approve"
	// OutcomeReject recusa a ação.
	OutcomeReject Outcome = "reject"
	// OutcomeEscalate devolve a decisão ao operador.
	OutcomeEscalate Outcome = "escalate"
)

// DecisionContent são os campos decididos pela política e pelo motor.
type DecisionContent struct {
	Point      DecisionPoint       `json:"point"`
	Project    string              `json:"project"`
	WorkID     string              `json:"work_id"`
	TaskID     string              `json:"task_id"`
	Decider    string              `json:"decider"`
	Model      *string             `json:"model"`
	StateSHA   *string             `json:"state_sha256"`
	Questions  map[string]Question `json:"questions"`
	Answers    map[string]Answer   `json:"answers"`
	Usage      *Usage              `json:"usage"`
	Thresholds map[string]any      `json:"thresholds"`
	Outcome    Outcome             `json:"outcome"`
	Action     *string             `json:"action"`
	Reasons    []string            `json:"reasons"`
}

// DecisionVerifier identifica quem assinou a decisão.
type DecisionVerifier struct {
	ID                   string `json:"id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type decisionBase struct {
	Version int `json:"version"`
	DecisionContent
	CreatedAt string           `json:"created_at"`
	Verifier  DecisionVerifier `json:"verifier"`
}

// DecisionSubject é o payload assinado: o registro sem a assinatura.
type DecisionSubject struct {
	Version    int    `json:"version"`
	DecisionID string `json:"decision_id"`
	DecisionContent
	CreatedAt string           `json:"created_at"`
	Verifier  DecisionVerifier `json:"verifier"`
}

// DecisionRecord é o registro gravado, com a assinatura Ed25519.
type DecisionRecord struct {
	DecisionSubject
	Signature string `json:"signature"`
}

// DecisionRepoCopy devolve a cópia do registro no repositório, para revisão
// humana.
func DecisionRepoCopy(rootDir, workID, decisionID string) string {
	path, err := filepath.Abs(filepath.Join(rootDir, ".pwn", "decisions", workID, decisionID+".json"))
	if err != nil {
		return filepath.Join(rootDir, ".pwn", "decisions", workID, decisionID+".json")
	}
	return path
}

func decisionsDir(root string) string { return filepath.Join(root, "decisions") }

// RecordDecision assina e grava a decisão. Devolve o registro com o id que a
// ação cita (ex.: `approved_by`).
func RecordDecision(content DecisionContent, rootDir, root string) (DecisionRecord, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return DecisionRecord{}, err
	}
	initialization, err := verify.InitializeVerifierHome(resolved)
	if err != nil {
		return DecisionRecord{}, err
	}
	privateKey, ok := verify.LoadPrivateKey(resolved)
	if !ok {
		return DecisionRecord{}, fmt.Errorf("verificador sem chave para assinar a decisão: rode 'pwn verify init'")
	}
	fingerprint, ok := verify.PublicKeyFingerprint(resolved)
	if !ok {
		return DecisionRecord{}, fmt.Errorf("verificador sem chave para assinar a decisão: rode 'pwn verify init'")
	}
	createdAt := nowISO()
	base := decisionBase{
		Version:         1,
		DecisionContent: content,
		CreatedAt:       createdAt,
		Verifier:        DecisionVerifier{ID: initialization.Config.VerifierID, PublicKeyFingerprint: fingerprint},
	}
	canonicalBase, err := jsonx.Canonical(base)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("decider: serializar a decisão: %w", err)
	}
	decisionID := verify.DigestOfText(string(canonicalBase))[:24]
	subject := DecisionSubject{
		Version:         1,
		DecisionID:      decisionID,
		DecisionContent: content,
		CreatedAt:       createdAt,
		Verifier:        DecisionVerifier{ID: initialization.Config.VerifierID, PublicKeyFingerprint: fingerprint},
	}
	canonicalSubject, err := jsonx.Canonical(subject)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("decider: serializar a decisão: %w", err)
	}
	signature, err := cryptox.SignBase64(privateKey, canonicalSubject)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("decider: assinar a decisão: %w", err)
	}
	record := DecisionRecord{DecisionSubject: subject, Signature: signature}
	if err := verify.WriteJSONAtomic(filepath.Join(decisionsDir(resolved), record.DecisionID+".json"), record); err != nil {
		return DecisionRecord{}, err
	}
	if err := verify.WriteJSONAtomic(DecisionRepoCopy(rootDir, record.WorkID, record.DecisionID), record); err != nil {
		return DecisionRecord{}, err
	}
	return record, nil
}

// DecisionSignatureValid confere a assinatura da decisão contra a chave pública
// da raiz protegida.
func DecisionSignatureValid(record DecisionRecord, root string) bool {
	resolved, err := resolveRoot(root)
	if err != nil {
		return false
	}
	publicKey, ok := verify.LoadPublicKey(resolved)
	if !ok {
		return false
	}
	canonical, err := jsonx.Canonical(record.DecisionSubject)
	if err != nil {
		return false
	}
	return cryptox.VerifyBase64(publicKey, canonical, record.Signature)
}

// ReadDecision lê uma decisão da raiz do verificador. Devolve nil quando o
// arquivo não existe.
func ReadDecision(decisionID, root string) (*DecisionRecord, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(decisionsDir(resolved), decisionID+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("decider: ler a decisão: %w", err)
	}
	var record DecisionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decider: decisão inválida: %w", err)
	}
	return &record, nil
}

// ListDecisions devolve as decisões de um projeto, da mais antiga para a mais
// nova. Raiz sem configuração do verificador devolve lista vazia.
func ListDecisions(project, root string) ([]DecisionRecord, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	directory := decisionsDir(resolved)
	if !verify.IsDirectory(directory) || verify.ReadConfig(resolved) == nil {
		return nil, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("decider: listar as decisões: %w", err)
	}
	records := make([]DecisionRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("decider: ler a decisão: %w", err)
		}
		var record DecisionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("decider: decisão inválida: %w", err)
		}
		if record.Project == project {
			records = append(records, record)
		}
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].CreatedAt < records[j].CreatedAt })
	return records, nil
}
