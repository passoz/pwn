// Package queue porta a fila de revisão humana (AFK) de src/core/queue.ts.
//
// Cada item vive em <root>/queue/review/<run-id>.json. O arquivo é escrito com
// a mesma forma do JSON.stringify(item, null, 2): chaves na ordem do campo e
// indentação de dois espaços.
package queue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// Status é o estado de um item na fila.
type Status string

const (
	StatusPendingReview Status = "pending_review"
	StatusApproved      Status = "approved"
	StatusRejected      Status = "rejected"
)

func (s Status) valid() bool {
	return s == StatusPendingReview || s == StatusApproved || s == StatusRejected
}

// Item é uma tarefa suspensa aguardando revisão.
type Item struct {
	RunID        string         `json:"runId"`
	WorkID       string         `json:"workId"`
	TaskID       string         `json:"taskId"`
	Title        string         `json:"title"`
	PausedAtStep string         `json:"pausedAtStep"`
	Reason       string         `json:"reason"`
	RiskLevel    string         `json:"riskLevel"`
	CreatedAt    string         `json:"createdAt"`
	Status       Status         `json:"status"`
	Payload      map[string]any `json:"payload,omitempty"`
}

// ReviewBinding é o vínculo de uma aprovação L4: a aprovação vale só para o
// contrato e o comando que foram revisados.
type ReviewBinding struct {
	ContractSHA256 string   `json:"contract_sha256"`
	Command        []string `json:"command"`
}

// Dir garante que <rootDir>/queue/review existe e devolve o caminho.
// rootDir vazio usa o diretório de trabalho atual.
func Dir(rootDir string) (string, error) {
	root, err := resolveRoot(rootDir)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "queue", "review")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("queue: criar %s: %w", dir, err)
	}
	return dir, nil
}

// Enqueue grava o item em queue/review/<runId>.json e devolve o item gravado.
//
// CreatedAt e Status do item recebido são descartados: CreatedAt vem do relógio
// e Status vem do argumento. Status vazio equivale a pending_review.
func Enqueue(item Item, rootDir string, status Status) (Item, error) {
	if status == "" {
		status = StatusPendingReview
	}
	if !status.valid() {
		return Item{}, fmt.Errorf("queue: status inválido: %q", status)
	}
	dir, err := Dir(rootDir)
	if err != nil {
		return Item{}, err
	}
	item.CreatedAt = nowISO()
	item.Status = status
	data, err := marshalIndented(item)
	if err != nil {
		return Item{}, err
	}
	file := filepath.Join(dir, item.RunID+".json")
	if err := fsx.WriteFileAtomic(file, string(data)); err != nil {
		return Item{}, err
	}
	return item, nil
}

// List devolve os itens da fila em ordem de nome de arquivo. Arquivos ilegíveis
// ou com JSON inválido são ignorados, como no TypeScript.
func List(rootDir string) ([]Item, error) {
	dir, err := Dir(rootDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("queue: ler %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	items := make([]Item, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var item Item
		if err := json.Unmarshal(data, &item); err != nil {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

// UpdateStatus troca o estado do item. Devolve nil, sem erro, quando o run não
// existe na fila.
func UpdateStatus(runID string, status Status, rootDir string) (*Item, error) {
	if status != StatusApproved && status != StatusRejected {
		return nil, fmt.Errorf("queue: status de atualização inválido: %q", status)
	}
	dir, err := Dir(rootDir)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dir, runID+".json")
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("queue: ler %s: %w", file, err)
	}
	var item Item
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("queue: decodificar %s: %w", file, err)
	}
	item.Status = status
	data, err = marshalIndented(item)
	if err != nil {
		return nil, err
	}
	if err := fsx.WriteFileAtomic(file, string(data)); err != nil {
		return nil, err
	}
	return &item, nil
}

// FindApproved devolve a aprovação vigente na fila para a task, com o mesmo
// contrato e o mesmo comando. Devolve nil quando não há aprovação.
func FindApproved(workID, taskID string, binding ReviewBinding, rootDir string) (*Item, error) {
	items, err := List(rootDir)
	if err != nil {
		return nil, err
	}
	for i := range items {
		item := &items[i]
		if item.Status != StatusApproved || item.WorkID != workID || item.TaskID != taskID {
			continue
		}
		if payloadString(item.Payload, "contract_sha256") != binding.ContractSHA256 {
			continue
		}
		if !commandEqual(item.Payload, binding.Command) {
			continue
		}
		return item, nil
	}
	return nil, nil
}

func payloadString(payload map[string]any, key string) string {
	value, ok := payload[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

// commandEqual compara o comando do payload com o comando do vínculo, como o
// JSON.stringify das duas listas no TypeScript.
func commandEqual(payload map[string]any, want []string) bool {
	value, ok := payload["command"]
	if !ok {
		return false
	}
	var got []string
	switch command := value.(type) {
	case []any:
		got = make([]string, len(command))
		for i, element := range command {
			text, ok := element.(string)
			if !ok {
				return false
			}
			got[i] = text
		}
	case []string:
		got = command
	default:
		return false
	}
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

const isoLayout = "2006-01-02T15:04:05.000Z"

func nowISO() string {
	return time.Now().UTC().Format(isoLayout)
}

func resolveRoot(rootDir string) (string, error) {
	if rootDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("queue: obter diretório atual: %w", err)
		}
		return wd, nil
	}
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("queue: resolver %s: %w", rootDir, err)
	}
	return root, nil
}

// marshalIndented serializa com a ordem do campo e a indentação do
// JSON.stringify(value, null, 2).
func marshalIndented(value any) ([]byte, error) {
	compact, err := jsonx.Insertion(value)
	if err != nil {
		return nil, fmt.Errorf("queue: serializar item: %w", err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("queue: indentar item: %w", err)
	}
	return out.Bytes(), nil
}
