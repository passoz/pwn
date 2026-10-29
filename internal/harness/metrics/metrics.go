// Package metrics porta o registro de métricas de src/core/metrics.ts.
//
// Cada execução vira uma linha de <root>/.pwn/metrics.jsonl. A linha é escrita
// com a mesma forma do JSON.stringify(entry): chaves na ordem do campo, sem
// espaços. A anexação passa por fsx.AppendLine, que toma fsx.WithFileLock.
package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// AgentRole é o papel que executou a task.
type AgentRole string

const (
	RoleCheap  AgentRole = "cheap"
	RoleStrong AgentRole = "strong"
	RoleReview AgentRole = "review"
	RolePlan   AgentRole = "plan"
)

// Status é o desfecho da execução medida.
type Status string

const (
	StatusSuccess   Status = "success"
	StatusFailed    Status = "failed"
	StatusEscalated Status = "escalated"
)

// Entry é uma linha de métrica.
type Entry struct {
	Timestamp    string    `json:"timestamp"`
	RunID        string    `json:"runId"`
	WorkID       string    `json:"workId"`
	TaskID       string    `json:"taskId"`
	AgentRole    AgentRole `json:"agentRole"`
	Model        string    `json:"model"`
	TokensInput  int       `json:"tokensInput"`
	TokensOutput int       `json:"tokensOutput"`
	CostUSD      float64   `json:"costUSD"`
	DurationMs   int64     `json:"durationMs"`
	Status       Status    `json:"status"`
	Attempts     int       `json:"attempts"`
	// Isolated é true quando a execução rodou num sandbox de worktree Git com
	// diff guard.
	Isolated bool `json:"isolated"`
}

// Suggestion é uma sugestão declarativa de roteamento. Nenhuma decisão é
// derivada dela automaticamente.
type Suggestion struct {
	TaskID                  string `json:"taskId,omitempty"`
	AgentRole               string `json:"agentRole"`
	CurrentModel            string `json:"currentModel"`
	RecommendedRole         string `json:"recommendedRole"`
	Reason                  string `json:"reason"`
	EstimatedSavingsPercent int    `json:"estimatedSavingsPercent"`
}

// StrongToCheapSavingsPercent é o desconto suposto ao rebaixar um papel
// 'strong' para 'cheap'.
const StrongToCheapSavingsPercent = 65

// File garante que <rootDir>/.pwn existe e devolve o caminho do metrics.jsonl.
func File(rootDir string) (string, error) {
	root, err := resolveRoot(rootDir)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, ".pwn")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("metrics: criar %s: %w", dir, err)
	}
	return filepath.Join(dir, "metrics.jsonl"), nil
}

// Record anexa a entrada como uma linha JSONL. A anexação é serializada entre
// processos pela trava de fsx.AppendLine.
func Record(entry Entry, rootDir string) error {
	file, err := File(rootDir)
	if err != nil {
		return err
	}
	line, err := jsonx.Insertion(entry)
	if err != nil {
		return fmt.Errorf("metrics: serializar entrada: %w", err)
	}
	if err := fsx.AppendLine(file, string(line), fsx.LockOptions{}); err != nil {
		return err
	}
	return nil
}

// Read devolve as entradas válidas. Linhas vazias ou com JSON inválido são
// ignoradas, como no TypeScript. Arquivo ausente devolve lista vazia.
func Read(rootDir string) ([]Entry, error) {
	file, err := File(rootDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("metrics: ler %s: %w", file, err)
	}

	lines := strings.Split(string(data), "\n")
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Optimize analisa as métricas e devolve sugestões de roteamento.
//
// A heurística é a mesma do TypeScript: tarefas 'strong' com sucesso na
// primeira tentativa podem migrar para 'cheap'. O modelo reportado vem das
// métricas reais, na ordem da primeira ocorrência.
func Optimize(rootDir string) ([]Suggestion, error) {
	entries, err := Read(rootDir)
	if err != nil {
		return nil, err
	}
	suggestions := make([]Suggestion, 0, 1)
	if len(entries) == 0 {
		return suggestions, nil
	}

	count := 0
	models := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.AgentRole != RoleStrong || entry.Status != StatusSuccess || entry.Attempts != 1 {
			continue
		}
		count++
		if _, ok := seen[entry.Model]; ok {
			continue
		}
		seen[entry.Model] = struct{}{}
		models = append(models, entry.Model)
	}
	if count == 0 {
		return suggestions, nil
	}

	suggestions = append(suggestions, Suggestion{
		AgentRole:               string(RoleStrong),
		CurrentModel:            strings.Join(models, ", "),
		RecommendedRole:         string(RoleCheap),
		Reason:                  fmt.Sprintf("%d execuções com papel 'strong' tiveram sucesso no 1º turno. Podem ser migradas para papel 'cheap' com economia.", count),
		EstimatedSavingsPercent: StrongToCheapSavingsPercent,
	})
	return suggestions, nil
}

func resolveRoot(rootDir string) (string, error) {
	if rootDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("metrics: obter diretório atual: %w", err)
		}
		return wd, nil
	}
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("metrics: resolver %s: %w", rootDir, err)
	}
	return root, nil
}
