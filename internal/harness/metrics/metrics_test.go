package metrics_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/passoz/pwn/internal/harness/metrics"
)

func entry(runID, role, model string) metrics.Entry {
	return metrics.Entry{
		Timestamp:    "2026-01-02T03:04:05.000Z",
		RunID:        runID,
		WorkID:       "0001",
		TaskID:       "T-001",
		AgentRole:    metrics.AgentRole(role),
		Model:        model,
		TokensInput:  1000,
		TokensOutput: 500,
		CostUSD:      0.002,
		DurationMs:   1200,
		Status:       metrics.StatusSuccess,
		Attempts:     1,
		Isolated:     true,
	}
}

func TestRecordAndRead(t *testing.T) {
	root := t.TempDir()
	want := entry("RUN-100", "cheap", "qwen3.5:27b")

	if err := metrics.Record(want, root); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pwn", "metrics.jsonl")); err != nil {
		t.Fatalf("metrics.jsonl não criado: %v", err)
	}

	entries, err := metrics.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entradas = %d, quer 1", len(entries))
	}
	got := entries[0]
	if got.RunID != want.RunID || got.TaskID != want.TaskID || got.WorkID != want.WorkID {
		t.Fatalf("identificação divergente: %+v", got)
	}
	if got.AgentRole != want.AgentRole || got.Model != want.Model {
		t.Fatalf("papel/modelo divergente: %+v", got)
	}
	if got.TokensInput != 1000 || got.TokensOutput != 500 {
		t.Fatalf("tokens divergentes: %+v", got)
	}
	if got.CostUSD != 0.002 || got.DurationMs != 1200 {
		t.Fatalf("custo/duração divergentes: %+v", got)
	}
	if got.Status != metrics.StatusSuccess || got.Attempts != 1 || !got.Isolated {
		t.Fatalf("status/tentativas/isolated divergentes: %+v", got)
	}
}

func TestRecordWritesStableJSONL(t *testing.T) {
	root := t.TempDir()
	want := metrics.Entry{
		Timestamp:    "2026-01-02T03:04:05.000Z",
		RunID:        "RUN-100",
		WorkID:       "0001",
		TaskID:       "T-001",
		AgentRole:    metrics.RoleCheap,
		Model:        "qwen3.5:27b",
		TokensInput:  1000,
		TokensOutput: 500,
		CostUSD:      0.002,
		DurationMs:   1200,
		Status:       metrics.StatusSuccess,
		Attempts:     1,
		Isolated:     true,
	}
	if err := metrics.Record(want, root); err != nil {
		t.Fatalf("Record: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".pwn", "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	wantLine := `{"timestamp":"2026-01-02T03:04:05.000Z","runId":"RUN-100","workId":"0001","taskId":"T-001","agentRole":"cheap","model":"qwen3.5:27b","tokensInput":1000,"tokensOutput":500,"costUSD":0.002,"durationMs":1200,"status":"success","attempts":1,"isolated":true}` + "\n"
	if string(data) != wantLine {
		t.Fatalf("linha divergente:\ngot  %q\nwant %q", data, wantLine)
	}
}

func TestReadMissingFile(t *testing.T) {
	entries, err := metrics.Read(t.TempDir())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entradas = %d, quer 0", len(entries))
	}
}

func TestReadSkipsMalformedLines(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, ".pwn", "metrics.jsonl")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	valid := `{"runId":"RUN-1","attempts":1}`
	content := "\n" + valid + "\n{linha quebrada\n   \n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := metrics.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 1 || entries[0].RunID != "RUN-1" {
		t.Fatalf("entradas = %+v, quer só RUN-1", entries)
	}
}

func TestOptimize(t *testing.T) {
	tests := []struct {
		name       string
		entries    []metrics.Entry
		wantCount  int
		wantModel  string
		wantReason string
	}{
		{
			name:      "sem entradas não sugere nada",
			entries:   nil,
			wantCount: 0,
		},
		{
			name:       "strong com sucesso na 1ª tentativa sugere cheap",
			entries:    []metrics.Entry{entry("RUN-1", "strong", "claude-3-7-sonnet")},
			wantCount:  1,
			wantModel:  "claude-3-7-sonnet",
			wantReason: "1 execuções com papel 'strong' tiveram sucesso no 1º turno. Podem ser migradas para papel 'cheap' com economia.",
		},
		{
			name: "agrega modelos na ordem da primeira ocorrência",
			entries: []metrics.Entry{
				entry("RUN-1", "strong", "model-a"),
				entry("RUN-2", "strong", "model-b"),
				entry("RUN-3", "strong", "model-a"),
			},
			wantCount:  1,
			wantModel:  "model-a, model-b",
			wantReason: "3 execuções com papel 'strong' tiveram sucesso no 1º turno. Podem ser migradas para papel 'cheap' com economia.",
		},
		{
			name: "strong com retentativa não conta",
			entries: []metrics.Entry{
				func() metrics.Entry { e := entry("RUN-1", "strong", "model-a"); e.Attempts = 2; return e }(),
			},
			wantCount: 0,
		},
		{
			name: "strong com falha não conta",
			entries: []metrics.Entry{
				func() metrics.Entry {
					e := entry("RUN-1", "strong", "model-a")
					e.Status = metrics.StatusFailed
					return e
				}(),
			},
			wantCount: 0,
		},
		{
			name: "papel cheap não gera sugestão de cheap",
			entries: []metrics.Entry{
				entry("RUN-1", "cheap", "model-a"),
			},
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for _, e := range tt.entries {
				if err := metrics.Record(e, root); err != nil {
					t.Fatal(err)
				}
			}
			suggestions, err := metrics.Optimize(root)
			if err != nil {
				t.Fatalf("Optimize: %v", err)
			}
			if len(suggestions) != tt.wantCount {
				t.Fatalf("sugestões = %+v, quer %d", suggestions, tt.wantCount)
			}
			if tt.wantCount == 0 {
				return
			}
			got := suggestions[0]
			if got.AgentRole != "strong" || got.RecommendedRole != "cheap" {
				t.Fatalf("papéis = %q → %q", got.AgentRole, got.RecommendedRole)
			}
			if got.CurrentModel != tt.wantModel {
				t.Fatalf("modelo = %q, quer %q", got.CurrentModel, tt.wantModel)
			}
			if got.Reason != tt.wantReason {
				t.Fatalf("motivo = %q, quer %q", got.Reason, tt.wantReason)
			}
			if got.EstimatedSavingsPercent != metrics.StrongToCheapSavingsPercent {
				t.Fatalf("economia = %d, quer %d", got.EstimatedSavingsPercent, metrics.StrongToCheapSavingsPercent)
			}
			if got.TaskID != "" {
				t.Fatalf("taskId = %q, quer vazio", got.TaskID)
			}
		})
	}
}

func TestRecordConcurrentAppends(t *testing.T) {
	root := t.TempDir()
	const workers = 8
	const perWorker = 20

	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				e := entry(fmt.Sprintf("RUN-%d-%d", worker, i), "cheap", "model")
				if err := metrics.Record(e, root); err != nil {
					t.Errorf("Record: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	file := filepath.Join(root, ".pwn", "metrics.jsonl")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != workers*perWorker {
		t.Fatalf("linhas = %d, quer %d", len(lines), workers*perWorker)
	}
	for _, line := range lines {
		var decoded metrics.Entry
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("linha corrompida %q: %v", line, err)
		}
		if decoded.RunID == "" {
			t.Fatalf("linha sem runId: %q", line)
		}
	}

	entries, err := metrics.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != workers*perWorker {
		t.Fatalf("entradas = %d, quer %d", len(entries), workers*perWorker)
	}
}
