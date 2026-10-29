package queue_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/passoz/pwn/internal/harness/queue"
)

var isoPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func baseItem(runID string) queue.Item {
	return queue.Item{
		RunID:        runID,
		WorkID:       "0001",
		TaskID:       "1.1",
		Title:        "Rodar o script",
		PausedAtStep: "pre-execution",
		Reason:       "Tarefa de risco L4",
		RiskLevel:    "L4",
		Payload: map[string]any{
			"contract_sha256": "abc123",
			"command":         []string{"echo", "hi"},
		},
	}
}

func readItem(t *testing.T, path string) (queue.Item, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var item queue.Item
	if err := json.Unmarshal(data, &item); err != nil {
		t.Fatalf("Unmarshal(%s): %v", path, err)
	}
	return item, data
}

func TestEnqueue(t *testing.T) {
	tests := []struct {
		name       string
		status     queue.Status
		wantStatus queue.Status
	}{
		{name: "status vazio vira pending_review", status: "", wantStatus: queue.StatusPendingReview},
		{name: "pending_review", status: queue.StatusPendingReview, wantStatus: queue.StatusPendingReview},
		{name: "approved", status: queue.StatusApproved, wantStatus: queue.StatusApproved},
		{name: "rejected", status: queue.StatusRejected, wantStatus: queue.StatusRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			item := baseItem("RUN-100")
			item.CreatedAt = "valor antigo"
			item.Status = queue.StatusRejected

			published, err := queue.Enqueue(item, root, tt.status)
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if published.Status != tt.wantStatus {
				t.Fatalf("status = %q, quer %q", published.Status, tt.wantStatus)
			}
			if !isoPattern.MatchString(published.CreatedAt) {
				t.Fatalf("createdAt = %q, quer ISO com milissegundos", published.CreatedAt)
			}

			path := filepath.Join(root, "queue", "review", "RUN-100.json")
			onDisk, _ := readItem(t, path)
			if onDisk.RunID != item.RunID || onDisk.WorkID != item.WorkID || onDisk.TaskID != item.TaskID {
				t.Fatalf("identificação divergente: %+v", onDisk)
			}
			if onDisk.Title != item.Title || onDisk.PausedAtStep != item.PausedAtStep {
				t.Fatalf("campos de pausa divergentes: %+v", onDisk)
			}
			if onDisk.Reason != item.Reason || onDisk.RiskLevel != item.RiskLevel {
				t.Fatalf("campos de risco divergentes: %+v", onDisk)
			}
			if onDisk.Status != tt.wantStatus {
				t.Fatalf("status no disco = %q, quer %q", onDisk.Status, tt.wantStatus)
			}
			if onDisk.CreatedAt != published.CreatedAt {
				t.Fatalf("createdAt no disco = %q, quer %q", onDisk.CreatedAt, published.CreatedAt)
			}
			if onDisk.Payload["contract_sha256"] != "abc123" {
				t.Fatalf("payload.contract_sha256 = %v", onDisk.Payload["contract_sha256"])
			}
		})
	}
}

func TestEnqueueRejectsInvalidStatus(t *testing.T) {
	if _, err := queue.Enqueue(baseItem("RUN-1"), t.TempDir(), queue.Status("aprovado")); err == nil {
		t.Fatal("status inválido deveria falhar")
	}
}

func TestEnqueueWritesStringifyShape(t *testing.T) {
	root := t.TempDir()
	published, err := queue.Enqueue(baseItem("RUN-9"), root, queue.StatusApproved)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "queue", "review", "RUN-9.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "runId": "RUN-9",
  "workId": "0001",
  "taskId": "1.1",
  "title": "Rodar o script",
  "pausedAtStep": "pre-execution",
  "reason": "Tarefa de risco L4",
  "riskLevel": "L4",
  "createdAt": "` + published.CreatedAt + `",
  "status": "approved",
  "payload": {
    "command": [
      "echo",
      "hi"
    ],
    "contract_sha256": "abc123"
  }
}`
	if got := string(data); got != want {
		t.Fatalf("conteúdo divergente:\ngot  %q\nwant %q", got, want)
	}
}

func TestList(t *testing.T) {
	root := t.TempDir()
	for _, runID := range []string{"RUN-2", "RUN-1"} {
		if _, err := queue.Enqueue(baseItem(runID), root, queue.StatusPendingReview); err != nil {
			t.Fatal(err)
		}
	}

	dir := filepath.Join(root, "queue", "review")
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nota.txt"), []byte("ignorado"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "pasta.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		rootDir  string
		wantRuns []string
	}{
		{name: "ordena e ignora arquivos inválidos", rootDir: root, wantRuns: []string{"RUN-1", "RUN-2"}},
		{name: "fila vazia", rootDir: t.TempDir(), wantRuns: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, err := queue.List(tt.rootDir)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(items) != len(tt.wantRuns) {
				t.Fatalf("itens = %d, quer %d", len(items), len(tt.wantRuns))
			}
			for i, runID := range tt.wantRuns {
				if items[i].RunID != runID {
					t.Fatalf("item %d = %q, quer %q", i, items[i].RunID, runID)
				}
			}
		})
	}
}

func TestListCreatesEmptyQueue(t *testing.T) {
	root := t.TempDir()
	items, err := queue.List(root)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("itens = %d, quer 0", len(items))
	}
	if _, err := os.Stat(filepath.Join(root, "queue", "review")); err != nil {
		t.Fatalf("diretório da fila não criado: %v", err)
	}
}

func TestUpdateStatus(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		status     queue.Status
		prepare    bool
		corrupt    bool
		wantFound  bool
		wantErr    bool
		wantStatus queue.Status
	}{
		{
			name:       "aprova item existente",
			runID:      "RUN-1",
			status:     queue.StatusApproved,
			prepare:    true,
			wantFound:  true,
			wantStatus: queue.StatusApproved,
		},
		{
			name:       "rejeita item existente",
			runID:      "RUN-1",
			status:     queue.StatusRejected,
			prepare:    true,
			wantFound:  true,
			wantStatus: queue.StatusRejected,
		},
		{
			name:      "run ausente devolve nil",
			runID:     "RUN-404",
			status:    queue.StatusApproved,
			wantFound: false,
		},
		{
			name:      "status pending_review é recusado",
			runID:     "RUN-1",
			status:    queue.StatusPendingReview,
			prepare:   true,
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "JSON inválido devolve erro",
			runID:     "RUN-BAD",
			status:    queue.StatusApproved,
			corrupt:   true,
			wantFound: false,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if tt.prepare {
				if _, err := queue.Enqueue(baseItem(tt.runID), root, queue.StatusPendingReview); err != nil {
					t.Fatal(err)
				}
			}
			if tt.corrupt {
				dir := filepath.Join(root, "queue", "review")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, tt.runID+".json")
				if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			updated, err := queue.UpdateStatus(tt.runID, tt.status, root)
			if tt.wantErr {
				if err == nil {
					t.Fatal("esperava erro")
				}
				return
			}
			if err != nil {
				t.Fatalf("UpdateStatus: %v", err)
			}
			if !tt.wantFound {
				if updated != nil {
					t.Fatalf("item = %+v, quer nil", updated)
				}
				return
			}
			if updated == nil {
				t.Fatal("item = nil, quer item atualizado")
			}
			if updated.Status != tt.wantStatus {
				t.Fatalf("status = %q, quer %q", updated.Status, tt.wantStatus)
			}
			onDisk, _ := readItem(t, filepath.Join(root, "queue", "review", tt.runID+".json"))
			if onDisk.Status != tt.wantStatus {
				t.Fatalf("status no disco = %q, quer %q", onDisk.Status, tt.wantStatus)
			}
		})
	}
}

func TestFindApproved(t *testing.T) {
	binding := queue.ReviewBinding{
		ContractSHA256: "abc123",
		Command:        []string{"echo", "hi"},
	}

	tests := []struct {
		name    string
		status  queue.Status
		mutate  func(*queue.Item)
		wantNil bool
	}{
		{
			name:   "aprovação vigente é encontrada",
			status: queue.StatusApproved,
		},
		{
			name:    "item pendente não aprova",
			status:  queue.StatusPendingReview,
			wantNil: true,
		},
		{
			name:    "item rejeitado não aprova",
			status:  queue.StatusRejected,
			wantNil: true,
		},
		{
			name:    "contrato diferente não aprova",
			status:  queue.StatusApproved,
			mutate:  func(item *queue.Item) { item.Payload["contract_sha256"] = "outro" },
			wantNil: true,
		},
		{
			name:    "comando diferente não aprova",
			status:  queue.StatusApproved,
			mutate:  func(item *queue.Item) { item.Payload["command"] = []string{"echo", "bye"} },
			wantNil: true,
		},
		{
			name:    "task diferente não aprova",
			status:  queue.StatusApproved,
			mutate:  func(item *queue.Item) { item.TaskID = "1.2" },
			wantNil: true,
		},
		{
			name:    "work diferente não aprova",
			status:  queue.StatusApproved,
			mutate:  func(item *queue.Item) { item.WorkID = "0002" },
			wantNil: true,
		},
		{
			name:    "payload ausente não aprova",
			status:  queue.StatusApproved,
			mutate:  func(item *queue.Item) { item.Payload = nil },
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			item := baseItem("RUN-1")
			if tt.mutate != nil {
				tt.mutate(&item)
			}
			if _, err := queue.Enqueue(item, root, tt.status); err != nil {
				t.Fatal(err)
			}
			// Outro item aprovado não pode vencer a busca.
			other := baseItem("RUN-0")
			other.TaskID = "9.9"
			if _, err := queue.Enqueue(other, root, queue.StatusApproved); err != nil {
				t.Fatal(err)
			}

			found, err := queue.FindApproved("0001", "1.1", binding, root)
			if err != nil {
				t.Fatalf("FindApproved: %v", err)
			}
			if tt.wantNil {
				if found != nil {
					t.Fatalf("item = %+v, quer nil", found)
				}
				return
			}
			if found == nil {
				t.Fatal("item = nil, quer aprovação")
			}
			if found.RunID != "RUN-1" {
				t.Fatalf("runId = %q, quer RUN-1", found.RunID)
			}
		})
	}
}
