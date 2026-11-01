package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/metrics"
	"github.com/passoz/pwn/internal/harness/telemetry"
)

func request(t *testing.T, handler http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestHealthAndIndex(t *testing.T) {
	handler := Handler(Options{Root: t.TempDir(), Version: "9.9.9"})
	health := request(t, handler, http.MethodGet, "/api/health", nil)
	if health.Code != http.StatusOK {
		t.Fatalf("health = %d", health.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(health.Body.Bytes(), &body); err != nil {
		t.Fatalf("health JSON: %v", err)
	}
	if body["ok"] != true || body["version"] != "9.9.9" {
		t.Fatalf("health = %v", body)
	}

	index := request(t, handler, http.MethodGet, "/", nil)
	if index.Code != http.StatusOK || !strings.Contains(index.Body.String(), "PWN — Observabilidade") {
		t.Fatalf("index = %d", index.Code)
	}
	if contentType := index.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("content-type = %q", contentType)
	}

	if code := request(t, handler, http.MethodPost, "/api/works", nil).Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, esperava 405", code)
	}
	if code := request(t, handler, http.MethodGet, "/nao-existe", nil).Code; code != http.StatusNotFound {
		t.Fatalf("rota desconhecida = %d", code)
	}
}

func TestWorksEmptyRoot(t *testing.T) {
	handler := Handler(Options{Root: t.TempDir()})
	response := request(t, handler, http.MethodGet, "/api/works", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("works = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Works []any `json:"works"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if body.Works == nil || len(body.Works) != 0 {
		t.Fatalf("works = %v, esperava lista vazia (não null)", body.Works)
	}
}

func TestWorkDetailRejectsInvalidID(t *testing.T) {
	handler := Handler(Options{Root: t.TempDir()})
	for _, id := range []string{"12", "0001x", "..%2f..%2fetc"} {
		response := request(t, handler, http.MethodGet, "/api/works/"+id, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("id %q = %d, esperava 400", id, response.Code)
		}
	}
}

func TestRunsAndDetailJoinMetricsAndEvents(t *testing.T) {
	root := t.TempDir()
	tracker, err := telemetry.Start(root, "RUN-panel", telemetry.Meta{WorkID: "0001", TaskID: "1.1"})
	if err != nil {
		t.Fatalf("telemetry.Start: %v", err)
	}
	if err := tracker.Update("step", "executando"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := metrics.Record(metrics.Entry{
		Timestamp:    "2026-01-01T00:00:00.000Z",
		RunID:        "RUN-panel",
		WorkID:       "0001",
		TaskID:       "1.1",
		AgentRole:    metrics.RoleCheap,
		Model:        "modelo",
		TokensInput:  10,
		TokensOutput: 5,
		CostUSD:      0.25,
		Status:       metrics.StatusSuccess,
		Attempts:     1,
		Isolated:     true,
	}, root); err != nil {
		t.Fatalf("metrics.Record: %v", err)
	}
	events := "{\"timestamp\":\"t1\",\"type\":\"start\",\"message\":\"a\"}\n{\"timestamp\":\"t2\",\"type\":\"step\",\"message\":\"b\"}\n"
	if err := os.WriteFile(filepath.Join(root, ".pwn", "RUN-panel.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatalf("eventos: %v", err)
	}
	receipt := `{"receipt_id":"r1","work_id":"0001","task_id":"1.1","outcome":"pass","created_at":"2026-01-01T00:00:00.000Z","signature":"abc","verifier":{"id":"ver"}}`
	verificationDir := filepath.Join(root, ".todo", "verification")
	if err := os.MkdirAll(verificationDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verificationDir, "0001-1.1-receipt.json"), []byte(receipt), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := Handler(Options{Root: root})
	response := request(t, handler, http.MethodGet, "/api/runs", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("runs = %d: %s", response.Code, response.Body.String())
	}
	var list struct {
		Runs []runSummary `json:"runs"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatalf("JSON runs: %v", err)
	}
	if len(list.Runs) != 1 {
		t.Fatalf("runs = %d", len(list.Runs))
	}
	got := list.Runs[0]
	if got.RunID != "RUN-panel" || got.EventCount != 2 || got.Metrics == nil || got.Metrics.CostUSD != 0.25 {
		t.Fatalf("resumo = %+v", got)
	}

	detail := request(t, handler, http.MethodGet, "/api/runs/RUN-panel", nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("run detail = %d: %s", detail.Code, detail.Body.String())
	}
	var body struct {
		State    telemetry.State   `json:"state"`
		Events   []json.RawMessage `json:"events"`
		Metrics  *metrics.Entry    `json:"metrics"`
		Receipts []receiptSummary  `json:"receipts"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &body); err != nil {
		t.Fatalf("JSON detail: %v", err)
	}
	if body.State.RunID != "RUN-panel" || len(body.Events) != 2 || body.Metrics == nil {
		t.Fatalf("detalhe = %+v", body)
	}
	if len(body.Receipts) != 1 || !body.Receipts[0].Signed {
		t.Fatalf("recibos = %+v", body.Receipts)
	}
}

func TestRunDetailValidatesIDAndMissingRun(t *testing.T) {
	handler := Handler(Options{Root: t.TempDir()})
	if code := request(t, handler, http.MethodGet, "/api/runs/..%2f..%2fetc", nil).Code; code != http.StatusBadRequest {
		t.Fatalf("id inválido = %d", code)
	}
	if code := request(t, handler, http.MethodGet, "/api/runs/RUN-inexistente", nil).Code; code != http.StatusNotFound {
		t.Fatalf("run ausente = %d", code)
	}
}

func TestTokenIsRequiredWhenConfigured(t *testing.T) {
	handler := Handler(Options{Root: t.TempDir(), Token: "segredo"})
	if code := request(t, handler, http.MethodGet, "/api/health", nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("sem token = %d", code)
	}
	if code := request(t, handler, http.MethodGet, "/api/health", map[string]string{"Authorization": "Bearer segredo"}).Code; code != http.StatusOK {
		t.Fatalf("token via header = %d", code)
	}
	if code := request(t, handler, http.MethodGet, "/api/health?token=segredo", nil).Code; code != http.StatusOK {
		t.Fatalf("token via query = %d", code)
	}
	if code := request(t, handler, http.MethodGet, "/api/health", map[string]string{"Authorization": "Bearer errado"}).Code; code != http.StatusUnauthorized {
		t.Fatalf("token errado = %d", code)
	}
}

func TestReceiptsEmptyAndMalformed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".todo", "verification")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "quebrado-receipt.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler := Handler(Options{Root: root})
	response := request(t, handler, http.MethodGet, "/api/receipts", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("receipts = %d", response.Code)
	}
	var body struct {
		Receipts []receiptSummary `json:"receipts"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if len(body.Receipts) != 0 {
		t.Fatalf("recibo inválido deveria ser ignorado: %+v", body.Receipts)
	}
}
