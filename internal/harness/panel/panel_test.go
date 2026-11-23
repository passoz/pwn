package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestIndexEmbedsTokenForFetchAndSSE(t *testing.T) {
	token := `s"e<g`
	handler := Handler(Options{Root: t.TempDir(), Token: token})
	page := request(t, handler, http.MethodGet, "/?token="+url.QueryEscape(token), nil)
	if page.Code != http.StatusOK {
		t.Fatalf("index = %d", page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, `const TOKEN = "s\"e\u003cg";`) {
		t.Fatalf("token não embutido de forma segura:\n%s", body)
	}
	if strings.Contains(body, "__PWN_TOKEN__") {
		t.Fatal("placeholder do token não substituído")
	}

	open := Handler(Options{Root: t.TempDir()})
	body = request(t, open, http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(body, `const TOKEN = "";`) {
		t.Fatal("sem token configurado, a página deve embutir string vazia")
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

func TestEventsStreamPublishesChanges(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".pwn"), 0o755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(Handler(Options{Root: root, PollInterval: 10 * time.Millisecond}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("abrir SSE: %v", err)
	}
	defer response.Body.Close()
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("content-type = %q", contentType)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(root, ".pwn", "metrics.jsonl"), []byte("x"), 0o644)
	}()

	scanner := bufio.NewScanner(response.Body)
	seenReady := false
	seenChange := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "event: ready" {
			seenReady = true
		}
		if line == "event: change" {
			seenChange = true
			break
		}
	}
	if !seenReady || !seenChange {
		t.Fatalf("stream incompleto: ready=%v change=%v", seenReady, seenChange)
	}
}

// noFlusherWriter não implementa http.Flusher, como um writer genérico.
type noFlusherWriter struct {
	header http.Header
	status int
	body   strings.Builder
}

func (w *noFlusherWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *noFlusherWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *noFlusherWriter) WriteHeader(status int) { w.status = status }

func TestEventsRequiresFlusher(t *testing.T) {
	handler := Handler(Options{Root: t.TempDir()})
	writer := &noFlusherWriter{}
	handler.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/api/events", nil))
	if writer.status != http.StatusInternalServerError {
		t.Fatalf("código = %d, esperava 500 sem Flusher", writer.status)
	}
}
