// Package panel expõe o estado do harness em HTTP, somente leitura.
//
// As rotas devolvem JSON derivado das mesmas funções que o CLI usa
// (work.CollectWorkIndex, work.CollectPlanStatus, telemetry.List e
// metrics.Read). O painel nunca decide se uma task está concluída.
package panel

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/harness/metrics"
	"github.com/passoz/pwn/internal/harness/telemetry"
	"github.com/passoz/pwn/internal/harness/work"
)

//go:embed index.html
var assets embed.FS

// Options configura o handler do painel.
type Options struct {
	// Root é a raiz do projeto observado.
	Root string
	// Token exige autenticação quando não é vazio.
	Token string
	// Version aparece em /api/health.
	Version string
}

// Handler devolve o roteador do painel.
func Handler(options Options) http.Handler {
	root := options.Root
	if root == "" {
		root = "."
	}
	app := &app{root: root, token: options.Token, version: options.Version}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", app.health)
	mux.HandleFunc("GET /api/works", app.works)
	mux.HandleFunc("GET /api/works/{id}", app.workDetail)
	mux.HandleFunc("GET /api/runs", app.runs)
	mux.HandleFunc("GET /api/runs/{id}", app.runDetail)
	mux.HandleFunc("GET /api/receipts", app.receipts)
	mux.HandleFunc("GET /api/events", app.events)
	mux.HandleFunc("GET /", app.index)
	return app.authorize(mux)
}

type app struct {
	root    string
	token   string
	version string
}

var (
	workIDPattern = regexp.MustCompile(`^[0-9]{4}$`)
	runIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// authorize aplica o token quando ele existe. A comparação é de tempo constante.
func (a *app) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.token != "" {
			provided := r.Header.Get("Authorization")
			provided = strings.TrimPrefix(provided, "Bearer ")
			if provided == "" {
				provided = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(provided), []byte(a.token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="pwn"`)
				writeError(w, http.StatusUnauthorized, "token inválido")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"version":    a.version,
		"root":       a.root,
		"server_now": time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *app) works(w http.ResponseWriter, _ *http.Request) {
	report, err := work.CollectWorkIndex(a.root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if report.Works == nil {
		report.Works = []work.WorkIndexEntry{}
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *app) workDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !workIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "work id inválido; use NNNN")
		return
	}
	report, err := work.CollectPlanStatus(id, a.root)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// runSummary combina o heartbeat, a métrica e a contagem de eventos.
type runSummary struct {
	telemetry.State
	Metrics    *metrics.Entry `json:"metrics,omitempty"`
	EventCount int            `json:"event_count"`
}

func (a *app) runs(w http.ResponseWriter, _ *http.Request) {
	states, err := telemetry.List(a.root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	entries, err := metrics.Read(a.root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byRun := make(map[string]*metrics.Entry, len(entries))
	for index := range entries {
		byRun[entries[index].RunID] = &entries[index]
	}
	summaries := make([]runSummary, 0, len(states))
	seen := make(map[string]bool, len(states))
	for _, state := range states {
		summary := runSummary{State: state, Metrics: byRun[state.RunID]}
		summary.EventCount = countEvents(a.root, state.RunID)
		summaries = append(summaries, summary)
		seen[state.RunID] = true
	}
	// Runs antigas têm métrica mas podem não ter heartbeat.
	for index := range entries {
		entry := &entries[index]
		if seen[entry.RunID] {
			continue
		}
		summaries = append(summaries, runSummary{
			State: telemetry.State{
				RunID:     entry.RunID,
				WorkID:    entry.WorkID,
				TaskID:    entry.TaskID,
				Status:    telemetry.StatusFinished,
				Phase:     string(entry.Status),
				StartedAt: entry.Timestamp,
				UpdatedAt: entry.Timestamp,
			},
			Metrics:    entry,
			EventCount: countEvents(a.root, entry.RunID),
		})
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		return summaries[i].StartedAt > summaries[j].StartedAt
	})
	writeJSON(w, http.StatusOK, map[string]any{"runs": summaries})
}

func (a *app) runDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !runIDPattern.MatchString(id) || strings.Contains(id, "..") {
		writeError(w, http.StatusBadRequest, "run id inválido")
		return
	}
	state, err := telemetry.Read(a.root, id)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if errors.Is(err, fs.ErrNotExist) {
		events, eventErr := readEvents(a.root, id)
		if eventErr != nil || len(events) == 0 {
			writeError(w, http.StatusNotFound, "run não encontrada")
			return
		}
		state = telemetry.State{RunID: id, Status: telemetry.StatusFinished, Phase: "desconhecida"}
	}
	events, err := readEvents(a.root, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	entry := findMetric(a.root, id)
	writeJSON(w, http.StatusOK, map[string]any{
		"state":    state,
		"metrics":  entry,
		"events":   events,
		"receipts": filterReceipts(a.readReceipts(), state.WorkID, state.TaskID),
	})
}

func (a *app) receipts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"receipts": a.readReceipts()})
}

// receiptSummary é o subconjunto estável de um recibo assinado.
type receiptSummary struct {
	File      string `json:"file"`
	ReceiptID string `json:"receipt_id"`
	WorkID    string `json:"work_id"`
	TaskID    string `json:"task_id"`
	Outcome   string `json:"outcome"`
	CreatedAt string `json:"created_at"`
	Verifier  string `json:"verifier"`
	Signed    bool   `json:"signed"`
}

func (a *app) readReceipts() []receiptSummary {
	dir := filepath.Join(a.root, ".todo", "verification")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []receiptSummary{}
	}
	receipts := make([]receiptSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "-receipt.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var raw struct {
			ReceiptID string `json:"receipt_id"`
			WorkID    string `json:"work_id"`
			TaskID    string `json:"task_id"`
			Outcome   string `json:"outcome"`
			CreatedAt string `json:"created_at"`
			Signature string `json:"signature"`
			Verifier  struct {
				ID string `json:"id"`
			} `json:"verifier"`
		}
		if json.Unmarshal(data, &raw) != nil {
			continue
		}
		receipts = append(receipts, receiptSummary{
			File:      entry.Name(),
			ReceiptID: raw.ReceiptID,
			WorkID:    raw.WorkID,
			TaskID:    raw.TaskID,
			Outcome:   raw.Outcome,
			CreatedAt: raw.CreatedAt,
			Verifier:  raw.Verifier.ID,
			Signed:    raw.Signature != "",
		})
	}
	sort.SliceStable(receipts, func(i, j int) bool {
		return receipts[i].CreatedAt > receipts[j].CreatedAt
	})
	return receipts
}

func filterReceipts(receipts []receiptSummary, workID, taskID string) []receiptSummary {
	if workID == "" && taskID == "" {
		return receipts
	}
	filtered := make([]receiptSummary, 0, len(receipts))
	for _, receipt := range receipts {
		if workID != "" && receipt.WorkID != workID {
			continue
		}
		if taskID != "" && receipt.TaskID != taskID {
			continue
		}
		filtered = append(filtered, receipt)
	}
	return filtered
}

func findMetric(root, runID string) *metrics.Entry {
	entries, err := metrics.Read(root)
	if err != nil {
		return nil
	}
	for index := range entries {
		if entries[index].RunID == runID {
			return &entries[index]
		}
	}
	return nil
}

func countEvents(root, runID string) int {
	events, err := readEvents(root, runID)
	if err != nil {
		return 0
	}
	return len(events)
}

// readEvents devolve as linhas JSON do arquivo de eventos da run.
func readEvents(root, runID string) ([]json.RawMessage, error) {
	path := filepath.Join(root, ".pwn", runID+".jsonl")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	events := make([]json.RawMessage, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !json.Valid([]byte(line)) {
			continue
		}
		events = append(events, json.RawMessage(line))
	}
	return events, nil
}

// events publica mudanças por SSE. O payload só sinaliza invalidação; o
// cliente refaz as consultas. O custo por tick é um stat de diretórios.
func (a *app) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming não suportado")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	last := a.signature()
	_, _ = w.Write([]byte("event: ready\ndata: {}\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			current := a.signature()
			if current == last {
				_, _ = w.Write([]byte(": ping\n\n"))
				flusher.Flush()
				continue
			}
			last = current
			_, _ = w.Write([]byte("event: change\ndata: {\"signature\":\"" + current + "\"}\n\n"))
			flusher.Flush()
		}
	}
}

// signature resume mtime e tamanho das fontes observadas.
func (a *app) signature() string {
	targets := []string{
		filepath.Join(a.root, ".pwn"),
		filepath.Join(a.root, ".pwn", "runs"),
		filepath.Join(a.root, ".pwn", "metrics.jsonl"),
		filepath.Join(a.root, ".todo"),
		filepath.Join(a.root, ".todo", "verification"),
	}
	hasher := sha256.New()
	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			hasher.Write([]byte(target + ":missing;"))
			continue
		}
		hasher.Write([]byte(target))
		hasher.Write([]byte(info.ModTime().UTC().Format(time.RFC3339Nano)))
		hasher.Write([]byte(strconv.FormatInt(info.Size(), 10)))
	}
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page, err := assets.ReadFile("index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
