// Package telemetry guarda o estado observável de cada run em disco.
//
// O heartbeat existe para que um consumidor externo (o painel) veja uma run em
// execução antes de ela terminar. O arquivo é reescrito de forma atômica a cada
// fase, então um leitor nunca vê conteúdo parcial.
package telemetry

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// StatusRunning indica uma run em execução.
const StatusRunning = "running"

// StatusFinished indica uma run encerrada. O detalhe fica em Phase.
const StatusFinished = "finished"

// StaleAfter é o tempo sem atualização a partir do qual uma run "running" é
// considerada órfã. O processo pode ter morrido sem chamar Finish.
const StaleAfter = 5 * time.Minute

// State é o conteúdo de `.pwn/runs/<runID>/state.json`.
type State struct {
	RunID     string `json:"run_id"`
	WorkID    string `json:"work_id,omitempty"`
	TaskID    string `json:"task_id,omitempty"`
	Status    string `json:"status"`
	Phase     string `json:"phase"`
	Message   string `json:"message,omitempty"`
	Sandbox   string `json:"sandbox,omitempty"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
	UpdatedAt string `json:"updated_at"`
	Events    int    `json:"events"`
	// Stale é calculado na leitura, não persistido.
	Stale bool `json:"stale"`
}

// Meta identifica a run no primeiro heartbeat.
type Meta struct {
	WorkID  string
	TaskID  string
	Sandbox string
}

// Tracker grava o heartbeat de uma run.
type Tracker struct {
	mu    sync.Mutex
	path  string
	state State
	now   func() time.Time
}

// Dir devolve o diretório de estado de uma run.
func Dir(rootDir, runID string) string {
	return filepath.Join(rootDir, ".pwn", "runs", runID)
}

// StatePath devolve o caminho do state.json de uma run.
func StatePath(rootDir, runID string) string {
	return filepath.Join(Dir(rootDir, runID), "state.json")
}

// Start grava o primeiro heartbeat. O timestamp usa UTC com milissegundos.
func Start(rootDir, runID string, meta Meta) (*Tracker, error) {
	return startAt(rootDir, runID, meta, time.Now)
}

func startAt(rootDir, runID string, meta Meta, now func() time.Time) (*Tracker, error) {
	started := now().UTC()
	tracker := &Tracker{
		path: StatePath(rootDir, runID),
		now:  now,
		state: State{
			RunID:     runID,
			WorkID:    meta.WorkID,
			TaskID:    meta.TaskID,
			Status:    StatusRunning,
			Phase:     "start",
			Sandbox:   meta.Sandbox,
			PID:       os.Getpid(),
			StartedAt: formatTime(started),
			UpdatedAt: formatTime(started),
		},
	}
	if err := tracker.write(); err != nil {
		return nil, err
	}
	return tracker, nil
}

// SetSandbox publica o caminho do worktree assim que o sandbox existe.
func (t *Tracker) SetSandbox(path string) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.Sandbox = path
	t.state.UpdatedAt = formatTime(t.now().UTC())
	return t.write()
}

// Update registra uma nova fase e incrementa a contagem de eventos.
func (t *Tracker) Update(phase, message string) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.Phase = phase
	t.state.Message = message
	t.state.Events++
	t.state.UpdatedAt = formatTime(t.now().UTC())
	return t.write()
}

// Finish encerra o heartbeat com o estado final.
func (t *Tracker) Finish(status, message string) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.Status = StatusFinished
	t.state.Phase = status
	t.state.Message = message
	t.state.UpdatedAt = formatTime(t.now().UTC())
	return t.write()
}

// State devolve uma cópia do estado atual.
func (t *Tracker) State() State {
	if t == nil {
		return State{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *Tracker) write() error {
	data, err := jsonx.Insertion(t.state)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(t.path, string(data))
}

// Read lê o estado de uma run. Run inexistente devolve fs.ErrNotExist.
func Read(rootDir, runID string) (State, error) {
	data, err := os.ReadFile(StatePath(rootDir, runID))
	if err != nil {
		return State{}, err
	}
	state, err := decode(data)
	if err != nil {
		return State{}, err
	}
	state.Stale = isStale(state, time.Now().UTC())
	return state, nil
}

// List devolve os estados de todas as runs, mais recentes primeiro.
func List(rootDir string) ([]State, error) {
	entries, err := os.ReadDir(filepath.Join(rootDir, ".pwn", "runs"))
	if errors.Is(err, fs.ErrNotExist) {
		return []State{}, nil
	}
	if err != nil {
		return nil, err
	}
	states := make([]State, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		state, err := Read(rootDir, entry.Name())
		if err != nil {
			continue
		}
		states = append(states, state)
	}
	sort.SliceStable(states, func(i, j int) bool {
		return states[i].StartedAt > states[j].StartedAt
	})
	return states, nil
}

func decode(data []byte) (State, error) {
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func isStale(state State, now time.Time) bool {
	if state.Status != StatusRunning {
		return false
	}
	updated, err := time.Parse(time.RFC3339, state.UpdatedAt)
	if err != nil {
		return true
	}
	return now.Sub(updated) > StaleAfter
}

func formatTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000Z")
}
