package telemetry

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStartUpdateFinish(t *testing.T) {
	root := t.TempDir()
	tracker, err := Start(root, "RUN-a", Meta{WorkID: "0001", TaskID: "1.2", Sandbox: "/tmp/wt"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	path := filepath.Join(root, ".pwn", "runs", "RUN-a", "state.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state.json ausente: %v", err)
	}

	state, err := Read(root, "RUN-a")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if state.Status != StatusRunning || state.Phase != "start" || state.PID != os.Getpid() {
		t.Fatalf("estado inicial = %+v", state)
	}
	if state.WorkID != "0001" || state.TaskID != "1.2" || state.Sandbox != "/tmp/wt" {
		t.Fatalf("metadados = %+v", state)
	}

	if err := tracker.Update("step", "sandbox criado"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := tracker.Finish("success", "fim"); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	state, err = Read(root, "RUN-a")
	if err != nil {
		t.Fatalf("Read final: %v", err)
	}
	if state.Status != StatusFinished || state.Phase != "success" || state.Events != 1 {
		t.Fatalf("estado final = %+v", state)
	}
	if state.Stale {
		t.Fatal("run finalizada não pode ser stale")
	}
}

func TestReadMissingRun(t *testing.T) {
	_, err := Read(t.TempDir(), "RUN-inexistente")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("erro = %v, esperava fs.ErrNotExist", err)
	}
}

func TestListSortsNewestFirst(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for index, runID := range []string{"RUN-velha", "RUN-nova"} {
		now := func() time.Time { return base.Add(time.Duration(index) * time.Hour) }
		if _, err := startAt(root, runID, Meta{}, now); err != nil {
			t.Fatalf("startAt(%s): %v", runID, err)
		}
	}
	states, err := List(root)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(states) != 2 || states[0].RunID != "RUN-nova" {
		t.Fatalf("ordem = %+v", states)
	}
}

func TestListIgnoresFilesAndMissingDirectory(t *testing.T) {
	root := t.TempDir()
	states, err := List(root)
	if err != nil || len(states) != 0 {
		t.Fatalf("List vazio = %+v, %v", states, err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".pwn", "runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".pwn", "runs", "arquivo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	states, err = List(root)
	if err != nil || len(states) != 0 {
		t.Fatalf("List com arquivo = %+v, %v", states, err)
	}
}

func TestIsStale(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	fresh := State{Status: StatusRunning, UpdatedAt: now.Add(-time.Minute).Format("2006-01-02T15:04:05.000Z")}
	if isStale(fresh, now) {
		t.Fatal("heartbeat recente marcado como stale")
	}
	old := State{Status: StatusRunning, UpdatedAt: now.Add(-2 * StaleAfter).Format("2006-01-02T15:04:05.000Z")}
	if !isStale(old, now) {
		t.Fatal("heartbeat antigo não marcado como stale")
	}
	finished := State{Status: StatusFinished, UpdatedAt: now.Add(-2 * StaleAfter).Format("2006-01-02T15:04:05.000Z")}
	if isStale(finished, now) {
		t.Fatal("run finalizada marcada como stale")
	}
	invalid := State{Status: StatusRunning, UpdatedAt: "ontem"}
	if !isStale(invalid, now) {
		t.Fatal("timestamp inválido deveria contar como stale")
	}
}

func TestNilTrackerIsSafe(t *testing.T) {
	var tracker *Tracker
	if err := tracker.Update("x", "y"); err != nil {
		t.Fatalf("Update nil: %v", err)
	}
	if err := tracker.Finish("x", "y"); err != nil {
		t.Fatalf("Finish nil: %v", err)
	}
	if err := tracker.SetSandbox("x"); err != nil {
		t.Fatalf("SetSandbox nil: %v", err)
	}
	if state := tracker.State(); state != (State{}) {
		t.Fatalf("State nil = %+v", state)
	}
}
