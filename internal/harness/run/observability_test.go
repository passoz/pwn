package run

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/telemetry"
)

func TestEmitEventStreamsToFileAndHeartbeat(t *testing.T) {
	root := t.TempDir()
	tracker, err := telemetry.Start(root, "RUN-obs", telemetry.Meta{WorkID: "0001", TaskID: "1.1"})
	if err != nil {
		t.Fatalf("telemetry.Start: %v", err)
	}
	eventsFile := filepath.Join(root, ".pwn", "RUN-obs.jsonl")
	runCtx := &RunContext{RunID: "RUN-obs", RootDir: root, EventsFile: eventsFile, Heartbeat: tracker}

	emitEvent(runCtx, EventStart, "início", nil)
	emitEvent(runCtx, EventStep, "passo", map[string]string{"arquivo": "src/a.ts"})

	if runCtx.EventErr != nil {
		t.Fatalf("erro ao gravar eventos: %v", runCtx.EventErr)
	}
	data, err := os.ReadFile(eventsFile)
	if err != nil {
		t.Fatalf("arquivo de eventos ausente: %v", err)
	}
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("linha inválida %q: %v", line, err)
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("linhas = %d, esperava 2 (uma por evento)", lines)
	}

	state, err := telemetry.Read(root, "RUN-obs")
	if err != nil {
		t.Fatalf("telemetry.Read: %v", err)
	}
	if state.Events != 2 || state.Phase != string(EventStep) || state.Status != telemetry.StatusRunning {
		t.Fatalf("heartbeat = %+v", state)
	}

	FinalizeRun(runCtx, true)
	finished, err := telemetry.Read(root, "RUN-obs")
	if err != nil {
		t.Fatalf("telemetry.Read após finalizar: %v", err)
	}
	if finished.Status != telemetry.StatusFinished || finished.Phase != string(StatusSuccess) {
		t.Fatalf("heartbeat final = %+v", finished)
	}
}

func TestEmitEventWithoutObservabilityKeepsWorking(t *testing.T) {
	runCtx := &RunContext{RunID: "RUN-mem"}
	emitEvent(runCtx, EventStep, "só em memória", nil)
	emitEvent(runCtx, EventStart, "início", nil)
	if len(runCtx.Events) != 2 {
		t.Fatalf("eventos em memória = %d", len(runCtx.Events))
	}
	if runCtx.EventErr != nil {
		t.Fatalf("erro inesperado: %v", runCtx.EventErr)
	}
}
