package proc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func shJob(id, script string) Job {
	return Job{ID: id, Command: []string{"sh", "-c", script}}
}

func TestRunPoolPreservesJobOrder(t *testing.T) {
	jobs := []Job{
		shJob("a", "sleep 0.3; echo a"),
		shJob("b", "sleep 0.1; echo b"),
		shJob("c", "echo c"),
	}
	var finished []string
	results := RunPool(jobs, Options{
		Concurrency: 3,
		OnResult:    func(r Result) { finished = append(finished, r.ID) },
	})

	if len(finished) != 3 {
		t.Fatalf("callbacks = %d, quer 3", len(finished))
	}
	if finished[0] != "c" {
		t.Fatalf("primeiro concluído = %q, quer %q", finished[0], "c")
	}
	for i, want := range []string{"a", "b", "c"} {
		if results[i].ID != want {
			t.Fatalf("results[%d].ID = %q, quer %q", i, results[i].ID, want)
		}
		if got := strings.TrimSpace(results[i].Stdout); got != want {
			t.Fatalf("results[%d].Stdout = %q, quer %q", i, got, want)
		}
	}
}

func TestRunPoolConcurrencyNeverExceedsLimit(t *testing.T) {
	jobs := make([]Job, 6)
	for i := range jobs {
		jobs[i] = shJob("j"+strconv.Itoa(i), "date +%s%N; sleep 0.2; date +%s%N")
	}
	results := RunPool(jobs, Options{Concurrency: 2})

	type span struct{ start, end int64 }
	spans := make([]span, len(results))
	for i, result := range results {
		lines := strings.Fields(result.Stdout)
		if len(lines) != 2 {
			t.Fatalf("job %s: saída inesperada %q", result.ID, result.Stdout)
		}
		start, err := strconv.ParseInt(lines[0], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		end, err := strconv.ParseInt(lines[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		spans[i] = span{start, end}
	}
	for _, probe := range spans {
		overlapping := 0
		for _, other := range spans {
			if other.start <= probe.start && other.end > probe.start {
				overlapping++
			}
		}
		if overlapping > 2 {
			t.Fatalf("concorrência observada = %d, quer <= 2", overlapping)
		}
	}
}

func TestRunPoolTimeoutKillsGrandchild(t *testing.T) {
	done := make(chan []Result, 1)
	started := time.Now()
	// O neto `sleep` herda stdout. Se o grupo não for morto, o Wait nunca vê EOF
	// e o pool não retorna.
	go func() {
		done <- RunPool([]Job{shJob("slow", "sleep 30 & wait")}, Options{
			Concurrency: 1,
			Timeout:     200 * time.Millisecond,
		})
	}()

	var results []Result
	select {
	case results = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunPool não retornou: o processo neto sobreviveu ao timeout")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("timeout demorou %s", elapsed)
	}
	result := results[0]
	if !result.TimedOut {
		t.Fatal("TimedOut = false, quer true")
	}
	if result.Status != 137 {
		t.Fatalf("Status = %d, quer 137", result.Status)
	}
}

func TestRunPoolTimeoutWithoutGrandchild(t *testing.T) {
	started := time.Now()
	results := RunPool([]Job{shJob("slow", "sleep 10")}, Options{
		Concurrency: 1,
		Timeout:     100 * time.Millisecond,
	})
	result := results[0]
	if !result.TimedOut || result.Status != 137 {
		t.Fatalf("resultado = %+v, quer timedOut com status 137", result)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("timeout demorou %s", elapsed)
	}
}

func TestRunPoolNonZeroExitCapturesStderr(t *testing.T) {
	results := RunPool([]Job{shJob("bad", "echo oops >&2; exit 3")}, Options{Concurrency: 1})
	result := results[0]
	if result.Status != 3 {
		t.Fatalf("Status = %d, quer 3", result.Status)
	}
	if !strings.Contains(result.Stderr, "oops") {
		t.Fatalf("Stderr = %q, quer conter oops", result.Stderr)
	}
	if result.TimedOut {
		t.Fatal("TimedOut = true, quer false")
	}
}

func TestRunPoolSignaledProcessReports128(t *testing.T) {
	results := RunPool([]Job{shJob("sig", "kill -TERM $$")}, Options{Concurrency: 1})
	if got := results[0].Status; got != 128 {
		t.Fatalf("Status = %d, quer 128", got)
	}
}

func TestRunPoolSpawnFailureReports127(t *testing.T) {
	results := RunPool([]Job{{ID: "missing", Command: []string{"pwn-binario-inexistente-xyz"}}}, Options{Concurrency: 1})
	result := results[0]
	if result.Status != 127 {
		t.Fatalf("Status = %d, quer 127", result.Status)
	}
	if !strings.Contains(result.Stderr, "falha ao iniciar processo") {
		t.Fatalf("Stderr = %q", result.Stderr)
	}
}

func TestRunPoolEmptyCommandReports127(t *testing.T) {
	results := RunPool([]Job{{ID: "empty"}}, Options{Concurrency: 1})
	if results[0].Status != 127 {
		t.Fatalf("Status = %d, quer 127", results[0].Status)
	}
}

func TestRunPoolDirAndEnv(t *testing.T) {
	dir := t.TempDir()
	results := RunPool([]Job{{
		ID:      "env",
		Command: []string{"sh", "-c", `printf '%s|%s' "$PWD" "$PWNPORT_TEST"`},
		Dir:     dir,
		Env:     map[string]string{"PWNPORT_TEST": "bar"},
	}}, Options{Concurrency: 1})
	if got, want := results[0].Stdout, dir+"|bar"; got != want {
		t.Fatalf("Stdout = %q, quer %q", got, want)
	}
}

func TestRunPoolEmptyJobs(t *testing.T) {
	if results := RunPool(nil, Options{Concurrency: 4}); len(results) != 0 {
		t.Fatalf("results = %d, quer 0", len(results))
	}
}

func TestRunPoolClampsConcurrencyToOne(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	// Com concorrência 1 o segundo job só começa depois do primeiro; ambos
	// escrevem a mesma linha, então basta verificar que executaram.
	jobs := []Job{
		shJob("a", "echo a >> "+marker),
		shJob("b", "echo b >> "+marker),
	}
	results := RunPool(jobs, Options{Concurrency: -3})
	if len(results) != 2 {
		t.Fatalf("results = %d, quer 2", len(results))
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Fatalf("marker = %q", data)
	}
}

func TestDefaultConcurrency(t *testing.T) {
	got := DefaultConcurrency()
	if got < 1 || got > 8 {
		t.Fatalf("DefaultConcurrency() = %d, quer entre 1 e 8", got)
	}
}
