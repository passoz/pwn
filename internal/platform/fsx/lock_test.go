package fsx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func execCommand(t *testing.T) *exec.Cmd {
	t.Helper()
	return exec.Command(os.Args[0], "-test.run=^TestLockHelper$")
}

// TestLockHelper é o worker dos testes entre processos: cada processo invoca
// AppendLine muitas vezes no mesmo alvo. Sem exclusão mútua entre processos as
// linhas se perdem.
func TestLockHelper(t *testing.T) {
	if os.Getenv("FSX_LOCK_HELPER") != "1" {
		return
	}
	target := os.Getenv("FSX_LOCK_TARGET")
	for i := range 50 {
		if err := AppendLine(target, fmt.Sprintf("worker-%d", i), LockOptions{}); err != nil {
			t.Fatalf("AppendLine: %v", err)
		}
	}
}

func TestAppendLineConcurrentProcesses(t *testing.T) {
	target := filepath.Join(t.TempDir(), "metrics.jsonl")
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := execCommand(t)
			cmd.Env = append(os.Environ(),
				"FSX_LOCK_HELPER=1",
				"FSX_LOCK_TARGET="+target,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("worker: %v\n%s", err, out)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 200 {
		t.Fatalf("linhas = %d, quer 200", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "worker-") {
			t.Fatalf("linha corrompida: %q", line)
		}
	}
}

func TestWithFileLockStaleLockIsTaken(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	lockDir := target + ".lock"
	if err := os.Mkdir(lockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lockDir, old, old); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	err := WithFileLock(target, func() error { return nil }, LockOptions{
		Timeout: 2 * time.Second,
		Stale:   30 * time.Second,
		Retry:   5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("WithFileLock: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("trava obsoleta demorou %s", elapsed)
	}
	if _, err := os.Stat(lockDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trava não liberada: %v", err)
	}
}

func TestWithFileLockTimeout(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	lockDir := target + ".lock"
	if err := os.Mkdir(lockDir, 0o755); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	err := WithFileLock(target, func() error { return nil }, LockOptions{
		Timeout: 100 * time.Millisecond,
		Stale:   time.Hour,
		Retry:   5 * time.Millisecond,
	})
	var timeoutErr *LockTimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("erro = %v, quer *LockTimeoutError", err)
	}
	if timeoutErr.Target != target || timeoutErr.Timeout != 100*time.Millisecond {
		t.Fatalf("erro inesperado: %+v", timeoutErr)
	}
	elapsed := time.Since(started)
	if elapsed < 90*time.Millisecond || elapsed > time.Second {
		t.Fatalf("espera = %s, quer ~100ms", elapsed)
	}
}

func TestWithFileLockSerializesGoroutines(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "counter")

	var active, maxActive atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithFileLock(target, func() error {
				current := active.Add(1)
				for {
					observed := maxActive.Load()
					if current <= observed || maxActive.CompareAndSwap(observed, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				active.Add(-1)
				return nil
			}, LockOptions{Timeout: 10 * time.Second})
			if err != nil {
				t.Errorf("WithFileLock: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("seções críticas simultâneas = %d, quer 1", got)
	}
}

func TestWithFileLockPropagatesFnError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	want := errors.New("falha do dono")
	err := WithFileLock(target, func() error { return want }, LockOptions{})
	if !errors.Is(err, want) {
		t.Fatalf("erro = %v, quer %v", err, want)
	}
	if _, statErr := os.Stat(target + ".lock"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("trava não liberada após erro: %v", statErr)
	}
}

func TestAppendLine(t *testing.T) {
	target := filepath.Join(t.TempDir(), "nested", "chain.jsonl")
	if err := AppendLine(target, "um", LockOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := AppendLine(target, "dois\n", LockOptions{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "um\ndois\n"; got != want {
		t.Fatalf("conteúdo = %q, quer %q", got, want)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "packs", "spec.json")
	if err := WriteFileAtomic(target, "conteúdo"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "conteúdo" {
		t.Fatalf("conteúdo = %q", data)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(target), "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("tmp restante: %v", leftovers)
	}
}

func TestWriteFileAtomicConcurrentReadersSeeWholeFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "spec.json")
	payloads := make([]string, 16)
	for i := range payloads {
		payloads[i] = strings.Repeat(fmt.Sprintf("payload-%02d;", i), 500)
	}

	var wg sync.WaitGroup
	for i := range payloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WriteFileAtomic(target, payloads[i]); err != nil {
				t.Errorf("WriteFileAtomic: %v", err)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(payloads, string(data)) {
		t.Fatalf("arquivo final não corresponde a nenhuma escrita completa (len=%d)", len(data))
	}
}

func TestIsDirectEntry(t *testing.T) {
	if !IsDirectEntry(os.Args[0]) {
		t.Fatalf("o binário de teste deveria ser o entrypoint: %q", os.Args[0])
	}
	if IsDirectEntry(filepath.Join(t.TempDir(), "inexistente")) {
		t.Fatal("caminho inexistente não pode ser entrypoint")
	}
	if IsDirectEntry("") {
		t.Fatal("caminho vazio não pode ser entrypoint")
	}
}
