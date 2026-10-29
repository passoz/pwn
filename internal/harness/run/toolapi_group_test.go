//go:build unix

package run

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/policy"
)

// Um comando que deixa um neto vivo não pode escapar do timeout: o neto segura
// o pipe de saída e, sem matar o grupo, o Exec esperaria o neto terminar.
func TestToolAPIExecTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	script := "sleep 20 &\necho $! > grandchild.pid\nwait\n"
	if err := os.WriteFile(filepath.Join(dir, "grand.sh"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	taskContract := testContract(t, contract.RiskL1, []string{"src/**"}, []string{})
	isolated := false
	tools := NewToolAPI(ToolAPIOptions{
		Policy: policy.NewEngine(taskContract, &policy.Overrides{
			Shell: &policy.ShellPolicy{AllowedCommands: []policy.CommandRule{{Command: "sh"}}},
		}),
		Budget:   contract.NewBudgetController(taskContract),
		Cwd:      dir,
		Isolated: &isolated,
	})

	started := time.Now()
	result := tools.Exec("sh", []string{"grand.sh"}, 400*time.Millisecond)
	elapsed := time.Since(started)

	if result.Success || !strings.Contains(result.Error, "timeout") {
		t.Fatalf("o timeout deveria falhar a execução: %+v", result)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("GRANDCHILD-ALIVE: o timeout esperou o neto por %s", elapsed)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "grand.pid"))
	if err != nil {
		raw, err = os.ReadFile(filepath.Join(dir, "grandchild.pid"))
	}
	if err != nil {
		t.Fatalf("o script não registrou o pid do neto: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("pid inválido %q: %v", raw, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("GRANDCHILD-ALIVE: o neto %d sobreviveu ao timeout", pid)
}
