package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

func TestSelectForRiskUnknownLevelFallsBackToL3(t *testing.T) {
	decision := SelectForRisk(contract.RiskLevel("L9"), t.TempDir())
	l3 := SelectForRisk(contract.RiskL3, t.TempDir())
	if decision.Role != l3.Role || decision.RequiresReview != l3.RequiresReview {
		t.Fatalf("decisão = %+v, esperava a mesma de L3 (%+v)", decision, l3)
	}
	if decision.ExecutionPolicy != l3.ExecutionPolicy {
		t.Fatalf("política = %+v, esperava %+v", decision.ExecutionPolicy, l3.ExecutionPolicy)
	}
	if !strings.Contains(decision.Reason, "Risk L3") {
		t.Fatalf("motivo = %q, esperava citar L3", decision.Reason)
	}
}

func TestGetRoutingTableDefaultsRootToWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".pwn/routing.json", `{"strong":{"defaultModel":"modelo-do-cwd"}}`)
	t.Chdir(root)

	table := GetRoutingTable("")
	if table[RoleStrong].DefaultModel != "modelo-do-cwd" {
		t.Fatalf("strong = %+v, esperava ler routing.json do diretório atual", table[RoleStrong])
	}
	// Seções ausentes no arquivo mantêm os defaults.
	if table[RoleCheap].DefaultModel != DefaultRoutingTable[RoleCheap].DefaultModel {
		t.Fatalf("cheap = %+v, esperava o default", table[RoleCheap])
	}
	if table[RolePlan] != DefaultRoutingTable[RolePlan] {
		t.Fatalf("plan = %+v, esperava o default", table[RolePlan])
	}
}

func TestRoutingEnvironmentOverridesAPIKeyPerRole(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PWN_API_KEY_REVIEW", "chave-de-teste-review")
	t.Setenv("PWN_MODEL_PLAN", "modelo-env-plan")

	table := GetRoutingTable(root)
	if table[RoleReview].APIKey != "chave-de-teste-review" {
		t.Fatalf("review = %+v", table[RoleReview])
	}
	if table[RoleCheap].APIKey != DefaultRoutingTable[RoleCheap].APIKey {
		t.Fatalf("chave vazou para outro papel: %+v", table[RoleCheap])
	}
	if table[RolePlan].DefaultModel != "modelo-env-plan" {
		t.Fatalf("plan = %+v", table[RolePlan])
	}
}

func TestSaveRoutingConfigErrors(t *testing.T) {
	t.Run("diretório .pwn impossível", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".pwn", "bloqueio")
		err := SaveRoutingConfig(map[AgentRole]RoutingPatch{RoleCheap: {DefaultModel: new("x")}}, root)
		if err == nil || !strings.Contains(err.Error(), "routing: criar") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("routing.json é um diretório", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".pwn", "routing.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		err := SaveRoutingConfig(map[AgentRole]RoutingPatch{RoleCheap: {DefaultModel: new("x")}}, root)
		if err == nil {
			t.Fatal("gravar sobre um diretório deveria falhar")
		}
	})

	t.Run("raiz vazia grava no diretório atual", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		if err := SaveRoutingConfig(map[AgentRole]RoutingPatch{RoleReview: {DefaultModel: new("revisor-cwd")}}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, ".pwn", "routing.json")); err != nil {
			t.Fatalf("routing.json não gravado no cwd: %v", err)
		}
		if got := GetRoutingTable(root)[RoleReview].DefaultModel; got != "revisor-cwd" {
			t.Fatalf("review = %q", got)
		}
	})
}
