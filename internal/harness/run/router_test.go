package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

func TestSelectForRisk(t *testing.T) {
	tests := []struct {
		risk           contract.RiskLevel
		wantRole       AgentRole
		requiresReview bool
		canWrite       bool
		canShell       bool
		canNetwork     bool
		maxFileWrites  int
	}{
		{contract.RiskL0, RoleCheap, false, true, true, true, 50},
		{contract.RiskL1, RoleCheap, false, true, true, true, 30},
		{contract.RiskL2, RoleCheap, true, true, true, false, 20},
		{contract.RiskL3, RoleStrong, false, true, false, false, 10},
		{contract.RiskL4, RoleStrong, true, false, false, false, 0},
	}
	for _, test := range tests {
		t.Run(string(test.risk), func(t *testing.T) {
			decision := SelectForRisk(test.risk, t.TempDir())
			if decision.Role != test.wantRole {
				t.Fatalf("role = %q, esperava %q", decision.Role, test.wantRole)
			}
			if decision.RequiresReview != test.requiresReview {
				t.Fatalf("requiresReview = %t", decision.RequiresReview)
			}
			policy := decision.ExecutionPolicy
			if policy.CanWrite != test.canWrite || policy.CanShell != test.canShell ||
				policy.CanNetwork != test.canNetwork || policy.MaxFileWrites != test.maxFileWrites {
				t.Fatalf("política = %+v", policy)
			}
			if decision.Model.DefaultModel == "" {
				t.Fatal("modelo vazio")
			}
		})
	}
}

func TestRiskMapsAreConsistent(t *testing.T) {
	levels := []contract.RiskLevel{
		contract.RiskL0, contract.RiskL1, contract.RiskL2, contract.RiskL3, contract.RiskL4,
	}
	for _, level := range levels {
		riskRole, present := RiskRoleMap[level]
		if !present {
			t.Fatalf("RISK_ROLE_MAP sem %s", level)
		}
		if riskRole.InitialRole != RoleCheap && riskRole.InitialRole != RoleStrong {
			t.Fatalf("papel inesperado para %s: %q", level, riskRole.InitialRole)
		}
		if _, present := RiskExecutionPolicy[level]; !present {
			t.Fatalf("RISK_EXECUTION_POLICY sem %s", level)
		}
	}
	for role, config := range DefaultRoutingTable {
		if config.DefaultModel == "" || config.Role != role || config.MaxTokens <= 0 {
			t.Fatalf("configuração default inválida para %q: %+v", role, config)
		}
	}
}

func TestRoutingTableFileAndEnvironment(t *testing.T) {
	root := t.TempDir()
	err := SaveRoutingConfig(map[AgentRole]RoutingPatch{
		RoleCheap: {
			DefaultModel:    new("custom-cheap-model"),
			MaxTokens:       new(1234),
			BaseURL:         new("http://localhost:11434/v1"),
			Provider:        new("ollama"),
			APIKeyEnv:       new("OLLAMA_API_KEY"),
			APIKey:          new("test-placeholder-not-a-real-key"),
			ReasoningEffort: new(EffortMedium),
		},
		RoleStrong: {
			DefaultModel: new("custom-strong-model"),
			BaseURL:      new("https://api.anthropic.com/v1"),
			Provider:     new("anthropic"),
		},
	}, root)
	if err != nil {
		t.Fatalf("SaveRoutingConfig: %v", err)
	}

	table := GetRoutingTable(root)
	cheap := table[RoleCheap]
	if cheap.DefaultModel != "custom-cheap-model" || cheap.MaxTokens != 1234 ||
		cheap.BaseURL != "http://localhost:11434/v1" || cheap.Provider != "ollama" ||
		cheap.APIKeyEnv != "OLLAMA_API_KEY" || cheap.APIKey != "test-placeholder-not-a-real-key" ||
		cheap.ReasoningEffort != EffortMedium {
		t.Fatalf("cheap = %+v", cheap)
	}
	strong := table[RoleStrong]
	if strong.DefaultModel != "custom-strong-model" || strong.BaseURL != "https://api.anthropic.com/v1" ||
		strong.Provider != "anthropic" {
		t.Fatalf("strong = %+v", strong)
	}
	if table[RoleReview].DefaultModel == "" || table[RolePlan].DefaultModel == "" {
		t.Fatalf("papéis não configurados: %+v", table)
	}

	t.Setenv("PWN_MODEL_CHEAP", "env-cheap")
	t.Setenv("PWN_REASONING_CHEAP", string(EffortHigh))
	t.Setenv("PWN_API_BASE_URL_STRONG", "http://env-strong.invalid")
	override := GetRoutingTable(root)
	if override[RoleCheap].DefaultModel != "env-cheap" {
		t.Fatalf("env não sobrepôs cheap: %+v", override[RoleCheap])
	}
	if override[RoleCheap].ReasoningEffort != EffortHigh {
		t.Fatalf("env não sobrepôs reasoning: %+v", override[RoleCheap])
	}
	if override[RoleCheap].MaxTokens != 1234 {
		t.Fatalf("env apagou campo do arquivo: %+v", override[RoleCheap])
	}
	if override[RoleStrong].BaseURL != "http://env-strong.invalid" {
		t.Fatalf("env não sobrepôs baseUrl: %+v", override[RoleStrong])
	}
}

func TestRoutingTableIgnoresCorruptedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".pwn"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".pwn", "routing.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	table := GetRoutingTable(root)
	if table[RoleCheap].DefaultModel != DefaultRoutingTable[RoleCheap].DefaultModel {
		t.Fatalf("arquivo corrompido alterou a tabela: %+v", table[RoleCheap])
	}
}

func TestEvaluateEscalation(t *testing.T) {
	tests := []struct {
		name               string
		role               AgentRole
		attempts           int
		maxAttempts        int
		writeViolation     bool
		contractViolation  bool
		risk               contract.RiskLevel
		wantEscalate       bool
		wantRole           AgentRole
		wantReasonContains string
	}{
		{
			name: "violação de escrita escala para strong",
			role: RoleCheap, attempts: 1, maxAttempts: 3, writeViolation: true,
			wantEscalate: true, wantRole: RoleStrong, wantReasonContains: "escrita",
		},
		{
			name: "violação de contrato escala para strong",
			role: RoleCheap, attempts: 1, maxAttempts: 3, contractViolation: true,
			wantEscalate: true, wantRole: RoleStrong, wantReasonContains: "contrato",
		},
		{
			name: "tentativas esgotadas escalam cheap",
			role: RoleCheap, attempts: 3, maxAttempts: 3,
			wantEscalate: true, wantRole: RoleStrong, wantReasonContains: "Tentativas",
		},
		{
			name: "execução normal não escala",
			role: RoleCheap, attempts: 1, maxAttempts: 3,
			wantEscalate: false, wantRole: RoleCheap,
		},
		{
			name: "L4 sempre vai para revisão humana",
			role: RoleCheap, attempts: 1, maxAttempts: 3, risk: contract.RiskL4,
			wantEscalate: true, wantRole: RoleReview, wantReasonContains: "L4",
		},
		{
			name: "L4 com violação de escrita ainda vai para revisão",
			role: RoleCheap, attempts: 1, maxAttempts: 3, writeViolation: true, risk: contract.RiskL4,
			wantEscalate: true, wantRole: RoleReview, wantReasonContains: "L4",
		},
		{
			name: "L3 escala na primeira falha",
			role: RoleCheap, attempts: 1, maxAttempts: 3, risk: contract.RiskL3,
			wantEscalate: true, wantRole: RoleStrong, wantReasonContains: "L3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := EvaluateEscalation(
				test.role, test.attempts, test.maxAttempts,
				test.writeViolation, test.contractViolation, test.risk,
			)
			if decision.ShouldEscalate != test.wantEscalate {
				t.Fatalf("shouldEscalate = %t", decision.ShouldEscalate)
			}
			if decision.TargetRole != test.wantRole {
				t.Fatalf("targetRole = %q, esperava %q", decision.TargetRole, test.wantRole)
			}
			if test.wantReasonContains != "" && !strings.Contains(decision.Reason, test.wantReasonContains) {
				t.Fatalf("reason = %q, esperava conter %q", decision.Reason, test.wantReasonContains)
			}
		})
	}
}
