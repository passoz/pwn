package contract_test

import (
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
)

func TestDeriveTaskRisk(t *testing.T) {
	tests := []struct {
		name    string
		signals contract.RiskSignals
		want    contract.RiskLevel
	}{
		{
			name:    "titulo comum fica em L2",
			signals: contract.RiskSignals{Title: "Ajustar o parser de argumentos"},
			want:    contract.RiskL2,
		},
		{
			name:    "readme em L1",
			signals: contract.RiskSignals{Title: "Atualizar o README"},
			want:    contract.RiskL1,
		},
		{
			name:    "documentacao com acento em L1",
			signals: contract.RiskSignals{Title: "Melhorar a documentação"},
			want:    contract.RiskL1,
		},
		{
			name:    "autenticacao em L3",
			signals: contract.RiskSignals{Title: "Corrigir autenticação"},
			want:    contract.RiskL3,
		},
		{
			name:    "palavra sensivel no comportamento em L3",
			signals: contract.RiskSignals{Behavior: "rotacionar a credencial"},
			want:    contract.RiskL3,
		},
		{
			name:    "palavra sensivel no comando de aceite em L3",
			signals: contract.RiskSignals{Acceptance: []contract.RiskAcceptance{{Command: "bun test webhook.test.ts"}}},
			want:    contract.RiskL3,
		},
		{
			name:    "palavra sensivel na descricao do RED em L3",
			signals: contract.RiskSignals{RedDescription: "rate-limit por IP"},
			want:    contract.RiskL3,
		},
		{
			name:    "arquivo sensivel em L3",
			signals: contract.RiskSignals{Files: []string{"src/auth/session.ts"}},
			want:    contract.RiskL3,
		},
		{
			name:    "L3 vence L1",
			signals: contract.RiskSignals{Title: "Documentar o login"},
			want:    contract.RiskL3,
		},
		{
			name:    "L4 nunca e heuristico",
			signals: contract.RiskSignals{Title: "Remover o banco de produção"},
			want:    contract.RiskL2,
		},
		{
			name:    "dado vazio fica em L2",
			signals: contract.RiskSignals{},
			want:    contract.RiskL2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := contract.DeriveTaskRisk(test.signals); got != test.want {
				t.Fatalf("DeriveTaskRisk() = %q, quer %q", got, test.want)
			}
		})
	}
}

func TestRiskLevelOrdering(t *testing.T) {
	if !contract.RiskL4.AtLeast(contract.RiskL3) {
		t.Fatal("L4 deveria ser pelo menos L3")
	}
	if contract.RiskL2.AtLeast(contract.RiskL3) {
		t.Fatal("L2 não deveria ser pelo menos L3")
	}
	if contract.RiskLevel("L9").Valid() {
		t.Fatal("L9 não deveria ser válido")
	}
	if _, err := contract.ParseRiskLevel("L9"); err == nil {
		t.Fatal("ParseRiskLevel aceitou L9")
	}
	if level, err := contract.ParseRiskLevel("L3"); err != nil || level != contract.RiskL3 {
		t.Fatalf("ParseRiskLevel(L3) = %q, %v", level, err)
	}
}

func TestFrozenTestsRequired(t *testing.T) {
	tests := []struct {
		risk contract.RiskLevel
		want bool
	}{
		{contract.RiskL0, false},
		{contract.RiskL1, false},
		{contract.RiskL2, false},
		{contract.RiskL3, true},
		{contract.RiskL4, true},
	}
	for _, test := range tests {
		if got := contract.FrozenTestsRequired(test.risk); got != test.want {
			t.Fatalf("FrozenTestsRequired(%q) = %v, quer %v", test.risk, got, test.want)
		}
	}
}
