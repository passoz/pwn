package config

import "testing"

func TestParseOperator(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want OperatorMode
	}{
		{name: "vazio usa o padrão do projeto", raw: "", want: OperatorUnset},
		{name: "espaços viram padrão", raw: "   ", want: OperatorUnset},
		{name: "human", raw: "human", want: OperatorHuman},
		{name: "human com espaços", raw: " human ", want: OperatorHuman},
		{name: "decider", raw: "decider", want: OperatorDecider},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseOperator(test.raw)
			if err != nil {
				t.Fatalf("ParseOperator(%q) devolveu erro: %v", test.raw, err)
			}
			if got != test.want {
				t.Fatalf("ParseOperator(%q) = %q, quer %q", test.raw, got, test.want)
			}
		})
	}
}

func TestParseOperatorRejectsInvalidValue(t *testing.T) {
	_, err := ParseOperator("auto")
	if err == nil {
		t.Fatal("ParseOperator aceitou valor inválido")
	}
	if got, want := err.Error(), "PWN_OPERATOR inválido: 'auto' (use human ou decider)"; got != want {
		t.Fatalf("erro = %q, quer %q", got, want)
	}
}

func TestLoad(t *testing.T) {
	t.Setenv(OperatorEnv, "decider")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load devolveu erro: %v", err)
	}
	if cfg.Operator != OperatorDecider {
		t.Fatalf("Operator = %q, quer %q", cfg.Operator, OperatorDecider)
	}
}

func TestLoadWithOperatorOverridesInvalidEnvironment(t *testing.T) {
	t.Setenv(OperatorEnv, "auto")
	cfg, err := LoadWithOperator(OperatorHuman)
	if err != nil {
		t.Fatalf("LoadWithOperator devolveu erro: %v", err)
	}
	if cfg.Operator != OperatorHuman {
		t.Fatalf("Operator = %q, quer %q", cfg.Operator, OperatorHuman)
	}
}
