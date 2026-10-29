package commands

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/decider"
)

func TestStdinIsTTY(t *testing.T) {
	if stdinIsTTY(strings.NewReader("s\n")) {
		t.Fatal("um leitor de memória não é terminal")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("abrir %s: %v", os.DevNull, err)
	}
	defer func() { _ = null.Close() }()
	if stdinIsTTY(null) {
		t.Fatalf("%s não é terminal", os.DevNull)
	}
}

func TestAskDecider(t *testing.T) {
	t.Setenv(decider.HostDeciderEnv, "jev:jev-latest")

	t.Run("aceita e valida as respostas", func(t *testing.T) {
		var stdout bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stdin: strings.NewReader("s\njev:custom-model\nPWN_KEY\nL2\n")}
		input, err := runner.askDecider(nil)
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		if input == nil || input.Decider != "jev:custom-model" || input.KeyEnv != "PWN_KEY" || input.MaxRisk != "L2" {
			t.Fatalf("input = %+v", input)
		}
		want := "Usar um modelo decisor no lugar do operador? (s/n) [n]: " +
			"Decisor (<provedor>:<modelo>) [jev:jev-latest]: " +
			"Variável de ambiente com a chave da API [TYPESAFE_API_KEY]: " +
			"Teto de risco decidido pelo modelo; acima dele a decisão volta para você [L3]: "
		if stdout.String() != want {
			t.Fatalf("prompt = %q, quer %q", stdout.String(), want)
		}
	})

	t.Run("resposta vazia usa o padrão", func(t *testing.T) {
		var stdout bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stdin: strings.NewReader("sim\n\n\nL1\n")}
		input, err := runner.askDecider(nil)
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		if input == nil || input.Decider != "jev:jev-latest" || input.KeyEnv != "TYPESAFE_API_KEY" || input.MaxRisk != "L1" {
			t.Fatalf("input = %+v", input)
		}
	})

	t.Run("negativa registra projeto sem decisor", func(t *testing.T) {
		var stdout bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stdin: strings.NewReader("n\n")}
		input, err := runner.askDecider(nil)
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		if input != nil {
			t.Fatalf("input = %+v, quer nil", input)
		}
		want := "Usar um modelo decisor no lugar do operador? (s/n) [n]: "
		if stdout.String() != want {
			t.Fatalf("prompt = %q, quer %q", stdout.String(), want)
		}
	})

	t.Run("fim de entrada aceita o padrão", func(t *testing.T) {
		var stdout bytes.Buffer
		runner := &Runner{Stdout: &stdout, Stdin: strings.NewReader("")}
		input, err := runner.askDecider(nil)
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		if input != nil {
			t.Fatalf("input = %+v, quer nil", input)
		}
		want := "Usar um modelo decisor no lugar do operador? (s/n) [n]: \n"
		if stdout.String() != want {
			t.Fatalf("prompt = %q, quer %q", stdout.String(), want)
		}
	})

	t.Run("configuração anterior vira o padrão", func(t *testing.T) {
		var stdout bytes.Buffer
		previous := &decider.Config{
			Enabled: true,
			Decider: "jev:outro-modelo",
			KeyEnv:  "OUTRA_CHAVE",
			MaxRisk: "L1",
		}
		runner := &Runner{Stdout: &stdout, Stdin: strings.NewReader("s\n\n\n\n")}
		input, err := runner.askDecider(previous)
		if err != nil {
			t.Fatalf("erro = %v", err)
		}
		if input == nil || input.Decider != "jev:outro-modelo" || input.KeyEnv != "OUTRA_CHAVE" || input.MaxRisk != "L1" {
			t.Fatalf("input = %+v", input)
		}
		if !strings.Contains(stdout.String(), "Usar um modelo decisor no lugar do operador? (s/n) [s]: ") {
			t.Fatalf("prompt = %q", stdout.String())
		}
	})
}

func TestDescribeDecider(t *testing.T) {
	endpoint := "https://exemplo.test/v1"
	tests := []struct {
		name   string
		config decider.Config
		want   string
	}{
		{
			name:   "desabilitado",
			config: decider.Config{},
			want:   "sem decisor: as decisões do operador continuam com você",
		},
		{
			name:   "habilitado",
			config: decider.Config{Enabled: true, Decider: "jev:jev-latest", KeyEnv: "TYPESAFE_API_KEY", MaxRisk: "L3"},
			want:   "decisor jev:jev-latest (chave em $TYPESAFE_API_KEY, teto de risco L3)",
		},
		{
			name:   "com endpoint",
			config: decider.Config{Enabled: true, Decider: "jev:jev-latest", KeyEnv: "K", MaxRisk: "L2", Endpoint: &endpoint},
			want:   "decisor jev:jev-latest (chave em $K, teto de risco L2, endpoint https://exemplo.test/v1)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := describeDecider(&test.config); got != test.want {
				t.Fatalf("describeDecider = %q, quer %q", got, test.want)
			}
		})
	}
}
