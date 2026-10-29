package decider

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/verify"
)

// initVerifier cria uma raiz do verificador com par de chaves Ed25519.
func initVerifier(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if _, err := verify.InitializeVerifierHome(root); err != nil {
		t.Fatalf("InitializeVerifierHome: %v", err)
	}
	return root
}

// writeEnabled grava uma configuração habilitada com endpoint de teste.
func writeEnabled(t *testing.T, repo, verifier, endpoint, keyEnv string, maxRisk contract.RiskLevel) *Config {
	t.Helper()
	config, err := WriteConfig(repo, &Input{
		Decider:  "jev:jev-latest",
		KeyEnv:   keyEnv,
		MaxRisk:  string(maxRisk),
		Endpoint: &endpoint,
	}, verifier)
	if err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	return config
}

func TestValidateInput(t *testing.T) {
	endpoint := "http://127.0.0.1:9/v1/systemone"
	tests := []struct {
		name    string
		input   Input
		want    *ValidInput
		wantErr string
	}{
		{
			name:  "válido normaliza o teto e o endpoint",
			input: Input{Decider: " jev:jev-latest ", KeyEnv: " MY_KEY ", MaxRisk: "l2", Endpoint: &endpoint},
			want:  &ValidInput{Decider: "jev:jev-latest", KeyEnv: "MY_KEY", MaxRisk: contract.RiskL2, Endpoint: &endpoint},
		},
		{
			name:  "endpoint vazio vira nulo",
			input: Input{Decider: "jev:x", KeyEnv: "K", MaxRisk: "L3", Endpoint: new("  ")},
			want:  &ValidInput{Decider: "jev:x", KeyEnv: "K", MaxRisk: contract.RiskL3},
		},
		{name: "sem provedor", input: Input{Decider: ":x", KeyEnv: "K", MaxRisk: "L3"}, wantErr: "decisor inválido"},
		{name: "sem separador", input: Input{Decider: "jev", KeyEnv: "K", MaxRisk: "L3"}, wantErr: "decisor inválido"},
		{name: "provedor sem adaptador", input: Input{Decider: "foo:bar", KeyEnv: "K", MaxRisk: "L3"}, wantErr: "sem adaptador"},
		{name: "nome de variável inválido", input: Input{Decider: "jev:x", KeyEnv: "bad-name", MaxRisk: "L3"}, wantErr: "variável de ambiente inválido"},
		{name: "teto inválido", input: Input{Decider: "jev:x", KeyEnv: "K", MaxRisk: "L9"}, wantErr: "teto de risco inválido"},
		{name: "endpoint inválido", input: Input{Decider: "jev:x", KeyEnv: "K", MaxRisk: "L3", Endpoint: new("ftp://x")}, wantErr: "endpoint do decisor inválido"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ValidateInput(test.input)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("erro = %v, quer %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateInput: %v", err)
			}
			if got.Decider != test.want.Decider || got.KeyEnv != test.want.KeyEnv || got.MaxRisk != test.want.MaxRisk {
				t.Fatalf("got %+v, quer %+v", got, *test.want)
			}
			if (got.Endpoint == nil) != (test.want.Endpoint == nil) {
				t.Fatalf("endpoint = %v, quer %v", got.Endpoint, test.want.Endpoint)
			}
		})
	}
}

func TestConfigWriteReadRemove(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	config := writeEnabled(t, repo, verifier, "http://127.0.0.1:9/v1/systemone", "TEST_KEY", contract.RiskL2)
	if !config.Enabled || config.Decider != "jev:jev-latest" || config.MaxRisk != contract.RiskL2 {
		t.Fatalf("config = %+v", config)
	}
	if len(config.Scope) != len(Scopes) {
		t.Fatalf("escopo = %v", config.Scope)
	}

	file, err := ConfigPath(repo, verifier)
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	if !strings.HasPrefix(file, filepath.Join(verifier, "deciders")+string(filepath.Separator)) {
		t.Fatalf("configuração fora de deciders/: %s", file)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("modo = %o, quer 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte("secret-value")) {
		t.Fatalf("configuração contém a chave: %s", data)
	}
	var encoded map[string]any
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	if encoded["key_env"] != "TEST_KEY" || encoded["endpoint"] != "http://127.0.0.1:9/v1/systemone" {
		t.Fatalf("configuração serializada = %v", encoded)
	}

	read, err := ReadConfig(repo, verifier)
	if err != nil || read == nil || read.KeyEnv != "TEST_KEY" || read.MaxRisk != contract.RiskL2 {
		t.Fatalf("ReadConfig = %+v, %v", read, err)
	}

	removed, err := RemoveConfig(repo, verifier)
	if err != nil || !removed {
		t.Fatalf("RemoveConfig = %v, %v", removed, err)
	}
	removed, err = RemoveConfig(repo, verifier)
	if err != nil || removed {
		t.Fatalf("RemoveConfig repetido = %v, %v", removed, err)
	}
	if read, err := ReadConfig(repo, verifier); err != nil || read != nil {
		t.Fatalf("ReadConfig após remoção = %+v, %v", read, err)
	}
}

func TestConfigDisabledAndProjectIdentity(t *testing.T) {
	repo := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(repo, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	verifier := initVerifier(t)
	config, err := WriteConfig(link, nil, verifier)
	if err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if config.Enabled {
		t.Fatalf("configuração desabilitada esperada: %+v", config)
	}
	read, err := ReadConfig(repo, verifier)
	if err != nil || read == nil || read.Enabled {
		t.Fatalf("ReadConfig pela raiz = %+v, %v", read, err)
	}
	entries, err := os.ReadDir(filepath.Join(verifier, "deciders"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("arquivos = %d, quer 1", len(entries))
	}
	if _, err := os.Stat(filepath.Join(repo, ".pwn")); !os.IsNotExist(err) {
		t.Fatalf("configuração criou .pwn no repositório: %v", err)
	}
}

func TestConfigRejectsOtherProjectAndInsideRepository(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	writeEnabled(t, repo, verifier, "http://127.0.0.1:9/x", "K", contract.RiskL3)
	file, err := ConfigPath(repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"version":1,"enabled":false,"project":"outro","configured_at":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(repo, verifier); err == nil || !strings.Contains(err.Error(), "inválida") {
		t.Fatalf("erro = %v, quer configuração inválida", err)
	}

	inside := filepath.Join(repo, "verifier")
	if _, err := WriteConfig(repo, nil, inside); err == nil {
		t.Fatal("raiz do verificador dentro do repositório foi aceita")
	}
}
