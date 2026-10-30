package decider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

func coverContent(project string) DecisionContent {
	return DecisionContent{
		Point:      PointApprove,
		Project:    project,
		WorkID:     "0001",
		TaskID:     "1.1",
		Decider:    "jev:x",
		Questions:  map[string]Question{},
		Answers:    map[string]Answer{},
		Thresholds: map[string]any{},
		Outcome:    OutcomeEscalate,
		Reasons:    []string{"r"},
	}
}

func TestResolveRootEmptyUsesEnvironment(t *testing.T) {
	home := filepath.Join(t.TempDir(), "v")
	t.Setenv(verify.HomeEnv, home)
	got, err := resolveRoot("")
	if err != nil || got != home {
		t.Fatalf("resolveRoot = %q, %v; queria %q", got, err, home)
	}
	if got, _ := resolveRoot("/x"); got != "/x" {
		t.Fatalf("raiz explícita deve ser mantida: %q", got)
	}
	// Com a raiz padrão, ConfigPath fica sob PWN_VERIFIER_HOME/deciders.
	file, err := ConfigPath(t.TempDir(), "")
	if err != nil || !strings.HasPrefix(file, filepath.Join(home, "deciders")) {
		t.Fatalf("ConfigPath = %q, %v", file, err)
	}
}

func TestConfigFunctionsFailForMissingRepository(t *testing.T) {
	verifier := initVerifier(t)
	missing := filepath.Join(t.TempDir(), "nao-existe")
	if _, err := ProjectIdentity(missing); err == nil {
		t.Error("ProjectIdentity: esperava erro")
	}
	if _, err := ConfigPath(missing, verifier); err == nil {
		t.Error("ConfigPath: esperava erro")
	}
	if _, err := ReadConfig(missing, verifier); err == nil {
		t.Error("ReadConfig: esperava erro")
	}
	if _, err := WriteConfig(missing, nil, verifier); err == nil {
		t.Error("WriteConfig: esperava erro")
	}
	if _, err := RemoveConfig(missing, verifier); err == nil {
		t.Error("RemoveConfig: esperava erro")
	}
}

func TestReadConfigInvalidFiles(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	file, err := ConfigPath(repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	identity, _ := ProjectIdentity(repo)

	for name, content := range map[string]string{
		"json corrompido": "{",
		"versão errada":   `{"version":2,"enabled":false,"project":"` + identity + `"}`,
	} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if cfg, err := ReadConfig(repo, verifier); err == nil || cfg != nil || !strings.Contains(err.Error(), "inválida") {
			t.Errorf("%s: cfg=%v err=%v", name, cfg, err)
		}
	}

	// Caminho que é diretório: erro de leitura, não "ausente".
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(file, 0o755); err != nil {
		t.Fatal(err)
	}
	if cfg, err := ReadConfig(repo, verifier); err == nil || cfg != nil {
		t.Errorf("diretório: cfg=%v err=%v", cfg, err)
	}
	// Remover um diretório não vazio falha e não é "nada a remover".
	if err := os.WriteFile(filepath.Join(file, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveConfig(repo, verifier); err == nil || removed {
		t.Errorf("RemoveConfig sobre diretório: removed=%v err=%v", removed, err)
	}
}

func TestWriteConfigRejectsInvalidInputWithoutWriting(t *testing.T) {
	repo := t.TempDir()
	verifier := initVerifier(t)
	_, err := WriteConfig(repo, &Input{Decider: "jev", KeyEnv: "K", MaxRisk: "L3"}, verifier)
	if err == nil || !strings.Contains(err.Error(), "decisor inválido") {
		t.Fatalf("erro = %v", err)
	}
	file, _ := ConfigPath(repo, verifier)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("configuração não deveria existir: %v", err)
	}
}

func TestWriteConfigVerifierRootIsFile(t *testing.T) {
	repo := t.TempDir()
	blocked := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteConfig(repo, nil, blocked); err == nil {
		t.Fatal("esperava erro: raiz do verificador é arquivo")
	}
}

func TestRecordDecisionFailures(t *testing.T) {
	t.Run("raiz é arquivo", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "arquivo")
		if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := RecordDecision(coverContent("p"), t.TempDir(), blocked); err == nil {
			t.Fatal("esperava erro")
		}
	})
	t.Run("chave privada inválida", func(t *testing.T) {
		verifier := initVerifier(t)
		if err := os.WriteFile(verify.PrivateKeyFile(verifier), []byte("lixo"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := RecordDecision(coverContent("p"), t.TempDir(), verifier)
		if err == nil || !strings.Contains(err.Error(), "sem chave") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("chave pública inválida", func(t *testing.T) {
		verifier := initVerifier(t)
		if err := os.WriteFile(verify.PublicKeyFile(verifier), []byte("lixo"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := RecordDecision(coverContent("p"), t.TempDir(), verifier)
		if err == nil || !strings.Contains(err.Error(), "sem chave") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("pasta de decisões bloqueada", func(t *testing.T) {
		verifier := initVerifier(t)
		if err := os.WriteFile(filepath.Join(verifier, "decisions"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := RecordDecision(coverContent("p"), t.TempDir(), verifier); err == nil {
			t.Fatal("esperava erro ao gravar a autoridade")
		}
	})
	t.Run("cópia no repositório bloqueada", func(t *testing.T) {
		verifier := initVerifier(t)
		repo := t.TempDir()
		if err := os.WriteFile(filepath.Join(repo, ".pwn"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := RecordDecision(coverContent("p"), repo, verifier); err == nil {
			t.Fatal("esperava erro ao gravar a cópia")
		}
	})
}

func TestDecisionSignatureValidWithoutPublicKey(t *testing.T) {
	verifier := initVerifier(t)
	record, err := RecordDecision(coverContent("p"), t.TempDir(), verifier)
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if !DecisionSignatureValid(record, verifier) {
		t.Fatal("assinatura deveria ser válida")
	}
	if err := os.Remove(verify.PublicKeyFile(verifier)); err != nil {
		t.Fatal(err)
	}
	if DecisionSignatureValid(record, verifier) {
		t.Error("sem chave pública a assinatura não pode ser válida")
	}
	if DecisionSignatureValid(record, filepath.Join(t.TempDir(), "outra")) {
		t.Error("raiz sem chave não pode validar")
	}
}

func TestReadDecisionInvalid(t *testing.T) {
	verifier := initVerifier(t)
	dir := filepath.Join(verifier, "decisions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec, err := ReadDecision("bad", verifier); err == nil || rec != nil || !strings.Contains(err.Error(), "inválida") {
		t.Errorf("JSON inválido: %v %v", rec, err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if rec, err := ReadDecision("dir", verifier); err == nil || rec != nil {
		t.Errorf("diretório: %v %v", rec, err)
	}
}

func TestListDecisionsEdgeCases(t *testing.T) {
	// Sem pasta de decisões: lista nula, sem erro.
	empty := initVerifier(t)
	if list, err := ListDecisions("p", empty); err != nil || len(list) != 0 {
		t.Fatalf("sem pasta: %v %v", list, err)
	}

	// Pasta existe, mas a raiz não tem config do verificador.
	noConfig := t.TempDir()
	if err := os.MkdirAll(filepath.Join(noConfig, "decisions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if list, err := ListDecisions("p", noConfig); err != nil || len(list) != 0 {
		t.Fatalf("sem config: %v %v", list, err)
	}

	verifier := initVerifier(t)
	repo := t.TempDir()
	first, err := RecordDecision(coverContent(repo), repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	second := coverContent(repo)
	second.TaskID = "2.2"
	secondRec, err := RecordDecision(second, repo, verifier)
	if err != nil {
		t.Fatal(err)
	}
	// Ignora subdiretório e arquivo sem extensão .json.
	dir := filepath.Join(verifier, "decisions")
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notas.txt"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := ListDecisions(repo, verifier)
	if err != nil || len(list) != 2 {
		t.Fatalf("lista = %d, %v", len(list), err)
	}
	if list[0].CreatedAt > list[1].CreatedAt {
		t.Errorf("ordem por created_at violada: %s > %s", list[0].CreatedAt, list[1].CreatedAt)
	}
	ids := map[string]bool{list[0].DecisionID: true, list[1].DecisionID: true}
	if !ids[first.DecisionID] || !ids[secondRec.DecisionID] {
		t.Errorf("ids inesperados: %v", ids)
	}

	// Registro corrompido interrompe a listagem com erro.
	if err := os.WriteFile(filepath.Join(dir, "corrupto.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListDecisions(repo, verifier); err == nil {
		t.Error("JSON corrompido: esperava erro")
	}
	if err := os.Remove(filepath.Join(dir, "corrupto.json")); err != nil {
		t.Fatal(err)
	}
	// Entrada .json ilegível (diretório não é pulado quando IsDir; use arquivo sem permissão).
	if os.Geteuid() != 0 {
		unreadable := filepath.Join(dir, "sem-leitura.json")
		if err := os.WriteFile(unreadable, []byte("{}"), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := ListDecisions(repo, verifier); err == nil {
			t.Error("arquivo ilegível: esperava erro")
		}
	}
}

func TestDecisionRepoCopyPath(t *testing.T) {
	base := t.TempDir()
	got := DecisionRepoCopy(base, "0007", "abc")
	if got != filepath.Join(base, ".pwn", "decisions", "0007", "abc.json") {
		t.Errorf("got %s", got)
	}
}
