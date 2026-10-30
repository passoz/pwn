package gates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateSessionKey zera a chave em memória do processo durante o teste e a
// restaura no fim, para que os testes de fallback não vazem para os demais.
func isolateSessionKey(t *testing.T) {
	t.Helper()
	verifierKeyMutex.Lock()
	previous := sessionKey
	sessionKey = ""
	verifierKeyMutex.Unlock()
	t.Cleanup(func() {
		verifierKeyMutex.Lock()
		sessionKey = previous
		verifierKeyMutex.Unlock()
	})
}

func TestGetVerifierKeyKeepsSessionKeyWhenDiskIsNotWritable(t *testing.T) {
	isolateSessionKey(t)
	t.Setenv("PWN_VERIFIER_KEY", "")

	workDir := t.TempDir()
	// `.pwn` como arquivo regular impede criar `.pwn/.verifier_key`.
	if err := os.WriteFile(filepath.Join(workDir, ".pwn"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	key := GetVerifierKey(workDir)
	if key == "" {
		t.Fatal("chave vazia")
	}
	if again := GetVerifierKey(workDir); again != key {
		t.Fatalf("chave de sessão mudou: %q != %q", again, key)
	}
	// A chave de sessão vale também para outro diretório sem chave em disco.
	if other := GetVerifierKey(t.TempDir()); other != key {
		t.Fatalf("chave de sessão não foi reutilizada: %q != %q", other, key)
	}
	if stored := ReadVerifierKey(workDir); stored != "" {
		t.Fatalf("ReadVerifierKey = %q, quer vazio", stored)
	}
}

func TestGetVerifierKeyFallsBackWhenKeyCannotBeRenamed(t *testing.T) {
	isolateSessionKey(t)
	t.Setenv("PWN_VERIFIER_KEY", "")

	workDir := t.TempDir()
	// `.verifier_key` como diretório: a leitura falha e o rename do tmp também.
	keyPath := filepath.Join(workDir, ".pwn", ".verifier_key")
	if err := os.MkdirAll(keyPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	key := GetVerifierKey(workDir)
	if key == "" {
		t.Fatal("chave vazia")
	}
	if info, err := os.Stat(keyPath); err != nil || !info.IsDir() {
		t.Fatalf("diretório da chave foi substituído: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(workDir, ".pwn", "*.tmp"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("tmp não removido: %v, %v", leftovers, err)
	}
	if again := GetVerifierKey(workDir); again != key {
		t.Fatalf("chave de sessão mudou: %q != %q", again, key)
	}
}

// writeCanonicalBaseline grava a Work canônica embutida num diretório.
func writeCanonicalBaseline(t *testing.T, dir, workID string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, value := range canonicalArtifacts(workID) {
		if err := writeJSONFile(filepath.Join(dir, name), value); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestRunSingleMutationReportsUnknownGate(t *testing.T) {
	tempRoot := t.TempDir()
	baseline := filepath.Join(tempRoot, "baseline")
	writeCanonicalBaseline(t, baseline, "0001")

	result := runSingleMutation(MutationCase{
		ID:          "mut-missing-ac",
		Description: "caso com gate inexistente",
		Gate:        "GATE-NAO-EXISTE",
	}, baseline, tempRoot, "0001", false)

	if result.Detected || result.Detail != "gate desconhecido: GATE-NAO-EXISTE" {
		t.Fatalf("result = %+v", result)
	}
	if result.ID != "mut-missing-ac" || result.Gate != "GATE-NAO-EXISTE" || result.Description == "" {
		t.Fatalf("metadados perdidos: %+v", result)
	}
}

func TestRunSingleMutationFlagsHardenedAdvisoryCase(t *testing.T) {
	tempRoot := t.TempDir()
	baseline := filepath.Join(tempRoot, "baseline")
	writeCanonicalBaseline(t, baseline, "0001")

	// mut-missing-ac bloqueia o GATE-SPEC-PLAN; declarado como advisory, o
	// resultado precisa avisar que o gate endureceu.
	result := runSingleMutation(MutationCase{
		ID:            "mut-missing-ac",
		Description:   "caso declarado advisory",
		Gate:          "GATE-SPEC-PLAN",
		ExpectBlocked: false,
	}, baseline, tempRoot, "0001", true)

	if !result.Detected {
		t.Fatalf("mutação deveria ser detectada: %+v", result)
	}
	for _, want := range []string{
		"antes='pass'",
		"depois='blocked'",
		"gate passou a bloquear com",
		"gate endureceu desde a lista canônica (caso declarado advisory)",
		"[baseline canônica]",
	} {
		if !strings.Contains(result.Detail, want) {
			t.Fatalf("detail sem %q: %q", want, result.Detail)
		}
	}
	if _, err := os.Stat(filepath.Join(tempRoot, "case-mut-missing-ac")); err == nil {
		t.Fatal("cópia do caso deveria ser removida")
	}
}

func TestRunSingleMutationReportsMissingBaseline(t *testing.T) {
	tempRoot := t.TempDir()
	result := runSingleMutation(MutationCase{
		ID:            "mut-missing-ac",
		Gate:          "GATE-SPEC-PLAN",
		ExpectBlocked: true,
	}, filepath.Join(tempRoot, "inexistente"), tempRoot, "0001", false)

	if result.Detected || !strings.HasPrefix(result.Detail, "erro ao executar a mutação: ") {
		t.Fatalf("result = %+v", result)
	}
}

func TestApplyMutationIgnoresUnknownID(t *testing.T) {
	note, err := applyMutation("mut-inexistente", t.TempDir())
	if note != "" || err != nil {
		t.Fatalf("note = %q, err = %v", note, err)
	}
}

func TestJSONScalarFormatting(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"nulo", nil, "null"},
		{"verdadeiro", true, "true"},
		{"falso", false, "false"},
		{"inteiro", float64(42), "42"},
		{"negativo", float64(-3), "-3"},
		{"fração", 1.5, "1.5"},
		{"além de 1e21", 1e21, "1e+21"},
		{"lista", []any{"a", float64(1)}, `["a",1]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsScalarString(tc.value); got != tc.want {
				t.Fatalf("jsScalarString(%v) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestEmptyLengthAndTruthinessFollowJavaScript(t *testing.T) {
	empty := []any{nil, false, float64(0), "", []any{}, map[string]any{"length": float64(0)}}
	for _, value := range empty {
		if !isEmptyLength(value) {
			t.Fatalf("isEmptyLength(%#v) = false, want true", value)
		}
	}
	filled := []any{true, float64(5), "x", []any{1}, map[string]any{}, map[string]any{"length": float64(2)}}
	for _, value := range filled {
		if isEmptyLength(value) {
			t.Fatalf("isEmptyLength(%#v) = true, want false", value)
		}
	}
	if jsTruthy(nil) || jsTruthy(false) || jsTruthy("") || jsTruthy(float64(0)) {
		t.Fatal("valores falsy foram tratados como truthy")
	}
	if !jsTruthy(true) || !jsTruthy("x") || !jsTruthy(float64(-1)) || !jsTruthy([]any{}) || !jsTruthy(map[string]any{}) {
		t.Fatal("valores truthy foram tratados como falsy")
	}
}

func TestContractsHashIgnoresNonObjectTasksAndTracksContractContent(t *testing.T) {
	workDir := t.TempDir()
	plan := `{"tasks": ["texto solto", {"id": "T1", "contract_id": "CTR-1"}, {"id": "T2"}]}`
	if err := os.WriteFile(filepath.Join(workDir, "plan.json"), []byte(plan), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "CTR-1.json"), []byte(`{"a": 1}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	first := contractsHash(workDir)
	if len(first) != 12 {
		t.Fatalf("hash = %q", first)
	}
	if again := contractsHash(workDir); again != first {
		t.Fatalf("hash instável: %q != %q", again, first)
	}
	if err := os.WriteFile(filepath.Join(workDir, "CTR-1.json"), []byte(`{"a": 2}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if changed := contractsHash(workDir); changed == first {
		t.Fatal("contrato editado deveria mudar o hash")
	}
	if absent := contractsHash(t.TempDir()); absent != "absent" {
		t.Fatalf("hash sem plano = %q", absent)
	}
}
