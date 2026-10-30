package gates_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/gates"
)

// writeRawFile grava conteúdo literal (inclusive JSON inválido) num Work.
func writeRawFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// mutationsByID indexa os resultados de RunMutations pelo ID do caso.
func mutationsByID(t *testing.T, results []gates.MutationResult) map[string]gates.MutationResult {
	t.Helper()
	byID := make(map[string]gates.MutationResult, len(results))
	for _, result := range results {
		byID[result.ID] = result
	}
	if len(byID) != len(gates.MutationCases()) {
		t.Fatalf("resultados = %d, casos = %d", len(byID), len(gates.MutationCases()))
	}
	return byID
}

// writeBareWork grava os seis artefatos obrigatórios sem estrutura-alvo: nenhuma
// mutação encontra o que alterar.
func writeBareWork(t *testing.T, dir string) {
	t.Helper()
	writeJSON(t, dir, "discovery.json", map[string]any{})
	writeJSON(t, dir, "requirements.json", map[string]any{})
	writeJSON(t, dir, "prd.json", map[string]any{})
	writeJSON(t, dir, "spec.json", map[string]any{
		"capabilities": []any{
			"texto solto",
			map[string]any{"id": "CAP-SEM-RULES"},
			map[string]any{"id": "CAP-VAZIA", "rules": []any{}},
		},
	})
	writeJSON(t, dir, "plan.json", map[string]any{
		"tasks": []any{"texto solto", map[string]any{"id": "A"}},
	})
	writeJSON(t, dir, "traceability-matrix.json", map[string]any{"matrix": []any{}})
}

func TestRunMutationsReportsInapplicableMutations(t *testing.T) {
	rootDir := t.TempDir()
	writeBareWork(t, rootDir)

	options := gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir}
	if baseline := gates.DescribeBaseline(options); baseline != "Work 0001 ("+rootDir+")" {
		t.Fatalf("baseline = %q", baseline)
	}
	byID := mutationsByID(t, gates.RunMutations(options))
	for id, result := range byID {
		if result.Detected {
			t.Fatalf("%s não deveria ser detectado: %s", id, result.Detail)
		}
		if !strings.HasPrefix(result.Detail, "mutação não aplicável") {
			t.Fatalf("%s detail = %q", id, result.Detail)
		}
		if strings.Contains(result.Detail, "baseline canônica") {
			t.Fatalf("%s usou a baseline canônica: %q", id, result.Detail)
		}
	}
}

func TestRunMutationsReportsUnreadableArtifacts(t *testing.T) {
	rootDir := t.TempDir()
	writeRawFile(t, rootDir, "discovery.json", "{}")
	writeRawFile(t, rootDir, "requirements.json", "{}")
	writeRawFile(t, rootDir, "prd.json", "{ isto não é json")
	// spec.json como diretório: Stat passa, a leitura falha com erro de IO.
	if err := os.Mkdir(filepath.Join(rootDir, "spec.json"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeRawFile(t, rootDir, "plan.json", "[")
	writeRawFile(t, rootDir, "traceability-matrix.json", "{\"matrix\": ")

	byID := mutationsByID(t, gates.RunMutations(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir}))
	for id, result := range byID {
		if result.Detected {
			t.Fatalf("%s não deveria ser detectado: %s", id, result.Detail)
		}
		if !strings.HasPrefix(result.Detail, "erro ao executar a mutação: ") {
			t.Fatalf("%s detail = %q", id, result.Detail)
		}
	}
}

func TestRunMutationsReportsWriteFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignora permissões de arquivo")
	}
	rootDir := t.TempDir()
	workDir := writeValidWork(t, rootDir, "0001")
	for _, name := range []string{"plan.json", "prd.json", "spec.json", "traceability-matrix.json"} {
		if err := os.Chmod(filepath.Join(workDir, name), 0o444); err != nil {
			t.Fatalf("chmod: %v", err)
		}
	}

	byID := mutationsByID(t, gates.RunMutations(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir}))
	for id, result := range byID {
		if result.Detected {
			t.Fatalf("%s não deveria ser detectado: %s", id, result.Detail)
		}
		if !strings.HasPrefix(result.Detail, "erro ao executar a mutação: ") || !strings.Contains(result.Detail, "permission denied") {
			t.Fatalf("%s detail = %q", id, result.Detail)
		}
	}
}

func TestRunMutationsFailsWhenBaselineIsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignora permissões de arquivo")
	}
	rootDir := t.TempDir()
	workDir := writeValidWork(t, rootDir, "0001")
	if err := os.WriteFile(filepath.Join(workDir, "segredo.txt"), []byte("x"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}

	results := gates.RunMutations(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir})
	if results != nil {
		t.Fatalf("baseline ilegível deveria devolver nil, got %d resultados", len(results))
	}
}

func TestRunMutationsCopiesNestedDirectories(t *testing.T) {
	rootDir := t.TempDir()
	workDir := writeValidWork(t, rootDir, "0001")
	nested := filepath.Join(workDir, "evidencias", "logs")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeRawFile(t, nested, "run.log", "ok")
	before := hashDir(t, workDir)

	byID := mutationsByID(t, gates.RunMutations(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir}))
	if !byID["mut-missing-ac"].Detected {
		t.Fatalf("mut-missing-ac = %+v", byID["mut-missing-ac"])
	}
	if after := hashDir(t, workDir); after != before {
		t.Fatal("RunMutations alterou o Work original com subdiretórios")
	}
}

func TestRunMutationsFlagsBaselineAlreadyBlocked(t *testing.T) {
	rootDir := t.TempDir()
	workDir := writeValidWork(t, rootDir, "0001")
	// Requisito sem critério de aceite: GATE-DISC-REQ já bloqueia antes da mutação.
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"work_id":      "0001",
		"requirements": []any{map[string]any{"id": "FR-001", "title": "Sem critério"}},
	})

	byID := mutationsByID(t, gates.RunMutations(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir}))
	result := byID["mut-broken-traceability"]
	if result.Detected {
		t.Fatalf("baseline inválida não pode contar como detecção: %+v", result)
	}
	if !strings.Contains(result.Detail, "antes='blocked', depois='blocked'") ||
		!strings.Contains(result.Detail, "gate já bloqueava antes da mutação") {
		t.Fatalf("detail = %q", result.Detail)
	}
}

func TestRunMutationsFallsBackToCanonicalBaselineForIncompleteWork(t *testing.T) {
	rootDir := t.TempDir()
	workDir := filepath.Join(rootDir, ".pwn", "work", "0007")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeJSON(t, workDir, "discovery.json", map[string]any{"work_id": "0007"})

	options := gates.RunMutationsOptions{WorkID: "0007", RootDir: rootDir}
	baseline := gates.DescribeBaseline(options)
	want := "incompleto: falta requirements.json, prd.json, spec.json, plan.json, traceability-matrix.json"
	if !strings.Contains(baseline, want) || !strings.HasPrefix(baseline, "baseline canônica (Work 0007") {
		t.Fatalf("baseline = %q", baseline)
	}

	byID := mutationsByID(t, gates.RunMutations(options))
	if !byID["mut-missing-ac"].Detected {
		t.Fatalf("canônica deveria detectar mut-missing-ac: %+v", byID["mut-missing-ac"])
	}
	for id, result := range byID {
		if !strings.Contains(result.Detail, "[baseline canônica]") {
			t.Fatalf("%s sem marca de baseline canônica: %q", id, result.Detail)
		}
	}
	if _, err := os.Stat(filepath.Join(workDir, "plan.json")); err == nil {
		t.Fatal("Work incompleto não deve ser completado em disco")
	}
}

func TestRunMutationsDefaultsRootDirToCurrentDirectory(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	writeValidWork(t, cwd, "0001")

	options := gates.RunMutationsOptions{WorkID: "0001"}
	if baseline := gates.DescribeBaseline(options); !strings.HasPrefix(baseline, "Work 0001 (") {
		t.Fatalf("baseline = %q", baseline)
	}
	byID := mutationsByID(t, gates.RunMutations(options))
	if !byID["mut-missing-contract"].Detected {
		t.Fatalf("mut-missing-contract = %+v", byID["mut-missing-contract"])
	}

	missing := gates.RunMutationsOptions{WorkID: "9999"}
	absolute, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if baseline := gates.DescribeBaseline(missing); !strings.Contains(baseline, "não encontrado em "+absolute) {
		t.Fatalf("baseline = %q", baseline)
	}
}
