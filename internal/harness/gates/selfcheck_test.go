package gates_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

// writeValidWork grava um Work mínimo porém válido: todos os gates passam antes
// das mutações.
func writeValidWork(t *testing.T, rootDir, workID string) string {
	t.Helper()
	workDir := filepath.Join(rootDir, ".pwn", "work", workID)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	taskContract, err := contract.CreateDefaultContractV4("1.1", workID, "Task de teste", contract.RiskL2, nil)
	if err != nil {
		t.Fatalf("contrato: %v", err)
	}
	writeJSON(t, workDir, "discovery.json", map[string]any{
		"work_id":     workID,
		"problem":     "Problema de teste",
		"actors":      []any{"ACT-001"},
		"objectives":  []any{"Objetivo de teste"},
		"constraints": []any{"Restrição de teste"},
	})
	writeJSON(t, workDir, "requirements.json", map[string]any{
		"work_id": workID,
		"requirements": []any{
			map[string]any{
				"id":                  "FR-001",
				"title":               "Requisito de teste",
				"user_story":          "Como operador, quero X para obter Y",
				"acceptance_criteria": []any{"Critério observável"},
			},
		},
	})
	writeJSON(t, workDir, "prd.json", map[string]any{
		"id":                    "PRD-" + workID,
		"title":                 "PRD de teste do Work " + workID,
		"status":                "draft",
		"accepted_requirements": []any{"FR-001"},
		"requirements":          []any{map[string]any{"id": "FR-001", "statement": "Manter a rastreabilidade entre artefatos."}},
	})
	writeJSON(t, workDir, "spec.json", map[string]any{
		"work_id": workID,
		"capabilities": []any{
			map[string]any{"id": "CAP-001", "description": "Capacidade que atende FR-001", "rules": []any{"RULE-001: preservar rastreabilidade"}},
		},
	})
	writeJSON(t, workDir, "plan.json", map[string]any{
		"work_id":      workID,
		"title":        "Plano de teste",
		"components":   []any{map[string]any{"name": "core", "purpose": "Componente de teste"}},
		"global_gates": []any{"`bun test` — a suíte completa permanece verde"},
		"tasks": []any{
			map[string]any{
				"id":                   "1.1",
				"title":                "Task de teste",
				"requirement_id":       "FR-001",
				"spec_reference":       "CAP-001",
				"contract_id":          "CTR-001",
				"components":           []any{"core"},
				"files":                []any{"src/feature.ts", "tests/feature.test.ts"},
				"implementation_files": []any{"src/feature.ts"},
				"test_files":           []any{"tests/feature.test.ts"},
				"red":                  map[string]any{"command": "bun test tests/feature.test.ts", "description": "a asserção FEATURE-TEST falha antes da implementação"},
				"implementation_steps": []any{"Implementar o comportamento de teste"},
				"acceptance_criteria":  []any{map[string]any{"command": "bun test tests/feature.test.ts", "description": "o comportamento de teste é observado"}},
			},
		},
	})
	writeJSON(t, workDir, "CTR-001.json", taskContract)
	writeJSON(t, workDir, "traceability-matrix.json", map[string]any{
		"work_id": workID,
		"matrix": []any{
			map[string]any{
				"origin":         "DISC-001",
				"requirement_id": "FR-001",
				"decision_id":    "TD-001",
				"spec_section":   "CAP-001",
				"task_id":        "1.1",
				"contract_id":    "CTR-001",
				"evidence_id":    "EVD-001",
				"status":         "planned",
			},
		},
	})
	return workDir
}

// hashDir devolve um hash estável do conteúdo de um diretório.
func hashDir(t *testing.T, dir string) string {
	t.Helper()
	hasher := sha256.New()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hasher.Write([]byte(relative))
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hasher.Write(data)
		return nil
	})
	if err != nil {
		t.Fatalf("hash dir: %v", err)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func TestMutationCasesContract(t *testing.T) {
	cases := gates.MutationCases()
	if len(cases) < 5 {
		t.Fatalf("cases = %d", len(cases))
	}
	ids := make(map[string]bool)
	gatesSeen := make(map[string]bool)
	for _, mutationCase := range cases {
		if ids[mutationCase.ID] {
			t.Fatalf("id duplicado: %s", mutationCase.ID)
		}
		ids[mutationCase.ID] = true
		if gatesSeen[mutationCase.Gate] {
			t.Fatalf("gate duplicado: %s", mutationCase.Gate)
		}
		gatesSeen[mutationCase.Gate] = true
		if mutationCase.Description == "" {
			t.Fatalf("descrição vazia em %s", mutationCase.ID)
		}
		if !strings.HasPrefix(mutationCase.Gate, "GATE-") {
			t.Fatalf("gate = %q", mutationCase.Gate)
		}
	}
	for _, id := range []string{
		"mut-missing-ac",
		"mut-missing-contract",
		"mut-broken-traceability",
		"mut-prd-missing-accepted",
		"mut-spec-no-rules",
	} {
		if !ids[id] {
			t.Fatalf("falta %s", id)
		}
	}
}

func TestRunMutationsOnValidWork(t *testing.T) {
	rootDir := t.TempDir()
	workDir := writeValidWork(t, rootDir, "0001")
	before := hashDir(t, workDir)

	results := gates.RunMutations(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir})
	cases := gates.MutationCases()
	if len(results) != len(cases) {
		t.Fatalf("results = %d", len(results))
	}
	byID := make(map[string]gates.MutationCase, len(cases))
	for _, mutationCase := range cases {
		byID[mutationCase.ID] = mutationCase
	}
	for _, result := range results {
		mutationCase, ok := byID[result.ID]
		if !ok {
			t.Fatalf("resultado sem caso: %s", result.ID)
		}
		if result.Gate != mutationCase.Gate {
			t.Fatalf("gate = %q, want %q", result.Gate, mutationCase.Gate)
		}
		if result.Detail == "" {
			t.Fatalf("detail vazio em %s", result.ID)
		}
	}
	if baseline := gates.DescribeBaseline(gates.RunMutationsOptions{WorkID: "0001", RootDir: rootDir}); strings.Contains(baseline, "baseline canônica") {
		t.Fatalf("baseline = %q", baseline)
	}

	blocked := 0
	for _, result := range results {
		if !byID[result.ID].ExpectBlocked {
			continue
		}
		blocked++
		if !result.Detected {
			t.Fatalf("%s não detectado: %s", result.ID, result.Detail)
		}
		if !strings.Contains(result.Detail, "depois='blocked'") {
			t.Fatalf("%s detail = %q", result.ID, result.Detail)
		}
	}
	if blocked < 2 {
		t.Fatalf("casos bloqueantes = %d", blocked)
	}

	advisory := 0
	for _, result := range results {
		if byID[result.ID].ExpectBlocked {
			continue
		}
		advisory++
		if !strings.Contains(result.Detail, "antes=") {
			t.Fatalf("%s detail = %q", result.ID, result.Detail)
		}
		explained := strings.Contains(result.Detail, "gate não bloqueia") ||
			strings.Contains(result.Detail, "não aplicável") ||
			strings.Contains(result.Detail, "gate endureceu")
		if !explained {
			t.Fatalf("%s sem explicação: %q", result.ID, result.Detail)
		}
	}
	if advisory < 1 {
		t.Fatalf("casos advisory = %d", advisory)
	}
	for _, result := range results {
		if result.ID == "mut-spec-no-rules" && !strings.Contains(result.Detail, "pass_with_notes") {
			t.Fatalf("mut-spec-no-rules detail = %q", result.Detail)
		}
	}

	if after := hashDir(t, workDir); after != before {
		t.Fatal("RunMutations modificou o Work original")
	}
}

func TestRunMutationsUsesCanonicalBaseline(t *testing.T) {
	rootDir := t.TempDir()

	baseline := gates.DescribeBaseline(gates.RunMutationsOptions{WorkID: "9999", RootDir: rootDir})
	if !strings.Contains(baseline, "não encontrado") {
		t.Fatalf("baseline = %q", baseline)
	}
	results := gates.RunMutations(gates.RunMutationsOptions{WorkID: "9999", RootDir: rootDir})
	if len(results) != len(gates.MutationCases()) {
		t.Fatalf("results = %d", len(results))
	}
	detected := false
	for _, result := range results {
		if result.Detected {
			detected = true
		}
	}
	if !detected {
		t.Fatal("nenhuma mutação detectada na baseline canônica")
	}
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rootDir não deve ser escrito: %v", entries)
	}
}
