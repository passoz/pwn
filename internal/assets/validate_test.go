package assets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const validPlanJSON = `{
  "work_id": "0001",
  "title": "app",
  "components": [{"name": "core", "purpose": "nucleo"}],
  "global_gates": ["suite verde"],
  "tasks": [
    {
      "id": "1.1",
      "title": "Nucleo",
      "requirement_id": "FR-001",
      "spec_reference": "CAP-001",
      "contract_id": "CTR-001",
      "depends_on": [],
      "components": ["core"],
      "files": ["src/a.ts", "tests/a.test.ts"],
      "implementation_files": ["src/a.ts"],
      "test_files": ["tests/a.test.ts"],
      "red": {"command": "bun test", "description": "falha esperada"},
      "implementation_steps": ["implementar"],
      "acceptance_criteria": [{"command": "bun test", "description": "passa"}]
    }
  ]
}`

const validPRDJSON = `{
  "id": "PRD-0001",
  "meta": {"version": "1.0", "created_at": "2026-09-10T00:00:00.000Z", "author": "operator"},
  "title": "PRD do app de teste",
  "status": "draft",
  "problem": {"statement": "Problema que precisa ser resolvido pelo produto em teste"},
  "solution": {"statement": "Solucao que resolve o problema descrito"},
  "decisions": [{"id": "DEC-001", "statement": "Decisao inicial", "status": "proposed"}],
  "accepted_requirements": ["FR-001"]
}`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestValidateNormativeDocumentValid(t *testing.T) {
	root := t.TempDir()
	document := strings.Replace(validPlanJSON, "{", `{"$schema": "https://pwn.dev/schemas/plan.schema.json",`, 1)
	writeFile(t, root, "plan.json", document)

	result := ValidateNormativeDocument("plan.json", root)
	if !result.Valid {
		t.Fatalf("valid plan rejected: %v", result.Errors)
	}
	if result.File != "plan.json" {
		t.Errorf("File = %q, want plan.json", result.File)
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors = %v, want empty", result.Errors)
	}
}

func TestValidateNormativeDocumentWithoutDeclaredSchema(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "evidencia.json", `{"conteudo": "sem schema"}`)

	result := ValidateNormativeDocument("evidencia.json", root)
	if !result.Valid {
		t.Fatalf("document without $schema rejected: %v", result.Errors)
	}
}

func TestValidateNormativeDocumentMissingFile(t *testing.T) {
	result := ValidateNormativeDocument("ausente.json", t.TempDir())
	if result.Valid {
		t.Fatal("missing file reported as valid")
	}
	want := []string{"File not found: ausente.json"}
	if !slices.Equal(result.Errors, want) {
		t.Errorf("Errors = %q, want %q", result.Errors, want)
	}
}

func TestValidateNormativeDocumentSyntaxError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "plan.json", "{")

	result := ValidateNormativeDocument("plan.json", root)
	if result.Valid {
		t.Fatal("invalid JSON reported as valid")
	}
	if len(result.Errors) != 1 || !strings.HasPrefix(result.Errors[0], "JSON Syntax Error: ") {
		t.Errorf("Errors = %q, want a JSON Syntax Error", result.Errors)
	}
}

func TestValidateNormativeDocumentRejectsUnknownSchema(t *testing.T) {
	root := t.TempDir()
	document := strings.Replace(validPlanJSON, "{", `{"$schema": "https://pwn.dev/schemas/inexistente.schema.json",`, 1)
	writeFile(t, root, "plan.json", document)

	result := ValidateNormativeDocument("plan.json", root)
	if result.Valid {
		t.Fatal("document with unknown schema reported as valid")
	}
	joined := strings.Join(result.Errors, "\n")
	if !strings.Contains(joined, "inexistente.schema.json") || !strings.Contains(joined, "não verificável") {
		t.Errorf("Errors = %q, want the unavailable schema named", result.Errors)
	}
}

func TestValidateNormativeDocumentRejectsUnusableSchemaName(t *testing.T) {
	root := t.TempDir()
	cases := []any{"", "/", "schemas/", 42, nil, true, map[string]any{}, []any{}}
	for _, declared := range cases {
		document, err := json.Marshal(map[string]any{"$schema": declared, "conteudo": "qualquer coisa"})
		if err != nil {
			t.Fatalf("marshal document: %v", err)
		}
		writeFile(t, root, "evidencia.json", string(document))

		result := ValidateNormativeDocument("evidencia.json", root)
		if result.Valid {
			t.Errorf("$schema=%v accepted as valid", declared)
			continue
		}
		if !strings.Contains(strings.Join(result.Errors, "\n"), "não verificável") {
			t.Errorf("$schema=%v errors = %q", declared, result.Errors)
		}
	}
}

func TestValidateNormativeDocumentRejectsInheritedNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"constructor", "toString", "__proto__", "valueOf", "hasOwnProperty", "name"} {
		document, err := json.Marshal(map[string]any{"$schema": name, "conteudo": "qualquer coisa"})
		if err != nil {
			t.Fatalf("marshal document: %v", err)
		}
		writeFile(t, root, "evidencia.json", string(document))

		result := ValidateNormativeDocument("evidencia.json", root)
		if result.Valid {
			t.Errorf("$schema=%q accepted as a law", name)
		}
	}
}

func TestValidateWorkDocuments(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, filepath.Join(".pwn", "work", "0001", "plan.json"), validPlanJSON)
	writeFile(t, root, filepath.Join(".pwn", "work", "0001", "prd.json"), validPRDJSON)

	results := ValidateWorkDocuments("0001", root)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (prd and plan, evidence absent)", len(results))
	}
	wantFiles := []string{".pwn/work/0001/prd.json", ".pwn/work/0001/plan.json"}
	for index, result := range results {
		if result.File != wantFiles[index] {
			t.Errorf("result %d file = %q, want %q", index, result.File, wantFiles[index])
		}
		if !result.Valid {
			t.Errorf("%s rejected: %v", result.File, result.Errors)
		}
	}
}

func TestValidateWorkDocumentsReportsInvalidPRD(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, filepath.Join(".pwn", "work", "0001", "prd.json"), `{"id": "PRD-0001"}`)

	results := ValidateWorkDocuments("0001", root)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	result := results[0]
	if result.Valid {
		t.Fatal("prd.json without required fields reported as valid")
	}
	if !strings.Contains(strings.Join(result.Errors, "\n"), "must have required property") {
		t.Errorf("Errors = %q, want a required property message", result.Errors)
	}
}

func TestValidateWorkDocumentsReportsSyntaxError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, filepath.Join(".pwn", "work", "0001", "evidence.json"), "{")

	results := ValidateWorkDocuments("0001", root)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Valid || !strings.HasPrefix(results[0].Errors[0], "JSON Syntax Error: ") {
		t.Errorf("result = %+v, want a JSON Syntax Error", results[0])
	}
}

func TestValidateWorkDocumentsWithoutWorkDirectory(t *testing.T) {
	if results := ValidateWorkDocuments("9999", t.TempDir()); len(results) != 0 {
		t.Errorf("got %d results, want none", len(results))
	}
}

func TestValidateAllCoreNormatives(t *testing.T) {
	results := ValidateAllCoreNormatives(repositoryRoot)
	if len(results) != len(coreNormatives) {
		t.Fatalf("got %d results, want %d", len(results), len(coreNormatives))
	}
	for index, result := range results {
		if result.File != coreNormatives[index] {
			t.Errorf("result %d file = %q, want %q", index, result.File, coreNormatives[index])
		}
		if !result.Valid {
			t.Errorf("%s rejected: %v", result.File, result.Errors)
		}
	}
}
