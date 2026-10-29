package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// objectKeys devolve as chaves do objeto JSON na ordem do arquivo.
func objectKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, token.(string))
		var skipped json.RawMessage
		if err := decoder.Decode(&skipped); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// A referência grava os instantâneos e audit_checks em ordem de inserção
// (Object.fromEntries da lista de arquivos, atribuição em ordem de execução).
func TestSaveStateKeepsInsertionOrder(t *testing.T) {
	paths := workPaths{stateDir: t.TempDir()}
	sum := "abc"
	digest := FileDigest{Exists: true, SHA256: &sum}
	state := &State{
		Task:                   "1.1",
		ImplementationFiles:    []string{"z/impl.go", "a/impl.go"},
		TestFiles:              []string{"t/users_test.go", "t/acceptance_test.go"},
		BaselineImplementation: Snapshot{"z/impl.go": digest, "a/impl.go": digest},
		BaselineTests:          Snapshot{"t/users_test.go": digest, "t/acceptance_test.go": digest},
		AuditChecks: map[string]AuditCheckRecord{
			"REGRESSION": {Verdict: "pass"},
			"AC-1":       {Verdict: "pass"},
		},
		AuditCheckOrder: []string{"REGRESSION", "AC-1"},
	}
	if err := saveState(paths, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(statePath(paths, "1.1"))
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"baseline_implementation": "z/impl.go,a/impl.go",
		"baseline_tests":          "t/users_test.go,t/acceptance_test.go",
		"audit_checks":            "REGRESSION,AC-1",
	} {
		if got := strings.Join(objectKeys(t, document[field]), ","); got != want {
			t.Errorf("%s: ordem = %s, quer %s", field, got, want)
		}
	}

	reloaded, reason := tryLoadState(paths, "1.1")
	if reloaded == nil {
		t.Fatalf("estado não recarregou: %s", reason)
	}
	if got := strings.Join(reloaded.AuditCheckOrder, ","); got != "REGRESSION,AC-1" {
		t.Errorf("ordem recarregada de audit_checks = %s", got)
	}
}
