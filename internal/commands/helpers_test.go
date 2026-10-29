package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFlagValue(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "ausente", args: []string{"validate"}, want: ""},
		{name: "valor presente", args: []string{"--work", "0001"}, want: "0001"},
		{name: "valor vazio", args: []string{"--work", ""}, want: ""},
		{name: "seguido de flag", args: []string{"--work", "--mutate"}, want: ""},
		{name: "sem valor", args: []string{"--work"}, want: ""},
		{name: "primeira ocorrência", args: []string{"--work", "0001", "--work", "0002"}, want: "0001"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := flagValue(test.args, "--work"); got != test.want {
				t.Fatalf("flagValue(%v) = %q, quer %q", test.args, got, test.want)
			}
		})
	}
}

func TestExistingWorkIDs(t *testing.T) {
	root := t.TempDir()

	ids, err := existingWorkIDs(root)
	if err != nil {
		t.Fatalf("diretório ausente: erro = %v, quer nil", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ids = %v, quer vazio", ids)
	}

	writeTestFile(t, filepath.Join(root, ".pwn", "work", "0001", "prd.json"), "{}")
	if err := os.MkdirAll(filepath.Join(root, ".pwn", "work", "0002"), 0o755); err != nil {
		t.Fatalf("criar Work vazio: %v", err)
	}
	writeTestFile(t, filepath.Join(root, ".pwn", "work", "nota.txt"), "nota")

	ids, err = existingWorkIDs(root)
	if err != nil {
		t.Fatalf("erro = %v, quer nil", err)
	}
	if len(ids) != 1 || ids[0] != "0001" {
		t.Fatalf("ids = %v, quer [0001]", ids)
	}
}

func TestLatestWorkID(t *testing.T) {
	t.Run("sem artefatos", func(t *testing.T) {
		id, err := latestWorkID(t.TempDir())
		if err != nil {
			t.Fatalf("erro = %v, quer nil", err)
		}
		if id != "0001" {
			t.Fatalf("id = %q, quer 0001", id)
		}
	})

	t.Run("maior número entre trilhas", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, ".work", "0007.json"), "{}")
		writeTestFile(t, filepath.Join(root, ".todo", "0012-tasks.md"), "# plano")
		writeTestFile(t, filepath.Join(root, ".pwn", "work", "0005", "prd.json"), "{}")
		// Diretório vazio não entra no espaço de IDs.
		if err := os.MkdirAll(filepath.Join(root, ".pwn", "work", "0099"), 0o755); err != nil {
			t.Fatalf("criar Work vazio: %v", err)
		}

		id, err := latestWorkID(root)
		if err != nil {
			t.Fatalf("erro = %v, quer nil", err)
		}
		if id != "0012" {
			t.Fatalf("id = %q, quer 0012", id)
		}
	})
}

func TestUpper(t *testing.T) {
	if got := upper("opencode"); got != "OPENCODE" {
		t.Fatalf("upper = %q", got)
	}
	if got := upper("Pi"); got != "PI" {
		t.Fatalf("upper = %q", got)
	}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("criar diretório: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("escrever %s: %v", path, err)
	}
}
