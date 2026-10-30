package learnings_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/learnings"
)

func TestFileEmptyRootUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	got, err := learnings.File("")
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	// Compara pelo arquivo real: o TempDir pode ser um symlink.
	want := filepath.Join(root, ".pwn", "learnings.json")
	gi, err1 := os.Stat(filepath.Dir(got))
	wi, err2 := os.Stat(filepath.Dir(want))
	if err1 != nil || err2 != nil || !os.SameFile(gi, wi) {
		t.Fatalf("File = %q, queria diretório de %q", got, want)
	}
	if filepath.Base(got) != "learnings.json" {
		t.Fatalf("nome = %q", filepath.Base(got))
	}
}

func TestFileRelativeRootIsResolved(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	got, err := learnings.File("sub")
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("caminho deveria ser absoluto: %q", got)
	}
	if _, err := os.Stat(filepath.Join(base, "sub", ".pwn")); err != nil {
		t.Fatalf(".pwn não criado: %v", err)
	}
}

func TestFileFailsWhenPwnIsRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".pwn"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := learnings.File(root); err == nil {
		t.Error("File: esperava erro")
	}
	if _, err := learnings.Read(root); err == nil {
		t.Error("Read: esperava erro")
	}
	if _, err := learnings.Add(sample(), root); err == nil {
		t.Error("Add: esperava erro")
	}
}

func writeLearnings(t *testing.T, root, content string) {
	t.Helper()
	dir := filepath.Join(root, ".pwn")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "learnings.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadNullAndEmptyListGiveEmptySlice(t *testing.T) {
	for _, content := range []string{"null", "[]"} {
		root := t.TempDir()
		writeLearnings(t, root, content)
		got, err := learnings.Read(root)
		if err != nil {
			t.Fatalf("%s: %v", content, err)
		}
		if got == nil || len(got) != 0 {
			t.Errorf("%s: got %#v, queria slice vazio não nulo", content, got)
		}
	}
}

func TestReadNormalizesNullTags(t *testing.T) {
	root := t.TempDir()
	writeLearnings(t, root, `[{"id":"LRN-1-aaaaaa","timestamp":"t","category":"gotcha","title":"a","description":"b","tags":null},{"id":"LRN-2-bbbbbb","timestamp":"t","category":"gotcha","title":"c","description":"d"}]`)
	got, err := learnings.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	for i, e := range got {
		if e.Tags == nil || len(e.Tags) != 0 {
			t.Errorf("entrada %d: tags = %#v, queria []", i, e.Tags)
		}
	}
	// Uma escrita posterior mantém "tags": [] nas entradas antigas.
	if _, err := learnings.Add(sample(), root); err != nil {
		t.Fatalf("Add: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".pwn", "learnings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"tags": null`) {
		t.Errorf("arquivo ainda contém tags nulas:\n%s", data)
	}
}

func TestReadFailsWhenFileIsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".pwn", "learnings.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := learnings.Read(root); err == nil {
		t.Error("Read: esperava erro de leitura")
	}
	if _, err := learnings.Add(sample(), root); err == nil {
		t.Error("Add: esperava erro")
	}
}

func TestAddWithEmptyRootUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if _, err := learnings.Add(sample(), ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := learnings.Read(root)
	if err != nil || len(got) != 1 {
		t.Fatalf("Read = %v, %v", got, err)
	}
}
