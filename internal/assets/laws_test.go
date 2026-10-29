package assets

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// referenceDigest is the value produced by lawsDigest() in
// src/core/validator.ts for the embedded laws.
const referenceDigest = "ab758ed1dc6a61b9"

func TestLawsDigestMatchesReference(t *testing.T) {
	if got := LawsDigest(); got != referenceDigest {
		t.Errorf("LawsDigest() = %q, want %q", got, referenceDigest)
	}
	if again := LawsDigest(); again != referenceDigest {
		t.Errorf("LawsDigest() is not stable: %q", again)
	}
}

func TestFindLawDriftOnRepository(t *testing.T) {
	if drifted := FindLawDrift(repositoryRoot); len(drifted) != 0 {
		t.Fatalf("FindLawDrift(%q) = %v, want none", repositoryRoot, drifted)
	}
	if err := AssertLawsPinned(repositoryRoot); err != nil {
		t.Fatalf("AssertLawsPinned(%q) = %v, want nil", repositoryRoot, err)
	}
}

func TestFindLawDriftWithoutSchemaDirectory(t *testing.T) {
	if drifted := FindLawDrift(t.TempDir()); len(drifted) != 0 {
		t.Errorf("FindLawDrift on empty dir = %v, want none", drifted)
	}
	if err := AssertLawsPinned(t.TempDir()); err != nil {
		t.Errorf("AssertLawsPinned on empty dir = %v, want nil", err)
	}
}

// writeDiskLaws copies every embedded law into root/schemas.
func writeDiskLaws(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "schemas")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir schemas: %v", err)
	}
	for _, name := range Names() {
		data, ok := Schema(name)
		if !ok {
			t.Fatalf("embedded law missing: %s", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestFindLawDriftIgnoresFormatting(t *testing.T) {
	root := t.TempDir()
	writeDiskLaws(t, root)

	path := filepath.Join(root, "schemas", "plan.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read plan schema: %v", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "\t", "    "); err != nil {
		t.Fatalf("indent plan schema: %v", err)
	}
	if err := os.WriteFile(path, indented.Bytes(), 0o644); err != nil {
		t.Fatalf("write indented plan schema: %v", err)
	}
	if drifted := FindLawDrift(root); len(drifted) != 0 {
		t.Errorf("formatting-only change reported as drift: %v", drifted)
	}
}

func TestFindLawDriftReportsContentChange(t *testing.T) {
	root := t.TempDir()
	writeDiskLaws(t, root)

	path := filepath.Join(root, "schemas", "plan.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read plan schema: %v", err)
	}
	tampered := bytes.Replace(raw, []byte("PWN Plan Schema"), []byte("PWN Plan Schema!"), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture did not change")
	}
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("write tampered schema: %v", err)
	}

	drifted := FindLawDrift(root)
	if len(drifted) != 1 || drifted[0] != "plan.schema.json" {
		t.Fatalf("FindLawDrift = %v, want [plan.schema.json]", drifted)
	}
	err = AssertLawsPinned(root)
	if err == nil {
		t.Fatal("AssertLawsPinned accepted drifted laws")
	}
	for _, want := range []string{"plan.schema.json", "leis embutidas divergem"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestFindLawDriftReportsMissingAndInvalidFiles(t *testing.T) {
	root := t.TempDir()
	writeDiskLaws(t, root)

	if err := os.Remove(filepath.Join(root, "schemas", "evidence.schema.json")); err != nil {
		t.Fatalf("remove evidence schema: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "schemas", "tasks.schema.json"), []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid schema: %v", err)
	}

	drifted := FindLawDrift(root)
	want := map[string]bool{
		"evidence.schema.json (ausente no disco)": true,
		"tasks.schema.json (JSON inválido)":       true,
	}
	if len(drifted) != len(want) {
		t.Fatalf("FindLawDrift = %v, want %v", drifted, want)
	}
	for _, entry := range drifted {
		if !want[entry] {
			t.Errorf("unexpected drift entry %q", entry)
		}
	}
}
