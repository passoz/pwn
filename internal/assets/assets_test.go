package assets

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// repositoryRoot is the pwn repository root, two levels above the package.
const repositoryRoot = "../.."

func TestEmbeddedLawsMatchRepository(t *testing.T) {
	wantNames := []string{
		"evidence.schema.json",
		"pipeline.schema.json",
		"plan.schema.json",
		"policy.schema.json",
		"prd.schema.json",
		"system.schema.json",
		"tasks.schema.json",
	}
	if names := Names(); !slices.Equal(names, wantNames) {
		t.Fatalf("Names() = %v, want %v", names, wantNames)
	}

	for _, name := range Names() {
		embedded, ok := Schema(name)
		if !ok {
			t.Fatalf("Schema(%q) not found", name)
		}
		onDisk, err := os.ReadFile(filepath.Join(repositoryRoot, "schemas", name))
		if err != nil {
			t.Fatalf("read repository law %s: %v", name, err)
		}
		if !bytes.Equal(embedded, onDisk) {
			t.Errorf("embedded copy of %s differs from schemas/%s", name, name)
		}
	}

	diskVersion, err := os.ReadFile(filepath.Join(repositoryRoot, "VERSION"))
	if err != nil {
		t.Fatalf("read repository VERSION: %v", err)
	}
	if !bytes.Equal(VersionBytes(), diskVersion) {
		t.Errorf("embedded VERSION %q differs from repository VERSION %q", VersionBytes(), diskVersion)
	}
}

func TestVersion(t *testing.T) {
	if got := Version(); got != "0.1.0" {
		t.Errorf("Version() = %q, want %q", got, "0.1.0")
	}
	if bytes.HasSuffix(VersionBytes(), []byte(" ")) {
		t.Errorf("VersionBytes() = %q should keep the file content", VersionBytes())
	}
}

func TestSchemaRejectsUnknownNames(t *testing.T) {
	for _, name := range []string{"", "plan.json", "Plan.schema.json", "../schemas/plan.schema.json", "constructor"} {
		if data, ok := Schema(name); ok || data != nil {
			t.Errorf("Schema(%q) = %v, %v; want not found", name, data, ok)
		}
	}
}

func TestSchemaReturnsIndependentCopies(t *testing.T) {
	first, ok := Schema("plan.schema.json")
	if !ok {
		t.Fatal("plan.schema.json not embedded")
	}
	first[0] = 'X'
	second, ok := Schema("plan.schema.json")
	if !ok {
		t.Fatal("plan.schema.json not embedded")
	}
	if second[0] != '{' {
		t.Errorf("Schema returned shared memory; first byte = %q", second[0])
	}
}

func TestNamesReturnsIndependentCopies(t *testing.T) {
	names := Names()
	names[0] = "mutated"
	if Names()[0] == "mutated" {
		t.Error("Names returned shared memory")
	}
}
