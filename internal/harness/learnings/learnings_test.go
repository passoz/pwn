package learnings_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/passoz/pwn/internal/harness/learnings"
)

var (
	idPattern        = regexp.MustCompile(`^LRN-\d+-[0-9a-f]{6}$`)
	timestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
)

func sample() learnings.NewEntry {
	return learnings.NewEntry{
		Category:    learnings.CategoryArchitecture,
		Title:       "Usar ES Modules (.js) no Node/Bun",
		Description: "Ao importar módulos locais em TypeScript/Bun compilados para ESM, usar extensões .js no import.",
		Tags:        []string{"esm", "typescript", "bun"},
	}
}

func TestAddAndRead(t *testing.T) {
	root := t.TempDir()

	added, err := learnings.Add(sample(), root)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !idPattern.MatchString(added.ID) {
		t.Fatalf("id = %q, quer LRN-<ms>-<6 hex>", added.ID)
	}
	if !timestampPattern.MatchString(added.Timestamp) {
		t.Fatalf("timestamp = %q, quer ISO com milissegundos", added.Timestamp)
	}
	if added.Category != learnings.CategoryArchitecture {
		t.Fatalf("categoria = %q", added.Category)
	}
	if len(added.Tags) != 3 || added.Tags[0] != "esm" {
		t.Fatalf("tags = %v", added.Tags)
	}

	file := filepath.Join(root, ".pwn", "learnings.json")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("learnings.json não criado: %v", err)
	}
	entries, err := learnings.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("lições = %d, quer 1", len(entries))
	}
	got := entries[0]
	if got.ID != added.ID || got.Timestamp != added.Timestamp {
		t.Fatalf("identificação divergente: %+v", got)
	}
	if got.Title != "Usar ES Modules (.js) no Node/Bun" {
		t.Fatalf("título = %q", got.Title)
	}
	if got.Description != added.Description {
		t.Fatalf("descrição = %q", got.Description)
	}
	if strings.Join(got.Tags, ",") != "esm,typescript,bun" {
		t.Fatalf("tags no disco = %v", got.Tags)
	}
}

func TestAddWritesStringifyShape(t *testing.T) {
	root := t.TempDir()
	added, err := learnings.Add(sample(), root)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".pwn", "learnings.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := `[
  {
    "id": "` + added.ID + `",
    "timestamp": "` + added.Timestamp + `",
    "category": "architecture",
    "title": "Usar ES Modules (.js) no Node/Bun",
    "description": "Ao importar módulos locais em TypeScript/Bun compilados para ESM, usar extensões .js no import.",
    "tags": [
      "esm",
      "typescript",
      "bun"
    ]
  }
]`
	if got := string(data); got != want {
		t.Fatalf("conteúdo divergente:\ngot  %q\nwant %q", got, want)
	}
}

func TestAddEmptyTagsAreArray(t *testing.T) {
	root := t.TempDir()
	added, err := learnings.Add(learnings.NewEntry{
		Category:    learnings.CategoryGotcha,
		Title:       "Sem tags",
		Description: "A lista de tags vazia continua sendo um array.",
	}, root)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if added.Tags == nil {
		t.Fatal("tags = nil, quer lista vazia")
	}
	data, err := os.ReadFile(filepath.Join(root, ".pwn", "learnings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tags": []`) {
		t.Fatalf("tags não serializadas como array vazio: %s", data)
	}
}

func TestAddSourceTaskID(t *testing.T) {
	root := t.TempDir()
	learning := sample()
	learning.SourceTaskID = "1.1"
	added, err := learnings.Add(learning, root)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if added.SourceTaskID != "1.1" {
		t.Fatalf("sourceTaskId = %q", added.SourceTaskID)
	}
	entries, err := learnings.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 1 || entries[0].SourceTaskID != "1.1" {
		t.Fatalf("lições no disco = %+v", entries)
	}
}

func TestReadMissingFile(t *testing.T) {
	entries, err := learnings.Read(t.TempDir())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("lições = %d, quer 0", len(entries))
	}
}

func TestReadCorruptFileReturnsError(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, ".pwn", "learnings.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := learnings.Read(root); err == nil {
		t.Fatal("JSON inválido deveria falhar")
	}
}

func TestAddDoesNotOverwriteCorruptFile(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, ".pwn", "learnings.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := learnings.Add(sample(), root); err == nil {
		t.Fatal("Add sobre arquivo corrompido deveria falhar")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{" {
		t.Fatalf("arquivo corrompido foi sobrescrito: %q", data)
	}
}

func TestAddConcurrentReadModifyWrite(t *testing.T) {
	root := t.TempDir()
	const writers = 10

	var wg sync.WaitGroup
	ids := make(chan string, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			learning := sample()
			learning.Title = "lição concorrente"
			added, err := learnings.Add(learning, root)
			if err != nil {
				t.Errorf("Add: %v", err)
				return
			}
			ids <- added.ID
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[string]struct{}, writers)
	for id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("id repetido: %s", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != writers {
		t.Fatalf("ids = %d, quer %d", len(seen), writers)
	}

	entries, err := learnings.Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != writers {
		t.Fatalf("lições = %d, quer %d", len(entries), writers)
	}
	for _, entry := range entries {
		if _, ok := seen[entry.ID]; !ok {
			t.Fatalf("id não retornado por Add: %s", entry.ID)
		}
	}

	// O arquivo final continua sendo JSON válido da lista completa.
	data, err := os.ReadFile(filepath.Join(root, ".pwn", "learnings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded []learnings.Entry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON final inválido: %v", err)
	}
	if len(decoded) != writers {
		t.Fatalf("JSON final tem %d itens, quer %d", len(decoded), writers)
	}
}
