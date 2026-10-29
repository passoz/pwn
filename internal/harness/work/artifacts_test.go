package work_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/work"
)

func TestWorkIDNumberingSharesEveryTrack(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name   string
		setup  func()
		latest string
		next   string
	}{
		{name: "repositório vazio", setup: func() {}, latest: "0001", next: "0001"},
		{
			name:   "manifest v3 reserva o ID",
			setup:  func() { writeFile(t, root, ".work/0001.json", "{}") },
			latest: "0001", next: "0002",
		},
		{
			name: "diretório canônico não vazio reserva o ID",
			setup: func() {
				writeFile(t, root, ".pwn/work/0002/intake.json", "{}")
			},
			latest: "0002", next: "0003",
		},
		{
			name: "diretório canônico vazio não desloca a numeração",
			setup: func() {
				if err := os.MkdirAll(filepath.Join(root, ".pwn/work/0003"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			latest: "0002", next: "0003",
		},
		{
			name:   ".todo, .sources e .prompts contam",
			setup:  func() { writeFile(t, root, ".prompts/0004-change.md", "x") },
			latest: "0004", next: "0005",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			test.setup()
			if got := work.GetLatestWorkID(root); got != test.latest {
				t.Fatalf("GetLatestWorkID = %q, quer %q", got, test.latest)
			}
			if got := work.GetNextWorkID(root); got != test.next {
				t.Fatalf("GetNextWorkID = %q, quer %q", got, test.next)
			}
		})
	}
}

func TestGetExistingWorkIDsIgnoresEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".pwn/work/0001/intake.json", "{}")
	if err := os.MkdirAll(filepath.Join(root, ".pwn/work/0002"), 0o755); err != nil {
		t.Fatal(err)
	}
	ids := work.GetExistingWorkIDs(root)
	if len(ids) != 1 || ids[0] != "0001" {
		t.Fatalf("GetExistingWorkIDs = %v, quer [0001]", ids)
	}
	if got := work.GetExistingWorkIDs(filepath.Join(root, "ausente")); len(got) != 0 {
		t.Fatalf("raiz ausente devolveu %v", got)
	}
}

func TestInitWorkDirectoryCreatesTemplatesOnce(t *testing.T) {
	root := t.TempDir()
	paths, err := work.InitWorkDirectory("auto", root)
	if err != nil {
		t.Fatalf("InitWorkDirectory: %v", err)
	}
	if filepath.Base(paths.WorkDir) != "0001" {
		t.Fatalf("workID automático = %s, quer 0001", paths.WorkDir)
	}
	for _, file := range []string{paths.Intake, paths.Discovery, paths.Requirements, paths.PRD, paths.TraceabilityMatrix} {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("template ausente: %s", file)
		}
	}
	before, err := os.ReadFile(paths.Discovery)
	if err != nil {
		t.Fatal(err)
	}
	// A segunda chamada preserva o conteúdo já escrito.
	if _, err := work.InitWorkDirectory("0001", root); err != nil {
		t.Fatalf("segunda InitWorkDirectory: %v", err)
	}
	after, err := os.ReadFile(paths.Discovery)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("InitWorkDirectory sobrescreveu um template existente")
	}
	if _, err := work.InitWorkDirectory("0002", root); err != nil {
		t.Fatalf("InitWorkDirectory 0002: %v", err)
	}
	if got := work.GetNextWorkID(root); got != "0003" {
		t.Fatalf("próximo ID depois de 0002 = %s", got)
	}
}

func TestGetWorkArtifactsPaths(t *testing.T) {
	root := t.TempDir()
	paths := work.GetWorkArtifactsPaths("0007", root)
	want := filepath.Join(root, ".pwn", "work", "0007", "plan.json")
	if paths.Plan != want {
		t.Fatalf("plan = %q, quer %q", paths.Plan, want)
	}
	if !filepath.IsAbs(paths.PRD) {
		t.Fatalf("caminho relativo: %q", paths.PRD)
	}
}
