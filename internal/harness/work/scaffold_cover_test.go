package work_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/work"
)

func TestScaffoldWorkSkeletonNamesComeFromTitleSlug(t *testing.T) {
	cases := []struct {
		title string
		slug  string
	}{
		{"Ação Rápida do Ñandú", "acao-rapida-do-nandu"},
		{"???????", "task"},
		{"Café   com    leite", "cafe-com-leite"},
		{"ÇÃO ÀÉÎÕÜ Ýz", "cao-aeiou-yz"},
		{"e\u0301tude spéciale", "etude-speciale"},
		{strings.Repeat("a", 60), strings.Repeat("a", 48)},
		{strings.Repeat("ab ", 20), strings.Repeat("ab-", 16)[:47]},
	}
	for _, test := range cases {
		t.Run(test.slug, func(t *testing.T) {
			root := t.TempDir()
			if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: test.title}); err != nil {
				t.Fatalf("ScaffoldWork: %v", err)
			}
			loaded := plan.LoadPlan("0001", root)
			if loaded == nil || len(loaded.Tasks) != 1 {
				t.Fatalf("plano = %+v", loaded)
			}
			task := loaded.Tasks[0]
			if len(task.ImplementationFiles) != 1 || task.ImplementationFiles[0] != "src/"+test.slug+".ts" {
				t.Fatalf("implementação = %v, quer src/%s.ts", task.ImplementationFiles, test.slug)
			}
			if len(task.TestFiles) != 1 || task.TestFiles[0] != "tests/"+test.slug+".test.ts" {
				t.Fatalf("testes = %v", task.TestFiles)
			}
		})
	}
}

func TestScaffoldWorkNarrativeOverridesDefaults(t *testing.T) {
	root := t.TempDir()
	_, err := work.ScaffoldWork(work.ScaffoldOptions{
		RootDir: root,
		Title:   "Narrativa própria",
		Narrative: &work.ScaffoldNarrative{
			Problem:   "Problema escrito pelo operador com mais de vinte caracteres",
			Solution:  "curta",
			Objective: "Objetivo explícito",
			Scenario:  "brownfield",
			Author:    "operador-teste",
		},
	})
	if err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	var discovery struct {
		Problem    string   `json:"problem"`
		Objectives []string `json:"objectives"`
	}
	if err := json.Unmarshal([]byte(readFile(t, root, ".pwn/work/0001/discovery.json")), &discovery); err != nil {
		t.Fatal(err)
	}
	if discovery.Problem != "Problema escrito pelo operador com mais de vinte caracteres" ||
		len(discovery.Objectives) != 1 || discovery.Objectives[0] != "Objetivo explícito" {
		t.Fatalf("discovery = %+v", discovery)
	}
	var prd struct {
		Scenario string `json:"scenario"`
		Meta     struct {
			Author string `json:"author"`
		} `json:"meta"`
		Solution struct {
			Statement string `json:"statement"`
		} `json:"solution"`
	}
	if err := json.Unmarshal([]byte(readFile(t, root, ".pwn/work/0001/prd.json")), &prd); err != nil {
		t.Fatal(err)
	}
	if prd.Scenario != "brownfield" || prd.Meta.Author != "operador-teste" {
		t.Fatalf("prd = %+v", prd)
	}
	// Solução com menos de 20 caracteres recebe o sufixo mínimo do schema.
	if prd.Solution.Statement != "curta (escopo mínimo)" {
		t.Fatalf("solution = %q", prd.Solution.Statement)
	}
}

func TestScaffoldWorkTruncatesLongPRDTitle(t *testing.T) {
	root := t.TempDir()
	title := strings.Repeat("ç", 120)
	if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: title}); err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	var prd struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal([]byte(readFile(t, root, ".pwn/work/0001/prd.json")), &prd); err != nil {
		t.Fatal(err)
	}
	if got := len([]rune(prd.Title)); got != 100 {
		t.Fatalf("título do PRD tem %d caracteres, quer 100", got)
	}
	if !strings.HasPrefix(prd.Title, "PRD — çç") {
		t.Fatalf("título do PRD = %q", prd.Title)
	}
}

func TestScaffoldWorkSourcePathVariants(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	absolute := filepath.Join(outside, "spec.md")
	if err := os.WriteFile(absolute, []byte("# Fonte absoluta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Fonte absoluta", SourcePath: absolute})
	if err != nil {
		t.Fatalf("fonte absoluta: %v", err)
	}
	if readFile(t, root, ".pwn/work/0001/legacy-spec.md") != "# Fonte absoluta\n" {
		t.Fatal("snapshot da fonte absoluta divergente")
	}
	var prd struct {
		Scenario string `json:"scenario"`
	}
	if err := json.Unmarshal([]byte(readFile(t, root, ".pwn/work/"+result.WorkID+"/prd.json")), &prd); err != nil {
		t.Fatal(err)
	}
	if prd.Scenario != "brownfield" {
		t.Fatalf("fonte legada deve gerar cenário brownfield, veio %q", prd.Scenario)
	}

	for name, source := range map[string]string{"ausente": "nao-existe.md", "diretório": "."} {
		if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: t.TempDir(), Title: "Fonte inválida", SourcePath: source}); err == nil ||
			!strings.Contains(err.Error(), "--source não encontrado") {
			t.Fatalf("fonte %s: erro = %v", name, err)
		}
	}
}

func TestScaffoldWorkExistingWorkPreservesFilesUnlessForced(t *testing.T) {
	root := t.TempDir()
	if _, err := work.InitWorkDirectory("0001", root); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, ".pwn/work/0001/discovery.json", `{"nota":"manual"}`)
	writeFile(t, root, ".todo/0001-tasks.md", "# manual\n")

	result, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Work preexistente", WorkID: "0001"})
	if err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	skipped := map[string]bool{}
	for _, entry := range result.Skipped {
		if !strings.Contains(entry.Reason, "já existe") {
			t.Fatalf("motivo = %q", entry.Reason)
		}
		skipped[entry.File] = true
	}
	if !skipped[".pwn/work/0001/discovery.json"] || !skipped[".todo/0001-tasks.md"] {
		t.Fatalf("skipped = %+v", result.Skipped)
	}
	if readFile(t, root, ".pwn/work/0001/discovery.json") != `{"nota":"manual"}` {
		t.Fatal("arquivo preexistente foi sobrescrito sem --force")
	}

	forced, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Work preexistente", WorkID: "0001", Force: true})
	if err != nil {
		t.Fatalf("ScaffoldWork --force: %v", err)
	}
	if len(forced.Skipped) != 0 {
		t.Fatalf("skipped com --force = %+v", forced.Skipped)
	}
	if strings.Contains(readFile(t, root, ".todo/0001-tasks.md"), "# manual") {
		t.Fatal("--force devia sobrescrever o markdown")
	}
}

func TestScaffoldWorkExplicitTasksUseScopeAndSkipSkeletonReview(t *testing.T) {
	root := t.TempDir()
	result, err := work.ScaffoldWork(work.ScaffoldOptions{
		RootDir: root,
		Title:   "Duas tasks explícitas",
		Risk:    contract.RiskL3,
		Tasks: []work.ScaffoldTaskSpec{
			{
				Title:               "Primeira",
				ImplementationFiles: []string{"src/a.ts"},
				TestFiles:           []string{"tests/a.test.ts"},
				Behavior:            "faz A",
				WriteAllow:          []string{"src/a.ts"},
			},
			{
				Title:               "Segunda",
				ImplementationFiles: []string{"src/b.ts"},
				TestFiles:           []string{"tests/b.test.ts"},
				WriteAllow:          []string{"src/b.ts"},
				WriteDeny:           []string{"secrets/**"},
			},
		},
	})
	if err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	for _, line := range result.Review {
		if strings.Contains(line, "esqueleto") || strings.Contains(line, "--freeze-tests") {
			t.Fatalf("tasks explícitas não pedem revisão de esqueleto: %v", result.Review)
		}
	}
	if len(result.Review) != 2 {
		t.Fatalf("review = %v", result.Review)
	}
	first, err := plan.LoadTaskContract("0001", "1.1", root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(first.ScopeContract.WriteDeny, ","); got != ".git/**,package.json,.env*" {
		t.Fatalf("write_deny padrão = %s", got)
	}
	second, err := plan.LoadTaskContract("0001", "1.2", root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(second.ScopeContract.WriteAllow, ","); got != "src/b.ts" {
		t.Fatalf("write_allow = %s", got)
	}
	if got := strings.Join(second.ScopeContract.WriteDeny, ","); got != "secrets/**" {
		t.Fatalf("write_deny explícito = %s", got)
	}
	loaded := plan.LoadPlan("0001", root)
	if loaded.Tasks[0].Behavior != "faz A" || !strings.Contains(loaded.Tasks[1].Behavior, "implementa \"Segunda\"") {
		t.Fatalf("behaviors = %q / %q", loaded.Tasks[0].Behavior, loaded.Tasks[1].Behavior)
	}
}

func TestScaffoldWorkDefaultTaskAtL3AddsFreezeInstruction(t *testing.T) {
	root := t.TempDir()
	result, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Congelar testes L3", Risk: contract.RiskL3})
	if err != nil {
		t.Fatalf("ScaffoldWork: %v", err)
	}
	joined := strings.Join(result.Review, "\n")
	if !strings.Contains(joined, "--freeze-tests tests/congelar-testes-l3.test.ts") {
		t.Fatalf("review sem instrução de congelar: %v", result.Review)
	}
	if !strings.Contains(joined, "Renomeie os arquivos esqueleto") {
		t.Fatalf("review sem aviso de esqueleto: %v", result.Review)
	}
}

func TestScaffoldWorkReportsFilesystemFailures(t *testing.T) {
	t.Run("raiz do Work inspecionável", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".pwn", "arquivo no lugar do diretório")
		_, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Falha de leitura", WorkID: "0001"})
		if err == nil || !strings.Contains(err.Error(), "inspecionar") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("diretório do markdown bloqueado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo", "arquivo no lugar do diretório")
		if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Falha de mkdir"}); err == nil {
			t.Fatal("markdown sob .todo-arquivo devia falhar")
		}
	})
	t.Run("destino é diretório", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".todo", "0001-tasks.md"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := work.ScaffoldWork(work.ScaffoldOptions{RootDir: root, Title: "Falha de rename", WorkID: "0001", Force: true}); err == nil {
			t.Fatal("renomear arquivo sobre diretório devia falhar")
		}
	})
}
