package work_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/cryptox"
)

// statusRootPlan grava um plano válido de uma task em .todo/0001-tasks.md.
func statusRootPlan(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	content := statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001")
	return root, writeStatusFixture(t, root, content)
}

func TestEvidenceWithoutWorkIDCannotBeAccepted(t *testing.T) {
	root := t.TempDir()
	content := statusPlanMarkdown([]string{statusTaskBlock("1.1", "x", "FR-001", "none", "Criar conta")},
		"- [ ] `bun test` — suíte completa.", "0001")
	content = strings.Replace(content, "**Work ID:** 0001\n", "", 1)
	tasksPath := writeStatusFixture(t, root, content)

	report := collectWithNeutralVerifier(t, tasksPath)
	if report.WorkID != nil {
		t.Fatalf("WorkID = %v", *report.WorkID)
	}
	if len(report.Tasks) != 1 || report.Tasks[0].Evidence.Stage != "not started" ||
		!strings.Contains(report.Tasks[0].Evidence.Attestation, "plano sem Work ID") {
		t.Fatalf("evidência = %+v", report.Tasks)
	}
	// Plano v3 sem Work ID é estruturalmente inválido, e o panorama reflete isso.
	if report.Panorama.State != work.PanoramaInvalidPlan || len(report.ValidationErrors) == 0 {
		t.Fatalf("panorama = %s errors=%v", report.Panorama.State, report.ValidationErrors)
	}
	if report.GlobalGates.State != "PENDING" || !strings.Contains(report.GlobalGates.Detail, "G-1: plano sem Work ID") {
		t.Fatalf("gates = %+v", report.GlobalGates)
	}
}

func TestEvidenceStateFileProblemsAreStale(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  string
	}{
		{
			name: "JSON inválido",
			setup: func(t *testing.T, root string) {
				evidenceStateJSON(t, root, "1.1", "{ quebrado")
			},
			want: "invalid evidence: ",
		},
		{
			name: "estado é diretório",
			setup: func(t *testing.T, root string) {
				if err := os.MkdirAll(filepath.Join(root, ".todo", "evidence", "0001", "state", "1.1.json"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "invalid evidence: ",
		},
		{
			name: "caminho do snapshot bloqueado",
			setup: func(t *testing.T, root string) {
				writeFile(t, root, "arquivo", "x\n")
				evidenceStateJSON(t, root, "1.1",
					`{"baseline_implementation":{"arquivo/dentro.ts":{"exists":true,"sha256":"aa"}},"baseline_tests":{},"red_tests":null}`)
			},
			want: "invalid evidence: work: ler estado de",
		},
		{
			name: "testes de baseline bloqueados",
			setup: func(t *testing.T, root string) {
				writeFile(t, root, "arquivo", "x\n")
				evidenceStateJSON(t, root, "1.1",
					`{"baseline_implementation":{},"baseline_tests":{"arquivo/dentro.test.ts":{"exists":true,"sha256":"aa"}},"red_tests":null}`)
			},
			want: "invalid evidence: work: ler estado de",
		},
		{
			name: "snapshot RED bloqueado",
			setup: func(t *testing.T, root string) {
				writeFile(t, root, "arquivo", "x\n")
				evidenceStateJSON(t, root, "1.1",
					`{"baseline_implementation":{},"baseline_tests":{},"red_tests":{"arquivo/dentro.test.ts":{"exists":true,"sha256":"aa"}}}`)
			},
			want: "invalid evidence: work: ler estado de",
		},
		{
			name: "implementação GREEN bloqueada",
			setup: func(t *testing.T, root string) {
				writeFile(t, root, "arquivo", "x\n")
				evidenceStateJSON(t, root, "1.1",
					`{"baseline_implementation":{},"baseline_tests":{},"red_tests":{},`+
						`"green_implementation":{"arquivo/dentro.ts":{"exists":true,"sha256":"aa"}},"green_tests":{}}`)
			},
			want: "invalid evidence: work: ler estado de",
		},
		{
			name: "testes GREEN bloqueados",
			setup: func(t *testing.T, root string) {
				writeFile(t, root, "arquivo", "x\n")
				evidenceStateJSON(t, root, "1.1",
					`{"baseline_implementation":{},"baseline_tests":{},"red_tests":{},`+
						`"green_implementation":{},"green_tests":{"arquivo/dentro.test.ts":{"exists":true,"sha256":"aa"}}}`)
			},
			want: "invalid evidence: work: ler estado de",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root, tasksPath := statusRootPlan(t)
			test.setup(t, root)
			report := collectWithNeutralVerifier(t, tasksPath)
			evidence := report.Tasks[0].Evidence
			if !strings.HasPrefix(evidence.Stage, test.want) || !evidence.Stale {
				t.Fatalf("evidência = %+v, quer estágio com prefixo %q e Stale", evidence, test.want)
			}
			if report.Panorama.State != work.PanoramaStaleEvidence {
				t.Fatalf("panorama = %s", report.Panorama.State)
			}
		})
	}
}

func TestEvidenceStagesFollowSnapshots(t *testing.T) {
	original := cryptox.SHA256HexText("original\n")

	t.Run("BASELINE atual", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, "src/a.ts", "original\n")
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{"src/a.ts":{"exists":true,"sha256":"`+original+`"},"src/ausente.ts":{"exists":false,"sha256":null}},"baseline_tests":{},"red_tests":null}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "BASELINE" || evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("BASELINE com implementação alterada", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, "src/a.ts", "alterado\n")
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{"src/a.ts":{"exists":true,"sha256":"`+original+`"}},"baseline_tests":{},"red_tests":null}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "BASELINE" || !evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("BASELINE com teste criado depois", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, "tests/a.test.ts", "novo\n")
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{},"baseline_tests":{"tests/a.test.ts":{"exists":false,"sha256":null}},"red_tests":null}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "BASELINE" || !evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("RED atual e RED alterado", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, "tests/a.test.ts", "original\n")
		body := `{"baseline_implementation":{},"baseline_tests":{},"red_tests":{"tests/a.test.ts":{"exists":true,"sha256":"` + original + `"}}}`
		evidenceStateJSON(t, root, "1.1", body)
		fresh := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if fresh.Stage != "RED" || fresh.Stale {
			t.Fatalf("RED = %+v", fresh)
		}
		writeFile(t, root, "tests/a.test.ts", "mudou\n")
		stale := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if stale.Stage != "RED" || !stale.Stale {
			t.Fatalf("RED alterado = %+v", stale)
		}
	})

	t.Run("GREEN sem log de verificação", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{},"baseline_tests":{},"red_tests":{},"green_implementation":{},"green_tests":{}}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "GREEN" || evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("GREEN com log sem veredito PASS", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{},"baseline_tests":{},"red_tests":{},"green_implementation":{},"green_tests":{}}`)
		writeFile(t, root, ".todo/evidence/0001/1.1-verify.log", "VERDICT: FAIL\n")
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "GREEN" {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("VERIFIED sem recibo aceito explica a atestação", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{},"baseline_tests":{},"red_tests":{},"green_implementation":{},"green_tests":{}}`)
		writeFile(t, root, ".todo/evidence/0001/1.1-verify.log", "saída\nVERDICT: PASS\n")
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "VERIFIED" || evidence.Stale || evidence.Attestation == "" {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("diretório no snapshot conta como arquivo inexistente", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		if err := os.MkdirAll(filepath.Join(root, "src", "pasta"), 0o755); err != nil {
			t.Fatal(err)
		}
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{"src/pasta":{"exists":false,"sha256":null}},"baseline_tests":{},"red_tests":null}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "BASELINE" || evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("snapshot com digest ausente diverge de arquivo existente", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, "src/a.ts", "original\n")
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{"src/a.ts":{"exists":true,"sha256":null}},"baseline_tests":{},"red_tests":null}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if !evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})

	t.Run("caminho absoluto no snapshot", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, "src/a.ts", "original\n")
		absolute := filepath.Join(root, "src", "a.ts")
		evidenceStateJSON(t, root, "1.1",
			`{"baseline_implementation":{"`+absolute+`":{"exists":true,"sha256":"`+original+`"}},"baseline_tests":{},"red_tests":null}`)
		evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
		if evidence.Stage != "BASELINE" || evidence.Stale {
			t.Fatalf("evidência = %+v", evidence)
		}
	})
}

func TestEvidenceUnreadableSnapshotFileIsInvalid(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê qualquer arquivo")
	}
	root, tasksPath := statusRootPlan(t)
	secret := filepath.Join(root, "src", "fechado.ts")
	writeFile(t, root, "src/fechado.ts", "x\n")
	if err := os.Chmod(secret, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o644) })
	evidenceStateJSON(t, root, "1.1",
		`{"baseline_implementation":{"src/fechado.ts":{"exists":true,"sha256":"aa"}},"baseline_tests":{},"red_tests":null}`)
	evidence := collectWithNeutralVerifier(t, tasksPath).Tasks[0].Evidence
	if !strings.HasPrefix(evidence.Stage, "invalid evidence: work: ler ") || !evidence.Stale {
		t.Fatalf("evidência = %+v", evidence)
	}
}

func TestArtifactStatusReadsSystemSpecAndLatestPrompt(t *testing.T) {
	root, tasksPath := statusRootPlan(t)
	writeFile(t, root, ".specs/system.md", "# Sistema\n\n**Status:** approved\n**Versão:** 2.1\n")
	writeFile(t, root, ".prompts/0001-change.md", "**Status:** draft\n")
	writeFile(t, root, ".prompts/nested/0002-change.md", "# sem campo de status\n")
	writeFile(t, root, ".prompts/notes.txt", "não é markdown\n")
	older := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	if err := os.Chtimes(filepath.Join(root, ".prompts", "0001-change.md"), older, older); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(root, ".prompts", "nested", "0002-change.md"), newer, newer); err != nil {
		t.Fatal(err)
	}

	report := collectWithNeutralVerifier(t, tasksPath)
	spec := report.Artifacts.SystemSpec
	if spec.Path != ".specs/system.md" || spec.State != "present" || spec.Detail != "approved; version 2.1" {
		t.Fatalf("system spec = %+v", spec)
	}
	prompt := report.Artifacts.Prompt
	if prompt.Path != ".prompts/nested/0002-change.md" || prompt.State != "present" || prompt.Detail != "status unknown" {
		t.Fatalf("prompt = %+v", prompt)
	}
	if report.Artifacts.Tasks.State != "valid" || !strings.Contains(report.Artifacts.Tasks.Detail, "structural validation PASS; contract v3") {
		t.Fatalf("tasks = %+v", report.Artifacts.Tasks)
	}
}

func TestArtifactStatusSystemSpecWithoutFields(t *testing.T) {
	root, tasksPath := statusRootPlan(t)
	writeFile(t, root, ".specs/system.md", "# Sistema sem campos\n")
	report := collectWithNeutralVerifier(t, tasksPath)
	if report.Artifacts.SystemSpec.Detail != "status unknown; version version unknown" {
		t.Fatalf("detail = %q", report.Artifacts.SystemSpec.Detail)
	}
	if report.Artifacts.Prompt.State != "absent" || report.Artifacts.Prompt.Detail != "run /make-prompt" {
		t.Fatalf("prompt = %+v", report.Artifacts.Prompt)
	}
}

func TestArtifactStatusPromptTieBreaksByPath(t *testing.T) {
	root, tasksPath := statusRootPlan(t)
	stamp := time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"b.md", "a.md"} {
		writeFile(t, root, ".prompts/"+name, "**Status:** "+name+"\n")
		if err := os.Chtimes(filepath.Join(root, ".prompts", name), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	report := collectWithNeutralVerifier(t, tasksPath)
	if report.Artifacts.Prompt.Path != ".prompts/a.md" || report.Artifacts.Prompt.Detail != "a.md" {
		t.Fatalf("prompt = %+v", report.Artifacts.Prompt)
	}
}

func TestCollectProjectStatusReportsUnreadableArtifactTrees(t *testing.T) {
	neutralVerifier(t)
	t.Run("system spec ilegível", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, ".specs", "arquivo no lugar do diretório")
		if _, err := work.CollectProjectStatus(tasksPath); err == nil || !strings.Contains(err.Error(), "system spec") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("diretório de prompts ilegível", func(t *testing.T) {
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, ".prompts", "arquivo no lugar do diretório")
		if _, err := work.CollectProjectStatus(tasksPath); err == nil || !strings.Contains(err.Error(), ".prompts") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("subdiretório de prompts ilegível", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lê qualquer diretório")
		}
		root, tasksPath := statusRootPlan(t)
		writeFile(t, root, ".prompts/fechado/a.md", "x\n")
		closed := filepath.Join(root, ".prompts", "fechado")
		if err := os.Chmod(closed, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })
		if _, err := work.CollectProjectStatus(tasksPath); err == nil || !strings.Contains(err.Error(), "fechado") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("plano ilegível", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lê qualquer arquivo")
		}
		_, tasksPath := statusRootPlan(t)
		if err := os.Chmod(tasksPath, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(tasksPath, 0o644) })
		if _, err := work.CollectProjectStatus(tasksPath); err == nil || !strings.Contains(err.Error(), "ler plano") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestCollectProjectStatusMissingPlanHasNoTasks(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	report, err := work.CollectProjectStatus(filepath.Join(root, ".todo", "0001-tasks.md"))
	if err != nil {
		t.Fatalf("CollectProjectStatus: %v", err)
	}
	if report.Panorama.State != work.PanoramaNoTasks || report.Panorama.StoppedAt != "No canonical tasks found" {
		t.Fatalf("panorama = %+v", report.Panorama)
	}
	if report.Artifacts.Tasks.State != "absent" || report.Artifacts.Tasks.Detail != "run /make-todo" {
		t.Fatalf("tasks = %+v", report.Artifacts.Tasks)
	}
	if report.ContractVersionSource != "absent" || report.ContractVersion != nil {
		t.Fatalf("contrato = %v/%q", report.ContractVersion, report.ContractVersionSource)
	}
	if report.GlobalGates.State != "MISSING" || report.GlobalGates.Detail != "missing" {
		t.Fatalf("gates = %+v", report.GlobalGates)
	}
	if report.ValidationErrors == nil || report.ValidationWarnings == nil || report.ValidationExceptions == nil {
		t.Fatalf("listas de validação não podem ser nil: %+v", report)
	}
	rendered := work.RenderMarkdown(work.PlanStatus{ProjectStatus: report})
	if !strings.Contains(rendered, "| — | — | — | — | — | No tasks found |") {
		t.Fatalf("markdown sem linha de plano vazio:\n%s", rendered)
	}
}

func TestGlobalGatesUntrackedAndTerminatedSections(t *testing.T) {
	root := t.TempDir()
	untracked := statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")},
		"Rodar a suíte completa antes de aceitar.", "0001")
	report := collectWithNeutralVerifier(t, writeStatusFixture(t, root, untracked))
	if report.GlobalGates.State != "UNTRACKED" || report.GlobalGates.Detail != "declared; no tracked checkbox state" {
		t.Fatalf("gates = %+v", report.GlobalGates)
	}

	missing := t.TempDir()
	noSection := strings.Replace(untracked, "## Global gates", "## Outra seção", 1)
	reportMissing := collectWithNeutralVerifier(t, writeStatusFixture(t, missing, noSection))
	if reportMissing.GlobalGates.State != "MISSING" {
		t.Fatalf("gates = %+v", reportMissing.GlobalGates)
	}

	// Gates seguidos de outra seção `##` terminam no limite da seção.
	bounded := t.TempDir()
	content := strings.Replace(untracked, "Rodar a suíte completa antes de aceitar.", "N/A\n\n## Notas\n\n- [ ] item fora dos gates", 1)
	reportBounded := collectWithNeutralVerifier(t, writeStatusFixture(t, bounded, content))
	if reportBounded.GlobalGates.State != "N/A" {
		t.Fatalf("gates = %+v", reportBounded.GlobalGates)
	}
}

func TestCollectProjectStatusDetectsCanonicalPlanDrift(t *testing.T) {
	root, verifierRoot := statusVerifierFixture(t, []statusSpec{defaultStatusSpec()}, nil)
	_ = verifierRoot
	tasksPath := filepath.Join(root, ".todo", "0001-tasks.md")
	clean, err := work.CollectProjectStatus(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.ValidationErrors) != 0 {
		t.Fatalf("plano consistente não pode ter erros: %v", clean.ValidationErrors)
	}

	edited := readFile(t, root, ".todo/0001-tasks.md")
	writeFile(t, root, ".todo/0001-tasks.md", strings.Replace(edited, "Create account", "Create account (editado à mão)", 1))
	drifted, err := work.CollectProjectStatus(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range drifted.ValidationErrors {
		if strings.HasPrefix(message, "DRIFT: ") && strings.Contains(message, ".pwn/work/0001/plan.json") {
			found = true
		}
	}
	if !found || drifted.Panorama.State != work.PanoramaInvalidPlan {
		t.Fatalf("drift não detectado: %v (%s)", drifted.ValidationErrors, drifted.Panorama.State)
	}

	writeFile(t, root, ".pwn/work/0001/plan.json", "{ quebrado")
	unreadable, err := work.CollectProjectStatus(tasksPath)
	if err != nil {
		t.Fatal(err)
	}
	foundUnreadable := false
	for _, message := range unreadable.ValidationErrors {
		if strings.HasPrefix(message, "DRIFT: ") {
			foundUnreadable = true
		}
	}
	if !foundUnreadable {
		t.Fatalf("plano canônico ilegível devia ser DRIFT: %v", unreadable.ValidationErrors)
	}
}

func TestCollectWorkIndexEntries(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	// 0001: Work com plano e panorama.
	writeFile(t, root, ".work/0001.json", manifestJSON("0001", "planned", ".todo/0001-tasks.md"))
	writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001"))
	// 0002: manifest sem plano em disco.
	writeFile(t, root, ".work/0002.json", manifestJSON("0002", "planned", ".todo/0002-tasks.md"))
	// 0003: manifest ilegível.
	writeFile(t, root, ".work/0003.json", "{ quebrado")

	report, err := work.CollectWorkIndex(root)
	if err != nil {
		t.Fatalf("CollectWorkIndex: %v", err)
	}
	byID := map[string]work.WorkIndexEntry{}
	for _, entry := range report.Works {
		byID[entry.WorkID] = entry
	}
	if len(report.Works) != 3 {
		t.Fatalf("works = %+v", report.Works)
	}
	first := byID["0001"]
	if first.Panorama == nil || first.Panorama.State != work.PanoramaNotStarted || first.GlobalGates == nil ||
		first.GlobalGates.State != "N/A" || first.ContractVersion == nil || *first.ContractVersion != 3 {
		t.Fatalf("0001 = %+v", first)
	}
	if second := byID["0002"]; second.Panorama != nil || second.PlanExists || second.Plan != ".todo/0002-tasks.md" {
		t.Fatalf("0002 = %+v", second)
	}
	if third := byID["0003"]; third.State != "invalid" || third.Error == "" || third.Panorama != nil {
		t.Fatalf("0003 = %+v", third)
	}

	rendered := work.RenderWorkIndex(report)
	for _, want := range []string{
		"# Work index",
		"| `0001` | planned | `.todo/0001-tasks.md` | 0/1 | NOT STARTED |",
		"| `0002` | planned | `.todo/0002-tasks.md` | — | no plan |",
		"| `0003` | invalid | `—` | — | ",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("índice sem %q:\n%s", want, rendered)
		}
	}
}

func TestCollectWorkIndexEmptyRootUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	report, err := work.CollectWorkIndex("")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Works) != 0 {
		t.Fatalf("works = %+v", report.Works)
	}
}

func TestRenderWorkIndexEscapesPipes(t *testing.T) {
	rendered := work.RenderWorkIndex(work.WorkIndexReport{Works: []work.WorkIndexEntry{
		{WorkID: "0001", State: "invalid", Error: "falha | com\nquebra"},
	}})
	if !strings.Contains(rendered, `| `+"`0001`"+` | invalid | `+"`—`"+` | — | falha \| com quebra |`) {
		t.Fatalf("índice:\n%s", rendered)
	}
}

func TestCollectPlanStatusTargets(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
	if _, err := work.CollectPlanStatus("", root); err == nil {
		t.Fatal("alvo vazio devia falhar")
	}
	if _, err := work.CollectPlanStatus("0042", root); err == nil || !strings.Contains(err.Error(), "plan not found") {
		t.Fatalf("plano ausente: %v", err)
	}
	legacy, err := work.CollectPlanStatus("legacy", root)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if legacy.WorkID != nil || len(legacy.CrossWorkBlockers) != 0 || legacy.CrossWorkBlockers == nil {
		t.Fatalf("legacy = %+v", legacy)
	}
}

func TestCollectPlanStatusEmptyRootUsesWorkingDirectory(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001"))
	t.Chdir(root)
	report, err := work.CollectPlanStatus("0001", "")
	if err != nil {
		t.Fatalf("CollectPlanStatus: %v", err)
	}
	if report.Panorama.Counts.Total != 1 {
		t.Fatalf("panorama = %+v", report.Panorama)
	}
}

func TestCollectPlanStatusCrossWorkBlockers(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	dependsOn := "0002/1.1, 0003/9.9, 0004/1.1, 0001/1.1, nao-e-referencia, 0005/1.1,,"
	writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", dependsOn, "Criar conta")}, "N/A", "0001"))
	// 0002: plano existe mas a task não está aceita.
	writeFile(t, root, ".work/0002.json", manifestJSON("0002", "planned", ".todo/0002-tasks.md"))
	writeFile(t, root, ".todo/0002-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Dependência")}, "N/A", "0002"))
	// 0003: plano sem a task dependida.
	writeFile(t, root, ".work/0003.json", manifestJSON("0003", "planned", ".todo/0003-tasks.md"))
	writeFile(t, root, ".todo/0003-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Outra")}, "N/A", "0003"))
	// 0004: manifest ilegível. 0005: sem manifest.
	writeFile(t, root, ".work/0004.json", "{ quebrado")

	report, err := work.CollectPlanStatus("0001", root)
	if err != nil {
		t.Fatalf("CollectPlanStatus: %v", err)
	}
	blockers := report.CrossWorkBlockers["1.1"]
	want := []string{"0002/1.1", "0003/9.9", "0004/1.1", "0005/1.1"}
	if strings.Join(blockers, ",") != strings.Join(want, ",") {
		t.Fatalf("bloqueios = %v, quer %v", blockers, want)
	}

	rendered := work.RenderMarkdown(report)
	if !strings.Contains(rendered, "## Cross-work blockers") ||
		!strings.Contains(rendered, "- `1.1`: `0002/1.1`, `0003/9.9`, `0004/1.1`, `0005/1.1`") {
		t.Fatalf("markdown sem bloqueios:\n%s", rendered)
	}
}

func TestCrossWorkDependencyIsReleasedByAcceptedTask(t *testing.T) {
	root, verifierRoot := statusVerifierFixture(t, []statusSpec{defaultStatusSpec()}, map[string]bool{"1.1": true})
	writeGreenEvidence(t, root, "1.1")
	approveAndStore(t, root, verifierRoot, "1.1", "")
	writeFile(t, root, ".work/0001.json", manifestJSON("0001", "active", ".todo/0001-tasks.md"))
	writeFile(t, root, ".todo/0002-tasks.md", statusPlanMarkdown(
		[]string{statusTaskBlock("1.1", " ", "FR-001", "0001/1.1", "Depende de outro Work")}, "N/A", "0002"))

	report, err := work.CollectPlanStatus("0002", root)
	if err != nil {
		t.Fatalf("CollectPlanStatus: %v", err)
	}
	if len(report.CrossWorkBlockers) != 0 {
		t.Fatalf("task aceita devia liberar a dependência: %v", report.CrossWorkBlockers)
	}
}

func TestRenderMarkdownSectionsAndEscaping(t *testing.T) {
	major, minor := 3, 2
	report := work.PlanStatus{
		ProjectStatus: work.ProjectStatus{
			Artifacts: work.ArtifactsStatus{
				SystemSpec: work.ArtifactState{Path: ".specs/system.md", State: "present", Detail: "approved | v1"},
				Prompt:     work.ArtifactState{Path: ".prompts/", State: "absent", Detail: "run /make-prompt"},
				Tasks:      work.ArtifactState{Path: "/x/.todo/0001-tasks.md", State: "invalid", Detail: "2 blocking error(s)"},
			},
			Panorama: work.Panorama{
				State:     work.PanoramaStaleEvidence,
				StoppedAt: "parou | aqui",
				Counts:    work.PanoramaCounts{Total: 3, Completed: 1, Pending: 1, Blocked: 1, UnverifiedChecked: 2, VerifiedOpen: 1},
				Progress:  33, CompatibilityWarning: 1,
			},
			GlobalGates: work.GlobalGates{State: "PENDING", Detail: "0/1"},
			Tasks: []work.StatusTask{
				{ID: "1.1", Marker: "x", Title: "Feita", Requirement: "FR-001", DependsOn: "none",
					Evidence: work.EvidenceState{Stage: "VERIFIED", Stale: true, Attestation: "falta recibo"}},
				{ID: "1.2", Marker: " ", Title: "Pendente | com barra", Requirement: "FR-002", DependsOn: "1.1",
					Evidence: work.EvidenceState{Stage: "not started"}},
				{ID: "1.3", Marker: "!", Title: "Presa", Requirement: "—", DependsOn: "—",
					Evidence: work.EvidenceState{Stage: "not started"}},
			},
			ValidationErrors:            []string{"erro um", "erro dois"},
			ValidationWarnings:          []string{"aviso um"},
			ValidationExceptions:        []string{"exceção um"},
			ContractVersion:             &major,
			MigratedFromContractVersion: &minor,
		},
		CrossWorkBlockers: map[string][]string{"1.3": {"0002/1.1"}, "1.2": {"0003/2.1", "0004/1.1"}},
	}
	rendered := work.RenderMarkdown(report)
	for _, want := range []string{
		"| System spec | `.specs/system.md` | present | approved \\| v1 |",
		"| Task plan | `/x/.todo/0001-tasks.md` | invalid | 2 blocking error(s) |",
		"- **Project state:** STALE EVIDENCE",
		"- **Progress:** 1/3 checked (33%)",
		"- **Tasks:** 1 pending | 1 checked | 1 blocked",
		"- **Consistency:** 2 checked without ACCEPTED evidence | 1 ACCEPTED but open",
		"- **Task contract:** v3 migrated from v2 | 1 compatibility warning(s) | 1 preserved legacy exception(s)",
		"- **Where it stopped:** parou \\| aqui",
		"- **Global gates:** PENDING — 0/1",
		"| `1.1` | [x] checked | `FR-001` | none | VERIFIED (STALE) — falta recibo | Feita |",
		"| `1.2` | [ ] pending | `FR-002` | 1.1 | not started | Pendente \\| com barra |",
		"| `1.3` | [!] blocked | `—` | — | not started | Presa |",
		"## Cross-work blockers\n\n- `1.2`: `0003/2.1`, `0004/1.1`\n- `1.3`: `0002/1.1`\n",
		"## Structural issues\n\n- erro um\n- erro dois\n",
		"## Compatibility warnings\n\n- aviso um\n\nMigration is optional:",
		"## Preserved legacy exceptions\n\n- exceção um\n",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("markdown sem %q:\n%s", want, rendered)
		}
	}
	if !strings.HasSuffix(rendered, "\n") || strings.HasSuffix(rendered, "\n\n") {
		t.Fatalf("o markdown termina com exatamente uma quebra de linha: %q", rendered[len(rendered)-8:])
	}
}

func TestRenderMarkdownUnknownContractVersion(t *testing.T) {
	rendered := work.RenderMarkdown(work.PlanStatus{})
	if !strings.Contains(rendered, "- **Task contract:** unknown | 0 compatibility warning(s) | 0 preserved legacy exception(s)") {
		t.Fatalf("markdown:\n%s", rendered)
	}
	for _, absent := range []string{"## Cross-work blockers", "## Structural issues", "## Compatibility warnings", "## Preserved legacy exceptions"} {
		if strings.Contains(rendered, absent) {
			t.Fatalf("seção %q não devia aparecer sem dados", absent)
		}
	}
}

func TestArtifactStatusLegacyPlanIsCompatibleWithWarnings(t *testing.T) {
	root := t.TempDir()
	content := statusPlanMarkdown([]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001")
	content = strings.Replace(content, "**Contract version:** 3\n", "", 1)
	content = strings.Replace(content, "**Requirement:** FR-001\n", "", 1)
	content = strings.Replace(content, "**Depends on:** none\n", "", 1)
	report := collectWithNeutralVerifier(t, writeStatusFixture(t, root, content))

	if report.Artifacts.Tasks.State != "compatible" ||
		!strings.HasSuffix(report.Artifacts.Tasks.Detail, "3 compatibility warning(s); contract v1") {
		t.Fatalf("tasks = %+v", report.Artifacts.Tasks)
	}
	if len(report.ValidationWarnings) != 3 || report.Panorama.CompatibilityWarning != 3 {
		t.Fatalf("warnings = %v (%d)", report.ValidationWarnings, report.Panorama.CompatibilityWarning)
	}
	if report.Panorama.State != work.PanoramaNotStarted {
		t.Fatalf("panorama = %s", report.Panorama.State)
	}
	rendered := work.RenderMarkdown(work.PlanStatus{ProjectStatus: report})
	if !strings.Contains(rendered, "## Compatibility warnings") || !strings.Contains(rendered, "- task contract version is missing; assuming legacy version 1") {
		t.Fatalf("markdown sem warnings:\n%s", rendered)
	}
}
