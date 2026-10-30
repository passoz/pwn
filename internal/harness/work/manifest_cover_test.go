package work_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/work"
)

// manifestJSON monta um manifest v1 mínimo para o Work informado.
func manifestJSON(workID, state, plan string) string {
	return `{"version":1,"work_id":"` + workID + `","state":"` + state + `","origin":{"type":"local","reference":null},` +
		`"artifacts":{"manifest":".work/` + workID + `.json","source":".sources/` + workID + `-local.md","prompt":".prompts/` + workID + `-change.md","plan":"` + plan + `",` +
		`"evidence":".todo/evidence/` + workID + `","diagnostics":".todo/diagnostics/` + workID + `","screenshots":".todo/screenshots/` + workID + `","attestations":".todo/attestations/` + workID + `"},` +
		`"created_at":"x","updated_at":"x"}`
}

func TestManifestPathAndCanonicalArtifactsRejectInvalidIDs(t *testing.T) {
	for _, id := range []string{"", "1", "12345", "abcd", "00 1"} {
		if _, err := work.ManifestPath(id); err == nil || !strings.Contains(err.Error(), "invalid Work ID") {
			t.Fatalf("ManifestPath(%q) erro = %v", id, err)
		}
		if _, err := work.CanonicalArtifacts(id, "local"); err == nil {
			t.Fatalf("CanonicalArtifacts(%q) devia falhar", id)
		}
	}
	path, err := work.ManifestPath("0042")
	if err != nil || path != filepath.Join(".work", "0042.json") {
		t.Fatalf("ManifestPath = %q, %v", path, err)
	}
}

func TestCanonicalArtifactsSanitizesSourceKind(t *testing.T) {
	cases := map[string]string{
		"Meu Tipo!!":  "meu-tipo",
		"--já--":      "j",
		"!!!":         "request",
		"":            "request",
		"issue-42":    "issue-42",
		"  GitHub PR": "github-pr",
	}
	for kind, want := range cases {
		artifacts, err := work.CanonicalArtifacts("0001", kind)
		if err != nil {
			t.Fatal(err)
		}
		if artifacts.Source != filepath.Join(".sources", "0001-"+want+".md") {
			t.Fatalf("kind %q: source = %s, quer 0001-%s.md", kind, artifacts.Source, want)
		}
	}
	artifacts, err := work.CanonicalArtifacts("0007", "x")
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.Plan != filepath.Join(".todo", "0007-tasks.md") ||
		artifacts.Evidence != filepath.Join(".todo", "evidence", "0007") ||
		artifacts.Attestations != filepath.Join(".todo", "attestations", "0007") {
		t.Fatalf("artefatos = %+v", artifacts)
	}
}

func TestLoadManifestRejectsBrokenFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := work.LoadManifest(root, "xx"); err == nil {
		t.Fatal("ID inválido devia falhar")
	}
	if _, err := work.LoadManifest(root, "0001"); err == nil || !strings.Contains(err.Error(), "work manifest not found: .work/0001.json") {
		t.Fatalf("manifest ausente: %v", err)
	}
	writeFile(t, root, ".work/0001.json", "{ não é json")
	if _, err := work.LoadManifest(root, "0001"); err == nil || !strings.Contains(err.Error(), ".work/0001.json") {
		t.Fatalf("JSON inválido: %v", err)
	}
	writeFile(t, root, ".work/0002.json", strings.Replace(manifestJSON("0002", "planned", ".todo/0002-tasks.md"), `"version":1`, `"version":2`, 1))
	if _, err := work.LoadManifest(root, "0002"); err == nil || !strings.Contains(err.Error(), "unsupported work manifest version: 2") {
		t.Fatalf("versão: %v", err)
	}
	writeFile(t, root, ".work/0003.json", manifestJSON("0009", "planned", ".todo/0003-tasks.md"))
	if _, err := work.LoadManifest(root, "0003"); err == nil || !strings.Contains(err.Error(), "expected 0003, found 0009") {
		t.Fatalf("Work ID divergente: %v", err)
	}
}

func TestReserveWorkDefaultsAndOriginReference(t *testing.T) {
	root := t.TempDir()
	reference := "https://example.invalid/issues/42"
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{OriginType: "github-issue", OriginReference: &reference})
	if err != nil {
		t.Fatalf("ReserveWork: %v", err)
	}
	if manifest.Origin.Type != "github-issue" || manifest.Origin.Reference == nil || *manifest.Origin.Reference != reference {
		t.Fatalf("origem = %+v", manifest.Origin)
	}
	if manifest.Artifacts.Source != filepath.Join(".sources", "0001-github-issue.md") {
		t.Fatalf("source = %s", manifest.Artifacts.Source)
	}
	if manifest.State != work.StateSourcePending {
		t.Fatalf("estado = %s", manifest.State)
	}
	info, err := os.Stat(filepath.Join(root, ".work", "0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("modo do manifest = %v, quer 0600", info.Mode().Perm())
	}

	second, err := work.ReserveWork(root, work.ReserveWorkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second.WorkID != "0002" || second.Origin.Type != "local" || second.Origin.Reference != nil {
		t.Fatalf("segundo = %+v", second)
	}
}

func TestReserveWorkErrors(t *testing.T) {
	t.Run("ID inválido", func(t *testing.T) {
		if _, err := work.ReserveWork(t.TempDir(), work.ReserveWorkOptions{WorkID: "12"}); err == nil ||
			!strings.Contains(err.Error(), "invalid Work ID") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("ID já reservado", func(t *testing.T) {
		root := t.TempDir()
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0005"}); err != nil {
			t.Fatal(err)
		}
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0005"}); err == nil ||
			!strings.Contains(err.Error(), "Work ID already reserved: 0005") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("espaço de IDs esgotado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".work/9999.json", "{}")
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{}); err == nil ||
			!strings.Contains(err.Error(), "work ID space exhausted at 9999") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("diretório do manifest bloqueado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".work", "arquivo no lugar do diretório")
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{}); err == nil ||
			!strings.Contains(err.Error(), "criar diretório do manifest") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("fonte é diretório", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "pasta"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001", SourcePath: "pasta"}); err == nil ||
			!strings.Contains(err.Error(), "source file not found: pasta") {
			t.Fatalf("erro = %v", err)
		}
	})
	t.Run("snapshot já existe", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "pedido.md", "# pedido\n")
		writeFile(t, root, ".sources/0001-request.md", "# antigo\n")
		_, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001", SourcePath: "pedido.md"})
		if err == nil || !strings.Contains(err.Error(), "source snapshot already exists: .sources/0001-request.md") {
			t.Fatalf("erro = %v", err)
		}
		if readFile(t, root, ".sources/0001-request.md") != "# antigo\n" {
			t.Fatal("snapshot preexistente foi sobrescrito")
		}
	})
	t.Run("diretório do snapshot bloqueado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "pedido.md", "# pedido\n")
		writeFile(t, root, ".sources", "arquivo no lugar do diretório")
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001", SourcePath: "pedido.md"}); err == nil ||
			!strings.Contains(err.Error(), "criar diretório do snapshot") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestReserveWorkWithSourceMovesToPromptPending(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pedido.md", "# pedido\n")
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{SourcePath: "pedido.md"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != work.StatePromptPending {
		t.Fatalf("estado = %s, quer prompt_pending", manifest.State)
	}
	if readFile(t, root, ".sources/0001-request.md") != "# pedido\n" {
		t.Fatal("snapshot divergente")
	}
}

func TestUpdateManifestChangesArtifactsOriginAndTimestamp(t *testing.T) {
	root := t.TempDir()
	created, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := created.Artifacts
	artifacts.Plan = filepath.Join(".todo", "outro-plano.md")
	reference := "ref-1"
	updated, err := work.UpdateManifest(root, "0001", work.ManifestChanges{
		Artifacts: &artifacts,
		Origin:    &work.WorkManifestOrigin{Type: "manual", Reference: &reference},
	})
	if err != nil {
		t.Fatalf("UpdateManifest: %v", err)
	}
	if updated.Artifacts.Plan != artifacts.Plan || updated.Origin.Type != "manual" || *updated.Origin.Reference != "ref-1" {
		t.Fatalf("atualizado = %+v", updated)
	}
	if updated.State != work.StateSourcePending || updated.CreatedAt != created.CreatedAt {
		t.Fatalf("campos não alterados mudaram: %+v", updated)
	}
	reloaded, err := work.LoadManifest(root, "0001")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Artifacts.Plan != artifacts.Plan || reloaded.Origin.Type != "manual" {
		t.Fatalf("persistido = %+v", reloaded)
	}
	info, err := os.Stat(filepath.Join(root, ".work", "0001.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("modo = %v err=%v", info.Mode().Perm(), err)
	}
}

func TestUpdateManifestErrors(t *testing.T) {
	root := t.TempDir()
	if _, err := work.UpdateManifest(root, "x", work.ManifestChanges{}); err == nil {
		t.Fatal("ID inválido devia falhar")
	}
	if _, err := work.UpdateManifest(root, "0001", work.ManifestChanges{}); err == nil ||
		!strings.Contains(err.Error(), "work manifest not found") {
		t.Fatalf("manifest ausente: %v", err)
	}
	if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"}); err != nil {
		t.Fatal(err)
	}
	invalid := work.WorkManifestState("em_andamento")
	if _, err := work.UpdateManifest(root, "0001", work.ManifestChanges{State: &invalid}); err == nil ||
		!strings.Contains(err.Error(), "invalid work state: em_andamento") {
		t.Fatalf("estado inválido: %v", err)
	}
	if work.IsWorkManifestState("em_andamento") || !work.IsWorkManifestState("blocked") {
		t.Fatal("IsWorkManifestState classificou errado")
	}
}

func TestResolvePlanTargetErrorsAndPaths(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0001-tasks.md", "# Tasks: x\n")
	writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
	writeFile(t, root, "outra/0001-tasks.md", "# Tasks: fora\n")

	if _, err := work.ResolvePlanTarget(root, ""); err == nil || !strings.Contains(err.Error(), "explicit plan target required") {
		t.Fatalf("alvo vazio: %v", err)
	}
	if _, err := work.ResolvePlanTarget(root, "../fora.md"); err == nil || !strings.Contains(err.Error(), "escapes repository root") {
		t.Fatalf("alvo fora da raiz: %v", err)
	}
	if _, err := work.ResolvePlanTarget(root, "outra/0001-tasks.md"); err == nil || !strings.Contains(err.Error(), "not a canonical plan target") {
		t.Fatalf("plano em outro diretório: %v", err)
	}
	if _, err := work.ResolvePlanTarget(root, "123"); err == nil || !strings.Contains(err.Error(), "preserve four digits") {
		t.Fatalf("ID curto: %v", err)
	}

	byPath, err := work.ResolvePlanTarget(root, ".todo/0001-tasks.md")
	if err != nil {
		t.Fatalf("por caminho: %v", err)
	}
	if byPath.WorkID == nil || *byPath.WorkID != "0001" || byPath.Legacy || byPath.Relative != filepath.Join(".todo", "0001-tasks.md") {
		t.Fatalf("por caminho = %+v", byPath)
	}
	legacyPath, err := work.ResolvePlanTarget(root, ".todo/tasks.md")
	if err != nil || !legacyPath.Legacy || legacyPath.WorkID != nil {
		t.Fatalf("legado por caminho = %+v err=%v", legacyPath, err)
	}

	writeFile(t, root, ".work/0001.json", "{ quebrado")
	if _, err := work.ResolvePlanTarget(root, "0001"); err == nil {
		t.Fatal("manifest ilegível devia falhar")
	}
}

func TestResolvePlanTargetEmptyRootUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0003-tasks.md", "# Tasks: x\n")
	t.Chdir(root)
	resolved, err := work.ResolvePlanTarget("", "0003")
	if err != nil {
		t.Fatalf("ResolvePlanTarget: %v", err)
	}
	if resolved.WorkID == nil || *resolved.WorkID != "0003" {
		t.Fatalf("alvo = %+v", resolved)
	}
	evalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	evalRoot2, err := filepath.EvalSymlinks(resolved.Root)
	if err != nil {
		t.Fatal(err)
	}
	if evalRoot != evalRoot2 {
		t.Fatalf("raiz = %s, quer %s", resolved.Root, root)
	}
}

func TestListWorksReportsInvalidAndMissingManifests(t *testing.T) {
	root := t.TempDir()
	// 0001: manifest ilegível.
	writeFile(t, root, ".work/0001.json", "{ quebrado")
	// 0002: só o snapshot da fonte, sem manifest nem diretório canônico.
	writeFile(t, root, ".sources/0002-request.md", "# fonte\n")
	// 0003: manifest válido cujo plano declarado não existe.
	writeFile(t, root, ".work/0003.json", manifestJSON("0003", "planned", ".todo/0003-tasks.md"))
	// 0004: manifest com versão desconhecida.
	writeFile(t, root, ".work/0004.json", strings.Replace(manifestJSON("0004", "planned", ".todo/0004-tasks.md"), `"version":1`, `"version":9`, 1))

	works, err := work.ListWorks(root)
	if err != nil {
		t.Fatalf("ListWorks: %v", err)
	}
	byID := map[string]work.WorkSummary{}
	for _, entry := range works {
		byID[entry.WorkID] = entry
	}
	if len(works) != 4 {
		t.Fatalf("works = %+v", works)
	}
	if byID["0001"].State != "invalid" || byID["0001"].Error == "" {
		t.Fatalf("0001 = %+v", byID["0001"])
	}
	if byID["0002"].State != "invalid" || byID["0002"].Error != "missing .work/0002.json" {
		t.Fatalf("0002 = %+v", byID["0002"])
	}
	if byID["0003"].State != "planned" || byID["0003"].PlanExists || byID["0003"].Origin == nil || byID["0003"].Plan != ".todo/0003-tasks.md" {
		t.Fatalf("0003 = %+v", byID["0003"])
	}
	if !strings.Contains(byID["0004"].Error, "unsupported work manifest version: 9") {
		t.Fatalf("0004 = %+v", byID["0004"])
	}
}

func TestListWorksAndIDsWithEmptyRootUseWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0002-tasks.md", "# Tasks: x\n")
	writeFile(t, root, ".pwn/work/0002/intake.json", "{}")
	t.Chdir(root)

	ids := work.ListWorkIDs("")
	if len(ids) != 1 || ids[0] != "0002" {
		t.Fatalf("ids = %v", ids)
	}
	works, err := work.ListWorks("")
	if err != nil {
		t.Fatal(err)
	}
	if len(works) != 1 || works[0].State != "planned" || !works[0].PlanExists {
		t.Fatalf("works = %+v", works)
	}
	if work.GetLatestWorkID("") != "0002" || work.GetNextWorkID("") != "0003" {
		t.Fatalf("latest=%s next=%s", work.GetLatestWorkID(""), work.GetNextWorkID(""))
	}
}

func TestLatestAndNextWorkIDOnEmptyRoot(t *testing.T) {
	root := t.TempDir()
	if work.GetLatestWorkID(root) != "0001" || work.GetNextWorkID(root) != "0001" {
		t.Fatalf("raiz vazia: latest=%s next=%s", work.GetLatestWorkID(root), work.GetNextWorkID(root))
	}
	writeFile(t, root, ".work/0007.json", "{}")
	writeFile(t, root, ".prompts/0003-change.md", "x\n")
	if work.GetLatestWorkID(root) != "0007" {
		t.Fatalf("latest = %s", work.GetLatestWorkID(root))
	}
	if work.GetNextWorkID(root) != "0008" {
		t.Fatalf("next = %s", work.GetNextWorkID(root))
	}
	if got := work.ListWorkIDs(root); strings.Join(got, ",") != "0003,0007" {
		t.Fatalf("ids = %v", got)
	}
}

func TestLegacyMigrationErrors(t *testing.T) {
	t.Run("sem plano legado", func(t *testing.T) {
		root := t.TempDir()
		if _, err := work.PreviewLegacyMigration(root); err == nil || !strings.Contains(err.Error(), "legacy plan not found") {
			t.Fatalf("prévia: %v", err)
		}
		if _, err := work.ApplyLegacyMigration(root); err == nil {
			t.Fatal("aplicar sem plano legado devia falhar")
		}
	})
	t.Run("destino já existe", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
		writeFile(t, root, ".todo/evidence/antigo/state.json", "{}")
		// O próximo Work ID livre é 0001: o destino da evidência já está ocupado.
		writeFile(t, root, ".todo/evidence/0001/antigo/state.json", "{}")
		_, err := work.PreviewLegacyMigration(root)
		if err == nil || !strings.Contains(err.Error(), "legacy migration destination already exists: .todo/evidence/0001/antigo") {
			t.Fatalf("destino ocupado: %v", err)
		}
		if _, err := work.ApplyLegacyMigration(root); err == nil {
			t.Fatal("aplicar com destino ocupado devia falhar")
		}
		if _, err := os.Stat(filepath.Join(root, ".work", "0001.json")); !os.IsNotExist(err) {
			t.Fatal("migração recusada não pode reservar o Work")
		}
	})
	t.Run("espaço de IDs esgotado", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
		writeFile(t, root, ".work/9999.json", "{}")
		if _, err := work.PreviewLegacyMigration(root); err == nil || !strings.Contains(err.Error(), "exhausted") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestLegacyMigrationMovesEvidenceDiagnosticsAndScreenshots(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
	writeFile(t, root, ".todo/evidence/1.1-verify.log", "ok\n")
	writeFile(t, root, ".todo/diagnostics/d.txt", "d\n")
	writeFile(t, root, ".todo/screenshots/s.png", "s\n")
	// Diretório já numerado por outro Work não é movido.
	writeFile(t, root, ".todo/evidence/0009/keep.log", "keep\n")

	preview, err := work.PreviewLegacyMigration(root)
	if err != nil {
		t.Fatalf("PreviewLegacyMigration: %v", err)
	}
	if len(preview.Moves) != 4 {
		t.Fatalf("movimentos = %+v", preview.Moves)
	}
	applied, err := work.ApplyLegacyMigration(root)
	if err != nil {
		t.Fatalf("ApplyLegacyMigration: %v", err)
	}
	id := applied.WorkID
	for _, moved := range []string{
		".todo/" + id + "-tasks.md",
		".todo/evidence/" + id + "/1.1-verify.log",
		".todo/diagnostics/" + id + "/d.txt",
		".todo/screenshots/" + id + "/s.png",
		".todo/evidence/0009/keep.log",
	} {
		if _, err := os.Stat(filepath.Join(root, moved)); err != nil {
			t.Fatalf("faltou %s: %v", moved, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".todo", "tasks.md")); !os.IsNotExist(err) {
		t.Fatal("plano legado devia ter sido movido")
	}
}

func TestSyncWorkManifestMapsPanoramaToManifestStates(t *testing.T) {
	neutralVerifier(t)

	t.Run("plano ausente vira invalid", func(t *testing.T) {
		root := t.TempDir()
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"}); err != nil {
			t.Fatal(err)
		}
		state, err := work.SyncWorkManifest("0001", root)
		if err != nil {
			t.Fatalf("SyncWorkManifest: %v", err)
		}
		if state != string(work.StateInvalid) {
			t.Fatalf("estado = %s, quer invalid", state)
		}
		manifest, err := work.LoadManifest(root, "0001")
		if err != nil || manifest.State != work.StateInvalid {
			t.Fatalf("manifest = %+v err=%v", manifest, err)
		}
	})

	t.Run("task bloqueada vira blocked", func(t *testing.T) {
		root := t.TempDir()
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"}); err != nil {
			t.Fatal(err)
		}
		writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown(
			[]string{
				statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta"),
				"### [!] [1.2] Rejeitar duplicata — bloqueada: contrato externo ausente\n",
			}, "N/A", "0001"))
		state, err := work.SyncWorkManifest("0001", root)
		if err != nil {
			t.Fatalf("SyncWorkManifest: %v", err)
		}
		if state != string(work.StateBlocked) {
			t.Fatalf("estado = %s, quer blocked", state)
		}
	})

	t.Run("plano sem task iniciada vira planned", func(t *testing.T) {
		root := t.TempDir()
		if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"}); err != nil {
			t.Fatal(err)
		}
		writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown(
			[]string{statusTaskBlock("1.1", " ", "FR-001", "none", "Criar conta")}, "N/A", "0001"))
		state, err := work.SyncWorkManifest("0001", root)
		if err != nil {
			t.Fatalf("SyncWorkManifest: %v", err)
		}
		if state != string(work.StatePlanned) {
			t.Fatalf("estado = %s, quer planned", state)
		}
	})

	t.Run("manifest ilegível devolve erro", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".work/0001.json", "{ quebrado")
		if _, err := work.SyncWorkManifest("0001", root); err == nil {
			t.Fatal("manifest ilegível devia falhar ao atualizar")
		}
	})

	t.Run("diretório .work inacessível", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".work", "arquivo")
		if _, err := work.SyncWorkManifest("0001", root); err == nil || !strings.Contains(err.Error(), "ler manifest") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("raiz vazia usa o diretório atual", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		state, err := work.SyncWorkManifest("0001", "")
		if err != nil || state != work.ManifestAbsent {
			t.Fatalf("estado = %s err=%v", state, err)
		}
	})
}
