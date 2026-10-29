package work_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/work"
)

func TestReserveWorkWritesCanonicalManifest(t *testing.T) {
	root := t.TempDir()
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{})
	if err != nil {
		t.Fatalf("ReserveWork: %v", err)
	}
	if manifest.WorkID != "0001" {
		t.Fatalf("WorkID = %s", manifest.WorkID)
	}
	if manifest.Version != work.WorkManifestVersion || manifest.State != work.StateSourcePending {
		t.Fatalf("manifest inesperado: %+v", manifest)
	}
	if manifest.Artifacts.Plan != filepath.Join(".todo", "0001-tasks.md") {
		t.Fatalf("plan = %s", manifest.Artifacts.Plan)
	}
	info, err := os.Stat(filepath.Join(root, ".work", "0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("modo do manifest = %o, quer 600", info.Mode().Perm())
	}

	if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"}); err == nil {
		t.Fatal("reserva duplicada devia falhar")
	}
	second, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0002"})
	if err != nil {
		t.Fatalf("ReserveWork 0002: %v", err)
	}
	if second.WorkID != "0002" {
		t.Fatalf("WorkID = %s", second.WorkID)
	}
	if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "1"}); err == nil {
		t.Fatal("Work ID de um dígito devia falhar")
	}
}

func TestReserveWorkSnapshotsSource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "request.md", "# Pedido\n\nconteúdo\n")
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{SourcePath: "request.md", OriginType: "request"})
	if err != nil {
		t.Fatalf("ReserveWork: %v", err)
	}
	if manifest.State != work.StatePromptPending {
		t.Fatalf("state = %s, quer prompt_pending", manifest.State)
	}
	snapshot := readFile(t, root, filepath.Join(".sources", "0001-request.md"))
	if snapshot != "# Pedido\n\nconteúdo\n" {
		t.Fatalf("snapshot divergente: %q", snapshot)
	}
	if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0002", SourcePath: "ausente.md"}); err == nil {
		t.Fatal("fonte ausente devia falhar")
	}
	if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0003", SourcePath: "../escape.md"}); err == nil {
		t.Fatal("caminho que escapa da raiz devia falhar")
	}
}

func TestLoadManifestCoercesUnknownState(t *testing.T) {
	root := t.TempDir()
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, ".work/0001.json", `{"version":1,"work_id":"0001","state":"in_progress","origin":{"type":"local","reference":null},"artifacts":`+
		`{"manifest":".work/0001.json","source":".sources/0001-request.md","prompt":".prompts/0001-change.md","plan":".todo/0001-tasks.md",`+
		`"evidence":".todo/evidence/0001","diagnostics":".todo/diagnostics/0001","screenshots":".todo/screenshots/0001","attestations":".todo/attestations/0001"},`+
		`"created_at":"x","updated_at":"x"}`)
	loaded, err := work.LoadManifest(root, manifest.WorkID)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if loaded.State != work.StateInvalid {
		t.Fatalf("state = %s, quer invalid", loaded.State)
	}

	if _, err := work.UpdateManifest(root, "0001", work.ManifestChanges{State: new(work.StateActive)}); err != nil {
		t.Fatalf("UpdateManifest: %v", err)
	}
	repaired, err := work.LoadManifest(root, "0001")
	if err != nil {
		t.Fatal(err)
	}
	if repaired.State != work.StateActive {
		t.Fatalf("state = %s, quer active", repaired.State)
	}
	if _, err := work.UpdateManifest(root, "0001", work.ManifestChanges{State: new(work.WorkManifestState("in_progress"))}); err == nil {
		t.Fatal("estado fora do vocabulário devia ser recusado")
	}
}

func TestResolvePlanTarget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0001-tasks.md", "# Tasks: x\n")
	resolved, err := work.ResolvePlanTarget(root, "0001")
	if err != nil {
		t.Fatalf("ResolvePlanTarget: %v", err)
	}
	if resolved.WorkID == nil || *resolved.WorkID != "0001" || resolved.Legacy {
		t.Fatalf("alvo inesperado: %+v", resolved)
	}
	if resolved.Absolute != filepath.Join(root, ".todo", "0001-tasks.md") {
		t.Fatalf("absoluto = %s", resolved.Absolute)
	}
	if _, err := work.ResolvePlanTarget(root, "1"); err == nil {
		t.Fatal("Work ID sem quatro dígitos devia falhar")
	}
	if _, err := work.ResolvePlanTarget(root, "0002"); err == nil {
		t.Fatal("plano ausente devia falhar")
	}
	if _, err := work.ResolvePlanTarget(root, ".todo/outro.md"); err == nil {
		t.Fatal("alvo não canônico devia falhar")
	}
	writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
	legacy, err := work.ResolvePlanTarget(root, "legacy")
	if err != nil || !legacy.Legacy {
		t.Fatalf("alvo legado: %+v err=%v", legacy, err)
	}
}

func TestResolvePlanTargetChecksManifestPlan(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0001-tasks.md", "# Tasks: x\n")
	if _, err := work.ReserveWork(root, work.ReserveWorkOptions{WorkID: "0001"}); err != nil {
		t.Fatal(err)
	}
	if _, err := work.ResolvePlanTarget(root, "0001"); err != nil {
		t.Fatalf("plano declarado no manifest devia concordar: %v", err)
	}
	artifacts, err := work.CanonicalArtifacts("0001", "local")
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Plan = ".todo/0002-tasks.md"
	if _, err := work.UpdateManifest(root, "0001", work.ManifestChanges{Artifacts: &artifacts}); err != nil {
		t.Fatal(err)
	}
	if _, err := work.ResolvePlanTarget(root, "0001"); err == nil {
		t.Fatal("manifest com plano divergente devia falhar")
	}
}

func TestListWorks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/0002-tasks.md", "# Tasks: x\n")
	writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
	writeFile(t, root, ".work/0002.json", `{"version":1,"work_id":"0002","state":"planned","origin":{"type":"local","reference":null},`+
		`"artifacts":{"manifest":".work/0002.json","source":".sources/0002-local.md","prompt":".prompts/0002-change.md","plan":".todo/0002-tasks.md",`+
		`"evidence":".todo/evidence/0002","diagnostics":".todo/diagnostics/0002","screenshots":".todo/screenshots/0002","attestations":".todo/attestations/0002"},`+
		`"created_at":"x","updated_at":"x"}`)
	writeFile(t, root, ".pwn/work/0001/intake.json", "{}")
	works, err := work.ListWorks(root)
	if err != nil {
		t.Fatalf("ListWorks: %v", err)
	}
	if len(works) != 3 {
		t.Fatalf("works = %+v", works)
	}
	states := map[string]string{}
	for _, entry := range works {
		states[entry.WorkID] = entry.State
	}
	if states["0001"] != "plan_pending" {
		t.Fatalf("0001 sem plano = %s", states["0001"])
	}
	if states["0002"] != "planned" {
		t.Fatalf("0002 = %s", states["0002"])
	}
	if states["legacy"] != "legacy" {
		t.Fatalf("legacy = %s", states["legacy"])
	}
}

func TestLegacyMigrationPreviewAndApply(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".todo/tasks.md", "# Tasks: legado\n")
	writeFile(t, root, ".todo/evidence/antigo/state.json", "{}")
	preview, err := work.PreviewLegacyMigration(root)
	if err != nil {
		t.Fatalf("PreviewLegacyMigration: %v", err)
	}
	if preview.WorkID != "0001" || len(preview.Moves) != 2 {
		t.Fatalf("prévia = %+v", preview)
	}
	if _, err := os.Stat(filepath.Join(root, ".todo", "tasks.md")); err != nil {
		t.Fatal("a prévia não pode mover arquivos")
	}

	applied, err := work.ApplyLegacyMigration(root)
	if err != nil {
		t.Fatalf("ApplyLegacyMigration: %v", err)
	}
	if applied.Created != filepath.Join(".work", "0001.json") {
		t.Fatalf("manifest = %s", applied.Created)
	}
	if _, err := os.Stat(filepath.Join(root, ".todo", "0001-tasks.md")); err != nil {
		t.Fatal("plano legado não foi movido")
	}
	if _, err := os.Stat(filepath.Join(root, ".todo", "evidence", "0001", "antigo", "state.json")); err != nil {
		t.Fatal("evidência legada não foi movida")
	}
	manifest, err := work.LoadManifest(root, "0001")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Origin.Type != "legacy-migration" || manifest.State != work.StatePlanned {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := work.PreviewLegacyMigration(root); err == nil {
		t.Fatal("segunda migração devia falhar sem plano legado")
	}
}
