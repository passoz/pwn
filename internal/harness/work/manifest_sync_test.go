package work_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/work"
)

func TestSyncWorkManifestProjectsPanorama(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, ".todo/0001-tasks.md", "# Tasks: broken\n")

	state, err := work.SyncWorkManifest(manifest.WorkID, root)
	if err != nil {
		t.Fatalf("SyncWorkManifest: %v", err)
	}
	if state != string(work.StateActive) {
		t.Fatalf("estado = %s, quer active", state)
	}
	if !work.IsWorkManifestState(state) {
		t.Fatalf("estado fora do vocabulário: %s", state)
	}
	written, err := work.LoadManifest(root, manifest.WorkID)
	if err != nil {
		t.Fatal(err)
	}
	if written.State != work.StateActive {
		t.Fatalf("manifest = %s", written.State)
	}
}

func TestSyncWorkManifestWithoutManifest(t *testing.T) {
	root := t.TempDir()
	state, err := work.SyncWorkManifest("0001", root)
	if err != nil {
		t.Fatalf("SyncWorkManifest: %v", err)
	}
	if state != work.ManifestAbsent {
		t.Fatalf("estado = %s", state)
	}
}

func TestSyncWorkManifestRepairsLegacyState(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(root, ".work", "0001.json")
	data := readFile(t, root, ".work/0001.json")
	replace := `"state": "source_pending"`
	if !contains(data, replace) {
		t.Fatalf("manifest inesperado: %s", data)
	}
	writeFile(t, root, ".work/0001.json", replaceOnce(data, replace, `"state": "in_progress"`))
	if _, err := os.Stat(manifestFile); err != nil {
		t.Fatal(err)
	}
	loaded, err := work.LoadManifest(root, manifest.WorkID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != work.StateInvalid {
		t.Fatalf("estado legado = %s, quer invalid", loaded.State)
	}

	writeFile(t, root, ".todo/0001-tasks.md", "# Tasks: broken\n")
	state, err := work.SyncWorkManifest(manifest.WorkID, root)
	if err != nil {
		t.Fatal(err)
	}
	if state != string(work.StateActive) {
		t.Fatalf("estado = %s", state)
	}
	repaired, err := work.LoadManifest(root, manifest.WorkID)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.State != work.StateActive {
		t.Fatalf("manifest = %s", repaired.State)
	}
}

func TestSyncWorkManifestKeepsCheckedWithoutReceiptOutOfCompleted(t *testing.T) {
	neutralVerifier(t)
	root := t.TempDir()
	manifest, err := work.ReserveWork(root, work.ReserveWorkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, ".todo/0001-tasks.md", statusPlanMarkdown([]string{
		statusTaskBlock("1.1", "x", "FR-001", "none", "Criar conta"),
		statusTaskBlock("1.2", "x", "FR-002", "1.1", "Rejeitar duplicata"),
	}, "- [ ] `bun test` — a suíte passa.", "0001"))
	for _, id := range []string{"1.1", "1.2"} {
		writeGreenEvidence(t, root, id)
	}

	status, err := work.CollectPlanStatus(manifest.WorkID, root)
	if err != nil {
		t.Fatalf("CollectPlanStatus: %v", err)
	}
	if status.Panorama.State != work.PanoramaInconsistent {
		t.Fatalf("panorama = %s", status.Panorama.State)
	}
	if status.Panorama.Counts.UnverifiedChecked != 2 {
		t.Fatalf("unverifiedChecked = %d", status.Panorama.Counts.UnverifiedChecked)
	}
	state, err := work.SyncWorkManifest(manifest.WorkID, root)
	if err != nil {
		t.Fatal(err)
	}
	if state != string(work.StateActive) {
		t.Fatalf("estado = %s, quer active", state)
	}
	written, err := work.LoadManifest(root, manifest.WorkID)
	if err != nil {
		t.Fatal(err)
	}
	if written.State != work.StateActive {
		t.Fatalf("manifest = %s", written.State)
	}
}
