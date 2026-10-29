package verify_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

func TestCaptureSnapshotDeterminismAndExclusions(t *testing.T) {
	rootDir := t.TempDir()
	writeFile(t, rootDir, "src/a.ts", "a")
	writeFile(t, rootDir, "src/deep/b.ts", "b")
	writeFile(t, rootDir, "package.json", `{"name":"x"}`)

	first, err := verify.CaptureSnapshot(rootDir)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}
	second, err := verify.CaptureSnapshot(rootDir)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}
	if first.Digest != second.Digest {
		t.Error("o snapshot deveria ser determinístico")
	}

	// Arquivo indireto (não declarado na task) muda o estado executável.
	writeFile(t, rootDir, "src/deep/b.ts", "b-alterado")
	afterIndirect, err := verify.CaptureSnapshot(rootDir)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}
	if afterIndirect.Digest == first.Digest {
		t.Error("arquivo indireto deveria mudar o digest")
	}

	// Estado do harness e dependências nunca entram no snapshot.
	writeFile(t, rootDir, ".todo/x.md", "x")
	writeFile(t, rootDir, ".pwn/work/0001/plan.json", "{}")
	writeFile(t, rootDir, ".work/tmp.txt", "tmp")
	writeFile(t, rootDir, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, rootDir, "queue/q.json", "{}")
	writeFile(t, rootDir, ".pwn-verifier/key", "k")
	writeFile(t, rootDir, "node_modules/pkg/index.js", "module.exports = 1;\n")

	snapshot, err := verify.CaptureSnapshot(rootDir)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}
	if snapshot.Digest != afterIndirect.Digest {
		t.Error("estado do harness não pode mudar o snapshot")
	}
	for _, entry := range snapshot.Files {
		for _, prefix := range []string{".todo", ".pwn", ".work", ".git", "queue", ".pwn-verifier", "node_modules"} {
			if entry.Path == prefix || filepath.Dir(entry.Path) == prefix || hasPrefix(entry.Path, prefix+"/") {
				t.Errorf("%s não deveria entrar no snapshot", entry.Path)
			}
		}
	}
}

func hasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func TestMaterializeSnapshotRoundTrip(t *testing.T) {
	source := t.TempDir()
	writeFile(t, source, "a.txt", "alpha\n")
	writeFile(t, source, "sub/b.txt", "beta\n")
	if err := os.Symlink("a.txt", filepath.Join(source, "link.txt")); err != nil {
		t.Fatalf("criar o vínculo: %v", err)
	}
	snapshot, err := verify.CaptureSnapshot(source)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}

	destination := t.TempDir()
	if err := verify.MaterializeSnapshot(snapshot, destination, source); err != nil {
		t.Fatalf("materializar: %v", err)
	}
	materialized, err := verify.CaptureSnapshot(destination)
	if err != nil {
		t.Fatalf("capturar o materializado: %v", err)
	}
	if materialized.Digest != snapshot.Digest {
		t.Errorf("digest materializado = %s, quer %s", materialized.Digest, snapshot.Digest)
	}
	target, err := os.Readlink(filepath.Join(destination, "link.txt"))
	if err != nil || target != "a.txt" {
		t.Errorf("vínculo materializado = %q, erro = %v", target, err)
	}
}

func TestCaptureDependencyDigest(t *testing.T) {
	rootDir := t.TempDir()
	writeFile(t, rootDir, "package.json", `{"name":"x"}`)
	first, err := verify.CaptureDependencyDigest(rootDir)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}
	if len(first.Files) != len(verify.DependencyManifests) {
		t.Errorf("manifestos = %+v", first.Files)
	}
	if first.Files[0].SHA256 == nil {
		t.Error("package.json presente deveria ter sha256")
	}
	if first.Files[1].SHA256 != nil {
		t.Error("bun.lock ausente deveria ter sha256 nulo")
	}

	writeFile(t, rootDir, "package.json", `{"name":"y"}`)
	second, err := verify.CaptureDependencyDigest(rootDir)
	if err != nil {
		t.Fatalf("capturar: %v", err)
	}
	if first.Digest == second.Digest {
		t.Error("o digest deveria mudar com o manifesto")
	}

	writeFile(t, rootDir, "node_modules/pkg/index.js", "x")
	present := verify.PresentDependencyPaths(rootDir)
	if len(present) != 1 || present[0] != filepath.Join(rootDir, "node_modules") {
		t.Errorf("presentDependencyPaths = %v", present)
	}
}
