package run

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/passoz/pwn/internal/platform/sandbox"
)

func TestPrepareSandboxArtifacts(t *testing.T) {
	root := t.TempDir()
	sandboxDir := t.TempDir()
	writeFile(t, root, "node_modules/pkg/index.js", "module.exports = 1;\n")
	writeFile(t, root, "bunfig.toml", "[test]\nroot = \"tests\"\n")

	injected, err := PrepareSandbox(sandboxDir, root)
	if err != nil {
		t.Fatalf("PrepareSandbox: %v", err)
	}
	keys := make([]string, 0, len(injected))
	for key := range injected {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"bunfig.toml", "node_modules"}) {
		t.Fatalf("artefatos = %v", keys)
	}

	info, err := os.Lstat(filepath.Join(sandboxDir, "node_modules"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("node_modules deve ser um symlink: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(sandboxDir, "bunfig.toml"))
	if err != nil || string(data) != "[test]\nroot = \"tests\"\n" {
		t.Fatalf("bunfig.toml não copiado: %q (%v)", data, err)
	}
}

func TestPathFingerprint(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	writeFile(t, dir, "file.txt", "abc")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "sub")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}

	if got := PathFingerprint(filepath.Join(dir, "missing")); got != "absent" {
		t.Fatalf("ausente = %q", got)
	}
	if got := PathFingerprint(directory); got != "dir" {
		t.Fatalf("diretório = %q", got)
	}
	if got := PathFingerprint(link); got != "link:"+file {
		t.Fatalf("link = %q", got)
	}
	before := PathFingerprint(file)
	writeFile(t, dir, "file.txt", "xyz")
	if after := PathFingerprint(file); after == before {
		t.Fatalf("conteúdo reescrito manteve a assinatura %q", after)
	}
}

func TestModifiedFilesRenamesArtifactsAndFailClosed(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "old.txt", "x\n")
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-qm", "seed")

	// Artefatos que o harness injeta: node_modules linkado e bunfig.toml copiado.
	// Mesmo tamanho de old.txt para o rename preservar a assinatura do artefato.
	writeFile(t, root, "node_modules/pkg/index.js", "x\n")
	writeFile(t, root, "bunfig.toml", "x\n")

	session, err := sandbox.CreateGitWorktreeSandbox(context.Background(), "RUN-parse", root)
	if err != nil {
		t.Fatalf("criar sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = sandbox.CleanupGitWorktreeSandbox(context.Background(), session, root)
	})

	injected, err := PrepareSandbox(session.WorktreePath, root)
	if err != nil {
		t.Fatalf("PrepareSandbox: %v", err)
	}

	gitCmd(t, session.WorktreePath, "mv", "old.txt", "new.txt")
	writeFile(t, session.WorktreePath, "forbidden.txt", "x\n")

	inventory := ModifiedFiles(session.WorktreePath, session.GitDir, injected)
	if !inventory.OK {
		t.Fatalf("inventário falhou: %s", inventory.Reason)
	}
	for _, expected := range []string{"new.txt", "old.txt", "forbidden.txt"} {
		if !slices.Contains(inventory.Files, expected) {
			t.Fatalf("%q ausente do inventário: %v", expected, inventory.Files)
		}
	}
	for _, artifact := range []string{"node_modules", "bunfig.toml"} {
		if slices.Contains(inventory.Files, artifact) {
			t.Fatalf("artefato do harness reportado como mudança: %q (%v)", artifact, inventory.Files)
		}
	}

	// Mover um arquivo PARA DENTRO do artefato: o destino é filtrado, mas a
	// remoção da origem continua sendo uma mudança real.
	gitCmd(t, session.WorktreePath, "mv", "-f", "new.txt", "bunfig.toml")
	intoArtifact := ModifiedFiles(session.WorktreePath, session.GitDir, injected)
	if !intoArtifact.OK {
		t.Fatalf("inventário falhou: %s", intoArtifact.Reason)
	}
	if !slices.Contains(intoArtifact.Files, "old.txt") {
		t.Fatalf("origem do rename para dentro do artefato sumiu: %v", intoArtifact.Files)
	}
	if slices.Contains(intoArtifact.Files, "bunfig.toml") {
		t.Fatalf("destino continua sendo artefato: %v", intoArtifact.Files)
	}

	// Substituir o artefato não pode virar passe livre permanente.
	nodeModules := filepath.Join(session.WorktreePath, "node_modules")
	if err := os.Remove(nodeModules); err != nil {
		t.Fatal(err)
	}
	writeFile(t, session.WorktreePath, "node_modules", "payload\n")
	tampered := ModifiedFiles(session.WorktreePath, session.GitDir, injected)
	if !tampered.OK || !slices.Contains(tampered.Files, "node_modules") {
		t.Fatalf("artefato substituído não voltou ao inventário: %+v", tampered)
	}

	// Um nome com ' -> ' não pode ser truncado.
	writeFile(t, session.WorktreePath, "evil -> src/x.ts", "x\n")
	arrow := ModifiedFiles(session.WorktreePath, session.GitDir, injected)
	if !arrow.OK || !slices.Contains(arrow.Files, "evil -> src/x.ts") {
		t.Fatalf("nome com ' -> ' truncado: %+v", arrow)
	}

	// Fail-closed: sem repositório não existe inventário.
	if err := os.RemoveAll(filepath.Join(session.WorktreePath, ".git")); err != nil {
		t.Fatal(err)
	}
	broken := ModifiedFiles(session.WorktreePath, session.GitDir, injected)
	if broken.OK {
		t.Fatalf("worktree sem repositório devolveu inventário: %v", broken.Files)
	}
	if broken.Reason == "" {
		t.Fatal("falha sem motivo")
	}
}

func TestModifiedFilesArtifactSignature(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "seed.txt", "x\n")
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-qm", "seed")
	writeFile(t, root, "node_modules/pkg/index.js", "x\n")
	writeFile(t, root, "bunfig.toml", "x\n")

	session, err := sandbox.CreateGitWorktreeSandbox(context.Background(), "RUN-sig", root)
	if err != nil {
		t.Fatalf("criar sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = sandbox.CleanupGitWorktreeSandbox(context.Background(), session, root)
	})
	injected, err := PrepareSandbox(session.WorktreePath, root)
	if err != nil {
		t.Fatalf("PrepareSandbox: %v", err)
	}

	report := func() []string {
		result := ModifiedFiles(session.WorktreePath, session.GitDir, injected)
		if !result.OK {
			t.Fatalf("inventário falhou: %s", result.Reason)
		}
		return result.Files
	}

	if files := report(); len(files) != 0 {
		t.Fatalf("artefatos intactos foram reportados: %v", files)
	}

	nodeModules := filepath.Join(session.WorktreePath, "node_modules")
	if err := os.Remove(nodeModules); err != nil {
		t.Fatal(err)
	}
	if files := report(); !slices.Contains(files, "node_modules") {
		t.Fatalf("link apagado não reportado: %v", files)
	}

	if err := os.Symlink(filepath.Join(root, "node_modules"), nodeModules); err != nil {
		t.Fatal(err)
	}
	if files := report(); len(files) != 0 {
		t.Fatalf("link restaurado ainda reportado: %v", files)
	}

	if err := os.Remove(nodeModules); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nodeModules, 0o755); err != nil {
		t.Fatal(err)
	}
	if files := report(); !slices.Contains(files, "node_modules") {
		t.Fatalf("link trocado por diretório não reportado: %v", files)
	}

	if err := os.RemoveAll(nodeModules); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "seed.txt"), nodeModules); err != nil {
		t.Fatal(err)
	}
	if files := report(); !slices.Contains(files, "node_modules") {
		t.Fatalf("link reapontado não reportado: %v", files)
	}

	if err := os.Remove(nodeModules); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "node_modules"), nodeModules); err != nil {
		t.Fatal(err)
	}
	writeFile(t, session.WorktreePath, "bunfig.toml", "y\n")
	if files := report(); !slices.Contains(files, "bunfig.toml") {
		t.Fatalf("conteúdo reescrito não reportado: %v", files)
	}
}

func TestOverlayWorkingTree(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, "rastreado.txt", "original\n")
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-qm", "seed")

	writeFile(t, root, "rastreado.txt", "modificado\n")
	writeFile(t, root, "novo.txt", "novo\n")
	writeFile(t, root, ".todo/nota.txt", "interno\n")

	session, err := sandbox.CreateGitWorktreeSandbox(context.Background(), "RUN-overlay", root)
	if err != nil {
		t.Fatalf("criar sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = sandbox.CleanupGitWorktreeSandbox(context.Background(), session, root)
	})

	result := OverlayWorkingTree(root, session.WorktreePath, nil)
	if !result.OK {
		t.Fatalf("overlay falhou: %s", result.Reason)
	}
	data, err := os.ReadFile(filepath.Join(session.WorktreePath, "rastreado.txt"))
	if err != nil || string(data) != "modificado\n" {
		t.Fatalf("diff rastreado não aplicado: %q (%v)", data, err)
	}
	data, err = os.ReadFile(filepath.Join(session.WorktreePath, "novo.txt"))
	if err != nil || string(data) != "novo\n" {
		t.Fatalf("arquivo novo não copiado: %q (%v)", data, err)
	}
	if _, err := os.Stat(filepath.Join(session.WorktreePath, ".todo")); !os.IsNotExist(err) {
		t.Fatalf(".todo foi para o sandbox: %v", err)
	}
	if slices.Contains(result.Files, ".todo/nota.txt") {
		t.Fatalf("estado do harness listado no overlay: %v", result.Files)
	}
}

func TestOverlayWorkingTreeRespectsSkipAndIgnore(t *testing.T) {
	root := newRepo(t)
	writeFile(t, root, ".gitignore", "ignorado.log\n")
	writeFile(t, root, "seed.txt", "seed\n")
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-qm", "seed")

	writeFile(t, root, "referencia.txt", "a\n")
	writeFile(t, root, "normal.txt", "normal\n")
	writeFile(t, root, "ignorado.log", "log\n")

	session, err := sandbox.CreateGitWorktreeSandbox(context.Background(), "RUN-overlay-skip", root)
	if err != nil {
		t.Fatalf("criar sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = sandbox.CleanupGitWorktreeSandbox(context.Background(), session, root)
	})

	result := OverlayWorkingTree(root, session.WorktreePath, HarnessArtifacts{"referencia.txt": "x"})
	if !result.OK {
		t.Fatalf("overlay falhou: %s", result.Reason)
	}
	data, err := os.ReadFile(filepath.Join(session.WorktreePath, "normal.txt"))
	if err != nil || string(data) != "normal\n" {
		t.Fatalf("arquivo novo não copiado: %q (%v)", data, err)
	}
	if !slices.Contains(result.Files, "normal.txt") {
		t.Fatalf("inventário sem normal.txt: %v", result.Files)
	}
	if _, err := os.Stat(filepath.Join(session.WorktreePath, "referencia.txt")); !os.IsNotExist(err) {
		t.Fatal("skip não impediu a cópia")
	}
	if slices.Contains(result.Files, "referencia.txt") {
		t.Fatalf("arquivo pulado listado: %v", result.Files)
	}
	if _, err := os.Stat(filepath.Join(session.WorktreePath, "ignorado.log")); !os.IsNotExist(err) {
		t.Fatal("arquivo ignorado foi copiado")
	}
}

func TestOverlayWorkingTreeFailsOutsideRepository(t *testing.T) {
	root := t.TempDir()
	sandboxDir := t.TempDir()
	result := OverlayWorkingTree(root, sandboxDir, nil)
	if result.OK {
		t.Fatal("overlay em diretório não Git deveria falhar")
	}
	if result.Reason == "" {
		t.Fatal("falha sem motivo")
	}
}
