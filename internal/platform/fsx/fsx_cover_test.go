package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignora permissões de diretório")
	}
}

func TestIsDirectEntryArgsEdgeCases(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "prog")
	if err := os.WriteFile(prog, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(prog, link); err != nil {
		t.Skipf("symlink indisponível: %v", err)
	}

	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	os.Args = []string{link}
	if !IsDirectEntry(prog) {
		t.Error("symlink para o mesmo arquivo deve contar como entrypoint")
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("y"), 0o755); err != nil {
		t.Fatal(err)
	}
	if IsDirectEntry(other) {
		t.Error("arquivo diferente não pode ser entrypoint")
	}
	os.Args = []string{}
	if IsDirectEntry(prog) {
		t.Error("sem argv não pode ser entrypoint")
	}
	os.Args = []string{""}
	if IsDirectEntry(prog) {
		t.Error("argv[0] vazio não pode ser entrypoint")
	}
	os.Args = []string{filepath.Join(dir, "inexistente")}
	if IsDirectEntry(prog) {
		t.Error("argv[0] inexistente não pode ser entrypoint")
	}
}

func TestWriteFileAtomicErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "arquivo")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(filepath.Join(file, "filho"), "c"); err == nil {
		t.Error("diretório pai é arquivo: esperava erro")
	}

	// Alvo é um diretório: o rename falha e o tmp é removido.
	target := filepath.Join(dir, "alvo")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, "c"); err == nil {
		t.Error("alvo diretório não vazio: esperava erro")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "arquivo" && e.Name() != "alvo" {
			t.Errorf("tmp não removido: %s", e.Name())
		}
	}
}

func TestWriteFileAtomicTmpWriteFails(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := WriteFileAtomic(filepath.Join(dir, "f"), "c"); err == nil {
		t.Error("diretório sem escrita: esperava erro")
	}
}

func TestWithFileLockErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "arquivo")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	err := WithFileLock(filepath.Join(file, "t"), func() error { called = true; return nil }, LockOptions{})
	if err == nil || called {
		t.Errorf("pai é arquivo: esperava erro sem chamar fn (err=%v, called=%v)", err, called)
	}
	var timeout *LockTimeoutError
	if errors.As(err, &timeout) {
		t.Error("erro de diretório não é timeout")
	}
}

func TestWithFileLockMkdirPermissionDenied(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	called := false
	err := WithFileLock(filepath.Join(dir, "t"), func() error { called = true; return nil }, LockOptions{})
	if err == nil || called {
		t.Fatalf("esperava erro sem chamar fn (err=%v, called=%v)", err, called)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("erro deveria embrulhar ErrPermission: %v", err)
	}
}

func TestAppendLineOpenFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "alvo")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := AppendLine(target, "x", LockOptions{}); err == nil {
		t.Fatal("alvo é diretório: esperava erro")
	}
	if _, err := os.Stat(target + ".lock"); !os.IsNotExist(err) {
		t.Errorf("trava deve ser liberada após erro: %v", err)
	}
}

func TestAppendLineParentIsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AppendLine(filepath.Join(file, "t"), "x", LockOptions{}); err == nil {
		t.Fatal("esperava erro")
	}
}
