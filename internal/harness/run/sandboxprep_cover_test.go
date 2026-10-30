package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// newCoverSandbox cria um repositório com um commit e o worktree isolado.
func newCoverSandbox(t *testing.T, runID string, files map[string]string) (root string, session sandbox.Session) {
	t.Helper()
	root = newRepo(t)
	for name, content := range files {
		writeFile(t, root, name, content)
	}
	commitAll(t, root, "seed")
	session, err := sandbox.CreateGitWorktreeSandbox(context.Background(), runID, root)
	if err != nil {
		t.Fatalf("criar sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = sandbox.CleanupGitWorktreeSandbox(context.Background(), session, root)
	})
	return root, session
}

func TestPrepareSandboxFailsWhenSandboxDirectoryIsMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nao-existe")

	t.Run("node_modules", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "node_modules/pkg/index.js", "x")
		injected, err := PrepareSandbox(missing, root)
		if err == nil || !strings.Contains(err.Error(), "linkar node_modules") {
			t.Fatalf("erro = %v", err)
		}
		if injected != nil {
			t.Fatalf("falha devolveu artefatos: %v", injected)
		}
	})

	t.Run("bunfig.toml", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "bunfig.toml", "[test]\n")
		injected, err := PrepareSandbox(missing, root)
		if err == nil || !strings.Contains(err.Error(), "copiar bunfig.toml") {
			t.Fatalf("erro = %v", err)
		}
		if injected != nil {
			t.Fatalf("falha devolveu artefatos: %v", injected)
		}
	})

	t.Run("bunfig.toml ilegível", func(t *testing.T) {
		requireNotRoot(t)
		root := t.TempDir()
		writeFile(t, root, "bunfig.toml", "[test]\n")
		if err := os.Chmod(filepath.Join(root, "bunfig.toml"), 0); err != nil {
			t.Fatal(err)
		}
		_, err := PrepareSandbox(t.TempDir(), root)
		if err == nil || !strings.Contains(err.Error(), "ler bunfig.toml") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestPrepareSandboxKeepsVersionedArtifacts(t *testing.T) {
	root := t.TempDir()
	sandboxDir := t.TempDir()
	writeFile(t, root, "node_modules/pkg/index.js", "x")
	writeFile(t, root, "bunfig.toml", "da raiz\n")
	// O worktree já tem os dois: nada é injetado nem sobrescrito.
	writeFile(t, sandboxDir, "node_modules/versionado.js", "y")
	writeFile(t, sandboxDir, "bunfig.toml", "versionado\n")

	injected, err := PrepareSandbox(sandboxDir, root)
	if err != nil {
		t.Fatalf("PrepareSandbox: %v", err)
	}
	if len(injected) != 0 {
		t.Fatalf("artefatos injetados sobre arquivos existentes: %v", injected)
	}
	if data, err := os.ReadFile(filepath.Join(sandboxDir, "bunfig.toml")); err != nil || string(data) != "versionado\n" {
		t.Fatalf("bunfig.toml do worktree foi sobrescrito: %q (%v)", data, err)
	}
}

func TestPathFingerprintUnreadableFileIsAbsent(t *testing.T) {
	requireNotRoot(t)
	dir := t.TempDir()
	writeFile(t, dir, "fechado.txt", "x")
	if err := os.Chmod(filepath.Join(dir, "fechado.txt"), 0); err != nil {
		t.Fatal(err)
	}
	if got := PathFingerprint(filepath.Join(dir, "fechado.txt")); got != "absent" {
		t.Fatalf("assinatura = %q, esperava absent", got)
	}
}

func TestModifiedFilesOutsideGitRepositoryFailsClosed(t *testing.T) {
	dir := t.TempDir()
	result := ModifiedFiles(dir, filepath.Join(dir, ".git"), nil)
	if result.OK || len(result.Files) != 0 {
		t.Fatalf("diretório sem Git devolveu inventário: %+v", result)
	}
	if !strings.Contains(result.Reason, "não resolve para um repositório Git") {
		t.Fatalf("motivo = %q", result.Reason)
	}
}

func TestModifiedFilesDetectsReplacedRepository(t *testing.T) {
	_, session := newCoverSandbox(t, "RUN-anchor", map[string]string{"seed.txt": "x\n"})
	result := ModifiedFiles(session.WorktreePath, filepath.Join(t.TempDir(), "outro.git"), nil)
	if result.OK {
		t.Fatalf("âncora divergente deveria falhar: %+v", result)
	}
	if !strings.Contains(result.Reason, "árvore substituída durante a execução") {
		t.Fatalf("motivo = %q", result.Reason)
	}
}

func TestModifiedFilesFailsClosedWhenGitStatusFails(t *testing.T) {
	_, session := newCoverSandbox(t, "RUN-status", map[string]string{"seed.txt": "x\n"})
	// Índice corrompido: rev-parse ainda resolve, mas git status falha.
	if err := os.WriteFile(filepath.Join(session.GitDir, "index"), []byte("isto não é um índice git"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := ModifiedFiles(session.WorktreePath, session.GitDir, nil)
	if result.OK || len(result.Files) != 0 {
		t.Fatalf("git status com falha devolveu inventário: %+v", result)
	}
	if !strings.Contains(result.Reason, "inventário de mudanças indisponível") {
		t.Fatalf("motivo = %q", result.Reason)
	}
}

func TestOverlayWorkingTreeFailureModes(t *testing.T) {
	t.Run("patch que não aplica no sandbox", func(t *testing.T) {
		root, session := newCoverSandbox(t, "RUN-apply", map[string]string{"a.txt": "original\n"})
		writeFile(t, root, "a.txt", "da raiz\n")
		// O sandbox divergiu do HEAD no mesmo arquivo: o diff da raiz não aplica.
		writeFile(t, session.WorktreePath, "a.txt", "do sandbox\n")

		result := OverlayWorkingTree(root, session.WorktreePath, nil)
		if result.OK || !strings.Contains(result.Reason, "não foi possível aplicar a working tree no sandbox") {
			t.Fatalf("resultado = %+v", result)
		}
		if data, err := os.ReadFile(filepath.Join(session.WorktreePath, "a.txt")); err != nil || string(data) != "do sandbox\n" {
			t.Fatalf("sandbox alterado apesar da falha: %q (%v)", data, err)
		}
	})

	t.Run("diretório de destino ocupado por arquivo", func(t *testing.T) {
		root, session := newCoverSandbox(t, "RUN-mkdir", map[string]string{"seed.txt": "x\n"})
		writeFile(t, root, "pasta/novo.txt", "novo\n")
		writeFile(t, session.WorktreePath, "pasta", "sou um arquivo\n")

		result := OverlayWorkingTree(root, session.WorktreePath, nil)
		if result.OK || !strings.Contains(result.Reason, "criar o diretório de pasta/novo.txt") {
			t.Fatalf("resultado = %+v", result)
		}
	})

	t.Run("arquivo de destino ocupado por diretório", func(t *testing.T) {
		root, session := newCoverSandbox(t, "RUN-write", map[string]string{"seed.txt": "x\n"})
		writeFile(t, root, "novo.txt", "novo\n")
		if err := os.Mkdir(filepath.Join(session.WorktreePath, "novo.txt"), 0o755); err != nil {
			t.Fatal(err)
		}

		result := OverlayWorkingTree(root, session.WorktreePath, nil)
		if result.OK || !strings.Contains(result.Reason, "copiar novo.txt") {
			t.Fatalf("resultado = %+v", result)
		}
	})
}

func TestOverlayWorkingTreeCopiesUntrackedSymlinks(t *testing.T) {
	root, session := newCoverSandbox(t, "RUN-link", map[string]string{"seed.txt": "x\n"})
	if err := os.Symlink("seed.txt", filepath.Join(root, "atalho")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "exec.sh", "exit 0\n")
	if err := os.Chmod(filepath.Join(root, "exec.sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	result := OverlayWorkingTree(root, session.WorktreePath, nil)
	if !result.OK {
		t.Fatalf("overlay falhou: %s", result.Reason)
	}
	target, err := os.Readlink(filepath.Join(session.WorktreePath, "atalho"))
	if err != nil || target != "seed.txt" {
		t.Fatalf("symlink não preservado: %q (%v)", target, err)
	}
	info, err := os.Stat(filepath.Join(session.WorktreePath, "exec.sh"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("modo do arquivo novo não preservado: %v (%v)", info, err)
	}

	t.Run("destino do link já existe", func(t *testing.T) {
		other, otherSession := newCoverSandbox(t, "RUN-link-exists", map[string]string{"seed.txt": "x\n"})
		if err := os.Symlink("seed.txt", filepath.Join(other, "atalho")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, otherSession.WorktreePath, "atalho", "ocupado\n")
		failed := OverlayWorkingTree(other, otherSession.WorktreePath, nil)
		if failed.OK || !strings.Contains(failed.Reason, "copiar o link atalho") {
			t.Fatalf("resultado = %+v", failed)
		}
	})
}

func TestGitFailureDetailUsesFirstLineOrExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "stderr do git, só a primeira linha",
			err:  &gitx.ExitError{Result: gitx.Result{Stderr: "fatal: primeiro\nsegunda linha", Exit: 128}},
			want: "fatal: primeiro",
		},
		{
			name: "stderr vazio usa o código de saída",
			err:  &gitx.ExitError{Result: gitx.Result{Exit: 3}},
			want: "git exited with code 3",
		},
		{
			name: "erro embrulhado ainda é reconhecido",
			err:  errors.Join(errors.New("contexto"), &gitx.ExitError{Result: gitx.Result{Stderr: "fatal: embrulhado", Exit: 1}}),
			want: "fatal: embrulhado",
		},
		{name: "falha de infraestrutura multilinha", err: errors.New("não iniciou\ndetalhe"), want: "não iniciou"},
		{name: "falha de infraestrutura de uma linha", err: errors.New("  sem quebra  "), want: "sem quebra"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := gitFailureDetail(test.err); got != test.want {
				t.Fatalf("gitFailureDetail = %q, esperava %q", got, test.want)
			}
		})
	}
}
