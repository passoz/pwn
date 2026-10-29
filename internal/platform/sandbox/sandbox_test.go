package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s em %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("criar diretório de %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("gravar %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler %s: %v", path, err)
	}
	return string(content)
}

// initRepo cria um repositório com dois commits; a.txt termina com "b\n".
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "-c", "init.defaultBranch=main", "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Teste")
	writeFile(t, filepath.Join(dir, "a.txt"), "a\n")
	runGit(t, dir, "add", "a.txt")
	runGit(t, dir, "commit", "-q", "-m", "base")
	writeFile(t, filepath.Join(dir, "a.txt"), "b\n")
	runGit(t, dir, "commit", "-q", "-am", "segundo")
	return dir
}

func requireSandboxError(t *testing.T, err error) *SandboxError {
	t.Helper()
	var sandboxErr *SandboxError
	if !errors.As(err, &sandboxErr) {
		t.Fatalf("erro = %v, quer *SandboxError", err)
	}
	if sandboxErr.Message == "" {
		t.Fatal("SandboxError sem Message")
	}
	return sandboxErr
}

func TestResolveGitDir(t *testing.T) {
	repo := initRepo(t)
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("criar %s: %v", sub, err)
	}

	tests := []struct {
		name string
		cwd  string
	}{
		{name: "raiz do repositório", cwd: repo},
		{name: "subdiretório do repositório", cwd: sub},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := strings.TrimSpace(runGit(t, test.cwd, "rev-parse", "--absolute-git-dir"))
			gitDir, ok := ResolveGitDir(context.Background(), test.cwd)
			if !ok || gitDir != want {
				t.Fatalf("ResolveGitDir(%s) = (%q, %v), quer (%q, true)", test.cwd, gitDir, ok, want)
			}
			if !filepath.IsAbs(gitDir) {
				t.Fatalf("ResolveGitDir devolveu caminho relativo %q", gitDir)
			}
		})
	}

	t.Run("fora de repositório", func(t *testing.T) {
		if gitDir, ok := ResolveGitDir(context.Background(), t.TempDir()); ok || gitDir != "" {
			t.Fatalf("ResolveGitDir = (%q, %v), quer vazio e false", gitDir, ok)
		}
	})
}

func TestCreateAndCleanup(t *testing.T) {
	repo := initRepo(t)
	ctx := context.Background()

	session, err := CreateGitWorktreeSandbox(ctx, "run-001", repo)
	if err != nil {
		t.Fatalf("CreateGitWorktreeSandbox: %v", err)
	}
	wantPath := filepath.Join(repo, ".pwn", "sandboxes", "run-001")
	if session.RunID != "run-001" {
		t.Fatalf("RunID = %q, quer run-001", session.RunID)
	}
	if !session.Created {
		t.Fatal("Created = false num worktree recém-criado")
	}
	if session.WorktreePath != wantPath {
		t.Fatalf("WorktreePath = %q, quer %q", session.WorktreePath, wantPath)
	}
	if session.BranchName != "pwn-sandbox-run-001" {
		t.Fatalf("BranchName = %q, quer pwn-sandbox-run-001", session.BranchName)
	}
	if got := readFile(t, filepath.Join(wantPath, "a.txt")); got != "b\n" {
		t.Fatalf("a.txt no sandbox = %q, quer b", got)
	}
	gitDir := strings.TrimSpace(runGit(t, wantPath, "rev-parse", "--absolute-git-dir"))
	if session.GitDir != gitDir {
		t.Fatalf("GitDir = %q, quer %q", session.GitDir, gitDir)
	}
	if got := strings.TrimSpace(runGit(t, repo, "branch", "--list", "pwn-sandbox-run-001")); got == "" {
		t.Fatal("branch pwn-sandbox-run-001 não foi criado")
	}

	if err := CleanupGitWorktreeSandbox(ctx, session, repo); err != nil {
		t.Fatalf("CleanupGitWorktreeSandbox: %v", err)
	}
	if _, err := os.Stat(wantPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("worktree ainda existe: %v", err)
	}
	if got := strings.TrimSpace(runGit(t, repo, "branch", "--list", "pwn-sandbox-run-001")); got != "" {
		t.Fatalf("branch pwn-sandbox-run-001 ainda existe: %q", got)
	}
	entries, err := os.ReadDir(filepath.Join(repo, ".pwn", "sandboxes"))
	if err != nil {
		t.Fatalf("ler .pwn/sandboxes: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf(".pwn/sandboxes tem sobras: %v", entries)
	}
}

func TestCreateSanitizesRunID(t *testing.T) {
	repo := initRepo(t)
	ctx := context.Background()

	session, err := CreateGitWorktreeSandbox(ctx, "run/1:2 é", repo)
	if err != nil {
		t.Fatalf("CreateGitWorktreeSandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = CleanupGitWorktreeSandbox(context.Background(), session, repo)
	})

	if got := filepath.Base(session.WorktreePath); got != "run_1_2__" {
		t.Fatalf("diretório do sandbox = %q, quer run_1_2__", got)
	}
	if session.BranchName != "pwn-sandbox-run_1_2__" {
		t.Fatalf("branch = %q, quer pwn-sandbox-run_1_2__", session.BranchName)
	}
	if session.GitDir == "" {
		t.Fatal("GitDir vazio")
	}
}

func TestCreateRejectsRunIDCollision(t *testing.T) {
	repo := initRepo(t)
	ctx := context.Background()

	first, err := CreateGitWorktreeSandbox(ctx, "run-colisao", repo)
	if err != nil {
		t.Fatalf("primeiro sandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = CleanupGitWorktreeSandbox(context.Background(), first, repo)
	})

	_, err = CreateGitWorktreeSandbox(ctx, "run-colisao", repo)
	sandboxErr := requireSandboxError(t, err)
	if sandboxErr.Reason != "run id collision: worktree already exists" {
		t.Fatalf("Reason = %q, quer colisão de run id", sandboxErr.Reason)
	}
	if !strings.Contains(sandboxErr.Message, "colisão de run id") {
		t.Fatalf("Message = %q, quer aviso de colisão", sandboxErr.Message)
	}
	if !strings.Contains(sandboxErr.Message, first.WorktreePath) {
		t.Fatalf("Message = %q, quer o caminho do worktree", sandboxErr.Message)
	}
}

func TestCreateRejectsPreExistingNonWorktree(t *testing.T) {
	root := t.TempDir() // fora de repositório: rev-parse não resolve nada
	path := filepath.Join(root, ".pwn", "sandboxes", "run-x")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("criar %s: %v", path, err)
	}

	_, err := CreateGitWorktreeSandbox(context.Background(), "run-x", root)
	sandboxErr := requireSandboxError(t, err)
	if sandboxErr.Reason != "pre-existing path is not a git worktree" {
		t.Fatalf("Reason = %q, quer caminho não-worktree", sandboxErr.Reason)
	}
	if !strings.Contains(sandboxErr.Message, "Remova o diretório antes de reexecutar") {
		t.Fatalf("Message = %q, quer instrução de remoção", sandboxErr.Message)
	}
}

func TestCreateFailsOutsideGitRepository(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	root := t.TempDir()

	_, err := CreateGitWorktreeSandbox(context.Background(), "run-fail", root)
	sandboxErr := requireSandboxError(t, err)
	if !strings.Contains(strings.ToLower(sandboxErr.Reason), "not a git repository") {
		t.Fatalf("Reason = %q, quer a recusa do git", sandboxErr.Reason)
	}
	if !strings.Contains(sandboxErr.Message, "Execução bloqueada") {
		t.Fatalf("Message = %q, quer o aviso de bloqueio", sandboxErr.Message)
	}
	if sandboxErr.RunID != "run-fail" {
		t.Fatalf("RunID = %q, quer run-fail", sandboxErr.RunID)
	}
}

func TestCreateUsesCurrentDirectoryWhenRootIsEmpty(t *testing.T) {
	repo := initRepo(t)
	t.Chdir(repo)

	session, err := CreateGitWorktreeSandbox(context.Background(), "run-cwd", "")
	if err != nil {
		t.Fatalf("CreateGitWorktreeSandbox: %v", err)
	}
	t.Cleanup(func() {
		_ = CleanupGitWorktreeSandbox(context.Background(), session, repo)
	})

	want := filepath.Join(repo, ".pwn", "sandboxes", "run-cwd")
	if session.WorktreePath != want {
		t.Fatalf("WorktreePath = %q, quer %q", session.WorktreePath, want)
	}
}

func TestCleanupWithoutCreatedIsNoOp(t *testing.T) {
	dir := t.TempDir()
	session := Session{RunID: "run-x", WorktreePath: dir, BranchName: "pwn-sandbox-run-x"}

	if err := CleanupGitWorktreeSandbox(context.Background(), session, ""); err != nil {
		t.Fatalf("CleanupGitWorktreeSandbox: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("diretório foi tocado: %v", err)
	}
}

func TestCleanupWorksWithCanceledContext(t *testing.T) {
	repo := initRepo(t)
	session, err := CreateGitWorktreeSandbox(context.Background(), "run-cancel", repo)
	if err != nil {
		t.Fatalf("CreateGitWorktreeSandbox: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CleanupGitWorktreeSandbox(ctx, session, repo); err != nil {
		t.Fatalf("CleanupGitWorktreeSandbox: %v", err)
	}
	if _, err := os.Stat(session.WorktreePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("worktree ainda existe com contexto cancelado: %v", err)
	}
}

func fakeBwrap(t *testing.T, exit int) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "bwrap")
	content := fmt.Sprintf("#!/bin/sh\nexit %d\n", exit)
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("gravar bwrap falso: %v", err)
	}
	return dir
}

func TestIsBwrapSupported(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) string
		want  bool
	}{
		{
			name:  "bwrap ausente do PATH",
			setup: func(t *testing.T) string { return t.TempDir() },
			want:  false,
		},
		{
			name:  "bwrap aceita o envelope",
			setup: func(t *testing.T) string { return fakeBwrap(t, 0) },
			want:  true,
		},
		{
			name:  "bwrap recusa o envelope",
			setup: func(t *testing.T) string { return fakeBwrap(t, 1) },
			want:  false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PATH", test.setup(t))
			if got := IsBwrapSupported(); got != test.want {
				t.Fatalf("IsBwrapSupported() = %v, quer %v", got, test.want)
			}
		})
	}
}

func TestWrapWithBwrapMasksAndBinds(t *testing.T) {
	cwd := t.TempDir()
	realCwd, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatalf("EvalSymlinks do cwd: %v", err)
	}
	verifierKey := filepath.Join(cwd, ".pwn", ".verifier_key")
	writeFile(t, verifierKey, "segredo")

	home := t.TempDir()
	for _, name := range []string{".ssh", ".aws"} {
		if err := os.MkdirAll(filepath.Join(home, name), 0o700); err != nil {
			t.Fatalf("criar %s: %v", name, err)
		}
	}
	extra := t.TempDir()
	realExtra, err := filepath.EvalSymlinks(extra)
	if err != nil {
		t.Fatalf("EvalSymlinks do extra: %v", err)
	}

	command, args := WrapWithBwrap("node", []string{"-e", "1"}, cwd, BwrapOptions{
		HomeDir:         home,
		ExtraWritePaths: []string{extra, filepath.Join(home, "inexistente")},
	})
	if command != "bwrap" {
		t.Fatalf("command = %q, quer bwrap", command)
	}

	want := []string{
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--bind", realCwd, realCwd,
		"--chdir", realCwd,
		"--unshare-pid",
		"--die-with-parent",
		"--tmpfs", filepath.Join(home, ".ssh"),
		"--tmpfs", filepath.Join(home, ".aws"),
		"--ro-bind", "/dev/null", filepath.Join(realCwd, ".pwn", ".verifier_key"),
		"--bind", realExtra, realExtra,
		"--unshare-net",
		"--", "node", "-e", "1",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("args =\n%v\nquer\n%v", args, want)
	}
}

func TestWrapWithBwrapAllowNetwork(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir() // sem .ssh e .aws: nada a mascarar

	command, args := WrapWithBwrap("true", nil, cwd, BwrapOptions{HomeDir: home, AllowNetwork: true})
	if command != "bwrap" {
		t.Fatalf("command = %q, quer bwrap", command)
	}
	if slices.Contains(args, "--unshare-net") {
		t.Fatalf("args = %v, rede deveria estar liberada", args)
	}
	if slices.Contains(args, "/dev/null") {
		t.Fatalf("args = %v, sem chave do verificador não há máscara", args)
	}
	tail := args[len(args)-2:]
	if tail[0] != "--" || tail[1] != "true" {
		t.Fatalf("fim dos args = %v, quer [-- true]", tail)
	}
}

func TestWrapWithBwrapResolvesCWDSymlink(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("criar %s: %v", realDir, err)
	}
	resolved, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("criar symlink: %v", err)
	}

	_, args := WrapWithBwrap("true", nil, link, BwrapOptions{HomeDir: t.TempDir()})
	if slices.Contains(args, link) {
		t.Fatalf("args = %v, caminho do symlink não pode ir para o bwrap", args)
	}
	chdir := slices.Index(args, "--chdir")
	if chdir < 0 || chdir+1 >= len(args) || args[chdir+1] != resolved {
		t.Fatalf("args = %v, quer --chdir %s", args, resolved)
	}
}
