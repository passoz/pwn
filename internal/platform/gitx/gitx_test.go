package gitx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

func TestRun(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	tests := []struct {
		name     string
		args     []string
		wantExit int
	}{
		{name: "rev-parse HEAD", args: []string{"rev-parse", "HEAD"}, wantExit: 0},
		{name: "referência inexistente", args: []string{"rev-parse", "--verify", "nao-existe"}, wantExit: 128},
		{name: "argumento não passa por shell", args: []string{"rev-parse", "--verify", "$(echo HEAD)"}, wantExit: 128},
		{name: "argumento com backtick não passa por shell", args: []string{"rev-parse", "--verify", "`echo HEAD`"}, wantExit: 128},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := runner.Run(context.Background(), test.args, Options{})
			if err != nil {
				t.Fatalf("Run devolveu erro de infraestrutura: %v", err)
			}
			if res.Exit != test.wantExit {
				t.Fatalf("exit = %d, quer %d (stderr %q)", res.Exit, test.wantExit, res.Stderr)
			}
			if res.OK() != (test.wantExit == 0) {
				t.Fatalf("Result.OK() = %v com exit %d", res.OK(), res.Exit)
			}
			if test.wantExit == 0 {
				if got := strings.TrimSpace(string(res.Stdout)); len(got) != 40 && len(got) != 64 {
					t.Fatalf("stdout = %q, quer hash completo", got)
				}
				return
			}
			if res.Stderr == "" {
				t.Fatal("stderr vazio numa falha do git")
			}
		})
	}
}

func TestRunDirOverride(t *testing.T) {
	repoA := initRepo(t)
	repoB := initRepo(t)
	writeFile(t, filepath.Join(repoB, "b.txt"), "novo\n")
	runGit(t, repoB, "add", "b.txt")
	runGit(t, repoB, "commit", "-q", "-m", "terceiro")

	runner := New(repoA)
	headA, err := runner.Head(context.Background())
	if err != nil {
		t.Fatalf("Head em A: %v", err)
	}
	res, err := runner.Run(context.Background(), []string{"rev-parse", "HEAD"}, Options{Dir: repoB})
	if err != nil {
		t.Fatalf("Run com Dir: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got == headA {
		t.Fatalf("Dir não foi aplicado: mesmo HEAD %s em A e B", headA)
	}
}

func TestRunWithoutGitBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	res, err := New(t.TempDir()).Run(context.Background(), []string{"--version"}, Options{})
	if err == nil {
		t.Fatalf("erro esperado sem git, Result %+v", res)
	}
	if res.Exit != -1 {
		t.Fatalf("exit = %d, quer -1 quando o processo não inicia", res.Exit)
	}
}

func TestRunCanceledContext(t *testing.T) {
	repo := initRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := New(repo).Run(ctx, []string{"rev-parse", "HEAD"}, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("erro = %v, quer context.Canceled", err)
	}
}

func TestRunMaxBuffer(t *testing.T) {
	repo := initRepo(t)
	runner := &Runner{Dir: repo, MaxBuffer: 8}
	_, err := runner.Run(context.Background(), []string{"rev-parse", "HEAD"}, Options{})
	if err == nil || !strings.Contains(err.Error(), "excedeu") {
		t.Fatalf("erro = %v, quer excesso de buffer", err)
	}
}

func TestHeadShowGitDir(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)

	head, err := runner.Head(context.Background())
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head != strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD")) {
		t.Fatalf("Head = %q, diverge do git", head)
	}

	gitDir, err := runner.GitDir(context.Background())
	if err != nil {
		t.Fatalf("GitDir: %v", err)
	}
	realRepo, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if gitDir != filepath.Join(realRepo, ".git") {
		t.Fatalf("GitDir = %q, quer %q", gitDir, filepath.Join(realRepo, ".git"))
	}

	content, err := runner.Show(context.Background(), "HEAD:a.txt")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if string(content) != "b\n" {
		t.Fatalf("Show = %q, quer %q", content, "b\n")
	}

	_, err = runner.Show(context.Background(), "HEAD:nao-existe.txt")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("erro = %v, quer *ExitError", err)
	}
}

func TestGitDirOutsideRepo(t *testing.T) {
	_, err := New(t.TempDir()).GitDir(context.Background())
	if err == nil {
		t.Fatal("GitDir fora de repositório devolveu sucesso")
	}
}

func TestDiffAndApply(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	ctx := context.Background()
	writeFile(t, filepath.Join(repo, "a.txt"), "c\n")

	patch, err := runner.Diff(ctx, DiffOptions{Base: "HEAD", Binary: true})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !strings.Contains(string(patch), "-b\n") || !strings.Contains(string(patch), "+c") {
		t.Fatalf("patch inesperado:\n%s", patch)
	}

	nameOnly, err := runner.Diff(ctx, DiffOptions{Base: "HEAD", NameOnly: true, NoRenames: true})
	if err != nil {
		t.Fatalf("Diff NameOnly: %v", err)
	}
	if got := strings.TrimSpace(string(nameOnly)); got != "a.txt" {
		t.Fatalf("NameOnly = %q, quer a.txt", got)
	}

	runGit(t, repo, "checkout", "--", "a.txt")
	if err := runner.Apply(ctx, patch, ApplyOptions{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := readFile(t, filepath.Join(repo, "a.txt")); got != "c\n" {
		t.Fatalf("a.txt após Apply = %q, quer c", got)
	}
	if err := runner.Apply(ctx, patch, ApplyOptions{Revert: true}); err != nil {
		t.Fatalf("Apply Revert: %v", err)
	}
	if got := readFile(t, filepath.Join(repo, "a.txt")); got != "b\n" {
		t.Fatalf("a.txt após Revert = %q, quer b", got)
	}

	if err := runner.Apply(ctx, []byte("isto não é um patch\n"), ApplyOptions{}); err == nil {
		t.Fatal("Apply de lixo devolveu sucesso")
	}
}

func TestDiffCachedNullTerminated(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	writeFile(t, filepath.Join(repo, "a.txt"), "c\n")
	runGit(t, repo, "add", "a.txt")

	out, err := runner.Diff(context.Background(), DiffOptions{
		Base:           "HEAD",
		Cached:         true,
		NameStatus:     true,
		NoRenames:      true,
		NullTerminated: true,
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	fields := strings.Split(string(out), "\x00")
	if len(fields) < 3 || fields[0] != "M" || fields[1] != "a.txt" {
		t.Fatalf("Diff -z = %q, quer [M a.txt]", fields)
	}
}

func TestLsFiles(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	writeFile(t, filepath.Join(repo, ".gitignore"), "ignorado.log\n")
	writeFile(t, filepath.Join(repo, "novo.txt"), "novo\n")
	writeFile(t, filepath.Join(repo, "ignorado.log"), "x\n")

	files, err := runner.LsFiles(context.Background(), LsFilesOptions{Others: true, ExcludeStandard: true})
	if err != nil {
		t.Fatalf("LsFiles: %v", err)
	}
	got := strings.Join(files, ",")
	if !strings.Contains(got, "novo.txt") || !strings.Contains(got, ".gitignore") {
		t.Fatalf("LsFiles = %v, quer novo.txt e .gitignore", files)
	}
	if strings.Contains(got, "ignorado.log") {
		t.Fatalf("LsFiles incluiu arquivo ignorado: %v", files)
	}

	tracked, err := runner.LsFiles(context.Background(), LsFilesOptions{Cached: true})
	if err != nil {
		t.Fatalf("LsFiles Cached: %v", err)
	}
	if len(tracked) != 1 || tracked[0] != "a.txt" {
		t.Fatalf("LsFiles Cached = %v, quer [a.txt]", tracked)
	}
}

func TestStatusPorcelain(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	ctx := context.Background()
	writeFile(t, filepath.Join(repo, "novo.txt"), "novo\n")
	runGit(t, repo, "mv", "a.txt", "renomeado.txt")

	entries, err := runner.StatusPorcelain(ctx, StatusOptions{})
	if err != nil {
		t.Fatalf("StatusPorcelain: %v", err)
	}

	byPath := make(map[string]StatusEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	tests := []struct {
		name     string
		path     string
		wantCode string
		wantOrig string
	}{
		{name: "rename", path: "renomeado.txt", wantCode: "R ", wantOrig: "a.txt"},
		{name: "não rastreado", path: "novo.txt", wantCode: "??"},
		{name: "a.txt sumiu da working tree", path: "a.txt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, ok := byPath[test.path]
			if test.wantCode == "" {
				if ok {
					t.Fatalf("%s não deveria aparecer, veio %+v", test.path, entry)
				}
				return
			}
			if !ok {
				t.Fatalf("%s ausente; entradas %+v", test.path, entries)
			}
			if entry.Code != test.wantCode {
				t.Fatalf("code = %q, quer %q", entry.Code, test.wantCode)
			}
			if entry.OrigPath != test.wantOrig {
				t.Fatalf("OrigPath = %q, quer %q", entry.OrigPath, test.wantOrig)
			}
		})
	}
}

func TestStatusPorcelainExcludes(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	writeFile(t, filepath.Join(repo, "novo.txt"), "novo\n")
	writeFile(t, filepath.Join(repo, ".pwn", "estado.json"), "{}\n")

	entries, err := runner.StatusPorcelain(context.Background(), StatusOptions{
		Paths:    []string{"."},
		Excludes: []string{".pwn"},
	})
	if err != nil {
		t.Fatalf("StatusPorcelain: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Path, ".pwn/") {
			t.Fatalf("exclusão ignorada: %+v", entry)
		}
	}
	if len(entries) != 1 || entries[0].Path != "novo.txt" {
		t.Fatalf("entradas = %+v, quer só novo.txt", entries)
	}
}

func TestWorktreeAddRemoveBranchDelete(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	ctx := context.Background()
	worktree := filepath.Join(t.TempDir(), "worktree")

	if err := runner.WorktreeAdd(ctx, WorktreeAddOptions{Path: worktree, Branch: "pwn-teste", Ref: "HEAD"}); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	if got := readFile(t, filepath.Join(worktree, "a.txt")); got != "b\n" {
		t.Fatalf("a.txt no worktree = %q, quer b", got)
	}
	gitDir, err := New(worktree).GitDir(ctx)
	if err != nil {
		t.Fatalf("GitDir no worktree: %v", err)
	}
	if gitDir == "" {
		t.Fatal("GitDir vazio no worktree")
	}

	if err := runner.WorktreeRemove(ctx, worktree, true); err != nil {
		t.Fatalf("WorktreeRemove: %v", err)
	}
	if _, err := os.Stat(worktree); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("worktree ainda existe: %v", err)
	}

	if err := runner.BranchDelete(ctx, "pwn-teste", true); err != nil {
		t.Fatalf("BranchDelete: %v", err)
	}
	res, err := runner.Run(ctx, []string{"rev-parse", "--verify", "pwn-teste"}, Options{})
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	if res.OK() {
		t.Fatal("branch pwn-teste ainda existe")
	}

	if err := runner.WorktreeAdd(ctx, WorktreeAddOptions{Path: worktree, Branch: "pwn-teste", Ref: "HEAD"}); err != nil {
		t.Fatalf("WorktreeAdd de novo: %v", err)
	}
	if err := runner.BranchDelete(ctx, "pwn-teste", true); err == nil {
		t.Fatal("BranchDelete de branch em uso devolveu sucesso")
	}
}

func TestIsAncestor(t *testing.T) {
	repo := initRepo(t)
	runner := New(repo)
	ctx := context.Background()
	head, err := runner.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	parent := strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD~1"))

	tests := []struct {
		name       string
		ancestor   string
		descendant string
		want       bool
	}{
		{name: "pai alcança o HEAD", ancestor: parent, descendant: head, want: true},
		{name: "HEAD não alcança o pai", ancestor: head, descendant: parent, want: false},
		{name: "commit alcança ele mesmo", ancestor: head, descendant: head, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := runner.IsAncestor(ctx, test.ancestor, test.descendant)
			if err != nil {
				t.Fatalf("IsAncestor: %v", err)
			}
			if got != test.want {
				t.Fatalf("IsAncestor = %v, quer %v", got, test.want)
			}
		})
	}

	_, err = runner.IsAncestor(ctx, "nao-existe", head)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("referência inválida: erro = %v, quer *ExitError", err)
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
