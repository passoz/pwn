package gitx

import (
	"context"
	"fmt"
	"strings"
)

// GitDir devolve o diretório git absoluto do repositório do Runner
// (`git rev-parse --absolute-git-dir`).
func (r *Runner) GitDir(ctx context.Context) (string, error) {
	return r.output(ctx, "rev-parse", "--absolute-git-dir")
}

// Head devolve o commit apontado por HEAD.
func (r *Runner) Head(ctx context.Context) (string, error) {
	return r.output(ctx, "rev-parse", "HEAD")
}

// Show devolve o conteúdo de spec, por exemplo `HEAD:arquivo.txt` ou um commit.
func (r *Runner) Show(ctx context.Context, spec string) ([]byte, error) {
	return r.bytes(ctx, "show", spec)
}

// IsAncestor informa se ancestor é ancestral de descendant
// (`git merge-base --is-ancestor`). Referência inexistente devolve erro.
func (r *Runner) IsAncestor(ctx context.Context, ancestor, descendant string) (bool, error) {
	args := []string{"merge-base", "--is-ancestor", ancestor, descendant}
	res, err := r.Run(ctx, args, Options{})
	if err != nil {
		return false, err
	}
	switch res.Exit {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, &ExitError{Args: args, Result: res}
	}
}

// DiffOptions descreve uma comparação de árvores.
type DiffOptions struct {
	// Base é a referência de comparação. Vazio compara com o índice ou a
	// working tree, conforme Cached.
	Base string
	// Cached compara o índice em vez da working tree (`--cached`).
	Cached bool
	// Binary inclui o conteúdo binário no patch (`--binary`).
	Binary bool
	// NameOnly lista só os caminhos (`--name-only`).
	NameOnly bool
	// NameStatus lista o código e o caminho (`--name-status`).
	NameStatus bool
	// NoRenames lista a origem de um rename como remoção (`--no-renames`).
	NoRenames bool
	// DiffFilter restringe pelo código de status (`--diff-filter=...`).
	DiffFilter string
	// NullTerminated separa as entradas por NUL (`-z`).
	NullTerminated bool
	// Paths são os pathspecs positivos. Vazio compara a árvore inteira.
	Paths []string
	// Excludes viram `:(exclude)<entrada>`, sempre depois de Paths.
	Excludes []string
}

// Diff devolve o diff conforme opts. Use Binary para patch aplicável.
func (r *Runner) Diff(ctx context.Context, opts DiffOptions) ([]byte, error) {
	args := []string{"diff"}
	if opts.Cached {
		args = append(args, "--cached")
	}
	if opts.Binary {
		args = append(args, "--binary")
	}
	if opts.NameOnly {
		args = append(args, "--name-only")
	}
	if opts.NameStatus {
		args = append(args, "--name-status")
	}
	if opts.NoRenames {
		args = append(args, "--no-renames")
	}
	if opts.DiffFilter != "" {
		args = append(args, "--diff-filter="+opts.DiffFilter)
	}
	if opts.NullTerminated {
		args = append(args, "-z")
	}
	if opts.Base != "" {
		args = append(args, opts.Base)
	}
	args = append(args, pathspecs(opts.Paths, opts.Excludes)...)
	return r.bytes(ctx, args...)
}

// ApplyOptions descreve a aplicação de um patch recebido por stdin.
type ApplyOptions struct {
	// ThreeWay resolve o patch com a mescla de três vias (`--3way`). Um
	// conflito fica na árvore para resolução humana.
	ThreeWay bool
	// Index atualiza o índice junto com a working tree (`--index`).
	Index bool
	// Revert desfaz o patch (`-R`).
	Revert bool
}

// Apply aplica patch com `--binary` e `--whitespace=nowarn`, como o batch de
// referência. Um git que recusa o patch devolve *ExitError com o stderr.
func (r *Runner) Apply(ctx context.Context, patch []byte, opts ApplyOptions) error {
	args := []string{"apply"}
	if opts.Revert {
		args = append(args, "-R")
	}
	if opts.ThreeWay {
		args = append(args, "--3way")
	}
	if opts.Index {
		args = append(args, "--index")
	}
	args = append(args, "--binary", "--whitespace=nowarn", "-")

	res, err := r.Run(ctx, args, Options{Stdin: patch})
	if err != nil {
		return err
	}
	if !res.OK() {
		return &ExitError{Args: args, Result: res}
	}
	return nil
}

// LsFilesOptions descreve a listagem de arquivos.
type LsFilesOptions struct {
	// Others lista arquivos não rastreados (`--others`).
	Others bool
	// ExcludeStandard aplica os padrões de exclusão (`--exclude-standard`).
	ExcludeStandard bool
	// Cached lista o índice (`--cached`).
	Cached bool
	// Paths são os pathspecs positivos.
	Paths []string
	// Excludes viram `:(exclude)<entrada>`.
	Excludes []string
}

// LsFiles devolve os caminhos separados por NUL de `git ls-files`, já
// divididos. Entradas vazias são descartadas.
func (r *Runner) LsFiles(ctx context.Context, opts LsFilesOptions) ([]string, error) {
	args := []string{"ls-files"}
	if opts.Others {
		args = append(args, "--others")
	}
	if opts.ExcludeStandard {
		args = append(args, "--exclude-standard")
	}
	if opts.Cached {
		args = append(args, "--cached")
	}
	args = append(args, "-z")
	args = append(args, pathspecs(opts.Paths, opts.Excludes)...)

	out, err := r.bytes(ctx, args...)
	if err != nil {
		return nil, err
	}
	return splitNUL(out), nil
}

// StatusOptions descreve a leitura de `git status --porcelain=v1 -z`.
type StatusOptions struct {
	// Paths são os pathspecs positivos.
	Paths []string
	// Excludes viram `:(exclude)<entrada>`.
	Excludes []string
}

// StatusEntry é uma entrada de `git status --porcelain=v1`.
type StatusEntry struct {
	// Code são as duas letras XY: X é o índice e Y a working tree.
	Code string
	// Path é o caminho atual da entrada.
	Path string
	// OrigPath é a origem de um rename ou cópia; vazio nos demais casos.
	OrigPath string
}

// StatusPorcelain devolve as entradas de `git status --porcelain=v1 -z` com
// arquivos não rastreados incluídos. A saída chega separada por NUL, então um
// nome com espaço, aspas ou ` -> ` nunca é confundido com outro campo.
func (r *Runner) StatusPorcelain(ctx context.Context, opts StatusOptions) ([]StatusEntry, error) {
	args := []string{"status", "--porcelain=v1", "-z", "--untracked-files=all"}
	args = append(args, pathspecs(opts.Paths, opts.Excludes)...)

	out, err := r.bytes(ctx, args...)
	if err != nil {
		return nil, err
	}
	return ParsePorcelain(out), nil
}

// ParsePorcelain interpreta `git status --porcelain=v1 -z`. Entradas inválidas
// ou truncadas são ignoradas. Em rename/cópia o primeiro caminho é o destino e
// o token seguinte a origem, como o formato -z do git define.
func ParsePorcelain(out []byte) []StatusEntry {
	tokens := strings.Split(string(out), "\x00")
	entries := make([]StatusEntry, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if len(token) < 4 {
			continue
		}
		entry := StatusEntry{Code: token[:2], Path: token[3:]}
		if entry.Code[0] == 'R' || entry.Code[0] == 'C' {
			i++
			if i < len(tokens) {
				entry.OrigPath = tokens[i]
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// WorktreeAddOptions descreve a criação de um worktree.
type WorktreeAddOptions struct {
	// Path é o diretório do worktree novo.
	Path string
	// Branch é o nome do branch criado com `-b`. Vazio usa o branch da ref.
	Branch string
	// Ref é o commit ou branch de partida. Vazio usa o HEAD.
	Ref string
	// Force reutiliza um caminho já registrado (`--force`).
	Force bool
	// Detach cria o worktree com HEAD destacado (`--detach`).
	Detach bool
}

// WorktreeAdd cria um worktree em opts.Path.
func (r *Runner) WorktreeAdd(ctx context.Context, opts WorktreeAddOptions) error {
	args := []string{"worktree", "add"}
	if opts.Force {
		args = append(args, "--force")
	}
	if opts.Detach {
		args = append(args, "--detach")
	}
	if opts.Branch != "" {
		args = append(args, "-b", opts.Branch)
	}
	args = append(args, opts.Path)
	if opts.Ref != "" {
		args = append(args, opts.Ref)
	}
	return r.mustSucceed(ctx, args)
}

// WorktreeRemove remove o worktree em path. force remove mesmo com alterações.
func (r *Runner) WorktreeRemove(ctx context.Context, path string, force bool) error {
	args := []string{"worktree", "remove"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, path)
	return r.mustSucceed(ctx, args)
}

// BranchDelete apaga o branch local. force usa `-D` (apaga mesmo sem merge).
func (r *Runner) BranchDelete(ctx context.Context, name string, force bool) error {
	flag := "-d"
	if force {
		flag = "-D"
	}
	return r.mustSucceed(ctx, []string{"branch", flag, name})
}

// mustSucceed executa git e exige código de saída zero.
func (r *Runner) mustSucceed(ctx context.Context, args []string) error {
	res, err := r.Run(ctx, args, Options{})
	if err != nil {
		return err
	}
	if !res.OK() {
		return &ExitError{Args: args, Result: res}
	}
	return nil
}

// pathspecs monta o separador `--`, os caminhos positivos e as exclusões, na
// mesma ordem do runGit de referência. Devolve nil quando não há pathspec.
func pathspecs(paths, excludes []string) []string {
	if len(paths) == 0 && len(excludes) == 0 {
		return nil
	}
	args := []string{"--"}
	args = append(args, paths...)
	for _, exclude := range excludes {
		args = append(args, fmt.Sprintf(":(exclude)%s", exclude))
	}
	return args
}

// splitNUL divide a saída separada por NUL e descarta entradas vazias.
func splitNUL(out []byte) []string {
	raw := strings.Split(string(out), "\x00")
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}
