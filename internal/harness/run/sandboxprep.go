package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// HarnessArtifacts mapeia caminho relativo → assinatura do que o harness criou
// no sandbox em PrepareSandbox.
type HarnessArtifacts map[string]string

// ModifiedFilesResult é o inventário de mudanças. OK=false significa que a
// detecção falhou; nunca deve ser confundido com "sem mudanças".
type ModifiedFilesResult struct {
	OK     bool
	Files  []string
	Reason string
}

// OverlayResult descreve a cópia da working tree para o sandbox.
type OverlayResult struct {
	OK     bool
	Files  []string
	Reason string
}

// harnessStatePaths é o estado do próprio harness: nunca vai para o sandbox
// nem entra no inventário do diff guard.
var harnessStatePaths = []string{".pwn", ".todo", ".work", "queue/review"}

// PathFingerprint devolve a assinatura do que existe no caminho: tipo do inode,
// alvo do symlink, ou tamanho + hash do conteúdo de um arquivo regular.
//
// Filtrar artefatos do harness por nome daria passe livre permanente: o
// comando pode apagar o link criado pelo harness, pôr um arquivo no lugar e
// continuar invisível. A assinatura faz a substituição aparecer como mudança.
func PathFingerprint(target string) string {
	info, err := os.Lstat(target)
	if err != nil {
		return "absent"
	}
	mode := info.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		link, err := os.Readlink(target)
		if err != nil {
			return "absent"
		}
		return "link:" + link
	case mode.IsDir():
		return "dir"
	case mode.IsRegular():
		data, err := os.ReadFile(target)
		if err != nil {
			return "absent"
		}
		digest := sha256.Sum256(data)
		return fmt.Sprintf("file:%d:%s", info.Size(), hex.EncodeToString(digest[:])[:16])
	default:
		return "other"
	}
}

// PrepareSandbox prepara o worktree para o comando de aceitação:
//   - linka node_modules do diretório principal;
//   - copia bunfig.toml quando não versionado.
//
// Devolve a assinatura de cada caminho criado para que o diff guard ignore
// somente esses artefatos.
func PrepareSandbox(sandboxPath, rootDir string) (HarnessArtifacts, error) {
	injected := HarnessArtifacts{}

	nodeModulesSource := filepath.Join(rootDir, "node_modules")
	nodeModulesTarget := filepath.Join(sandboxPath, "node_modules")
	if pathExists(nodeModulesSource) && !pathExists(nodeModulesTarget) {
		if err := os.Symlink(nodeModulesSource, nodeModulesTarget); err != nil {
			return nil, fmt.Errorf("sandbox: linkar node_modules: %w", err)
		}
		injected["node_modules"] = PathFingerprint(nodeModulesTarget)
	}

	bunfigSource := filepath.Join(rootDir, "bunfig.toml")
	bunfigTarget := filepath.Join(sandboxPath, "bunfig.toml")
	if pathExists(bunfigSource) && !pathExists(bunfigTarget) {
		info, err := os.Stat(bunfigSource)
		if err != nil {
			return nil, fmt.Errorf("sandbox: inspecionar bunfig.toml: %w", err)
		}
		data, err := os.ReadFile(bunfigSource)
		if err != nil {
			return nil, fmt.Errorf("sandbox: ler bunfig.toml: %w", err)
		}
		if err := os.WriteFile(bunfigTarget, data, info.Mode().Perm()); err != nil {
			return nil, fmt.Errorf("sandbox: copiar bunfig.toml: %w", err)
		}
		injected["bunfig.toml"] = PathFingerprint(bunfigTarget)
	}

	return injected, nil
}

// pathExists usa Stat, como o existsSync do original: um symlink pendente não
// conta como existente.
func pathExists(target string) bool {
	_, err := os.Stat(target)
	return err == nil
}

// ModifiedFiles inventaria as mudanças dentro do sandbox.
//
// expectedGitDir é o `git rev-parse --absolute-git-dir` registrado na criação
// do sandbox. Sem essa âncora, apagar o `.git` do worktree faz o Git subir a
// árvore e resolver o repositório-pai: o `git status` então "funciona" e
// descreve outra árvore, enquanto a escrita fora de escopo fica invisível.
//
// Renames e cópias são reportados pela origem e pelo destino: mover um arquivo
// para fora do escopo também é escrita fora do escopo.
func ModifiedFiles(sandboxPath, expectedGitDir string, injected HarnessArtifacts) ModifiedFilesResult {
	ctx := context.Background()
	gitDir, ok := sandbox.ResolveGitDir(ctx, sandboxPath)
	if !ok {
		return ModifiedFilesResult{
			Reason: fmt.Sprintf("worktree %s não resolve para um repositório Git", sandboxPath),
		}
	}
	if filepath.Clean(gitDir) != filepath.Clean(expectedGitDir) {
		return ModifiedFilesResult{
			Reason: fmt.Sprintf(
				"worktree %s aponta para %s, não para o repositório do sandbox (%s) — árvore substituída durante a execução",
				sandboxPath, gitDir, expectedGitDir,
			),
		}
	}

	entries, err := gitx.New(sandboxPath).StatusPorcelain(ctx, gitx.StatusOptions{})
	if err != nil {
		// Fail-closed: um `git status` que falha significa que não sabemos o que
		// foi escrito. Lista vazia faria o diff guard aprovar um run não inspecionado.
		return ModifiedFilesResult{
			Reason: fmt.Sprintf(
				"inventário de mudanças indisponível em %s: %s",
				sandboxPath, gitFailureDetail(err),
			),
		}
	}

	files := make([]string, 0, len(entries))
	isHarnessArtifact := func(filePath string) bool {
		signature, present := injected[filePath]
		return present && signature == PathFingerprint(filepath.Join(sandboxPath, filePath))
	}
	record := func(filePath string) {
		if filePath == "" || isHarnessArtifact(filePath) {
			return
		}
		files = append(files, filePath)
	}

	for _, entry := range entries {
		if len(entry.Code) < 2 {
			continue
		}
		record(entry.Path)
		if entry.Code[0] == 'R' || entry.Code[0] == 'C' {
			record(entry.OrigPath)
		}
	}

	// Ponto cego do `git status`: ele não reporta a remoção de uma entrada que
	// nunca foi rastreada. Reconferir cada assinatura fecha esse buraco.
	for filePath, signature := range injected {
		if signature != PathFingerprint(filepath.Join(sandboxPath, filePath)) && !slices.Contains(files, filePath) {
			files = append(files, filePath)
		}
	}

	return ModifiedFilesResult{OK: true, Files: files}
}

// OverlayWorkingTree leva para o sandbox o que existe na working tree e ainda
// não foi commitado: o diff rastreado contra HEAD, inclusive deleções, e os
// arquivos novos não ignorados.
//
// skip são os artefatos já injetados por PrepareSandbox: nada é copiado por
// cima deles nem através deles.
func OverlayWorkingTree(rootDir, sandboxPath string, skip HarnessArtifacts) OverlayResult {
	ctx := context.Background()
	// gitx aplica o prefixo `:(exclude)` a cada entrada de Excludes.
	excludes := append([]string(nil), harnessStatePaths...)

	rootRunner := gitx.New(rootDir)
	rootRunner.MaxBuffer = 256 * 1024 * 1024
	patch, err := rootRunner.Diff(ctx, gitx.DiffOptions{
		Base:     "HEAD",
		Binary:   true,
		Paths:    []string{"."},
		Excludes: excludes,
	})
	if err != nil {
		return OverlayResult{
			Reason: fmt.Sprintf(
				"não foi possível ler a working tree (git diff): %s", gitFailureDetail(err),
			),
		}
	}

	applied := make([]string, 0)
	if len(patch) > 0 {
		if err := gitx.New(sandboxPath).Apply(ctx, patch, gitx.ApplyOptions{}); err != nil {
			return OverlayResult{
				Reason: fmt.Sprintf(
					"não foi possível aplicar a working tree no sandbox: %s", gitFailureDetail(err),
				),
			}
		}
		applied = append(applied, "(diff rastreado)")
	}

	untracked, err := gitx.New(rootDir).LsFiles(ctx, gitx.LsFilesOptions{
		Others:          true,
		ExcludeStandard: true,
		Paths:           []string{"."},
		Excludes:        excludes,
	})
	if err != nil {
		return OverlayResult{
			Reason: fmt.Sprintf(
				"não foi possível listar arquivos novos da working tree: %s", gitFailureDetail(err),
			),
		}
	}

	skipped := make([]string, 0, len(skip))
	for entry := range skip {
		skipped = append(skipped, entry)
	}
	for _, file := range untracked {
		if file == "" {
			continue
		}
		if slices.ContainsFunc(skipped, func(entry string) bool {
			return file == entry || strings.HasPrefix(file, entry+"/")
		}) {
			continue
		}

		source := filepath.Join(rootDir, file)
		target := filepath.Join(sandboxPath, file)
		info, err := os.Lstat(source)
		if err != nil {
			return OverlayResult{Reason: fmt.Sprintf("não foi possível ler %s: %v", file, err)}
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return OverlayResult{Reason: fmt.Sprintf("não foi possível criar o diretório de %s: %v", file, err)}
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(source)
			if err != nil {
				return OverlayResult{Reason: fmt.Sprintf("não foi possível ler o link %s: %v", file, err)}
			}
			if err := os.Symlink(link, target); err != nil {
				return OverlayResult{Reason: fmt.Sprintf("não foi possível copiar o link %s: %v", file, err)}
			}
		case info.Mode().IsRegular():
			data, err := os.ReadFile(source)
			if err != nil {
				return OverlayResult{Reason: fmt.Sprintf("não foi possível ler %s: %v", file, err)}
			}
			if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
				return OverlayResult{Reason: fmt.Sprintf("não foi possível copiar %s: %v", file, err)}
			}
			if err := os.Chmod(target, info.Mode().Perm()); err != nil {
				return OverlayResult{Reason: fmt.Sprintf("não foi possível ajustar o modo de %s: %v", file, err)}
			}
		}
		applied = append(applied, file)
	}

	return OverlayResult{OK: true, Files: applied}
}

// gitFailureDetail extrai o detalhe curto de uma falha do gitx: stderr do
// git, o código de saída ou a falha de infraestrutura. Como o original, usa
// somente a primeira linha.
func gitFailureDetail(err error) string {
	var exitErr *gitx.ExitError
	if errors.As(err, &exitErr) {
		if detail := firstLine(exitErr.Result.Stderr); detail != "" {
			return detail
		}
		return fmt.Sprintf("git exited with code %d", exitErr.Result.Exit)
	}
	return firstLine(err.Error())
}

func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return strings.TrimSpace(value[:index])
	}
	return strings.TrimSpace(value)
}
