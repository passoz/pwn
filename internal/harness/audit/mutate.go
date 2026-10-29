package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passoz/pwn/internal/platform/gitx"
)

// gitPath devolve o caminho relativo à raiz no formato de `git show <rev>:<path>`.
func gitPath(filePath string) (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(current, absolute)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(relative), nil
}

// baselineFile é o conteúdo que a implementação tinha no baseline.
type baselineFile struct {
	path    string
	remove  bool
	content []byte
}

// savedFile é o conteúdo atual, restaurado ao final do mutation check.
type savedFile struct {
	path    string
	exists  bool
	content []byte
	mode    os.FileMode
}

// withoutImplementation restaura cada arquivo de implementação ao conteúdo do
// baseline, executa fn e devolve os arquivos exatamente como estavam.
func withoutImplementation[T any](state *State, fn func() (T, error)) (result T, err error) {
	commit := state.BaselineCommit
	if commit == "" {
		var zero T
		return zero, fmt.Errorf("mutation check exige baseline_commit; refaça o baseline")
	}

	git := gitx.New("")
	baseline := make([]baselineFile, 0, len(state.ImplementationFiles))
	for _, filePath := range state.ImplementationFiles {
		expected, ok := state.BaselineImplementation[filePath]
		if !ok || !expected.Exists {
			baseline = append(baseline, baselineFile{path: filePath, remove: true})
			continue
		}
		relative, err := gitPath(filePath)
		if err != nil {
			var zero T
			return zero, err
		}
		shown, runErr := git.Run(context.Background(), []string{"show", commit + ":" + relative}, gitx.Options{})
		if runErr != nil {
			var zero T
			return zero, runErr
		}
		if !shown.OK() {
			var zero T
			return zero, fmt.Errorf("mutation check: %s não está versionado em %s", filePath, shortHash(commit))
		}
		if expected.SHA256 == nil || sha256Hex(shown.Stdout) != *expected.SHA256 {
			var zero T
			return zero, fmt.Errorf(
				"mutation check: %s em %s não corresponde ao snapshot do baseline",
				filePath, shortHash(commit),
			)
		}
		baseline = append(baseline, baselineFile{path: filePath, content: shown.Stdout})
	}

	current := make([]savedFile, 0, len(state.ImplementationFiles))
	for _, filePath := range state.ImplementationFiles {
		info, statErr := os.Stat(filePath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				current = append(current, savedFile{path: filePath})
				continue
			}
			var zero T
			return zero, statErr
		}
		content, readErr := os.ReadFile(filePath)
		if readErr != nil {
			var zero T
			return zero, readErr
		}
		current = append(current, savedFile{path: filePath, exists: true, content: content, mode: info.Mode()})
	}

	defer func() {
		failures := restoreFiles(current)
		if len(failures) > 0 {
			var zero T
			result = zero
			err = fmt.Errorf(
				"DATA SAFETY: failed to restore implementation after mutation check: %s",
				joinFailures(failures),
			)
		}
	}()

	for _, file := range baseline {
		if file.remove {
			if removeErr := os.Remove(file.path); removeErr != nil && !os.IsNotExist(removeErr) {
				var zero T
				return zero, removeErr
			}
			continue
		}
		if mkdirErr := os.MkdirAll(filepath.Dir(file.path), 0o755); mkdirErr != nil {
			var zero T
			return zero, mkdirErr
		}
		if writeErr := os.WriteFile(file.path, file.content, 0o644); writeErr != nil {
			var zero T
			return zero, writeErr
		}
	}

	return fn()
}

func restoreFiles(files []savedFile) []string {
	failures := make([]string, 0)
	for _, file := range files {
		if !file.exists {
			if err := os.Remove(file.path); err != nil && !os.IsNotExist(err) {
				failures = append(failures, fmt.Sprintf("%s: %v", file.path, err))
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(file.path), 0o755); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", file.path, err))
			continue
		}
		if err := os.WriteFile(file.path, file.content, 0o644); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", file.path, err))
			continue
		}
		if err := os.Chmod(file.path, file.mode.Perm()); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", file.path, err))
		}
	}
	return failures
}

func joinFailures(failures []string) string {
	return strings.Join(failures, "; ")
}
