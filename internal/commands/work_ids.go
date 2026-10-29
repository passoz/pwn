package commands

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// workArtifactPatterns são as trilhas de artefatos que compartilham o espaço de
// IDs de Work, como em src/core/work-manifest.ts.
var workArtifactPatterns = []struct {
	directory string
	pattern   *regexp.Regexp
}{
	{".work", regexp.MustCompile(`^(\d{4})\.json$`)},
	{".sources", regexp.MustCompile(`^(\d{4})-.+\.md$`)},
	{".prompts", regexp.MustCompile(`^(\d{4})-change\.md$`)},
	{".todo", regexp.MustCompile(`^(\d{4})-tasks\.md$`)},
}

var workIDPattern = regexp.MustCompile(`^\d{4}$`)

// existingWorkIDs lista os diretórios de `.pwn/work` que têm conteúdo. Um
// diretório vazio não é um Work existente e não desloca a numeração.
//
// A ordem é a do sistema de arquivos, como fs.readdirSync na referência. Um
// diretório ausente não é erro; falha de leitura é propagada.
func existingWorkIDs(rootDir string) ([]string, error) {
	baseDir := filepath.Join(rootDir, ".pwn", "work")
	directory, err := os.Open(baseDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("commands: ler %s: %w", baseDir, err)
	}
	defer func() { _ = directory.Close() }()

	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("commands: ler %s: %w", baseDir, err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		workDir := filepath.Join(baseDir, entry.Name())
		children, err := os.ReadDir(workDir)
		if err != nil {
			return nil, fmt.Errorf("commands: ler %s: %w", workDir, err)
		}
		if len(children) == 0 {
			continue
		}
		ids = append(ids, entry.Name())
	}
	return ids, nil
}

// allWorkIDs lista os Work IDs conhecidos em qualquer trilha de artefatos.
// `.pwn/work/<NNNN>/` compartilha o espaço de IDs do manifest.
func allWorkIDs(rootDir string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, track := range workArtifactPatterns {
		trackDir := filepath.Join(rootDir, track.directory)
		entries, err := os.ReadDir(trackDir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("commands: ler %s: %w", trackDir, err)
		}
		// os.ReadDir ordena pelo nome; o conjunto é ordenado no fim, como o
		// sort da referência.
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			match := track.pattern.FindStringSubmatch(entry.Name())
			if match != nil {
				seen[match[1]] = struct{}{}
			}
		}
	}

	workRoot := filepath.Join(rootDir, ".pwn", "work")
	entries, err := os.ReadDir(workRoot)
	if errors.Is(err, fs.ErrNotExist) {
		entries = nil
	} else if err != nil {
		return nil, fmt.Errorf("commands: ler %s: %w", workRoot, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !workIDPattern.MatchString(entry.Name()) {
			continue
		}
		workDir := filepath.Join(workRoot, entry.Name())
		children, err := os.ReadDir(workDir)
		if err != nil {
			return nil, fmt.Errorf("commands: ler %s: %w", workDir, err)
		}
		if len(children) > 0 {
			seen[entry.Name()] = struct{}{}
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// latestWorkID devolve o maior Work ID conhecido, com quatro dígitos. Sem IDs,
// devolve "0001", como a referência.
func latestWorkID(rootDir string) (string, error) {
	ids, err := allWorkIDs(rootDir)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "0001", nil
	}
	maxNum := 0
	for _, id := range ids {
		number, err := strconv.Atoi(id)
		if err != nil {
			continue
		}
		if number > maxNum {
			maxNum = number
		}
	}
	if maxNum == 0 {
		return ids[len(ids)-1], nil
	}
	return fmt.Sprintf("%04d", maxNum), nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
