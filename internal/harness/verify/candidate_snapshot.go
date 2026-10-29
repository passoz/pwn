package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf16"

	"github.com/passoz/pwn/internal/platform/jsonx"
)

// HarnessStatePaths é o estado do próprio harness: não é entrada executável e
// não entra no snapshot.
var HarnessStatePaths = []string{".git", ".pwn", ".todo", ".work", "queue", ".pwn-verifier"}

// DependencyPaths são as dependências: materializadas à parte e resumidas em
// DependencyDigest.
var DependencyPaths = []string{"node_modules"}

// DependencyManifests são os arquivos que descrevem a árvore de dependências.
var DependencyManifests = []string{"package.json", "bun.lock", "bun.lockb", "bunfig.toml", "tsconfig.json"}

// SnapshotEntry é uma entrada da árvore executável.
type SnapshotEntry struct {
	Path   string  `json:"path"`
	Kind   string  `json:"kind"`
	Mode   int     `json:"mode"`
	SHA256 *string `json:"sha256,omitempty"`
	Target *string `json:"target,omitempty"`
}

// CandidateSnapshot é o estado completo da árvore executável.
type CandidateSnapshot struct {
	Version int             `json:"version"`
	Files   []SnapshotEntry `json:"files"`
	Digest  string          `json:"digest"`
}

// DependencyFile é o hash de um manifesto de dependências. Nil indica manifesto
// ausente.
type DependencyFile struct {
	Path   string  `json:"path"`
	SHA256 *string `json:"sha256"`
}

// DependencyDigest resume os manifestos de dependências.
type DependencyDigest struct {
	Files  []DependencyFile `json:"files"`
	Digest string           `json:"digest"`
}

// lessUTF16 ordena strings como o operador relacional do JavaScript: por
// unidades de código UTF-16, não por bytes UTF-8.
func lessUTF16(a, b string) bool {
	left := utf16.Encode([]rune(a))
	right := utf16.Encode([]rune(b))
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return len(left) < len(right)
}

func excludedRoot(target string) bool {
	for _, entry := range HarnessStatePaths {
		if entry == target {
			return true
		}
	}
	for _, entry := range DependencyPaths {
		if entry == target {
			return true
		}
	}
	return false
}

func walkSnapshot(rootDir, relative string, output *[]SnapshotEntry, count *int) error {
	if *count > 200_000 {
		return fmt.Errorf("snapshot excedeu o limite de entradas (200000)")
	}
	absolute := filepath.Join(rootDir, relative)
	stats, err := os.Lstat(absolute)
	if err != nil {
		return fmt.Errorf("verifier: ler %s: %w", absolute, err)
	}
	if stats.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(absolute)
		if err != nil {
			return fmt.Errorf("verifier: ler o vínculo %s: %w", absolute, err)
		}
		*output = append(*output, SnapshotEntry{
			Path:   relative,
			Kind:   "symlink",
			Mode:   int(stats.Mode().Perm()),
			Target: new(target),
		})
		return nil
	}
	if stats.IsDir() {
		entries, err := os.ReadDir(absolute)
		if err != nil {
			return fmt.Errorf("verifier: listar %s: %w", absolute, err)
		}
		sort.Slice(entries, func(i, j int) bool {
			return lessUTF16(entries[i].Name(), entries[j].Name())
		})
		for _, entry := range entries {
			if entry.IsDir() && excludedRoot(entry.Name()) && filepath.Dir(relative) == "." {
				continue
			}
			child := entry.Name()
			if relative != "." {
				child = filepath.Join(relative, child)
			}
			if err := walkSnapshot(rootDir, child, output, count); err != nil {
				return err
			}
		}
		return nil
	}
	if !stats.Mode().IsRegular() {
		// Sockets, fifos e dispositivos não são entrada de build.
		return nil
	}
	*count++
	data, err := os.ReadFile(absolute)
	if err != nil {
		return fmt.Errorf("verifier: ler %s: %w", absolute, err)
	}
	*output = append(*output, SnapshotEntry{
		Path:   relative,
		Kind:   "file",
		Mode:   int(stats.Mode().Perm()),
		SHA256: new(digestBytes(data)),
	})
	return nil
}

func snapshotDigest(files []SnapshotEntry) (string, error) {
	canonical := make([]SnapshotEntry, len(files))
	copy(canonical, files)
	sort.Slice(canonical, func(i, j int) bool {
		return lessUTF16(canonical[i].Path, canonical[j].Path)
	})
	data, err := jsonx.Insertion(canonical)
	if err != nil {
		return "", fmt.Errorf("verifier: serializar o snapshot: %w", err)
	}
	return digestBytes(data), nil
}

// CaptureSnapshot captura a árvore executável: caminho, tipo, modo e conteúdo.
func CaptureSnapshot(rootDir string) (CandidateSnapshot, error) {
	files := make([]SnapshotEntry, 0, 64)
	count := 0
	if err := walkSnapshot(rootDir, ".", &files, &count); err != nil {
		return CandidateSnapshot{}, err
	}
	digest, err := snapshotDigest(files)
	if err != nil {
		return CandidateSnapshot{}, err
	}
	return CandidateSnapshot{Version: 1, Files: files, Digest: digest}, nil
}

// CaptureDependencyDigest resume os manifestos que vinculam a árvore de
// dependências. Sem isso, trocar uma dependência entre a avaliação e o uso
// passaria despercebido.
func CaptureDependencyDigest(rootDir string) (DependencyDigest, error) {
	files := make([]DependencyFile, 0, len(DependencyManifests))
	for _, relative := range DependencyManifests {
		absolute := filepath.Join(rootDir, relative)
		info, err := os.Lstat(absolute)
		present := err == nil && info.Mode().IsRegular()
		var digest *string
		if present {
			data, err := os.ReadFile(absolute)
			if err != nil {
				return DependencyDigest{}, fmt.Errorf("verifier: ler %s: %w", absolute, err)
			}
			digest = new(digestBytes(data))
		}
		files = append(files, DependencyFile{Path: relative, SHA256: digest})
	}
	data, err := jsonx.Insertion(files)
	if err != nil {
		return DependencyDigest{}, fmt.Errorf("verifier: serializar as dependências: %w", err)
	}
	return DependencyDigest{Files: files, Digest: digestBytes(data)}, nil
}

// PresentDependencyPaths devolve as dependências existentes que o sandbox
// precisa montar.
func PresentDependencyPaths(rootDir string) []string {
	present := make([]string, 0, len(DependencyPaths))
	for _, relative := range DependencyPaths {
		absolute := filepath.Join(rootDir, relative)
		if _, err := os.Stat(absolute); err == nil {
			present = append(present, absolute)
		}
	}
	return present
}

// MaterializeSnapshot materializa o snapshot em um diretório descartável: só o
// que foi registrado é copiado, então nada que o candidato crie depois entra na
// avaliação.
func MaterializeSnapshot(snapshot CandidateSnapshot, destination, source string) error {
	for _, entry := range snapshot.Files {
		target := filepath.Join(destination, entry.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
			return fmt.Errorf("verifier: criar %s: %w", filepath.Dir(target), err)
		}
		if entry.Kind == "symlink" {
			value := ""
			if entry.Target != nil {
				value = *entry.Target
			}
			if err := os.Symlink(value, target); err != nil {
				return fmt.Errorf("verifier: criar o vínculo %s: %w", target, err)
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join(source, entry.Path))
		if err != nil {
			return fmt.Errorf("verifier: ler %s: %w", filepath.Join(source, entry.Path), err)
		}
		if err := os.WriteFile(target, data, os.FileMode(entry.Mode)); err != nil {
			return fmt.Errorf("verifier: gravar %s: %w", target, err)
		}
		if err := os.Chmod(target, os.FileMode(entry.Mode)); err != nil {
			return fmt.Errorf("verifier: ajustar modo de %s: %w", target, err)
		}
	}
	return nil
}
