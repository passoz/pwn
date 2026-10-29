// Package learnings porta o armazenamento de lições aprendidas (Teach Skills)
// de src/core/learnings.ts.
//
// O arquivo <root>/.pwn/learnings.json guarda uma lista JSON. A escrita usa
// fsx.WithFileLock e fsx.WriteFileAtomic: runs paralelas não se sobrescrevem e
// leitores nunca veem o arquivo pela metade.
package learnings

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// Category classifica a lição.
type Category string

const (
	CategoryCodeStyle    Category = "code_style"
	CategoryArchitecture Category = "architecture"
	CategoryGotcha       Category = "gotcha"
	CategoryDomainRule   Category = "domain_rule"
)

// Entry é uma lição persistida.
type Entry struct {
	ID           string   `json:"id"`
	Timestamp    string   `json:"timestamp"`
	Category     Category `json:"category"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	SourceTaskID string   `json:"sourceTaskId,omitempty"`
	Tags         []string `json:"tags"`
}

// NewEntry é uma lição ainda sem id e timestamp.
type NewEntry struct {
	Category     Category
	Title        string
	Description  string
	SourceTaskID string
	Tags         []string
}

// File garante que <rootDir>/.pwn existe e devolve o caminho do learnings.json.
func File(rootDir string) (string, error) {
	root, err := resolveRoot(rootDir)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, ".pwn")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("learnings: criar %s: %w", dir, err)
	}
	return filepath.Join(dir, "learnings.json"), nil
}

// Add acrescenta uma lição e devolve a entrada gravada.
//
// A leitura e a escrita acontecem na mesma seção crítica. O id combina o
// milissegundo atual com 3 bytes aleatórios, porque o milissegundo sozinho
// colide entre processos.
func Add(learning NewEntry, rootDir string) (Entry, error) {
	file, err := File(rootDir)
	if err != nil {
		return Entry{}, err
	}
	var added Entry
	err = fsx.WithFileLock(file, func() error {
		existing, err := Read(rootDir)
		if err != nil {
			return err
		}
		id, err := newID()
		if err != nil {
			return err
		}
		tags := learning.Tags
		if tags == nil {
			tags = []string{}
		}
		added = Entry{
			ID:           id,
			Timestamp:    nowISO(),
			Category:     learning.Category,
			Title:        learning.Title,
			Description:  learning.Description,
			SourceTaskID: learning.SourceTaskID,
			Tags:         tags,
		}
		data, err := marshalIndented(append(existing, added))
		if err != nil {
			return err
		}
		return fsx.WriteFileAtomic(file, string(data))
	}, fsx.LockOptions{})
	if err != nil {
		return Entry{}, err
	}
	return added, nil
}

// Read devolve as lições gravadas.
//
// Arquivo ausente devolve lista vazia. Falha de leitura ou JSON inválido
// devolve erro: descartar o erro apagaria as lições na próxima escrita.
func Read(rootDir string) ([]Entry, error) {
	file, err := File(rootDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("learnings: ler %s: %w", file, err)
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("learnings: decodificar %s: %w", file, err)
	}
	if entries == nil {
		return []Entry{}, nil
	}
	// O tipo do TypeScript sempre tem tags: uma lista nula relida continua
	// sendo um array na próxima escrita.
	for i := range entries {
		if entries[i].Tags == nil {
			entries[i].Tags = []string{}
		}
	}
	return entries, nil
}

func newID() (string, error) {
	var suffix [3]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("learnings: gerar id: %w", err)
	}
	return fmt.Sprintf("LRN-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(suffix[:])), nil
}

const isoLayout = "2006-01-02T15:04:05.000Z"

func nowISO() string {
	return time.Now().UTC().Format(isoLayout)
}

func resolveRoot(rootDir string) (string, error) {
	if rootDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("learnings: obter diretório atual: %w", err)
		}
		return wd, nil
	}
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("learnings: resolver %s: %w", rootDir, err)
	}
	return root, nil
}

// marshalIndented serializa com a ordem do campo e a indentação do
// JSON.stringify(value, null, 2).
func marshalIndented(value any) ([]byte, error) {
	compact, err := jsonx.Insertion(value)
	if err != nil {
		return nil, fmt.Errorf("learnings: serializar lista: %w", err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("learnings: indentar lista: %w", err)
	}
	return out.Bytes(), nil
}
