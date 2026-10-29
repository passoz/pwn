package assets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/passoz/pwn/internal/platform/jsonx"
)

var (
	compactOnce sync.Once
	compactLaws map[string][]byte

	digestOnce  sync.Once
	digestValue string
)

// LawsDigest is the deterministic hash of every embedded law.
//
// It follows src/core/validator.ts: SHA-256 over each law name followed by the
// law serialized as compact JSON, truncated to 16 hex characters. Any change
// to any embedded law changes the hash.
func LawsDigest() string {
	digestOnce.Do(func() {
		compacted := compactLawsAll()
		hasher := sha256.New()
		for _, name := range lawNames {
			hasher.Write([]byte(name))
			hasher.Write(compacted[name])
		}
		digestValue = hex.EncodeToString(hasher.Sum(nil))[:16]
	})
	return digestValue
}

// FindLawDrift lists the laws whose on-disk copy under rootDir/schemas differs
// from the embedded copy. A missing schemas/ directory yields no drift, which
// mirrors validator.ts when no disk copy follows the verifier.
//
// The embedded copy is authoritative. The disk copy exists so a human can
// review and diff it; editing it without rebuilding the verifier would turn a
// law edit into a gate bypass.
func FindLawDrift(rootDir string) []string {
	dir := filepath.Join(rootDir, "schemas")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}

	compacted := compactLawsAll()
	var drifted []string
	for _, name := range lawNames {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				drifted = append(drifted, name+" (ausente no disco)")
			} else {
				drifted = append(drifted, name+" (ilegível)")
			}
			continue
		}
		disk, err := jsonx.Insertion(data)
		if err != nil {
			drifted = append(drifted, name+" (JSON inválido)")
			continue
		}
		if !bytes.Equal(disk, compacted[name]) {
			drifted = append(drifted, name)
		}
	}
	return drifted
}

// AssertLawsPinned returns an error when the embedded laws diverge from the
// copies under rootDir/schemas. It replaces the process exit of
// assertLawsPinned in src/core/validator.ts, so callers decide how to fail.
func AssertLawsPinned(rootDir string) error {
	drifted := FindLawDrift(rootDir)
	if len(drifted) == 0 {
		return nil
	}
	return fmt.Errorf(
		"leis embutidas divergem de schemas/ no disco: %s. "+
			"A cópia embutida é a que vale. Reconstrua o harness para adotar a edição, ou reverta o arquivo.",
		strings.Join(drifted, ", "),
	)
}

func compactLawsAll() map[string][]byte {
	compactOnce.Do(func() {
		compactLaws = make(map[string][]byte, len(lawNames))
		for _, name := range lawNames {
			data, ok := Schema(name)
			if !ok {
				panic("assets: embedded law not readable: " + name)
			}
			compacted, err := jsonx.Insertion(data)
			if err != nil {
				panic("assets: embedded law is not valid JSON: " + name + ": " + err.Error())
			}
			compactLaws[name] = compacted
		}
	})
	return compactLaws
}
