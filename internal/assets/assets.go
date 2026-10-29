// Package assets embeds the harness laws (the Draft-07 JSON Schemas) and
// VERSION.
//
// Go's //go:embed cannot embed files above the package directory, so the laws
// are copied verbatim into schemas/ here. TestEmbeddedLawsMatchRepository
// enforces that the copies never drift from the authoritative schemas/ and
// VERSION at the repository root.
package assets

import (
	"embed"
	"io/fs"
	"slices"
	"strings"
)

//go:embed schemas/*.json VERSION
var files embed.FS

var (
	// lawNames is sorted; fs.ReadDir returns entries ordered by name.
	lawNames = loadLawNames()
	version  = loadVersion()
)

func loadLawNames() []string {
	entries, err := fs.ReadDir(files, "schemas")
	if err != nil {
		panic("assets: read embedded schemas: " + err.Error())
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

func loadVersion() string {
	data, err := files.ReadFile("VERSION")
	if err != nil {
		panic("assets: read embedded VERSION: " + err.Error())
	}
	return string(data)
}

// Names returns the embedded law file names in sorted order. The caller owns
// the returned slice.
func Names() []string {
	return slices.Clone(lawNames)
}

// Schema returns the embedded bytes of a law. The second result is false when
// the name is not one of the embedded laws.
func Schema(name string) ([]byte, bool) {
	if !slices.Contains(lawNames, name) {
		return nil, false
	}
	data, err := files.ReadFile("schemas/" + name)
	if err != nil {
		return nil, false
	}
	return data, true
}

// Version returns the embedded VERSION without surrounding whitespace.
func Version() string {
	return strings.TrimSpace(version)
}

// VersionBytes returns the embedded VERSION bytes exactly as stored.
func VersionBytes() []byte {
	return []byte(version)
}
