package run

import (
	"regexp"
	"strings"

	"github.com/passoz/pwn/internal/platform/glob"
)

var globMetacharacters = regexp.MustCompile(`[*?\[\]{}]`)

// globPrefix separa os segmentos literais antes do primeiro metacaractere.
func globPrefix(pattern string) (prefix []string, literal bool) {
	normalized := strings.ReplaceAll(pattern, "\\", "/")
	normalized = strings.TrimPrefix(normalized, "./")
	segments := make([]string, 0)
	for _, segment := range strings.Split(normalized, "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	firstGlob := -1
	for index, segment := range segments {
		if globMetacharacters.MatchString(segment) {
			firstGlob = index
			break
		}
	}
	if firstGlob == -1 {
		return segments, true
	}
	return segments[:firstGlob], false
}

// GlobsMayOverlap aplica a heurística conservadora do original: dois globs
// "podem sobrepor" quando os prefixos literais são um prefixo do outro.
// Caminho literal é testado exatamente contra o outro glob.
//
// false significa disjunção garantida; true pode ser falso positivo — quem
// decide paralelismo trata como conflito. Um padrão malformado devolve true,
// porque tratar como disjunto liberaria escrita concorrente sobre a mesma área.
func GlobsMayOverlap(a, b string) bool {
	prefixA, literalA := globPrefix(a)
	prefixB, literalB := globPrefix(b)

	common := min(len(prefixA), len(prefixB))
	for index := range common {
		if prefixA[index] != prefixB[index] {
			return false
		}
	}
	if literalA && literalB {
		return len(prefixA) == len(prefixB)
	}
	if literalA {
		matched, err := glob.Match(strings.Join(prefixA, "/"), b)
		if err != nil {
			return true
		}
		return matched
	}
	if literalB {
		matched, err := glob.Match(strings.Join(prefixB, "/"), a)
		if err != nil {
			return true
		}
		return matched
	}
	return true
}
