package audit

import (
	"sort"

	"github.com/passoz/pwn/internal/platform/jsonx"
)

// uniqueSorted devolve os valores sem repetição em ordem lexicográfica.
func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// jsonCanonical serializa com as chaves ordenadas em todos os níveis.
func jsonCanonical(value any) ([]byte, error) {
	return jsonx.Canonical(value)
}

// shortHash devolve o prefixo de 12 caracteres usado nas mensagens.
func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
