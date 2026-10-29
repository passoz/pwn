// Package shellwords tokeniza e compara linhas de comando no subconjunto POSIX
// usado pelos planos: espaço separa argumentos, aspas simples são literais,
// aspas duplas aceitam escape de `"`, `\`, `$` e crase, e a barra invertida fora
// de aspas escapa o próximo caractere.
//
// O porte segue splitCommandLine, normalizeCommand, displayCommand e
// commandMatches de src/core/acceptance.ts.
package shellwords

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// shells são os interpretadores aceitos em `sh -c <texto>`.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true}

// Split tokeniza uma linha de comando. Devolve ok=false quando as aspas não
// fecham.
func Split(command string) (tokens []string, ok bool) {
	tokens = make([]string, 0, 8)
	var current strings.Builder
	inToken := false
	var quote rune
	runes := []rune(command)
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		switch quote {
		case '\'':
			if char == '\'' {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			continue
		case '"':
			if char == '"' {
				quote = 0
			} else if char == '\\' && index+1 < len(runes) && strings.ContainsRune(`"\$`+"`", runes[index+1]) {
				index++
				current.WriteRune(runes[index])
			} else {
				current.WriteRune(char)
			}
			continue
		}
		if unicode.IsSpace(char) {
			if inToken {
				tokens = append(tokens, current.String())
			}
			current.Reset()
			inToken = false
			continue
		}
		inToken = true
		switch {
		case char == '\'' || char == '"':
			quote = char
		case char == '\\' && index+1 < len(runes):
			index++
			current.WriteRune(runes[index])
		default:
			current.WriteRune(char)
		}
	}
	if quote != 0 {
		return nil, false
	}
	if inToken {
		tokens = append(tokens, current.String())
	}
	return tokens, true
}

// Normalize devolve a forma canônica de um comando: os tokens separados por um
// espaço. Quando as aspas não fecham, colapsa os espaços em branco do texto
// original, como a referência.
func Normalize(command string) string {
	trimmed := strings.TrimSpace(command)
	tokens, ok := Split(trimmed)
	if ok {
		return strings.Join(tokens, " ")
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

var plainToken = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func quoteToken(value string) string {
	if plainToken.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// Display devolve a representação legível de um argv para mensagens.
func Display(argv []string) string {
	quoted := make([]string, len(argv))
	for i, token := range argv {
		quoted[i] = quoteToken(token)
	}
	return strings.Join(quoted, " ")
}

// Match informa se o argv do operador corresponde ao comando do plano: os
// tokens são iguais, ou o operador roda exatamente o texto do plano via
// `sh -c`/`bash -c` (forma necessária para comandos com pipe, `&&` ou
// redirecionamento).
func Match(planned string, argv []string) bool {
	expected := strings.TrimSpace(planned)
	if tokens, ok := Split(expected); ok && len(tokens) == len(argv) {
		matches := true
		for i := range tokens {
			if tokens[i] != argv[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return len(argv) == 3 && shells[filepath.Base(argv[0])] && argv[1] == "-c" && strings.TrimSpace(argv[2]) == expected
}
