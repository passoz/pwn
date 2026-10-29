// Package glob implementa a correspondência de caminhos usada pelo contrato de
// escrita do pwn. É um porte de src/core/glob-utils.ts.
//
// Sintaxe suportada:
//   - `*` casa qualquer sequência sem separador de caminho;
//   - `**` casa qualquer sequência, inclusive separadores;
//   - `?` casa exatamente um caractere sem separador de caminho;
//   - `{a,b}` alternação aninhável; cada alternativa pode conter `*` e `?`;
//   - `[abc]` classe de caracteres.
//
// `\` NÃO escapa. O caminho e o padrão são normalizados de `\` para `/` antes
// da compilação, então padrões em estilo Windows funcionam. Metacaracteres de
// expressão regular (`.`, `(`, `)`, `|`, `+`, `^`, `$`) são literais.
//
// A correspondência é ancorada: o padrão precisa casar o caminho inteiro.
// `*.ts` não casa `a/b.ts`; use `**/` para qualquer profundidade.
//
// Um padrão malformado (chave `{` sem `}` correspondente, alternativa vazia,
// aninhamento acima de maxBraceDepth ou classe inválida) devolve erro em vez de
// degradar em silêncio: um `write_deny` que não casa nada é uma proteção
// inexistente, e falhar alto é o único desfecho seguro.
//
// # Implementação
//
// O padrão é compilado para um autômato finito não determinístico (NFA) e o
// matcher simula o conjunto de estados. O custo é O(len(caminho) * len(padrão))
// e não há retrocesso por expressão regular: um padrão hostil não consome tempo
// exponencial nem produz erro de compilação de regex. A mesma construção aceita
// alternação aninhada sem expandir o padrão em todas as combinações.
//
// # Unidade de caractere
//
// O matcher opera em unidades UTF-16, como o RegExp do JavaScript sem a flag
// `u`. Por isso `?` NÃO casa um caractere fora do BMP (um emoji, por exemplo),
// que o JavaScript conta como duas unidades, e uma classe `[😀]` casa metade do
// par. Usar runas de Go mudaria esse resultado observável.
package glob

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// maxBraceDepth é a profundidade máxima de aninhamento de grupos. Acima disso o
// padrão é recusado.
const maxBraceDepth = 32

// Erros sentinela devolvidos por Compile e Match. Todos satisfazem
// errors.Is(err, ErrInvalidPattern).
var (
	// ErrInvalidPattern indica um padrão glob malformado.
	ErrInvalidPattern = errors.New("glob inválido")
	// ErrUnterminatedBrace indica um `{` sem `}` correspondente.
	ErrUnterminatedBrace = fmt.Errorf("%w: %q sem %q correspondente", ErrInvalidPattern, "{", "}")
	// ErrEmptyAlternative indica um grupo com alternativa vazia, como `{a,}`.
	ErrEmptyAlternative = fmt.Errorf("%w: alternativa vazia", ErrInvalidPattern)
	// ErrTooDeep indica aninhamento de grupos acima de maxBraceDepth.
	ErrTooDeep = fmt.Errorf("%w: aninhamento de grupos", ErrInvalidPattern)
	// ErrInvalidClass indica uma classe de caracteres que o JavaScript recusaria,
	// como o intervalo invertido `[z-a]`.
	ErrInvalidClass = fmt.Errorf("%w: classe de caracteres inválida", ErrInvalidPattern)
)

// Pattern é um padrão glob compilado. Use Compile uma vez e Match quantas vezes
// precisar.
type Pattern struct {
	source string
	states []state
	start  int
	accept int
}

// Source devolve o padrão original, antes da normalização de separadores.
func (p *Pattern) Source() string { return p.source }

// Compile compila pattern. Devolve erro se o padrão for malformado.
func Compile(pattern string) (*Pattern, error) {
	normalized := normalizeSeparators(pattern)
	units := utf16.Encode([]rune(normalized))
	b := &builder{}
	start, accept, err := b.compile(units, 0)
	if err != nil {
		return nil, err
	}
	return &Pattern{source: pattern, states: b.states, start: start, accept: accept}, nil
}

// Match informa se filePath casa com pattern. Devolve erro se o padrão for
// malformado.
//
// Um padrão inválido nunca devolve um resultado booleano: um deny-list que não
// casa nada seria uma proteção inexistente.
func Match(filePath, pattern string) (bool, error) {
	p, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return p.Match(filePath), nil
}

// Match informa se filePath casa com o padrão compilado.
func (p *Pattern) Match(filePath string) bool {
	units := utf16.Encode([]rune(normalizeSeparators(filePath)))

	n := len(p.states)
	seen := make([]uint32, n)
	set := make([]int, 0, n)
	raw := make([]int, 0, n)
	stack := make([]int, 0, n)

	var epoch uint32
	raw = append(raw, p.start)
	epoch++
	set, stack = p.closure(set, raw, seen, epoch, stack)

	for _, u := range units {
		raw = raw[:0]
		for _, s := range set {
			for _, e := range p.states[s].edges {
				if e.matches(u) {
					raw = append(raw, e.to)
				}
			}
		}
		if len(raw) == 0 {
			return false
		}
		epoch++
		set, stack = p.closure(set, raw, seen, epoch, stack)
	}

	for _, s := range set {
		if s == p.accept {
			return true
		}
	}
	return false
}

// closure calcula o fechamento por épsilon de src em dst. src não pode
// compartilhar memória com dst. Devolve os novos dst e stack.
func (p *Pattern) closure(dst, src []int, seen []uint32, epoch uint32, stack []int) ([]int, []int) {
	dst = dst[:0]
	stack = append(stack[:0], src...)
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[s] == epoch {
			continue
		}
		seen[s] = epoch
		dst = append(dst, s)
		stack = append(stack, p.states[s].epsilon...)
	}
	return dst, stack
}

func normalizeSeparators(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	return strings.ReplaceAll(s, "\\", "/")
}

// state é um estado do NFA.
type state struct {
	epsilon []int
	edges   []edge
}

// edgeKind classifica a condição de uma transição de consumo.
type edgeKind uint8

const (
	edgeLiteral edgeKind = iota
	edgeNotSlash
	edgeAnyNoTerminator
	edgeClass
)

// edge é uma transição que consome uma unidade UTF-16.
type edge struct {
	to    int
	kind  edgeKind
	lit   uint16
	class *charClass
}

func (e *edge) matches(u uint16) bool {
	switch e.kind {
	case edgeLiteral:
		return u == e.lit
	case edgeNotSlash:
		return u != '/'
	case edgeAnyNoTerminator:
		return !isLineTerminator(u)
	case edgeClass:
		return e.class.matches(u)
	default:
		return false
	}
}

// charClass é uma classe `[...]` já interpretada. Os intervalos usam unidades
// UTF-16, como o JavaScript.
type charClass struct {
	negated bool
	ranges  []runeRange
}

type runeRange struct {
	lo, hi uint16
}

func (c *charClass) matches(u uint16) bool {
	hit := false
	for _, r := range c.ranges {
		if u >= r.lo && u <= r.hi {
			hit = true
			break
		}
	}
	if c.negated {
		// `[^]` não tem intervalos e casa qualquer unidade, como no JavaScript.
		return !hit
	}
	return hit
}

// isLineTerminator replica os terminadores de linha que o `.` do JavaScript
// exclui. `*` e `?`, que viram `[^/]`, continuam casando esses caracteres.
func isLineTerminator(u uint16) bool {
	switch u {
	case '\n', '\r', 0x2028, 0x2029:
		return true
	default:
		return false
	}
}

// builder acumula estados do NFA. Todos os estados são criados em ordem
// crescente de índice, mas as arestas épsilon podem apontar para trás (o
// fechamento trata isso).
type builder struct {
	states []state
}

func (b *builder) newState() int {
	b.states = append(b.states, state{})
	return len(b.states) - 1
}

func (b *builder) addEpsilon(from, to int) {
	b.states[from].epsilon = append(b.states[from].epsilon, to)
}

func (b *builder) addEdge(from int, e edge) {
	b.states[from].edges = append(b.states[from].edges, e)
}

// compile converte a sequência units em um fragmento do NFA e devolve o estado
// inicial e o final. depth é a profundidade de aninhamento de grupos.
func (b *builder) compile(units []uint16, depth int) (start, end int, err error) {
	start = b.newState()
	cur := start

	for i := 0; i < len(units); {
		u := units[i]

		switch u {
		case '*':
			if i+1 < len(units) && units[i+1] == '*' {
				if i+2 < len(units) && units[i+2] == '/' {
					// `**/` corresponde a `(?:.+/)?`: prefixo opcional de um ou
					// mais caracteres terminado em barra.
					skip := b.newState()
					first := b.newState()
					loop := b.newState()
					join := b.newState()
					b.addEpsilon(cur, skip)
					b.addEpsilon(skip, join)
					b.addEpsilon(skip, first)
					b.addEdge(first, edge{to: loop, kind: edgeAnyNoTerminator})
					b.addEdge(loop, edge{to: loop, kind: edgeAnyNoTerminator})
					b.addEdge(loop, edge{to: join, kind: edgeLiteral, lit: '/'})
					cur = join
					i += 3
				} else {
					// `**` corresponde a `.*`.
					loop := b.newState()
					join := b.newState()
					b.addEpsilon(cur, loop)
					b.addEpsilon(loop, join)
					b.addEdge(loop, edge{to: loop, kind: edgeAnyNoTerminator})
					cur = join
					i += 2
				}
				continue
			}
			// `*` corresponde a `[^/]*`.
			loop := b.newState()
			join := b.newState()
			b.addEpsilon(cur, loop)
			b.addEpsilon(loop, join)
			b.addEdge(loop, edge{to: loop, kind: edgeNotSlash})
			cur = join
			i++

		case '?':
			next := b.newState()
			b.addEdge(cur, edge{to: next, kind: edgeNotSlash})
			cur = next
			i++

		case '{':
			if depth >= maxBraceDepth {
				return 0, 0, fmt.Errorf("%w acima de %d em %s", ErrTooDeep, maxBraceDepth, quoteUnits(units))
			}
			closeIdx := findClosingBrace(units, i)
			if closeIdx < 0 {
				return 0, 0, fmt.Errorf("%w em %s", ErrUnterminatedBrace, quoteUnits(units))
			}
			alternatives := splitAlternatives(units[i+1 : closeIdx])
			for _, alternative := range alternatives {
				if len(alternative) == 0 {
					return 0, 0, fmt.Errorf("%w em %s", ErrEmptyAlternative, quoteUnits(units))
				}
			}
			fork := b.newState()
			b.addEpsilon(cur, fork)
			ends := make([]int, 0, len(alternatives))
			for _, alternative := range alternatives {
				altStart, altEnd, err := b.compile(alternative, depth+1)
				if err != nil {
					return 0, 0, err
				}
				b.addEpsilon(fork, altStart)
				ends = append(ends, altEnd)
			}
			join := b.newState()
			for _, altEnd := range ends {
				b.addEpsilon(altEnd, join)
			}
			cur = join
			i = closeIdx + 1

		case '[':
			closeIdx := findClosingBracket(units, i)
			if closeIdx < 0 {
				// `[` sem `]`: literal, como no TypeScript.
				next := b.newState()
				b.addEdge(cur, edge{to: next, kind: edgeLiteral, lit: u})
				cur = next
				i++
				continue
			}
			class, err := parseClass(units[i+1 : closeIdx])
			if err != nil {
				return 0, 0, fmt.Errorf("%w: %w em %s", ErrInvalidClass, err, quoteUnits(units))
			}
			next := b.newState()
			b.addEdge(cur, edge{to: next, kind: edgeClass, class: class})
			cur = next
			i = closeIdx + 1

		default:
			next := b.newState()
			b.addEdge(cur, edge{to: next, kind: edgeLiteral, lit: u})
			cur = next
			i++
		}
	}

	end = b.newState()
	b.addEpsilon(cur, end)
	return start, end, nil
}

// findClosingBracket devolve o índice do `]` que fecha a classe aberta em open,
// ou -1 se não houver.
func findClosingBracket(units []uint16, open int) int {
	for i := open + 1; i < len(units); i++ {
		if units[i] == ']' {
			return i
		}
	}
	return -1
}

// findClosingBrace devolve o índice do `}` que fecha o `{` de open, respeitando
// aninhamento e ignorando o conteúdo de classes `[...]`, ou -1 se não houver.
func findClosingBrace(units []uint16, open int) int {
	depth := 0
	for i := open; i < len(units); i++ {
		switch units[i] {
		case '[':
			if close := findClosingBracket(units, i); close >= 0 {
				i = close
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitAlternatives divide o corpo de um grupo nas vírgulas de primeiro nível.
// Vírgulas dentro de classes ou de grupos aninhados não separam.
func splitAlternatives(inner []uint16) [][]uint16 {
	parts := make([][]uint16, 0, 2)
	current := make([]uint16, 0, len(inner))
	depth := 0
	for i := 0; i < len(inner); i++ {
		u := inner[i]
		if u == '[' {
			if close := findClosingBracket(inner, i); close >= 0 {
				current = append(current, inner[i:close+1]...)
				i = close
				continue
			}
		}
		if u == '{' {
			depth++
		} else if u == '}' {
			depth--
		}
		if u == ',' && depth == 0 {
			parts = append(parts, current)
			current = make([]uint16, 0, len(inner))
			continue
		}
		current = append(current, u)
	}
	parts = append(parts, current)
	return parts
}

// errRangeReversed indica um intervalo de classe invertido, como `[z-a]`. O
// JavaScript lança SyntaxError para o mesmo padrão.
var errRangeReversed = errors.New("intervalo invertido")

// parseClass interpreta o conteúdo de uma classe, sem os colchetes.
func parseClass(content []uint16) (*charClass, error) {
	c := &charClass{}
	if len(content) > 0 && content[0] == '^' {
		c.negated = true
		content = content[1:]
	}
	c.ranges = make([]runeRange, 0, len(content))
	for i := 0; i < len(content); i++ {
		lo := content[i]
		if i+2 < len(content) && content[i+1] == '-' {
			hi := content[i+2]
			if hi < lo {
				return nil, fmt.Errorf("%w: [%c-%c]", errRangeReversed, rune(lo), rune(hi))
			}
			c.ranges = append(c.ranges, runeRange{lo: lo, hi: hi})
			i += 2
			continue
		}
		c.ranges = append(c.ranges, runeRange{lo: lo, hi: lo})
	}
	return c, nil
}

// quoteUnits devolve o padrão citado, como JSON.stringify no TypeScript.
func quoteUnits(units []uint16) string {
	return strconv.Quote(string(utf16.Decode(units)))
}
