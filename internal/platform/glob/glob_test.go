package glob_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/platform/glob"
)

// TestMatchParity porta os casos de tests/glob-utils.test.ts.
func TestMatchParity(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		// src/** casa com src/ e subdiretórios.
		{"src/** arquivo direto", "src/cli.ts", "src/**", true},
		{"src/** subdiretório", "src/core/sandbox.ts", "src/**", true},
		{"src/** profundidade", "src/a/b/c/d.ts", "src/**", true},

		// src/** NÃO casa com src-foo/bar.ts.
		{"src/** não vaza prefixo", "src-foo/bar.ts", "src/**", false},
		{"src/** não casa outro diretório", "notsrc/cli.ts", "src/**", false},

		// src/*.ts casa apenas arquivos .ts diretos em src/.
		{"src/*.ts direto 1", "src/cli.ts", "src/*.ts", true},
		{"src/*.ts direto 2", "src/sandbox.ts", "src/*.ts", true},
		{"src/*.ts não atravessa barra", "src/core/sandbox.ts", "src/*.ts", false},
		{"src/*.ts não casa outra extensão", "src/cli.js", "src/*.ts", false},

		// *.ts casa .ts no nível raiz.
		{"*.ts raiz", "cli.ts", "*.ts", true},
		{"*.ts não casa aninhado", "src/cli.js", "*.ts", false},

		// .git/** bloqueia tudo dentro de .git.
		{".git/** config", ".git/config", ".git/**", true},
		{".git/** fundo", ".git/objects/pack/file", ".git/**", true},
		{".git/** não casa outro .gitignore", "src/.gitignore", ".git/**", false},

		// package.json casa com nome literal.
		{"package.json literal", "package.json", "package.json", true},
		{"package.json não aninhado", "src/package.json", "package.json", false},

		// tests/** casa com testes em qualquer profundidade.
		{"tests/** direto", "tests/cli.test.ts", "tests/**", true},
		{"tests/** fundo", "tests/core/sandbox.test.ts", "tests/**", true},
		{"tests/** não casa src/tests", "src/tests/foo.ts", "tests/**", false},

		// Alternação {a,b} casa cada alternativa.
		{"{a,b} a", "src/a.ts", "src/{a,b}.ts", true},
		{"{a,b} b", "src/b.ts", "src/{a,b}.ts", true},
		{"{a,b} c", "src/c.ts", "src/{a,b}.ts", false},
		{"{a,b} extensão diferente", "src/a.tsx", "src/{a,b}.ts", false},

		// Alternativas aceitam curingas e aninhamento.
		{"*.{ts,js} ts", "a.ts", "*.{ts,js}", true},
		{"*.{ts,js} js", "a.js", "*.{ts,js}", true},
		{"*.{ts,js} rb", "a.rb", "*.{ts,js}", false},
		{"*.{pem,key} key", "a.key", "*.{pem,key}", true},
		{"{a,{b,c}} b", "b", "{a,{b,c}}", true},
		{"{a,{b,c}} c", "c", "{a,{b,c}}", true},
		{"{a,{b,c}} fecha literal", "a}", "{a,{b,c}}", false},

		// Classe de caracteres é opaca para chaves e vírgulas.
		{"classe vírgula", "a,b", "{a[,]b}", true},
		{"classe fecha chave", "b", "{a[}],b}", true},
		{"classe fecha chave literal", "a}", "{a[}],b}", true},
		{"classe abre chave", "a{", "{a[{],b}", true},
		{"classe abre chave outra alternativa", "b", "{a[{],b}", true},

		// Casos extras de borda cobertos pela paridade com o TypeScript.
		{"**/ casa diretório vazio", "src/", "src/**/", true},
		{"**/ exige barra final", "src/a", "src/**/", false},
		{"**/ meio", "src/a/b", "src/**/b", true},
		{"**/ início", "a/b", "**/b", true},
		{"**/ início direto", "b", "**/b", true},
		{"**/ sem prefixo válido", "/b", "**/b", false},
		{"**/ prefixo com barra dupla", "a//b", "**/b", true},
		{"**/ não é prefixo de arquivo", "a/b", "a**/b", false},
		{"**/ prefixo vazio", "ab", "a**/b", true},
		{"**/ casa barra dupla", "a//b", "a**/b", true},
		{"** vazio", "", "**", true},
		{"** tudo", "src/a/b", "**", true},
		{"src/** não casa src", "src", "src/**", false},
		{"src/** casa src/", "src/", "src/**", true},
		{"** exclui terminador de linha", "a\nb", "a**b", false},
		{"* inclui terminador de linha", "a\nb", "a*b", true},
		{"? inclui terminador de linha", "a\nb", "a?b", true},
		{"? casa unidade UTF-16", "é", "?", true},
		{"? não casa par substituto", "😀", "?", false},
		{"* casa par substituto", "😀", "*", true},
		{"classe não casa fora do BMP", "😀", "[😀]", false},
		{"classe range", "b", "[a-c]", true},
		{"classe range fora", "d", "[a-c]", false},
		{"classe negação", "x", "[^x]", false},
		{"classe negação outra", "y", "[^x]", true},
		{"classe exclamação é literal", "x", "[!x]", true},
		{"classe vazia nunca casa", "5", "[]", false},
		{"classe negada vazia casa tudo", "\n", "[^]", true},
		{"classe sem fechamento é literal", "[", "[", true},
		{"classe sem fechamento não casa outro", "a", "[", false},
		{"classe vazia com sufixo nunca casa", "5]", "[]]", false},
		{"classe vazia com sufixo nunca casa 2", "]", "[]]", false},
		{"ponto é literal", "axb", "a.b", false},
		{"ponto literal positivo", "a.b", "a.b", true},
		{"pipe é literal", "ab", "a|b", false},
		{"pipe literal positivo", "a|b", "a|b", true},
		{"barra invertida normaliza no padrão", "a/b", `a\b`, true},
		{"barra invertida normalizada não escapa", "a*b", `a\*b`, false},
		{"barra invertida normalizada não escapa 2", "aXb", `a\*b`, false},
		{"padrão vazio casa caminho vazio", "", "", true},
		{"padrão vazio não casa caminho", "a", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := glob.Match(tt.path, tt.pattern)
			if err != nil {
				t.Fatalf("Match(%q, %q) devolveu erro: %v", tt.path, tt.pattern, err)
			}
			if got != tt.want {
				t.Fatalf("Match(%q, %q) = %v, quer %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestCompileReuse garante que o padrão compilado pode ser reutilizado e que
// Match(path, pattern) equivale a Compile + (*Pattern).Match.
func TestCompileReuse(t *testing.T) {
	p, err := glob.Compile("src/**/*.ts")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if p.Source() != "src/**/*.ts" {
		t.Fatalf("Source() = %q", p.Source())
	}
	for _, tt := range []struct {
		path string
		want bool
	}{
		{"src/a.ts", true},
		{"src/a/b.ts", true},
		{"x.ts", false},
	} {
		if got := p.Match(tt.path); got != tt.want {
			t.Fatalf("p.Match(%q) = %v, quer %v", tt.path, got, tt.want)
		}
		got, err := glob.Match(tt.path, "src/**/*.ts")
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if got != tt.want {
			t.Fatalf("Match(%q) = %v, quer %v", tt.path, got, tt.want)
		}
	}
}

// scopeResult espelha o veredito de checkFileAgainstScope para os casos de
// segurança. A normalização de `./` e `../` pertence ao contrato, não ao glob.
type scopeResult struct {
	allowed   bool
	violation string
}

func checkScope(t *testing.T, file string, writeAllow, writeDeny []string) scopeResult {
	t.Helper()
	for _, pattern := range writeDeny {
		matched, err := glob.Match(file, pattern)
		if err != nil {
			t.Fatalf("padrão deny inválido %q: %v", pattern, err)
		}
		if matched {
			return scopeResult{allowed: false, violation: "write_deny"}
		}
	}
	for _, pattern := range writeAllow {
		matched, err := glob.Match(file, pattern)
		if err != nil {
			t.Fatalf("padrão allow inválido %q: %v", pattern, err)
		}
		if matched {
			return scopeResult{allowed: true}
		}
	}
	return scopeResult{allowed: false, violation: "not_in_write_allow"}
}

// TestSecurityWriteDeny porta os testes de regressão de segurança do TypeScript.
func TestSecurityWriteDeny(t *testing.T) {
	t.Run("alternação bloqueia de fato", func(t *testing.T) {
		if got := checkScope(t, "secrets/a", []string{"**"}, []string{"secrets/{a,b}"}); got.allowed || got.violation != "write_deny" {
			t.Fatalf("secrets/a = %+v, quer deny write_deny", got)
		}
		if got := checkScope(t, "secrets/c", []string{"**"}, []string{"secrets/{a,b}"}); !got.allowed {
			t.Fatalf("secrets/c = %+v, quer allowed", got)
		}
	})

	t.Run("curinga dentro da alternação bloqueia de fato", func(t *testing.T) {
		if got := checkScope(t, "secrets/a.key", []string{"**"}, []string{"**/*.{key,pem}"}); got.allowed || got.violation != "write_deny" {
			t.Fatalf("secrets/a.key = %+v, quer deny write_deny", got)
		}
		if got := checkScope(t, "secrets/a.txt", []string{"**"}, []string{"**/*.{key,pem}"}); !got.allowed {
			t.Fatalf("secrets/a.txt = %+v, quer allowed", got)
		}
	})

	t.Run("src/** não casa src-foo/bar.ts", func(t *testing.T) {
		if got := checkScope(t, "src-foo/bar.ts", []string{"src/**"}, nil); got.allowed {
			t.Fatalf("src-foo/bar.ts = %+v, quer negação", got)
		}
	})

	t.Run("classe opaca não abre grupo", func(t *testing.T) {
		// Se a classe não fosse opaca, `{a[}],b}` seria um grupo malformado.
		if got := checkScope(t, "a}", nil, []string{"{a[}],b}"}); got.allowed || got.violation != "write_deny" {
			t.Fatalf("a} = %+v, quer deny write_deny", got)
		}
	})
}

// TestInvalidPattern garante que padrão malformado devolve erro em vez de virar
// proteção inexistente.
func TestInvalidPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    error
		message string
	}{
		{"chave sem fechamento", "*.{pem", glob.ErrUnterminatedBrace, "glob inválido"},
		{"alternativa vazia fim", "{a,}", glob.ErrEmptyAlternative, "alternativa vazia"},
		{"grupo vazio", "{}", glob.ErrEmptyAlternative, "alternativa vazia"},
		{"alternativa vazia meio", "a{,b}", glob.ErrEmptyAlternative, "alternativa vazia"},
		{"alternativa vazia aninhada", "{a,{b,}}", glob.ErrEmptyAlternative, "alternativa vazia"},
		{"intervalo invertido", "[z-a]", glob.ErrInvalidClass, "classe de caracteres inválida"},
		{"aninhamento absurdo", strings.Repeat("{a,", 200) + "b" + strings.Repeat("}", 200), glob.ErrTooDeep, "aninhamento de grupos"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := glob.Match("a.pem", tt.pattern)
			if err == nil {
				t.Fatalf("Match(%q) = %v, quer erro", tt.pattern, matched)
			}
			if matched {
				t.Fatalf("Match(%q) devolveu true junto com erro", tt.pattern)
			}
			if !errors.Is(err, glob.ErrInvalidPattern) {
				t.Fatalf("erro %v não é ErrInvalidPattern", err)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("erro %v não é %v", err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("erro %q não contém %q", err, tt.message)
			}
			if !strings.Contains(err.Error(), "glob inválido") {
				t.Fatalf("erro %q não contém %q", err, "glob inválido")
			}
			if _, cerr := glob.Compile(tt.pattern); cerr == nil {
				t.Fatalf("Compile(%q) devolveu nil", tt.pattern)
			}
		})
	}
}

// TestDeepNestingIsImmediate garante que o aninhamento absurdo é recusado de
// imediato, e não em tempo quadrático.
func TestDeepNestingIsImmediate(t *testing.T) {
	deep := strings.Repeat("{a,", 200) + "b" + strings.Repeat("}", 200)
	start := time.Now()
	_, err := glob.Match("b", deep)
	elapsed := time.Since(start)
	if !errors.Is(err, glob.ErrTooDeep) {
		t.Fatalf("erro = %v, quer ErrTooDeep", err)
	}
	if elapsed > time.Second {
		t.Fatalf("recusa levou %v, quer menos de 1s", elapsed)
	}
}

// TestNestingLimit prova a borda: 32 grupos aninhados compilam, 33 não.
func TestNestingLimit(t *testing.T) {
	nested := func(n int) string {
		return strings.Repeat("{a,", n) + "b" + strings.Repeat("}", n)
	}
	if _, err := glob.Compile(nested(32)); err != nil {
		t.Fatalf("32 níveis devolveram erro: %v", err)
	}
	if _, err := glob.Compile(nested(33)); !errors.Is(err, glob.ErrTooDeep) {
		t.Fatalf("33 níveis devolveram %v, quer ErrTooDeep", err)
	}
}

// TestHostilePatternDoesNotExplode garante que alternação ampla não trava a
// compilação nem a correspondência.
func TestHostilePatternDoesNotExplode(t *testing.T) {
	pattern := strings.Repeat("{a,b}", 32)
	start := time.Now()
	matched, err := glob.Match(strings.Repeat("a", 32), pattern)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !matched {
		t.Fatal("Match = false, quer true")
	}
	if elapsed > time.Second {
		t.Fatalf("correspondência levou %v, quer menos de 1s", elapsed)
	}
}

func FuzzMatch(f *testing.F) {
	seeds := []struct{ path, pattern string }{
		{"src/core/x.ts", "src/**/*.ts"},
		{"a,b", "{a[,]b}"},
		{"secrets/a.key", "**/*.{key,pem}"},
		{"", ""},
		{"[", "["},
		{"a\x00b", "a*b"},
		{"😀/x", "**"},
		{"a/b/c", "{a,{b,c}}/**"},
	}
	for _, s := range seeds {
		f.Add(s.path, s.pattern)
	}
	f.Fuzz(func(t *testing.T, path, pattern string) {
		matched, err := glob.Match(path, pattern)
		if err != nil && matched {
			t.Fatalf("Match(%q, %q) = true junto com erro %v", path, pattern, err)
		}
	})
}
