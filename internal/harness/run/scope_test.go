package run

import "testing"

func TestGlobsMayOverlap(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "diretórios disjuntos", a: "src/**", b: "tests/**", want: false},
		{name: "mesmo glob", a: "src/**", b: "src/**", want: true},
		{name: "literal coberto pelo glob", a: "src/a.ts", b: "src/*.ts", want: true},
		{name: "literal fora do glob", a: "src/a.ts", b: "tests/*.ts", want: false},
		{name: "literais irmãos com nomes diferentes", a: "src/a/b.ts", b: "src/a/c.ts", want: false},
		{name: "literais em árvores distintas", a: "docs/a.md", b: "src/b.ts", want: false},
		{name: "glob sem separador não cobre caminho aninhado", a: "*", b: "src/a", want: false},
		{name: "alternação que não cobre o caminho", a: "src/{a,b}/x.ts", b: "src/z/x.ts", want: false},
		{name: "prefixos diferentes por sufixo", a: "src/**", b: "srcx/**", want: false},
		{name: "glob cobre literal sob o mesmo prefixo", a: "src/**", b: "src/a.ts", want: true},
		{name: "literal contra glob profundo", a: "src/a.ts", b: "src/**/*.ts", want: true},
		{name: "barra invertida normalizada", a: "src\\a.ts", b: "src/*.ts", want: true},
		{name: "padrão malformado é conflito conservador", a: "src/{a", b: "src/a", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := GlobsMayOverlap(test.a, test.b); got != test.want {
				t.Fatalf("GlobsMayOverlap(%q, %q) = %t, esperava %t", test.a, test.b, got, test.want)
			}
		})
	}
}
