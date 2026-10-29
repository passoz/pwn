package shellwords

import (
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
		ok      bool
	}{
		{"aspas simples mantêm espaço", "bun test 'a b.test.mjs'", []string{"bun", "test", "a b.test.mjs"}, true},
		{"aspas duplas aceitam escape", `"valor com \"aspas\""`, []string{`valor com "aspas"`}, true},
		{"barra fora de aspas escapa", `echo a\ b`, []string{"echo", "a b"}, true},
		{"barra dentro de aspas simples é literal", `echo 'a\b'`, []string{"echo", `a\b`}, true},
		{"aspas simples dentro de duplas", `echo "a'b"`, []string{"echo", "a'b"}, true},
		{"aspas duplas sem escape de barra", `echo "a\nb"`, []string{"echo", `a\nb`}, true},
		{"aspas duplas não fechadas", `echo "aspas`, nil, false},
		{"aspas simples não fechadas", `echo 'aspas`, nil, false},
		{"vazio", "", []string{}, true},
		{"só espaço", "  ", []string{}, true},
		{"espaços em excesso", "  bun   test  ", []string{"bun", "test"}, true},
		{"token vazio entre aspas", "echo ''", []string{"echo", ""}, true},
		{"conecta aspas", `a"b c"d`, []string{"ab cd"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := Split(test.command)
			if ok != test.ok {
				t.Fatalf("ok = %v, want %v", ok, test.ok)
			}
			if test.ok && !reflect.DeepEqual(got, test.want) {
				t.Fatalf("tokens = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"bun    test   tests/x.test.ts", "bun test tests/x.test.ts"},
		{"bun test 'a b.test.mjs'", "bun test a b.test.mjs"},
		{`echo "aspas`, `echo "aspas`},
	}
	for _, test := range tests {
		if got := Normalize(test.command); got != test.want {
			t.Fatalf("Normalize(%q) = %q, want %q", test.command, got, test.want)
		}
	}
}

func TestDisplay(t *testing.T) {
	tests := []struct {
		argv []string
		want string
	}{
		{[]string{"bun", "test", "tests/x.test.ts"}, "bun test tests/x.test.ts"},
		{[]string{"echo", "a b"}, "echo 'a b'"},
		{[]string{"echo", "it's"}, `echo 'it'"'"'s'`},
		{[]string{""}, "''"},
	}
	for _, test := range tests {
		if got := Display(test.argv); got != test.want {
			t.Fatalf("Display(%#v) = %q, want %q", test.argv, got, test.want)
		}
	}
}

func TestMatch(t *testing.T) {
	const planned = "bun test tests/x.test.ts"
	tests := []struct {
		name    string
		planned string
		argv    []string
		want    bool
	}{
		{"mesmos tokens", planned, []string{"bun", "test", "tests/x.test.ts"}, true},
		{"bash -c com o texto do plano", planned, []string{"bash", "-c", planned}, true},
		{"caminho absoluto do shell", planned, []string{"/bin/sh", "-c", "  " + planned + "  "}, true},
		{"sh -c divergente", planned, []string{"sh", "-c", "bun test tests/outro.test.ts"}, false},
		{"programa diferente", planned, []string{"node", "test", "tests/x.test.ts"}, false},
		{"aspas no plano", "bun test 'a b.test.mjs'", []string{"bun", "test", "a b.test.mjs"}, true},
		{"aspas não fechadas e sem shell", `bun "x`, []string{"bun", `"x`}, false},
		{"shell não aceito", planned, []string{"fish", "-c", planned}, false},
		{"plano com espaços nas pontas", " " + planned + " ", []string{"bun", "test", "tests/x.test.ts"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Match(test.planned, test.argv); got != test.want {
				t.Fatalf("Match(%q, %#v) = %v, want %v", test.planned, test.argv, got, test.want)
			}
		})
	}
}
