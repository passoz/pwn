package jsonx

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func mustEncode(t *testing.T, fn func(any) ([]byte, error), v any) string {
	t.Helper()
	out, err := fn(v)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	return string(out)
}

func TestObjectSetGetLen(t *testing.T) {
	o := NewObject().Set("b", 1).Set("a", 2).Set("b", 3)
	if o.Len() != 2 {
		t.Fatalf("Len = %d, queria 2", o.Len())
	}
	if v, ok := o.Get("b"); !ok || v != 3 {
		t.Fatalf("Get(b) = %v,%v", v, ok)
	}
	if _, ok := o.Get("zz"); ok {
		t.Fatal("Get de chave ausente devolveu ok")
	}
	var nilObj *Object
	if nilObj.Len() != 0 {
		t.Fatal("Len de nil deve ser 0")
	}
	// Objeto sem índice (zero value com campos): Set reconstrói o índice.
	raw := &Object{fields: []Field{{Key: "x", Value: 1}, {Key: "y", Value: 2}}}
	raw.Set("y", 9).Set("z", 5)
	if got := mustEncode(t, Insertion, raw); got != `{"x":1,"y":9,"z":5}` {
		t.Fatalf("got %s", got)
	}
}

func TestEncodeScalarsAndContainers(t *testing.T) {
	var nilPtr *int
	var nilSlice []int
	var nilMap map[string]int
	n := 7
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"false", false, "false"},
		{"true", true, "true"},
		{"uint8", uint8(200), "200"},
		{"int-neg", int64(-5), "-5"},
		{"float32", float32(1.5), "1.5"},
		{"nilptr", nilPtr, "null"},
		{"ptr", &n, "7"},
		{"nilslice", nilSlice, "null"},
		{"nilmap", nilMap, "null"},
		{"array", [2]int{1, 2}, "[1,2]"},
		{"slice-nil-elem", []any{nil, "a", 1}, `[null,"a",1]`},
		{"nil-object", (*Object)(nil), "null"},
		{"object-value", *NewObject().Set("k", true), `{"k":true}`},
		{"empty-slice", []int{}, "[]"},
	}
	for _, c := range cases {
		for name, fn := range map[string]func(any) ([]byte, error){"canonical": Canonical, "insertion": Insertion} {
			if got := mustEncode(t, fn, c.in); got != c.want {
				t.Errorf("%s/%s: got %s, queria %s", c.name, name, got, c.want)
			}
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	cases := map[string]any{
		"chan":            make(chan int),
		"chan-em-slice":   []any{1, make(chan int)},
		"chan-em-map":     map[string]any{"a": make(chan int)},
		"chan-em-fields":  Fields{{Key: "a", Value: make(chan int)}},
		"chan-em-struct":  struct{ C any }{C: make(chan int)},
		"map-chave-int":   map[int]int{1: 1},
		"numero-invalido": json.Number("abc"),
		"func":            func() {},
	}
	for name, in := range cases {
		for mname, fn := range map[string]func(any) ([]byte, error){"canonical": Canonical, "insertion": Insertion} {
			if out, err := fn(in); err == nil {
				t.Errorf("%s/%s: esperava erro, saiu %s", name, mname, out)
			}
		}
	}
}

func TestInsertionRawDocumentErrors(t *testing.T) {
	bad := []any{
		json.RawMessage(`{"a":`),
		[]byte(`{"a":`),
		json.RawMessage(`{} {}`),
		[]byte(`[1,2] x`),
		json.RawMessage(``),
	}
	for i, in := range bad {
		if out, err := Insertion(in); err == nil {
			t.Errorf("caso %d: esperava erro, saiu %s", i, out)
		}
	}
}

func TestInsertionRawDocumentKeepsOrder(t *testing.T) {
	doc := `{"z":1,"b":[1.0,{"y":2e0,"x":null}],"2":"d","1":1e21}`
	want := `{"1":1e+21,"2":"d","z":1,"b":[1,{"y":2,"x":null}]}`
	if got := mustEncode(t, Insertion, json.RawMessage(doc)); got != want {
		t.Fatalf("RawMessage: got %s", got)
	}
	if got := mustEncode(t, Insertion, []byte(doc)); got != want {
		t.Fatalf("[]byte: got %s", got)
	}
	if got := mustEncode(t, Insertion, "texto"); got != `"texto"` {
		t.Fatalf("string comum: got %s", got)
	}
}

func TestFieldsAndMapKeyOrdering(t *testing.T) {
	fields := Fields{{"b", 1}, {"10", 2}, {"2", 3}, {"a", 4}}
	if got := mustEncode(t, Insertion, fields); got != `{"2":3,"10":2,"b":1,"a":4}` {
		t.Errorf("Insertion Fields: %s", got)
	}
	if got := mustEncode(t, Canonical, fields); got != `{"10":2,"2":3,"a":4,"b":1}` {
		t.Errorf("Canonical Fields: %s", got)
	}
	m := map[string]int{"b": 1, "2": 2, "1": 3, "a": 4, "01": 5}
	if got := mustEncode(t, Insertion, m); got != `{"1":3,"2":2,"01":5,"a":4,"b":1}` {
		t.Errorf("Insertion map: %s", got)
	}
	if got := mustEncode(t, Canonical, m); got != `{"01":5,"1":3,"2":2,"a":4,"b":1}` {
		t.Errorf("Canonical map: %s", got)
	}
}

func TestArrayIndex(t *testing.T) {
	cases := []struct {
		key string
		n   uint64
		ok  bool
	}{
		{"0", 0, true},
		{"42", 42, true},
		{"4294967294", 4294967294, true},
		{"4294967295", 0, false},
		{"99999999999", 0, false},
		{"", 0, false},
		{"01", 0, false},
		{"1a", 0, false},
		{"-1", 0, false},
	}
	for _, c := range cases {
		n, ok := arrayIndex(c.key)
		if ok != c.ok || n != c.n {
			t.Errorf("arrayIndex(%q) = %d,%v", c.key, n, ok)
		}
	}
}

func TestLessUTF16OutsideBMP(t *testing.T) {
	// U+1F600 vira o par substituto D83D DE00, que vem antes de U+FF5E.
	if !lessUTF16("\U0001F600", "\uFF5E") {
		t.Error("par substituto deve ser menor que U+FF5E")
	}
	if lessUTF16("ab", "ab") || !lessUTF16("a", "ab") || lessUTF16("ab", "a") {
		t.Error("comparação de prefixo errada")
	}
}

func TestWriteJSONStringEscapes(t *testing.T) {
	in := "\"\\\b\f\n\r\t\x01\x1f<>&\u2028é\xff"
	want := `"\"\\\b\f\n\r\t\u0001\u001f<>&` + "\u2028é\uFFFD" + `"`
	if got := mustEncode(t, Canonical, in); got != want {
		t.Fatalf("got %q, queria %q", got, want)
	}
}

func TestFormatNumberJavaScriptForm(t *testing.T) {
	cases := []struct {
		f    float64
		want string
	}{
		{math.NaN(), "null"},
		{math.Inf(1), "null"},
		{math.Inf(-1), "null"},
		{math.Copysign(0, -1), "0"},
		{1e21, "1e+21"},
		{1.5e-7, "1.5e-7"},
		{1e-7, "1e-7"},
		{0.000001, "0.000001"},
		{123.456, "123.456"},
		{-0.5, "-0.5"},
		{1e20, "100000000000000000000"},
		{-1.25e25, "-1.25e+25"},
	}
	for _, c := range cases {
		if got := formatNumber(c.f); got != c.want {
			t.Errorf("formatNumber(%v) = %s, queria %s", c.f, got, c.want)
		}
	}
	if got := mustEncode(t, Canonical, json.Number("1.0e2")); got != "100" {
		t.Errorf("json.Number: %s", got)
	}
}

type CoverInner struct {
	A int `json:"a"`
	Z int
}

type coverOuter struct {
	CoverInner
	*CoverPtrEmbedded
	B      string         `json:"b,omitempty"`
	C      []int          `json:"c,omitempty"`
	D      map[string]int `json:"d,omitempty"`
	E      bool           `json:"e,omitempty"`
	F      uint           `json:"f,omitempty"`
	G      float64        `json:"g,omitempty"`
	H      *int           `json:"h,omitempty"`
	I      any            `json:"i,omitempty"`
	J      struct{}       `json:"j,omitempty"`
	K      int            `json:"k,omitempty"`
	Skip   int            `json:"-"`
	hidden int
	Named  CoverInner `json:"named"`
}

type CoverPtrEmbedded struct {
	P int `json:"p"`
}

func TestStructEncoding(t *testing.T) {
	v := coverOuter{
		CoverInner:       CoverInner{A: 1, Z: 2},
		CoverPtrEmbedded: &CoverPtrEmbedded{P: 3},
		Skip:             9,
		hidden:           8,
	}
	_ = v.hidden
	// Campos omitempty vazios somem; struct vazia com omitempty permanece.
	want := `{"a":1,"Z":2,"p":3,"j":{},"named":{"a":0,"Z":0}}`
	if got := mustEncode(t, Insertion, v); got != want {
		t.Errorf("Insertion:\n got %s\nwant %s", got, want)
	}
	wantCanon := `{"Z":2,"a":1,"j":{},"named":{"Z":0,"a":0},"p":3}`
	if got := mustEncode(t, Canonical, &v); got != wantCanon {
		t.Errorf("Canonical:\n got %s\nwant %s", got, wantCanon)
	}

	n := 0
	full := coverOuter{
		CoverPtrEmbedded: &CoverPtrEmbedded{},
		B:                "x", C: []int{1}, D: map[string]int{"k": 1}, E: true, F: 2, G: 0.5,
		H: &n, I: "i", K: -1,
	}
	got := mustEncode(t, Insertion, full)
	for _, frag := range []string{`"b":"x"`, `"c":[1]`, `"d":{"k":1}`, `"e":true`, `"f":2`, `"g":0.5`, `"h":0`, `"i":"i"`, `"k":-1`} {
		if !strings.Contains(got, frag) {
			t.Errorf("faltou %s em %s", frag, got)
		}
	}
}

func TestIsEmptyValueKinds(t *testing.T) {
	type s struct {
		I8 int8    `json:"i8,omitempty"`
		U8 uint8   `json:"u8,omitempty"`
		F  float32 `json:"f,omitempty"`
		A  [0]int  `json:"a,omitempty"`
		S  string  `json:"s,omitempty"`
	}
	if got := mustEncode(t, Canonical, s{}); got != `{}` {
		t.Errorf("vazios devem sumir: %s", got)
	}
	if got := mustEncode(t, Canonical, s{I8: 1, U8: 2, F: 3, S: "x"}); got != `{"f":3,"i8":1,"s":"x","u8":2}` {
		t.Errorf("got %s", got)
	}
}
