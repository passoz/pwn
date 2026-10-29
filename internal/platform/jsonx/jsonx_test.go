package jsonx

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type goldenVectors struct {
	CanonicalJSON string `json:"canonical_json"`
	SHA256        string `json:"sha256"`
	HMACSHA256    string `json:"hmac_sha256"`
	Ed25519       string `json:"ed25519_signature"`
}

func goldenFile(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "parity", "golden", name)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod não encontrado a partir de %s", dir)
		}
		dir = parent
	}
}

func loadVectors(t *testing.T) goldenVectors {
	t.Helper()
	data, err := os.ReadFile(goldenFile(t, "vectors.json"))
	if err != nil {
		t.Fatalf("ler vectors.json: %v", err)
	}
	var vectors goldenVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decodificar vectors.json: %v", err)
	}
	return vectors
}

type subjectCheck struct {
	ID       string `json:"id"`
	ExitCode int    `json:"exit_code"`
}

type subject struct {
	ApprovalID string         `json:"approval_id"`
	WorkID     string         `json:"work_id"`
	TaskID     string         `json:"task_id"`
	Outcome    string         `json:"outcome"`
	Checks     []subjectCheck `json:"checks"`
}

func TestCanonicalGoldenVector(t *testing.T) {
	vectors := loadVectors(t)

	expected := vectors.CanonicalJSON
	inputs := map[string]any{
		"mapa": map[string]any{
			"approval_id": "APR-TEST-0002",
			"work_id":     "0002",
			"task_id":     "1.3",
			"outcome":     "pass",
			"checks": []any{
				map[string]any{"id": "AC-1", "exit_code": 0},
			},
		},
		"struct": subject{
			ApprovalID: "APR-TEST-0002",
			WorkID:     "0002",
			TaskID:     "1.3",
			Outcome:    "pass",
			Checks:     []subjectCheck{{ID: "AC-1", ExitCode: 0}},
		},
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			got, err := Canonical(input)
			if err != nil {
				t.Fatalf("Canonical: %v", err)
			}
			if string(got) != expected {
				t.Fatalf("canonical divergente\n got: %s\nwant: %s", got, expected)
			}
		})
	}
}

func TestCanonicalOrderAndEscapes(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"nulo", nil, "null"},
		{"chaves ordenadas", map[string]any{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"aninhado", map[string]any{"z": map[string]any{"y": 1, "x": 2}}, `{"z":{"x":2,"y":1}}`},
		{"sem escape html", "<a>&b</a>", `"<a>&b</a>"`},
		{"u2028 fora de escape", "a\u2028b", "\"a\u2028b\""},
		{"controles", "\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"aspas e barra", "a\"b\\c\n", `"a\"b\\c\n"`},
		{"utf16: fora do bmp antes do platô", map[string]any{"\U0001F600": 1, "\uFFFD": 2, "a": 3}, "{\"a\":3,\"\U0001F600\":1,\"\uFFFD\":2}"},
		{"array", []any{1, "x", nil}, `[1,"x",null]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Canonical(test.input)
			if err != nil {
				t.Fatalf("Canonical: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestCanonicalNumbers(t *testing.T) {
	tests := []struct {
		input any
		want  string
	}{
		{float64(0), "0"},
		{float64(-0.0), "0"},
		{float64(1.5), "1.5"},
		{float64(0.1), "0.1"},
		{float64(0.000001), "0.000001"},
		{float64(0.0000001), "1e-7"},
		{float64(1e20), "100000000000000000000"},
		{float64(1e21), "1e+21"},
		{float64(1.234e21), "1.234e+21"},
		{float64(123456789012345678901), "123456789012345680000"},
		{float64(5e-324), "5e-324"},
		{float64(1.7976931348623157e308), "1.7976931348623157e+308"},
		{float64(-2.5), "-2.5"},
		{float64(100), "100"},
		{float64(123.456), "123.456"},
		{float64(0.000001234), "0.000001234"},
		{float64(1e6), "1000000"},
		{float64(9.999999999999999e20), "999999999999999900000"},
		{json.Number("1e5"), "100000"},
		{int64(-7), "-7"},
		{uint64(18446744073709551615), "18446744073709551615"},
	}
	for _, test := range tests {
		got, err := Canonical(test.input)
		if err != nil {
			t.Fatalf("Canonical(%v): %v", test.input, err)
		}
		if string(got) != test.want {
			t.Fatalf("Canonical(%v) = %s, want %s", test.input, got, test.want)
		}
	}
	if got, err := Canonical(math.Inf(1)); err != nil || string(got) != "null" {
		t.Fatalf("infinito: got %s, err %v", got, err)
	}
}

type tagged struct {
	Zeta     string `json:"zeta"`
	Alpha    int    `json:"alpha,omitempty"`
	Skip     string `json:"-"`
	Internal string
	Beta     *string `json:"beta,omitempty"`
}

func TestCanonicalStructTags(t *testing.T) {
	beta := "b"
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"omissão", tagged{Zeta: "z"}, `{"Internal":"","zeta":"z"}`},
		{"ponta", &tagged{Zeta: "z", Alpha: 1, Skip: "s", Internal: "i", Beta: &beta}, `{"Internal":"i","alpha":1,"beta":"b","zeta":"z"}`},
		{"ponteiro nulo", (*tagged)(nil), "null"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Canonical(test.input)
			if err != nil {
				t.Fatalf("Canonical: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}

type orderedChild struct {
	Name string `json:"name"`
	Rank int    `json:"rank"`
}

func TestInsertionPreservesOrder(t *testing.T) {
	t.Run("documento json", func(t *testing.T) {
		raw := []byte(`{"b":1.0,"a":{"z":[1,2],"y":true},"c":null}`)
		got, err := Insertion(raw)
		if err != nil {
			t.Fatalf("Insertion: %v", err)
		}
		want := `{"b":1,"a":{"z":[1,2],"y":true},"c":null}`
		if string(got) != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})

	t.Run("índices de array primeiro", func(t *testing.T) {
		got, err := Insertion([]byte(`{"b":1,"2":2,"0":3,"a":4}`))
		if err != nil {
			t.Fatalf("Insertion: %v", err)
		}
		want := `{"0":3,"2":2,"b":1,"a":4}`
		if string(got) != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})

	t.Run("objeto de inserção", func(t *testing.T) {
		object := NewObject().
			Set("work_id", "0002").
			Set("task_id", "1.3").
			Set("checks", []any{map[string]any{"exit_code": 0, "id": "AC-1"}})
		got, err := Insertion(object)
		if err != nil {
			t.Fatalf("Insertion: %v", err)
		}
		want := `{"work_id":"0002","task_id":"1.3","checks":[{"exit_code":0,"id":"AC-1"}]}`
		if string(got) != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})

	t.Run("substituição mantém posição", func(t *testing.T) {
		object := NewObject().Set("a", 1).Set("b", 2).Set("a", 3)
		got, err := Insertion(object)
		if err != nil {
			t.Fatalf("Insertion: %v", err)
		}
		if want := `{"a":3,"b":2}`; string(got) != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})

	t.Run("chaves duplicadas no documento", func(t *testing.T) {
		got, err := Insertion([]byte(`{"a":1,"b":2,"a":3}`))
		if err != nil {
			t.Fatalf("Insertion: %v", err)
		}
		if want := `{"a":3,"b":2}`; string(got) != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})

	t.Run("struct mantém declaração", func(t *testing.T) {
		got, err := Insertion(orderedChild{Name: "n", Rank: 2})
		if err != nil {
			t.Fatalf("Insertion: %v", err)
		}
		if want := `{"name":"n","rank":2}`; string(got) != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})
}

func TestCanonicalMatchesEncodingJSONForASCII(t *testing.T) {
	input := map[string]any{"user": "ana", "tags": []any{"a", "b"}, "count": 3}
	got, err := Canonical(input)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	want, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSHA256(t *testing.T) {
	vectors := loadVectors(t)
	if got := SHA256Hex([]byte("pwn-golden")); got != vectors.SHA256 {
		t.Fatalf("SHA256Hex = %s, want %s", got, vectors.SHA256)
	}
	sum := SHA256Bytes([]byte("pwn-golden"))
	want, err := hex.DecodeString(vectors.SHA256)
	if err != nil {
		t.Fatalf("hex de referência: %v", err)
	}
	if string(sum[:]) != string(want) {
		t.Fatalf("SHA256Bytes = %x, want %s", sum, vectors.SHA256)
	}
}
