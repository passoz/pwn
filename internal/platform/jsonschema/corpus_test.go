package jsonschema_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/passoz/pwn/internal/platform/jsonschema"
)

// corpusPath is the Ajv-generated conformance set at the repository root.
const corpusPath = "../../../testdata/parity/schema/corpus.json"

type corpusCase struct {
	ID       string `json:"id"`
	Keyword  string `json:"keyword"`
	Document any    `json:"document"`
	Valid    bool   `json:"valid"`
}

type corpus struct {
	Schema   map[string]any `json:"schema"`
	Keywords []string       `json:"keywords"`
	Cases    []corpusCase   `json:"cases"`
}

// expectedErrors holds the exact Ajv 8 output for each failing case,
// captured from src/core/validator.ts's configuration.
var expectedErrors = map[string][]string{
	"valid":               {},
	"invalid-type":        {"/name must be string"},
	"missing-required":    {"/ must have required property 'name'"},
	"invalid-items":       {"/items must be array"},
	"extra-property":      {"/extra must NOT have additional properties"},
	"invalid-enum":        {"/mode must be equal to one of the allowed values"},
	"invalid-pattern":     {`/name must match pattern "^[a-z]+$"`},
	"short-name":          {"/name must NOT have fewer than 2 characters"},
	"long-name":           {"/name must NOT have more than 5 characters"},
	"empty-items":         {"/items must NOT have fewer than 1 items"},
	"too-many-items":      {"/items must NOT have more than 2 items"},
	"below-minimum":       {"/items/0 must be equal to one of the allowed values", "/items/0 must be >= 1"},
	"above-maximum":       {"/items/0 must be equal to one of the allowed values", "/items/0 must be <= 3"},
	"empty-extra":         {"/extra must NOT have fewer than 1 properties"},
	"invalid-one-of":      {"/choice must be string", "/choice must be number", "/choice must match exactly one schema in oneOf"},
	"invalid-ref":         {"/ref must be > 0"},
	"format-not-asserted": {},
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(corpusPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	decoded, err := jsonschema.Decode(data)
	if err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("corpus root must be an object")
	}
	rawCases, _ := object["cases"].([]any)
	rawKeywords, _ := object["keywords"].([]any)
	schema, _ := object["schema"].(map[string]any)

	result := corpus{Schema: schema}
	for _, keyword := range rawKeywords {
		if name, ok := keyword.(string); ok {
			result.Keywords = append(result.Keywords, name)
		}
	}
	for _, rawCase := range rawCases {
		entry, ok := rawCase.(map[string]any)
		if !ok {
			t.Fatalf("corpus case must be an object")
		}
		id, _ := entry["id"].(string)
		keyword, _ := entry["keyword"].(string)
		valid, _ := entry["valid"].(bool)
		result.Cases = append(result.Cases, corpusCase{
			ID:       id,
			Keyword:  keyword,
			Document: entry["document"],
			Valid:    valid,
		})
	}
	return result
}

// TestCorpusVerdictsAndMessages proves parity with Ajv for the 17 keywords of
// the conformance set: same verdict and same ordered error messages.
func TestCorpusVerdictsAndMessages(t *testing.T) {
	set := loadCorpus(t)
	schema, err := jsonschema.New(set.Schema)
	if err != nil {
		t.Fatalf("compile corpus schema: %v", err)
	}

	declared := make(map[string]bool, len(set.Keywords))
	for _, keyword := range set.Keywords {
		declared[keyword] = true
	}
	covered := make(map[string]bool, len(set.Keywords))
	// "properties" is declared as a keyword but exercised through the cases of
	// its child constraints, so case keywords are checked against the list.
	for _, testCase := range set.Cases {
		if !declared[testCase.Keyword] {
			t.Errorf("%s: keyword %q is not declared by the corpus", testCase.ID, testCase.Keyword)
		}
		covered[testCase.Keyword] = true
		errs := schema.Validate(testCase.Document)
		valid := len(errs) == 0
		if valid != testCase.Valid {
			t.Errorf("%s: valid = %v, want %v (errors: %v)", testCase.ID, valid, testCase.Valid, errs)
		}
		want, known := expectedErrors[testCase.ID]
		if !known {
			t.Errorf("%s: no expected error list recorded", testCase.ID)
			continue
		}
		if !slices.Equal(errs, want) {
			t.Errorf("%s: errors = %q, want %q", testCase.ID, errs, want)
		}
	}

	if len(covered) != 16 {
		t.Errorf("cases cover %d keywords, want 16 exercised keywords", len(covered))
	}
	if len(set.Cases) != len(expectedErrors) {
		t.Errorf("corpus has %d cases, expectations cover %d", len(set.Cases), len(expectedErrors))
	}
}

// TestCorpusSchemaCompilesWithoutPatternLoss guards that every pattern of the
// conformance schema compiles and is asserted.
func TestCorpusSchemaCompilesWithoutPatternLoss(t *testing.T) {
	set := loadCorpus(t)
	schema, err := jsonschema.New(set.Schema)
	if err != nil {
		t.Fatalf("compile corpus schema: %v", err)
	}
	errs := schema.Validate(map[string]any{
		"name":   "ABC",
		"items":  []any{1},
		"mode":   "a",
		"when":   "not-a-date",
		"ref":    1,
		"choice": "x",
		"extra":  map[string]any{"flag": true},
	})
	want := []string{`/name must match pattern "^[a-z]+$"`}
	if !slices.Equal(errs, want) {
		t.Errorf("errors = %q, want %q", errs, want)
	}
}
