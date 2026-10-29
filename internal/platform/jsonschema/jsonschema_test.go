package jsonschema_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/platform/jsonschema"
)

func compile(t *testing.T, source string) *jsonschema.Schema {
	t.Helper()
	schema, err := jsonschema.Compile([]byte(source))
	if err != nil {
		t.Fatalf("compile %s: %v", source, err)
	}
	return schema
}

func decode(t *testing.T, source string) any {
	t.Helper()
	value, err := jsonschema.Decode([]byte(source))
	if err != nil {
		t.Fatalf("decode %s: %v", source, err)
	}
	return value
}

func TestKeywordVerdicts(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		doc    string
		errors []string
	}{
		{"type object ok", `{"type":"object"}`, `{}`, nil},
		{"type array mismatch", `{"type":"object"}`, `[1]`, []string{"/ must be object"}},
		{"type null", `{"type":"null"}`, `0`, []string{"/ must be null"}},
		{"type boolean", `{"type":"boolean"}`, `"x"`, []string{"/ must be boolean"}},
		{"type number from integer literal", `{"type":"number"}`, `1`, nil},
		{"type integer accepts zero fraction", `{"type":"integer"}`, `1.0`, nil},
		{"type integer rejects fraction", `{"type":"integer"}`, `1.5`, []string{"/ must be integer"}},
		{"type list message", `{"type":["string","number"]}`, `true`, []string{"/ must be string,number"}},
		{"type failure keeps enum", `{"type":"string","enum":["a"]}`, `5`, []string{
			"/ must be string",
			"/ must be equal to one of the allowed values",
		}},
		{"properties nested path", `{"properties":{"a":{"properties":{"b":{"type":"string"}}}}}`, `{"a":{"b":1}}`, []string{"/a/b must be string"}},
		{"properties ignored for other type", `{"properties":{"a":{"type":"string"}}}`, `5`, nil},
		{"required reports every missing property", `{"type":"object","required":["z","a"]}`, `{}`, []string{
			"/ must have required property 'z'",
			"/ must have required property 'a'",
		}},
		{"required accepts null value", `{"type":"object","required":["a"]}`, `{"a":null}`, nil},
		{"additionalProperties false", `{"type":"object","properties":{"a":{}},"additionalProperties":false}`, `{"b":1}`, []string{"/ must NOT have additional properties"}},
		{"additionalProperties schema", `{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":{"type":"number"}}`, `{"a":"x","b":"y"}`, []string{"/b must be number"}},
		{"additionalProperties true", `{"type":"object","additionalProperties":true}`, `{"b":1}`, nil},
		{"items schema", `{"type":"array","items":{"type":"string"}}`, `[1]`, []string{"/0 must be string"}},
		{"items tuple", `{"type":"array","items":[{"type":"string"},{"type":"number"}]}`, `[1,"x"]`, []string{
			"/0 must be string",
			"/1 must be number",
		}},
		{"items tuple additionalItems", `{"type":"array","items":[{"type":"string"}],"additionalItems":false}`, `["a",2]`, []string{"/1 boolean schema is false"}},
		{"items false", `{"type":"array","items":false}`, `[1]`, []string{"/0 boolean schema is false"}},
		{"enum number equality", `{"enum":[1]}`, `1.0`, nil},
		{"enum object equality", `{"enum":[{"a":1}]}`, `{"a":1.0}`, nil},
		{"enum mismatch", `{"enum":["a","b"]}`, `"c"`, []string{"/ must be equal to one of the allowed values"}},
		{"pattern anchored", `{"type":"string","pattern":"^[a-z]+$"}`, `"ABC"`, []string{`/ must match pattern "^[a-z]+$"`}},
		{"pattern is a search", `{"type":"string","pattern":"b"}`, `"abc"`, nil},
		{"minLength counts code points", `{"type":"string","minLength":2}`, `"😀a"`, nil},
		{"minLength rejects short", `{"type":"string","minLength":2}`, `"é"`, []string{"/ must NOT have fewer than 2 characters"}},
		{"maxLength", `{"type":"string","maxLength":2}`, `"abcd"`, []string{"/ must NOT have more than 2 characters"}},
		{"minItems", `{"type":"array","minItems":2}`, `[1]`, []string{"/ must NOT have fewer than 2 items"}},
		{"maxItems", `{"type":"array","maxItems":1}`, `[1,2]`, []string{"/ must NOT have more than 1 items"}},
		{"minimum", `{"type":"number","minimum":1}`, `0`, []string{"/ must be >= 1"}},
		{"maximum", `{"type":"number","maximum":3}`, `4`, []string{"/ must be <= 3"}},
		{"exclusiveMinimum", `{"type":"number","exclusiveMinimum":0}`, `0`, []string{"/ must be > 0"}},
		{"exclusiveMaximum", `{"type":"number","exclusiveMaximum":0}`, `0`, []string{"/ must be < 0"}},
		{"minimum decimal message", `{"type":"number","minimum":0.5}`, `0.4`, []string{"/ must be >= 0.5"}},
		{"minProperties", `{"type":"object","minProperties":1}`, `{}`, []string{"/ must NOT have fewer than 1 properties"}},
		{"oneOf none", `{"oneOf":[{"type":"string"},{"type":"boolean"}]}`, `3`, []string{
			"/ must be string",
			"/ must be boolean",
			"/ must match exactly one schema in oneOf",
		}},
		{"oneOf two", `{"oneOf":[{"type":"number"},{"type":"integer"}]}`, `3`, []string{"/ must match exactly one schema in oneOf"}},
		{"oneOf exactly one", `{"oneOf":[{"type":"string"},{"type":"number"}]}`, `3`, nil},
		{"format is annotation", `{"type":"string","format":"date-time"}`, `"not-a-date"`, nil},
		{"unknown format is annotation", `{"type":"string","format":"no-such-format"}`, `"x"`, nil},
		{"ref applies", `{"definitions":{"p":{"type":"number","exclusiveMinimum":0}},"$ref":"#/definitions/p"}`, `0`, []string{"/ must be > 0"}},
		{"ref siblings apply", `{"definitions":{"p":{"type":"number"}},"$ref":"#/definitions/p","minimum":5}`, `1`, []string{"/ must be >= 5"}},
		{"empty schema", `{}`, `{"any":true}`, nil},
		{"boolean true schema", `true`, `{"any":true}`, nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := compile(t, test.schema)
			errors := schema.Validate(decode(t, test.doc))
			if !slices.Equal(errors, test.errors) {
				t.Errorf("errors = %q, want %q", errors, test.errors)
			}
		})
	}
}

func TestPointerEscapingInPaths(t *testing.T) {
	schema := compile(t, `{"properties":{"a/b":{"type":"string"},"c~d":{"type":"string"}}}`)
	errors := schema.Validate(decode(t, `{"a/b":1,"c~d":2}`))
	want := []string{"/a~1b must be string", "/c~0d must be string"}
	if !slices.Equal(errors, want) {
		t.Errorf("errors = %q, want %q", errors, want)
	}
}

func TestRefPointerEscaping(t *testing.T) {
	schema := compile(t, `{"definitions":{"a/b":{"type":"string"},"c~d":{"type":"integer"}},"properties":{"one":{"$ref":"#/definitions/a~1b"},"two":{"$ref":"#/definitions/c~0d"}}}`)
	errors := schema.Validate(decode(t, `{"one":1,"two":"x"}`))
	want := []string{"/one must be string", "/two must be integer"}
	if !slices.Equal(errors, want) {
		t.Errorf("errors = %q, want %q", errors, want)
	}
}

func TestCompileRejectsBadSchemas(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{"missing ref", `{"$ref":"#/definitions/nope"}`, "cannot resolve $ref"},
		{"external ref", `{"$ref":"https://pwn.dev/schemas/plan.schema.json"}`, "only local pointers are supported"},
		{"non string ref", `{"$ref":42}`, "$ref must be a string"},
		{"invalid pattern", `{"pattern":"(?<=a)b"}`, "invalid pattern"},
		{"non schema root", `[1]`, "schema root must be a JSON object or boolean"},
		{"invalid json", `{`, "unexpected"},
		{"unsupported keyword", `{"allOf":[{"type":"string"}]}`, "unsupported schema keyword"},
		{"unsupported nested keyword", `{"properties":{"a":{"anyOf":[{"type":"string"}]}}}`, "unsupported schema keyword"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := jsonschema.Compile([]byte(test.schema))
			if err == nil {
				t.Fatalf("Compile(%s) succeeded, want error", test.schema)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	if _, err := jsonschema.Decode([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("Decode accepted trailing data")
	}
	if value, err := jsonschema.Decode([]byte(" \n\t{\"a\":1}\n ")); err != nil {
		t.Fatalf("Decode rejected surrounding whitespace: %v", err)
	} else if _, ok := value.(map[string]any); !ok {
		t.Fatalf("Decode returned %T", value)
	}
}

func TestValidateAcceptsPlainGoValues(t *testing.T) {
	schema := compile(t, `{"type":"object","properties":{"n":{"type":"integer","minimum":2}},"required":["n"]}`)
	if errors := schema.Validate(map[string]any{"n": 3}); len(errors) != 0 {
		t.Errorf("int value rejected: %v", errors)
	}
	if errors := schema.Validate(map[string]any{"n": 3.5}); !slices.Equal(errors, []string{"/n must be integer"}) {
		t.Errorf("float value errors = %q", errors)
	}
}
