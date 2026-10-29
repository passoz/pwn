// Package jsonschema implements the JSON Schema Draft-07 subset used by the
// harness laws, with no external dependency.
//
// The reference implementation is src/core/validator.ts, which compiles the
// laws with Ajv 8 configured as
// `{allErrors: true, strict: false, formats: {date: true, "date-time": true}}`.
// This package reproduces the observable behaviour of that configuration:
//
//   - `format` is an annotation and never an error. Ajv receives `true` for
//     `date` and `date-time`, which means "ignore the format".
//   - Errors are reported as `<instancePath or /> <message>`, in the same
//     order Ajv emits them, with `allErrors` enabled.
//   - `oneOf` reports the branch errors only when no branch matches; when more
//     than one branch matches it reports the `oneOf` error alone.
//   - Keywords that apply to a JSON type only run when the instance has that
//     type. A failed `type` therefore suppresses `properties`, `items`,
//     `minLength`, `minimum` and friends, but not `enum` or `oneOf`.
//   - Keywords next to `$ref` are applied as well, matching Ajv with
//     `strict: false`.
//   - `additionalProperties` only considers `properties` as declared names;
//     `patternProperties` is not part of the supported subset.
//   - Schema keywords outside the supported subset are rejected at compile
//     time, never ignored: ignoring `allOf` or `anyOf` would validate less than
//     Ajv and could turn a law edit into a gate bypass.
//
// Documented divergences from Ajv:
//
//   - `properties` and additional property names are visited in sorted order,
//     not in JavaScript object insertion order, because Go maps are unordered.
//   - Patterns use Go RE2. JavaScript-only constructs (lookbehind, back
//     references) fail compilation instead of running.
//   - Message numbers are formatted without an exponent. Ajv prints
//     `1e-7` where this package prints `0.0000001`.
//   - Only local `$ref` values (`#` and `#/json/pointer`) are supported.
package jsonschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Schema is a compiled JSON Schema document.
//
// Compilation parses the document, resolves every local `$ref` and compiles
// every `pattern`, so Validate cannot fail on malformed schema input.
type Schema struct {
	root     any
	refs     map[string]any
	patterns map[string]*regexp.Regexp
}

// Decode parses a JSON document the way JSON.parse does for validation
// purposes: numbers stay exact (json.Number) and trailing data is rejected.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after top-level JSON value")
	}
	return value, nil
}

// Compile parses and compiles a schema document. The root may be an object or
// a boolean schema, as Draft-07 allows.
func Compile(data []byte) (*Schema, error) {
	value, err := Decode(data)
	if err != nil {
		return nil, err
	}
	switch root := value.(type) {
	case map[string]any:
		return New(root)
	case bool:
		return &Schema{
			root:     root,
			refs:     make(map[string]any),
			patterns: make(map[string]*regexp.Regexp),
		}, nil
	default:
		return nil, errors.New("schema root must be a JSON object or boolean")
	}
}

// New compiles an already decoded schema document.
func New(root map[string]any) (*Schema, error) {
	s := &Schema{
		root:     root,
		refs:     make(map[string]any),
		patterns: make(map[string]*regexp.Regexp),
	}
	var firstErr error
	walkSchemas(root, func(sch map[string]any) {
		if firstErr != nil {
			return
		}
		for _, keyword := range unsupportedKeywords {
			if _, present := sch[keyword]; present {
				firstErr = fmt.Errorf("unsupported schema keyword %q: this Draft-07 subset does not implement it", keyword)
				return
			}
		}
		if rawRef, ok := sch["$ref"]; ok {
			ref, ok := rawRef.(string)
			if !ok {
				firstErr = fmt.Errorf("$ref must be a string, got %T", rawRef)
				return
			}
			if _, seen := s.refs[ref]; !seen {
				target, err := resolvePointer(root, ref)
				if err != nil {
					firstErr = err
					return
				}
				switch target.(type) {
				case map[string]any, bool:
					s.refs[ref] = target
				default:
					firstErr = fmt.Errorf("$ref %q does not point to a schema", ref)
					return
				}
			}
		}
		if pattern, ok := sch["pattern"].(string); ok {
			if _, seen := s.patterns[pattern]; !seen {
				re, err := regexp.Compile(pattern)
				if err != nil {
					firstErr = fmt.Errorf("invalid pattern %q: %w", pattern, err)
					return
				}
				s.patterns[pattern] = re
			}
		}
	})
	if firstErr != nil {
		return nil, firstErr
	}
	return s, nil
}

// Validate returns the Ajv-style error list for instance. An empty list means
// the instance is valid.
func (s *Schema) Validate(instance any) []string {
	var errs []string
	s.validate(s.root, instance, "", &errs)
	return errs
}

// unsupportedKeywords are Draft-07 assertion and applicator keywords that this
// package does not implement. Compilation fails when a law uses one.
var unsupportedKeywords = []string{
	"allOf", "anyOf", "not", "if", "then", "else", "const", "multipleOf",
	"maxProperties", "uniqueItems", "contains", "patternProperties",
	"dependencies", "propertyNames",
}

// walkSchemas visits the root schema and every embedded subschema.
func walkSchemas(node any, visit func(map[string]any)) {
	sch, ok := node.(map[string]any)
	if !ok {
		return
	}
	visit(sch)
	for _, key := range []string{
		"additionalProperties", "additionalItems", "not", "if", "then", "else",
		"contains", "propertyNames",
	} {
		if sub, ok := sch[key]; ok {
			walkSchemas(sub, visit)
		}
	}
	if items, ok := sch["items"]; ok {
		if tuple, ok := items.([]any); ok {
			for _, sub := range tuple {
				walkSchemas(sub, visit)
			}
		} else {
			walkSchemas(items, visit)
		}
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		if list, ok := sch[key].([]any); ok {
			for _, sub := range list {
				walkSchemas(sub, visit)
			}
		}
	}
	for _, key := range []string{"properties", "patternProperties", "definitions"} {
		if props, ok := sch[key].(map[string]any); ok {
			for _, sub := range props {
				walkSchemas(sub, visit)
			}
		}
	}
}

// resolvePointer resolves a local reference (`#` or `#/json/pointer`).
func resolvePointer(root map[string]any, ref string) (any, error) {
	if ref == "#" {
		return root, nil
	}
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q: only local pointers are supported", ref)
	}
	var current any = root
	for _, token := range strings.Split(ref[2:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node := current.(type) {
		case map[string]any:
			value, ok := node[token]
			if !ok {
				return nil, fmt.Errorf("cannot resolve $ref %q: %q not found", ref, token)
			}
			current = value
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, fmt.Errorf("cannot resolve $ref %q: bad array index %q", ref, token)
			}
			current = node[index]
		default:
			return nil, fmt.Errorf("cannot resolve $ref %q: %q is not an object or array", ref, token)
		}
	}
	return current, nil
}

func (s *Schema) validate(node any, instance any, path string, out *[]string) {
	switch node := node.(type) {
	case bool:
		if !node {
			s.add(out, path, "boolean schema is false")
		}
	case map[string]any:
		s.validateKeywords(node, instance, path, out)
	}
}

func (s *Schema) validateKeywords(node map[string]any, instance any, path string, out *[]string) {
	// Ajv validates `$ref` first, then the remaining keywords of the same
	// schema object (draft-07 with strict: false).
	if ref, ok := node["$ref"].(string); ok {
		if target, ok := s.refs[ref]; ok {
			s.validate(target, instance, path, out)
		}
	}

	// Keywords that apply to any instance type, in Ajv rule-group order.
	if raw, ok := node["type"]; ok {
		if types := typeNames(raw); len(types) > 0 && !matchesAnyType(instance, types) {
			s.add(out, path, "must be "+strings.Join(types, ","))
		}
	}
	if values, ok := node["enum"].([]any); ok && !containsValue(values, instance) {
		s.add(out, path, "must be equal to one of the allowed values")
	}
	if branches, ok := node["oneOf"].([]any); ok {
		s.validateOneOf(branches, instance, path, out)
	}

	// Number keywords. Ajv orders limitNumber as maximum, minimum,
	// exclusiveMaximum, exclusiveMinimum.
	if number, ok := numberValue(instance); ok {
		if limit, ok := numberValue(node["maximum"]); ok && number.Cmp(limit) > 0 {
			s.add(out, path, "must be <= "+formatNumber(node["maximum"]))
		}
		if limit, ok := numberValue(node["minimum"]); ok && number.Cmp(limit) < 0 {
			s.add(out, path, "must be >= "+formatNumber(node["minimum"]))
		}
		if limit, ok := numberValue(node["exclusiveMaximum"]); ok && number.Cmp(limit) >= 0 {
			s.add(out, path, "must be < "+formatNumber(node["exclusiveMaximum"]))
		}
		if limit, ok := numberValue(node["exclusiveMinimum"]); ok && number.Cmp(limit) <= 0 {
			s.add(out, path, "must be > "+formatNumber(node["exclusiveMinimum"]))
		}
	}

	// String keywords: maxLength, minLength, pattern.
	if str, ok := instance.(string); ok {
		length := utf8.RuneCountInString(str)
		if limit, ok := intValue(node["maxLength"]); ok && length > limit {
			s.add(out, path, "must NOT have more than "+strconv.Itoa(limit)+" characters")
		}
		if limit, ok := intValue(node["minLength"]); ok && length < limit {
			s.add(out, path, "must NOT have fewer than "+strconv.Itoa(limit)+" characters")
		}
		if pattern, ok := node["pattern"].(string); ok {
			if re := s.patterns[pattern]; re != nil && !re.MatchString(str) {
				s.add(out, path, `must match pattern "`+pattern+`"`)
			}
		}
	}

	// Array keywords: maxItems, minItems, then items.
	if array, ok := instance.([]any); ok {
		if limit, ok := intValue(node["maxItems"]); ok && len(array) > limit {
			s.add(out, path, "must NOT have more than "+strconv.Itoa(limit)+" items")
		}
		if limit, ok := intValue(node["minItems"]); ok && len(array) < limit {
			s.add(out, path, "must NOT have fewer than "+strconv.Itoa(limit)+" items")
		}
		if items, ok := node["items"]; ok {
			s.validateItems(node, items, array, path, out)
		}
	}

	// Object keywords: minProperties, required, additionalProperties, properties.
	if object, ok := instance.(map[string]any); ok {
		if limit, ok := intValue(node["minProperties"]); ok && len(object) < limit {
			s.add(out, path, "must NOT have fewer than "+strconv.Itoa(limit)+" properties")
		}
		if required, ok := node["required"].([]any); ok {
			for _, rawName := range required {
				name, ok := rawName.(string)
				if !ok {
					continue
				}
				if _, present := object[name]; !present {
					s.add(out, path, "must have required property '"+name+"'")
				}
			}
		}
		properties, _ := node["properties"].(map[string]any)
		if additional, ok := node["additionalProperties"]; ok {
			s.validateAdditional(additional, properties, object, path, out)
		}
		for _, name := range sortedKeys(properties) {
			value, present := object[name]
			if !present {
				continue
			}
			s.validate(properties[name], value, childPath(path, name), out)
		}
	}
}

func (s *Schema) validateOneOf(branches []any, instance any, path string, out *[]string) {
	passing := 0
	branchErrors := make([][]string, 0, len(branches))
	for _, branch := range branches {
		var errs []string
		s.validate(branch, instance, path, &errs)
		if len(errs) == 0 {
			passing++
		}
		branchErrors = append(branchErrors, errs)
	}
	if passing == 1 {
		return
	}
	if passing == 0 {
		for _, errs := range branchErrors {
			*out = append(*out, errs...)
		}
	}
	s.add(out, path, "must match exactly one schema in oneOf")
}

func (s *Schema) validateItems(node map[string]any, items any, array []any, path string, out *[]string) {
	if tuple, ok := items.([]any); ok {
		for index, item := range array {
			itemPath := path + "/" + strconv.Itoa(index)
			if index < len(tuple) {
				s.validate(tuple[index], item, itemPath, out)
				continue
			}
			if additional, ok := node["additionalItems"]; ok {
				s.validate(additional, item, itemPath, out)
			}
		}
		return
	}
	for index, item := range array {
		s.validate(items, item, path+"/"+strconv.Itoa(index), out)
	}
}

func (s *Schema) validateAdditional(additional any, properties map[string]any, object map[string]any, path string, out *[]string) {
	switch schema := additional.(type) {
	case bool:
		if schema {
			return
		}
		for _, name := range sortedKeys(object) {
			if _, declared := properties[name]; declared {
				continue
			}
			s.add(out, path, "must NOT have additional properties")
		}
	case map[string]any:
		for _, name := range sortedKeys(object) {
			if _, declared := properties[name]; declared {
				continue
			}
			s.validate(schema, object[name], childPath(path, name), out)
		}
	}
}

func (s *Schema) add(out *[]string, path, message string) {
	*out = append(*out, errorPath(path)+" "+message)
}

// errorPath renders the Ajv instancePath, where the root is "/".
func errorPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func childPath(path, name string) string {
	escaped := strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
	return path + "/" + escaped
}

func typeNames(raw any) []string {
	switch value := raw.(type) {
	case string:
		return []string{value}
	case []any:
		names := make([]string, 0, len(value))
		for _, item := range value {
			if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
		return names
	}
	return nil
}

func matchesAnyType(instance any, types []string) bool {
	for _, name := range types {
		if matchesType(instance, name) {
			return true
		}
	}
	return false
}

func matchesType(instance any, name string) bool {
	switch name {
	case "object":
		_, ok := instance.(map[string]any)
		return ok
	case "array":
		_, ok := instance.([]any)
		return ok
	case "string":
		_, ok := instance.(string)
		return ok
	case "boolean":
		_, ok := instance.(bool)
		return ok
	case "null":
		return instance == nil
	case "number":
		_, ok := numberValue(instance)
		return ok
	case "integer":
		number, ok := numberValue(instance)
		return ok && number.IsInt()
	}
	// Unknown type names are a compile error in Ajv; treat them as matched.
	return true
}

// numberValue converts a decoded JSON number into an exact rational.
// strconv fallback covers exponents that big.Rat.SetString rejects.
func numberValue(value any) (*big.Rat, bool) {
	switch number := value.(type) {
	case json.Number:
		if rat, ok := new(big.Rat).SetString(string(number)); ok {
			return rat, true
		}
		parsed, err := strconv.ParseFloat(string(number), 64)
		if err != nil {
			return nil, false
		}
		return floatRat(parsed)
	case float64:
		return floatRat(number)
	case float32:
		return floatRat(float64(number))
	case int:
		return new(big.Rat).SetInt64(int64(number)), true
	case int64:
		return new(big.Rat).SetInt64(number), true
	case uint64:
		return new(big.Rat).SetUint64(number), true
	case *big.Rat:
		if number == nil {
			return nil, false
		}
		return number, true
	}
	return nil, false
}

func floatRat(value float64) (*big.Rat, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil, false
	}
	return new(big.Rat).SetFloat64(value), true
}

func intValue(value any) (int, bool) {
	rat, ok := numberValue(value)
	if !ok || !rat.IsInt() {
		return 0, false
	}
	numerator := rat.Num()
	if !numerator.IsInt64() || int64(int(numerator.Int64())) != numerator.Int64() {
		return 0, false
	}
	return int(numerator.Int64()), true
}

// formatNumber renders a schema limit the way Ajv interpolates it into the
// message: integral values without a fractional part.
func formatNumber(value any) string {
	raw := ""
	switch number := value.(type) {
	case json.Number:
		raw = string(number)
	case int:
		return strconv.Itoa(number)
	case int64:
		return strconv.FormatInt(number, 10)
	case float64:
		return formatFloat(number)
	}
	if raw != "" && !strings.ContainsAny(raw, ".eE") {
		return raw
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
		return formatFloat(parsed)
	}
	return raw
}

func formatFloat(value float64) string {
	if value == math.Trunc(value) && math.Abs(value) < 1e21 {
		return strconv.FormatFloat(value, 'f', 0, 64)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func containsValue(values []any, instance any) bool {
	for _, value := range values {
		if equalJSON(value, instance) {
			return true
		}
	}
	return false
}

// equalJSON compares two JSON values with number semantics: 1 and 1.0 are
// equal, as in JavaScript.
func equalJSON(a, b any) bool {
	if numberA, ok := numberValue(a); ok {
		numberB, ok := numberValue(b)
		return ok && numberA.Cmp(numberB) == 0
	}
	switch value := a.(type) {
	case nil:
		return b == nil
	case string:
		other, ok := b.(string)
		return ok && value == other
	case bool:
		other, ok := b.(bool)
		return ok && value == other
	case []any:
		other, ok := b.([]any)
		if !ok || len(value) != len(other) {
			return false
		}
		for index := range value {
			if !equalJSON(value[index], other[index]) {
				return false
			}
		}
		return true
	case map[string]any:
		other, ok := b.(map[string]any)
		if !ok || len(value) != len(other) {
			return false
		}
		for key, item := range value {
			otherItem, present := other[key]
			if !present || !equalJSON(item, otherItem) {
				return false
			}
		}
		return true
	}
	return false
}

func sortedKeys[V any](object map[string]V) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
