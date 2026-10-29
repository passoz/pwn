package assets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/passoz/pwn/internal/platform/jsonschema"
)

// ValidationResult is the outcome of validating one normative document.
type ValidationResult struct {
	Valid  bool
	File   string
	Errors []string
}

// workDocuments lists the work directory documents and their laws, in the
// order used by validateWorkDocuments in src/core/validator.ts.
var workDocuments = []struct {
	document string
	schema   string
}{
	{"prd.json", "prd.schema.json"},
	{"plan.json", "plan.schema.json"},
	{"evidence.json", "evidence.schema.json"},
}

// coreNormatives lists the framework's own normative documents, relative to
// the repository root.
var coreNormatives = []string{
	".specs/system.json",
	"spec.json",
	"todo.json",
	"packs/core/pipeline-core.json",
}

var (
	compileOnce sync.Once
	lawsByName  map[string]*jsonschema.Schema
	compileErr  error
)

// compiledLaws compiles the embedded laws once. Any embedded law that does not
// compile makes every validation fail with that error.
func compiledLaws() (map[string]*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		lawsByName = make(map[string]*jsonschema.Schema, len(lawNames))
		for _, name := range lawNames {
			data, ok := Schema(name)
			if !ok {
				compileErr = fmt.Errorf("unknown schema: %s (conhecidas: %s)", name, strings.Join(lawNames, ", "))
				return
			}
			schema, err := jsonschema.Compile(data)
			if err != nil {
				compileErr = fmt.Errorf("compile %s: %w", name, err)
				return
			}
			lawsByName[name] = schema
		}
	})
	return lawsByName, compileErr
}

// ValidateNormativeDocument validates one document against the law its
// `$schema` declares.
//
// Documents without `$schema` are valid here; the gates validate them
// structurally. A declared schema without a usable name, or a name the
// verifier does not carry, is an error and never a pass.
func ValidateNormativeDocument(filePath, rootDir string) ValidationResult {
	absolute := resolvePath(rootDir, filePath)
	relative := relativePath(rootDir, absolute)

	if _, err := os.Stat(absolute); err != nil {
		return ValidationResult{File: relative, Errors: []string{"File not found: " + relative}}
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return ValidationResult{File: relative, Errors: []string{"JSON Syntax Error: " + err.Error()}}
	}
	document, err := jsonschema.Decode(data)
	if err != nil {
		return ValidationResult{File: relative, Errors: []string{"JSON Syntax Error: " + err.Error()}}
	}

	declared, name := declaredSchemaName(document)
	if !declared {
		return ValidationResult{Valid: true, File: relative, Errors: []string{}}
	}
	if name == "" {
		return ValidationResult{
			File:   relative,
			Errors: []string{`Schema não verificável: "$schema" declarado sem nome de schema utilizável (conhecidas: ` + strings.Join(lawNames, ", ") + ")"},
		}
	}

	schemas, err := compiledLaws()
	if err != nil {
		return ValidationResult{File: relative, Errors: []string{err.Error()}}
	}
	schema, ok := schemas[name]
	if !ok {
		return ValidationResult{
			File:   relative,
			Errors: []string{"Schema não verificável: " + name + " (conhecidas: " + strings.Join(lawNames, ", ") + ")"},
		}
	}

	errs := schema.Validate(document)
	if errs == nil {
		errs = []string{}
	}
	return ValidationResult{Valid: len(errs) == 0, File: relative, Errors: errs}
}

// ValidateWorkDocuments validates the normative documents of one work
// directory. Documents that are absent are skipped.
func ValidateWorkDocuments(workID, rootDir string) []ValidationResult {
	workDir := filepath.Join(rootDir, ".pwn", "work", workID)
	results := make([]ValidationResult, 0, len(workDocuments))

	for _, entry := range workDocuments {
		absolute := filepath.Join(workDir, entry.document)
		relative := relativePath(rootDir, absolute)
		if _, err := os.Stat(absolute); err != nil {
			continue
		}
		data, err := os.ReadFile(absolute)
		if err != nil {
			results = append(results, ValidationResult{File: relative, Errors: []string{"JSON Syntax Error: " + err.Error()}})
			continue
		}
		document, err := jsonschema.Decode(data)
		if err != nil {
			results = append(results, ValidationResult{File: relative, Errors: []string{"JSON Syntax Error: " + err.Error()}})
			continue
		}
		schemas, err := compiledLaws()
		if err != nil {
			results = append(results, ValidationResult{File: relative, Errors: []string{err.Error()}})
			continue
		}
		schema, ok := schemas[entry.schema]
		if !ok {
			results = append(results, ValidationResult{File: relative, Errors: []string{"unknown schema: " + entry.schema}})
			continue
		}
		errs := schema.Validate(document)
		if errs == nil {
			errs = []string{}
		}
		results = append(results, ValidationResult{Valid: len(errs) == 0, File: relative, Errors: errs})
	}

	return results
}

// ValidateAllCoreNormatives validates the framework's own normative documents.
func ValidateAllCoreNormatives(rootDir string) []ValidationResult {
	results := make([]ValidationResult, 0, len(coreNormatives))
	for _, file := range coreNormatives {
		results = append(results, ValidateNormativeDocument(file, rootDir))
	}
	return results
}

// declaredSchemaName distinguishes "no `$schema`" from "`$schema` declared but
// without a usable schema name". The first case is a document the gates
// validate; the second must fail.
func declaredSchemaName(document any) (declared bool, name string) {
	object, ok := document.(map[string]any)
	if !ok {
		return false, ""
	}
	value, present := object["$schema"]
	if !present {
		return false, ""
	}
	text, ok := value.(string)
	if !ok {
		return true, ""
	}
	return true, baseName(text)
}

// baseName mirrors node:path.basename for POSIX paths: "" and "/" yield "",
// while "a/" yields "a".
func baseName(value string) string {
	for len(value) > 1 && strings.HasSuffix(value, "/") {
		value = strings.TrimSuffix(value, "/")
	}
	if value == "/" {
		return ""
	}
	if index := strings.LastIndexByte(value, '/'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func resolvePath(rootDir, filePath string) string {
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}
	return filepath.Join(rootDir, filePath)
}

func relativePath(rootDir, absolute string) string {
	relative, err := filepath.Rel(rootDir, absolute)
	if err != nil {
		return absolute
	}
	return relative
}
