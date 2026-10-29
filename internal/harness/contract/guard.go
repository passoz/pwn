package contract

import (
	"fmt"
	"strings"

	"github.com/passoz/pwn/internal/platform/glob"
)

// ViolationType classifica uma violação de escopo.
type ViolationType string

const (
	ViolationWriteDeny       ViolationType = "write_deny"
	ViolationNotInWriteAllow ViolationType = "not_in_write_allow"
)

// FileDiffCheckResult é o veredicto de um arquivo contra o escopo.
type FileDiffCheckResult struct {
	Allowed       bool          `json:"allowed"`
	ViolationType ViolationType `json:"violationType,omitempty"`
	File          string        `json:"file"`
	Reason        string        `json:"reason,omitempty"`
}

// ContractDiffCheckReport é o veredicto de um conjunto de arquivos.
type ContractDiffCheckReport struct {
	Passed     bool                  `json:"passed"`
	TotalFiles int                   `json:"totalFiles"`
	Violations []FileDiffCheckResult `json:"violations"`
}

// compiledScope é a allowlist e a denylist já compiladas.
type compiledScope struct {
	allow []*glob.Pattern
	deny  []*glob.Pattern
}

// CheckFileAgainstScope verifica um arquivo contra write_allow e write_deny.
//
// A denylist é avaliada antes da allowlist: uma negação sempre vence. O caminho é
// normalizado antes da comparação, então `./src/a.ts`, `src/../src/a.ts` e
// `src//a.ts` viram `src/a.ts`. Um padrão malformado devolve erro em vez de
// degradar a proteção para um no-op.
func CheckFileAgainstScope(filePath string, writeAllow, writeDeny []string) (FileDiffCheckResult, error) {
	scope, err := compileScope(writeAllow, writeDeny)
	if err != nil {
		return FileDiffCheckResult{}, err
	}
	return scope.check(filePath), nil
}

// InvalidScopePattern devolve o primeiro padrão inválido de write_allow e depois
// de write_deny. Devolve ok=false quando todos compilam.
func InvalidScopePattern(writeAllow, writeDeny []string) (pattern string, invalid bool) {
	for _, raw := range writeAllow {
		if _, err := glob.Compile(raw); err != nil {
			return raw, true
		}
	}
	for _, raw := range writeDeny {
		if _, err := glob.Compile(raw); err != nil {
			return raw, true
		}
	}
	return "", false
}

// CheckDiffAgainstContract aplica o Diff Guard a cada arquivo modificado.
func CheckDiffAgainstContract(modifiedFiles, writeAllow, writeDeny []string) (ContractDiffCheckReport, error) {
	scope, err := compileScope(writeAllow, writeDeny)
	if err != nil {
		return ContractDiffCheckReport{}, err
	}
	violations := make([]FileDiffCheckResult, 0)
	for _, file := range modifiedFiles {
		result := scope.check(file)
		if !result.Allowed {
			violations = append(violations, result)
		}
	}
	return ContractDiffCheckReport{
		Passed:     len(violations) == 0,
		TotalFiles: len(modifiedFiles),
		Violations: violations,
	}, nil
}

func compileScope(writeAllow, writeDeny []string) (*compiledScope, error) {
	// A denylist compila primeiro porque é avaliada primeiro, como no TypeScript.
	deny, err := compilePatterns(writeDeny)
	if err != nil {
		return nil, err
	}
	allow, err := compilePatterns(writeAllow)
	if err != nil {
		return nil, err
	}
	return &compiledScope{allow: allow, deny: deny}, nil
}

func compilePatterns(patterns []string) ([]*glob.Pattern, error) {
	compiled := make([]*glob.Pattern, 0, len(patterns))
	for _, raw := range patterns {
		pattern, err := glob.Compile(raw)
		if err != nil {
			return nil, fmt.Errorf("padrão de escopo inválido %q: %w", raw, err)
		}
		compiled = append(compiled, pattern)
	}
	return compiled, nil
}

func (s *compiledScope) check(filePath string) FileDiffCheckResult {
	normalized := normalizeScopePath(filePath)

	for _, pattern := range s.deny {
		if pattern.Match(normalized) {
			return FileDiffCheckResult{
				Allowed:       false,
				ViolationType: ViolationWriteDeny,
				File:          normalized,
				Reason:        fmt.Sprintf("Arquivo %s está explicitamente na lista write_deny: %s", normalized, pattern.Source()),
			}
		}
	}

	for _, pattern := range s.allow {
		if pattern.Match(normalized) {
			return FileDiffCheckResult{Allowed: true, File: normalized}
		}
	}

	return FileDiffCheckResult{
		Allowed:       false,
		ViolationType: ViolationNotInWriteAllow,
		File:          normalized,
		Reason:        fmt.Sprintf("Arquivo %s não consta na allowlist de escrita: [%s]", normalized, strings.Join(patternSources(s.allow), ", ")),
	}
}

func patternSources(patterns []*glob.Pattern) []string {
	sources := make([]string, len(patterns))
	for index, pattern := range patterns {
		sources[index] = pattern.Source()
	}
	return sources
}

// normalizeScopePath remove o prefixo `./` e colapsa `..` e `.` mantendo barras
// normais, como o contrato-guard do TypeScript. O colapso impede que
// `src/../secret.txt` escape da allowlist.
func normalizeScopePath(filePath string) string {
	normalized := strings.TrimPrefix(filePath, "./")
	parts := strings.Split(normalized, "/")
	resolved := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
		case ".", "":
			// Segmento vazio (barra dupla) e ponto atual não entram no caminho.
		default:
			resolved = append(resolved, part)
		}
	}
	return strings.Join(resolved, "/")
}
