package plan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// promptSections são as seções obrigatórias, na ordem canônica.
var promptSections = []string{
	"## Delta da system spec",
	"## Problema e resultado",
	"## Contexto confirmado",
	"## Atores e valor",
	"## Escopo",
	"## Cenários de usuário",
	"## Contrato observável",
	"## Requisitos",
	"## Casos de borda",
	"## Critérios de sucesso",
	"## Premissas",
	"## Componentes afetados",
	"## Rastreabilidade",
}

// promptSubsections são as subseções obrigatórias.
var promptSubsections = []string{
	"### Inclui",
	"### Não inclui",
	"### Funcionais",
	"### Qualidade e restrições",
}

const promptStatus = "**Status:** Pronto para planejamento"

var (
	promptTitle         = regexp.MustCompile(`(?m)^# PROMPT: \S.+$`)
	promptWorkID        = regexp.MustCompile(`(?m)^\*\*Work ID:\*\* ([0-9]{4})$`)
	promptSource        = regexp.MustCompile(`(?m)^\*\*Origem:\*\* ` + "`\\.sources/[0-9]{4}-.+\\.md`" + `$`)
	promptSystemSpec    = regexp.MustCompile("(?m)^\\*\\*System spec:\\*\\* `[^`]+`$")
	promptBaseline      = regexp.MustCompile(`(?m)^\*\*Baseline:\*\* \S.+$`)
	promptCanonicalFile = regexp.MustCompile(`^([0-9]{4})-change\.md$`)
	unresolvedMarker    = regexp.MustCompile(`<[^>\n]+>|\bTODO\b|\bTBD\b|\bNEEDS CLARIFICATION\b`)
	promptCheckbox      = regexp.MustCompile(`(?m)^\s*- \[[ xX!]\]`)
	userStoryPattern    = regexp.MustCompile(`(?m)^### (US-[0-9]{3}) — .+ \(P[1-3]\)$`)
	acceptancePattern   = regexp.MustCompile(`(?m)^[0-9]+\. \*\*Given\*\* .+ \*\*When\*\* .+ \*\*Then\*\* .+\(([^)]+)\)\s*$`)
	requirementPattern  = regexp.MustCompile(`(?m)^- \*\*((FR|QR)-[0-9]{3}):\*\*\s+(.+)$`)
	edgeCasePattern     = regexp.MustCompile(`(?m)^- \*\*(EC-[0-9]{3}):\*\*\s+(.+)$`)
	successCriterion    = regexp.MustCompile(`(?m)^- \*\*(SC-[0-9]{3}):\*\*\s+(.+)$`)
	assumptionPattern   = regexp.MustCompile(`(?m)^- \*\*(A-[0-9]{3}):\*\*\s+(.+)$`)
	traceRowPattern     = regexp.MustCompile("(?m)^\\| `((FR|QR)-[0-9]{3})` \\| ([^|]+) \\| ([^|]+) \\|\\s*$")
	referencePattern    = regexp.MustCompile(`\b(FR|QR|US|EC|SC|A)-[0-9]{3}\b`)
	systemReference     = regexp.MustCompile(`\b(ACT|CAP|BR|CON|ENT|SQR|INT|GAP)-[0-9]{3}\b`)
	vagueTermPattern    = regexp.MustCompile(`(?i)\b(rápid[oa]s?|segur[oa]s?|intuitiv[oa]s?|robust[oa]s?|adequad[oa]s?|corretamente|eficiente(mente)?)\b`)
	acceptanceReference = regexp.MustCompile(`(FR|QR)-[0-9]{3}`)
	coverageReference   = regexp.MustCompile(`(US|EC|SC)-[0-9]{3}`)
	evidenceTooGeneric  = regexp.MustCompile(`(?i)^testes? pass(a|am)$`)
)

// PromptValidationCounts resume o prompt validado.
type PromptValidationCounts struct {
	Requirements    int
	Scenarios       int
	SuccessCriteria int
}

// PromptValidation é o resultado da validação do prompt canônico.
type PromptValidation struct {
	Errors []string
	Counts *PromptValidationCounts
}

func occurrences(text, value string) int {
	count := 0
	for offset := 0; ; {
		index := strings.Index(text[offset:], value)
		if index == -1 {
			return count
		}
		count++
		offset += index + len(value)
	}
}

func lineFor(text string, index int) int {
	return strings.Count(text[:index], "\n") + 1
}

func duplicateIDs(entries []string, errors *[]string) {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if seen[entry] {
			*errors = append(*errors, "duplicate ID: "+entry)
		}
		seen[entry] = true
	}
}

func checkSequence(ids []string, prefix string, errors *[]string) {
	for index, id := range ids {
		expected := fmt.Sprintf("%s-%03d", prefix, index+1)
		if id != expected {
			*errors = append(*errors, fmt.Sprintf("%s IDs must be sequential: expected %s, found %s", prefix, expected, id))
		}
	}
}

func sectionText(text, heading string) string {
	start := strings.Index(text, heading)
	if start == -1 {
		return ""
	}
	contentStart := start + len(heading)
	next := strings.Index(text[contentStart:], "\n## ")
	if next == -1 {
		return text[contentStart:]
	}
	return text[contentStart : contentStart+next]
}

func validateReferences(text string, known map[string]bool, errors *[]string) {
	for _, match := range referencePattern.FindAllStringIndex(text, -1) {
		reference := text[match[0]:match[1]]
		if !known[reference] {
			*errors = append(*errors, fmt.Sprintf("line %d: reference to unknown ID: %s", lineFor(text, match[0]), reference))
		}
	}
}

// ValidatePrompt valida o prompt canônico contra a baseline do sistema. Passa
// systemSpecPath vazio quando a spec não está disponível.
func ValidatePrompt(filePath, systemSpecPath string) PromptValidation {
	if _, err := os.Stat(filePath); err != nil {
		return PromptValidation{Errors: []string{"file not found: " + filePath}, Counts: nil}
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return PromptValidation{Errors: []string{"file not found: " + filePath}, Counts: nil}
	}
	text := string(data)
	errors := make([]string, 0, 8)
	systemText := ""
	if systemSpecPath == "" {
		errors = append(errors, "system spec path is required")
	} else if systemData, readErr := os.ReadFile(systemSpecPath); readErr != nil {
		errors = append(errors, "system spec not found: "+systemSpecPath)
	} else {
		systemText = string(systemData)
	}

	if !promptTitle.MatchString(text) {
		errors = append(errors, "missing concrete title: # PROMPT: ...")
	}
	if !strings.Contains(text, promptStatus) {
		errors = append(errors, "missing status: "+promptStatus)
	}
	workMatch := promptWorkID.FindStringSubmatch(text)
	if workMatch == nil {
		errors = append(errors, "missing or invalid Work ID: **Work ID:** NNNN")
	}
	canonicalPrompt := promptCanonicalFile.FindStringSubmatch(filepath.Base(filePath))
	if canonicalPrompt == nil || filepath.Base(filepath.Dir(filePath)) != ".prompts" {
		errors = append(errors, "prompt must use canonical path .prompts/NNNN-change.md: "+filePath)
	} else if workMatch != nil && canonicalPrompt[1] != workMatch[1] {
		errors = append(errors, fmt.Sprintf("prompt filename Work ID %s does not match declaration %s", canonicalPrompt[1], workMatch[1]))
	}
	if !promptSource.MatchString(text) {
		errors = append(errors, "missing canonical numbered source snapshot reference")
	}
	if !promptSystemSpec.MatchString(text) {
		errors = append(errors, "missing system spec reference")
	}
	if !promptBaseline.MatchString(text) {
		errors = append(errors, "missing concrete system baseline version and status")
	}

	lastSectionIndex := -1
	for _, heading := range promptSections {
		count := occurrences(text, heading)
		if count == 0 {
			errors = append(errors, "missing section: "+heading)
			continue
		}
		if count > 1 {
			errors = append(errors, "duplicate section: "+heading)
		}
		index := strings.Index(text, heading)
		if index < lastSectionIndex {
			errors = append(errors, "section out of order: "+heading)
		}
		lastSectionIndex = index
		if strings.TrimSpace(sectionText(text, heading)) == "" {
			errors = append(errors, "empty section: "+heading)
		}
	}

	for _, heading := range promptSubsections {
		count := occurrences(text, heading)
		if count == 0 {
			errors = append(errors, "missing subsection: "+heading)
		}
		if count > 1 {
			errors = append(errors, "duplicate subsection: "+heading)
		}
	}

	for _, match := range unresolvedMarker.FindAllStringIndex(text, -1) {
		errors = append(errors, fmt.Sprintf("line %d: unresolved marker: %s", lineFor(text, match[0]), text[match[0]:match[1]]))
	}
	if promptCheckbox.MatchString(text) {
		errors = append(errors, "checkboxes are not allowed in a specification")
	}

	storyMatches := userStoryPattern.FindAllStringSubmatchIndex(text, -1)
	stories := make([]string, 0, len(storyMatches))
	for _, match := range storyMatches {
		stories = append(stories, text[match[2]:match[3]])
	}
	acceptanceScenarios := acceptancePattern.FindAllStringSubmatch(text, -1)
	requirements := requirementPattern.FindAllStringSubmatch(text, -1)
	edgeCases := edgeCasePattern.FindAllStringSubmatch(text, -1)
	successCriteria := successCriterion.FindAllStringSubmatch(text, -1)
	assumptions := assumptionPattern.FindAllStringSubmatch(text, -1)
	traceRows := traceRowPattern.FindAllStringSubmatch(text, -1)

	if len(stories) == 0 {
		errors = append(errors, "at least one canonical user scenario is required: ### US-001 — Title (P1)")
	}
	if len(acceptanceScenarios) == 0 {
		errors = append(errors, "at least one Given/When/Then acceptance scenario with requirement references is required")
	}
	for index, current := range storyMatches {
		start := current[0]
		end := len(text)
		if index+1 < len(storyMatches) {
			end = storyMatches[index+1][0]
		} else if sectionEnd := strings.Index(text[start:], "\n## "); sectionEnd != -1 {
			end = start + sectionEnd
		}
		block := text[start:end]
		for _, field := range []string{"Ator", "Valor independente", "Verificação independente"} {
			fieldPattern := regexp.MustCompile(`\*\*` + field + `:\*\*\s+\S`)
			if !fieldPattern.MatchString(block) {
				errors = append(errors, stories[index]+" missing concrete field: "+field)
			}
		}
		if len(acceptancePattern.FindAllStringSubmatch(block, -1)) == 0 {
			errors = append(errors, stories[index]+" needs at least one canonical Given/When/Then acceptance scenario")
		}
	}

	hasFunctional := false
	for _, match := range requirements {
		if strings.HasPrefix(match[1], "FR-") {
			hasFunctional = true
			break
		}
	}
	if !hasFunctional {
		errors = append(errors, "at least one functional requirement FR-001 is required")
	}
	if len(successCriteria) == 0 {
		errors = append(errors, "at least one success criterion SC-001 is required")
	}
	if len(edgeCases) == 0 {
		errors = append(errors, "at least one edge case EC-001 is required")
	}

	functionalIDs := make([]string, 0, len(requirements))
	qualityIDs := make([]string, 0, len(requirements))
	for _, match := range requirements {
		if strings.HasPrefix(match[1], "FR-") {
			functionalIDs = append(functionalIDs, match[1])
		} else {
			qualityIDs = append(qualityIDs, match[1])
		}
	}
	edgeIDs := make([]string, 0, len(edgeCases))
	for _, match := range edgeCases {
		edgeIDs = append(edgeIDs, match[1])
	}
	criterionIDs := make([]string, 0, len(successCriteria))
	for _, match := range successCriteria {
		criterionIDs = append(criterionIDs, match[1])
	}
	assumptionIDs := make([]string, 0, len(assumptions))
	for _, match := range assumptions {
		assumptionIDs = append(assumptionIDs, match[1])
	}
	groups := []struct {
		ids    []string
		prefix string
	}{
		{ids: stories, prefix: "US"},
		{ids: functionalIDs, prefix: "FR"},
		{ids: qualityIDs, prefix: "QR"},
		{ids: edgeIDs, prefix: "EC"},
		{ids: criterionIDs, prefix: "SC"},
		{ids: assumptionIDs, prefix: "A"},
	}
	for _, group := range groups {
		duplicateIDs(group.ids, &errors)
		if len(group.ids) > 0 {
			checkSequence(group.ids, group.prefix, &errors)
		}
	}

	requirementIDs := make([]string, 0, len(requirements))
	allIDs := make(map[string]bool)
	for _, story := range stories {
		allIDs[story] = true
	}
	for _, match := range requirements {
		requirementIDs = append(requirementIDs, match[1])
		allIDs[match[1]] = true
	}
	for _, id := range edgeIDs {
		allIDs[id] = true
	}
	for _, id := range criterionIDs {
		allIDs[id] = true
	}
	for _, id := range assumptionIDs {
		allIDs[id] = true
	}
	validateReferences(text, allIDs, &errors)

	if systemText != "" {
		knownSystemIDs := make(map[string]bool)
		for _, match := range systemReference.FindAllString(systemText, -1) {
			knownSystemIDs[match] = true
		}
		for _, match := range systemReference.FindAllStringIndex(text, -1) {
			reference := text[match[0]:match[1]]
			if !knownSystemIDs[reference] {
				errors = append(errors, fmt.Sprintf("line %d: system reference not found in baseline: %s", lineFor(text, match[0]), reference))
			}
		}
	}

	delta := sectionText(text, "## Delta da system spec")
	for _, field := range []string{
		"Capacidades afetadas",
		"Regras preservadas",
		"Regras alteradas",
		"Contratos afetados",
		"Qualidades, entidades e integrações relacionadas",
		"Gaps tocados",
		"Reconciliação esperada após implementação",
	} {
		fieldPattern := regexp.MustCompile(`(?m)^- \*\*` + regexp.QuoteMeta(field) + `:\*\* \S`)
		if !fieldPattern.MatchString(delta) {
			errors = append(errors, "Delta da system spec missing concrete field: "+field)
		}
	}
	if !regexp.MustCompile(`(?i)(CAP-[0-9]{3}|nenhuma)`).MatchString(delta) {
		errors = append(errors, "delta must identify affected CAP-* capabilities or explicitly state none")
	}
	if !regexp.MustCompile(`(?i)(CON-[0-9]{3}|nenhum)`).MatchString(delta) {
		errors = append(errors, "delta must identify affected CON-* contracts or explicitly state none")
	}

	acceptanceReferences := make(map[string]bool)
	for _, scenario := range acceptanceScenarios {
		for _, match := range acceptanceReference.FindAllString(scenario[1], -1) {
			acceptanceReferences[match] = true
		}
	}
	if len(acceptanceReferences) == 0 {
		errors = append(errors, "acceptance scenarios must reference FR-* or QR-* IDs")
	}

	for _, entry := range append(append([][]string{}, edgeCases...), successCriteria...) {
		if !acceptanceReference.MatchString(entry[2]) {
			errors = append(errors, entry[1]+" must reference at least one FR-* or QR-* ID")
		}
	}

	traceByRequirement := make(map[string][]string)
	for _, row := range traceRows {
		id := row[1]
		if _, exists := traceByRequirement[id]; exists {
			errors = append(errors, "duplicate traceability row: "+id)
		}
		traceByRequirement[id] = row
		coverageIDs := coverageReference.FindAllString(row[3], -1)
		if len(coverageIDs) == 0 {
			errors = append(errors, "traceability coverage needs US-*, EC-* or SC-* IDs: "+id)
		}
		evidence := strings.TrimSpace(row[4])
		trimmed := strings.TrimRight(evidence, ".!")
		if len(strings.Fields(evidence)) < 4 || evidenceTooGeneric.MatchString(trimmed) {
			errors = append(errors, "traceability evidence is not specific enough: "+id)
		}
	}
	for _, id := range requirementIDs {
		if _, exists := traceByRequirement[id]; !exists {
			errors = append(errors, "requirement missing from traceability table: "+id)
		}
	}
	for id := range traceByRequirement {
		if !containsString(requirementIDs, id) {
			errors = append(errors, "traceability row references unknown requirement: "+id)
		}
	}

	for _, match := range requirements {
		if len(strings.Fields(strings.TrimSpace(match[3]))) < 7 {
			errors = append(errors, match[1]+" is too short to be reliably testable")
		}
		for _, vague := range vagueTermPattern.FindAllString(match[3], -1) {
			errors = append(errors, match[1]+" uses vague term without an objective condition: "+vague)
		}
	}

	problem := sectionText(text, "## Problema e resultado")
	if !regexp.MustCompile(`\*\*Problema:\*\*\s+\S`).MatchString(problem) {
		errors = append(errors, "Problema e resultado must contain a concrete **Problema:** field")
	}
	if !regexp.MustCompile(`\*\*Resultado esperado:\*\*\s+\S`).MatchString(problem) {
		errors = append(errors, "Problema e resultado must contain a concrete **Resultado esperado:** field")
	}

	scope := sectionText(text, "## Escopo")
	for _, heading := range []string{"### Inclui", "### Não inclui"} {
		start := strings.Index(scope, heading)
		if start == -1 {
			continue
		}
		after := scope[start+len(heading):]
		content := after
		if next := strings.Index(after, "\n### "); next != -1 {
			content = after[:next]
		}
		if !regexp.MustCompile(`(?m)^\s*- \S`).MatchString(content) {
			errors = append(errors, heading+" must contain at least one concrete list item")
		}
	}

	contract := sectionText(text, "## Contrato observável")
	for _, field := range []string{"Entradas", "Saídas e efeitos", "Erros"} {
		fieldPattern := regexp.MustCompile(`(?m)^- \*\*` + regexp.QuoteMeta(field) + `:\*\* \S`)
		if !fieldPattern.MatchString(contract) {
			errors = append(errors, "Contrato observável missing concrete field: "+field)
		}
	}

	return PromptValidation{
		Errors: errors,
		Counts: &PromptValidationCounts{
			Requirements:    len(requirementIDs),
			Scenarios:       len(stories),
			SuccessCriteria: len(successCriteria),
		},
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// ValidatePromptMain executa a interface de linha de comando do validador de
// prompt e devolve o código de saída.
func ValidatePromptMain(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "Usage: validate_prompt.js <prompt.md> <system-spec.md>")
		return 2
	}
	result := ValidatePrompt(args[0], args[1])
	if len(result.Errors) > 0 {
		suffix := "s"
		if len(result.Errors) == 1 {
			suffix = ""
		}
		fmt.Fprintf(stderr, "PROMPT VALIDATION: FAIL (%d error%s)\n", len(result.Errors), suffix)
		for _, issue := range result.Errors {
			fmt.Fprintf(stderr, "- %s\n", issue)
		}
		return 1
	}
	fmt.Fprintln(stdout, "PROMPT VALIDATION: PASS")
	if result.Counts != nil {
		fmt.Fprintf(stdout, "Requirements: %d\n", result.Counts.Requirements)
		fmt.Fprintf(stdout, "Scenarios: %d\n", result.Counts.Scenarios)
		fmt.Fprintf(stdout, "Success criteria: %d\n", result.Counts.SuccessCriteria)
	}
	return 0
}
