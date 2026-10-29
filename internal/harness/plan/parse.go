package plan

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/passoz/pwn/internal/platform/jsonx"
)

// PlanCommand é um comando de RED/AC declarado no plano.
type PlanCommand struct {
	Command     string
	Description string
}

// PlanRequirement declara se a task exige uma verificação e qual comando a
// comprova. Command vazio indica ausência do comando, como `null` na referência.
type PlanRequirement struct {
	Required bool
	Command  string
}

// PlanTaskDefinition é a definição de uma task extraída do markdown v3
// (`.todo/NNNN-tasks.md`).
type PlanTaskDefinition struct {
	ID                  string
	Marker              string
	Title               string
	Lines               []string
	ImplementationFiles []string
	TestFiles           []string
	Components          []string
	Red                 *PlanCommand
	ACs                 []PlanCommand
	Visual              PlanRequirement
	Documentation       PlanRequirement
}

// PlanGlobalGate é um item de `## Global gates`.
type PlanGlobalGate struct {
	Marker  string
	Command string
	Text    string
}

// CheckBinding é o resultado de AllowedCheckCommands: os comandos autorizados
// para um check e, quando não há nenhum, o motivo.
type CheckBinding struct {
	Commands []string
	Error    string
}

var (
	taskHeadingPattern    = regexp.MustCompile("^### \\[([ x!])\\] \\[([0-9]+)\\.([0-9]+)\\] (.*)$")
	redLinePattern        = regexp.MustCompile("^- `([^`]+)`(\\s+—\\s+(.*))?\\s*$")
	acLinePattern         = regexp.MustCompile("^- \\[[ xX!]\\] `([^`]+)`(\\s+—\\s+(.*))?\\s*$")
	evidenceLinePattern   = regexp.MustCompile("^- \\*\\*Evidence:\\*\\* `([^`]+)`")
	gateLinePattern       = regexp.MustCompile("^- \\[([ xX!])\\]\\s*(.*)$")
	inlineCodePattern     = regexp.MustCompile("`([^`\n]+)`")
	taskIDPattern         = regexp.MustCompile(`^([0-9]+)\.([0-9]+)$`)
	checkACPattern        = regexp.MustCompile(`^AC-([1-9][0-9]*)$`)
	tableSeparatorPattern = regexp.MustCompile(`^[-:]+$`)
)

type taskBlock struct {
	ID     string
	Marker string
	Title  string
	Start  int
	End    int
}

func normalizeTaskID(taskID string) string {
	match := taskIDPattern.FindStringSubmatch(taskID)
	if match == nil {
		return taskID
	}
	return fmt.Sprintf("%d.%d", atoi(match[1]), atoi(match[2]))
}

// atoi converte dígitos ASCII, ignorando zeros à esquerda.
func atoi(value string) int {
	result := 0
	for _, digit := range value {
		result = result*10 + int(digit-'0')
	}
	return result
}

func fieldValue(block []string, name string) (string, bool) {
	prefixes := []string{"**" + name + ":**", "- **" + name + ":**"}
	for _, line := range block {
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				return strings.TrimSpace(line[len(prefix):]), true
			}
		}
	}
	return "", false
}

func fieldSection(block []string, name string) []string {
	start := -1
	heading := "**" + name + ":**"
	for index, line := range block {
		if line == heading {
			start = index
			break
		}
	}
	if start == -1 {
		return nil
	}
	end := len(block)
	for index := start + 1; index < len(block); index++ {
		if strings.HasPrefix(block[index], "**") {
			end = index
			break
		}
	}
	return block[start+1 : end]
}

func stripBackticks(value string) string {
	value = strings.TrimPrefix(value, "`")
	return strings.TrimSuffix(value, "`")
}

func listValues(value string, present bool) []string {
	if !present {
		return nil
	}
	seen := make(map[string]bool)
	values := make([]string, 0, 4)
	for _, part := range strings.Split(value, ",") {
		item := stripBackticks(strings.TrimSpace(part))
		if item == "" || item == "N/A" || seen[item] {
			continue
		}
		seen[item] = true
		values = append(values, item)
	}
	return values
}

func taskBlocks(lines []string) []taskBlock {
	type heading struct {
		index int
		match []string
	}
	headings := make([]heading, 0, 4)
	for index, line := range lines {
		if match := taskHeadingPattern.FindStringSubmatch(line); match != nil {
			headings = append(headings, heading{index: index, match: match})
		}
	}
	blocks := make([]taskBlock, 0, len(headings))
	for position, current := range headings {
		end := len(lines)
		if position+1 < len(headings) {
			end = headings[position+1].index
		}
		for cursor := current.index + 1; cursor < end; cursor++ {
			if strings.HasPrefix(lines[cursor], "## ") ||
				(strings.HasPrefix(lines[cursor], "### ") && taskHeadingPattern.FindStringSubmatch(lines[cursor]) == nil) {
				end = cursor
				break
			}
		}
		blocks = append(blocks, taskBlock{
			ID:     fmt.Sprintf("%d.%d", atoi(current.match[2]), atoi(current.match[3])),
			Marker: current.match[1],
			Title:  current.match[4],
			Start:  current.index,
			End:    end,
		})
	}
	return blocks
}

func definitionFromBlock(id, marker, title string, block []string) PlanTaskDefinition {
	var red *PlanCommand
	for _, line := range fieldSection(block, "RED") {
		if match := redLinePattern.FindStringSubmatch(line); match != nil {
			red = &PlanCommand{Command: strings.TrimSpace(match[1]), Description: strings.TrimSpace(optionalGroup(match, 3))}
			break
		}
	}

	acs := make([]PlanCommand, 0, 2)
	for _, line := range fieldSection(block, "ACs") {
		if match := acLinePattern.FindStringSubmatch(line); match != nil {
			acs = append(acs, PlanCommand{Command: strings.TrimSpace(match[1]), Description: strings.TrimSpace(optionalGroup(match, 3))})
		}
	}

	visualValue, _ := fieldValue(block, "Visual")
	visualRequired := visualValue == "REQUIRED"
	playwright, hasPlaywright := fieldValue(block, "Playwright")
	documentationValue, _ := fieldValue(block, "Documentation")
	documentationRequired := documentationValue == "REQUIRED"
	evidenceCommand := ""
	for _, line := range block {
		if match := evidenceLinePattern.FindStringSubmatch(line); match != nil {
			evidenceCommand = strings.TrimSpace(match[1])
			break
		}
	}

	visual := PlanRequirement{Required: visualRequired}
	if visualRequired && hasPlaywright && playwright != "" {
		if command, found := FirstInlineCommand(playwright); found {
			visual.Command = command
		}
	}
	documentation := PlanRequirement{Required: documentationRequired}
	if documentationRequired {
		documentation.Command = evidenceCommand
	}

	implementationFiles, hasImplementationFiles := fieldValue(block, "Implementation files")
	testFiles, hasTestFiles := fieldValue(block, "Test files")
	components, hasComponents := fieldValue(block, "Components")

	return PlanTaskDefinition{
		ID:                  id,
		Marker:              marker,
		Title:               title,
		Lines:               block,
		ImplementationFiles: listValues(implementationFiles, hasImplementationFiles),
		TestFiles:           listValues(testFiles, hasTestFiles),
		Components:          listValues(components, hasComponents),
		Red:                 red,
		ACs:                 acs,
		Visual:              visual,
		Documentation:       documentation,
	}
}

// optionalGroup devolve o grupo opcional ou "" quando ele não casou.
func optionalGroup(match []string, index int) string {
	if index < len(match) {
		return match[index]
	}
	return ""
}

// ParsePlanTask lê a definição de uma task do plano. Devolve nil quando a task
// não existe.
func ParsePlanTask(planText, taskID string) *PlanTaskDefinition {
	lines := splitLines(planText)
	wanted := normalizeTaskID(taskID)
	for _, entry := range taskBlocks(lines) {
		if entry.ID != wanted {
			continue
		}
		definition := definitionFromBlock(entry.ID, entry.Marker, entry.Title, lines[entry.Start:entry.End])
		return &definition
	}
	return nil
}

// ParsePlanTasks devolve todas as tasks do plano, na ordem do arquivo.
func ParsePlanTasks(planText string) []PlanTaskDefinition {
	lines := splitLines(planText)
	blocks := taskBlocks(lines)
	definitions := make([]PlanTaskDefinition, 0, len(blocks))
	for _, entry := range blocks {
		definitions = append(definitions, definitionFromBlock(entry.ID, entry.Marker, entry.Title, lines[entry.Start:entry.End]))
	}
	return definitions
}

var lineBreakPattern = regexp.MustCompile("\r?\n")

func splitLines(text string) []string {
	return lineBreakPattern.Split(text, -1)
}

func sectionLines(lines []string, heading string) ([]string, bool) {
	start := -1
	for index, line := range lines {
		if line == heading {
			start = index
			break
		}
	}
	if start == -1 {
		return nil, false
	}
	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index], "## ") || strings.HasPrefix(lines[index], "### ") {
			end = index
			break
		}
	}
	return lines[start+1 : end], true
}

// ParseGlobalGates lê os itens de `## Global gates`. found=false quando a seção
// não existe; a lista é vazia quando a seção é `N/A`.
func ParseGlobalGates(planText string) (gates []PlanGlobalGate, found bool) {
	section, present := sectionLines(splitLines(planText), "## Global gates")
	if !present {
		return nil, false
	}
	gates = make([]PlanGlobalGate, 0, 2)
	for _, line := range section {
		match := gateLinePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		text := strings.TrimSpace(match[2])
		command := ""
		if inline := inlineCodePattern.FindStringSubmatch(text); inline != nil {
			command = strings.TrimSpace(inline[1])
		}
		gates = append(gates, PlanGlobalGate{Marker: strings.ToLower(match[1]), Command: command, Text: text})
	}
	return gates, true
}

// assuranceColumns são as colunas de garantia que contam como gate local.
var assuranceColumns = []string{"regression", "lint", "build", "security"}

type assuranceRow struct {
	component string
	columns   map[string]string
}

func tableCells(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	cells := strings.Split(trimmed, "|")
	for index, cell := range cells {
		cells[index] = stripBackticks(strings.TrimSpace(cell))
	}
	return cells
}

func assuranceTable(planText string) []assuranceRow {
	section, present := sectionLines(splitLines(planText), "## Execution contract")
	if !present {
		return nil
	}
	rows := make([]string, 0, 4)
	for _, line := range section {
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			rows = append(rows, line)
		}
	}
	if len(rows) < 2 {
		return nil
	}
	headers := tableCells(rows[0])
	for index, header := range headers {
		headers[index] = strings.ToLower(header)
	}
	result := make([]assuranceRow, 0, len(rows)-1)
	for _, line := range rows[1:] {
		cells := tableCells(line)
		if len(cells) == 0 || tableSeparatorPattern.MatchString(cells[0]) || strings.ToLower(cells[0]) == "component" {
			continue
		}
		columns := make(map[string]string, len(headers))
		for index, header := range headers {
			if index < len(cells) {
				columns[header] = cells[index]
			} else {
				columns[header] = ""
			}
		}
		result = append(result, assuranceRow{component: cells[0], columns: columns})
	}
	return result
}

func tableCommands(planText string, columns []string, components []string) []string {
	wanted := make(map[string]bool, len(components))
	for _, component := range components {
		wanted[component] = true
	}
	filter := len(components) > 0
	commands := make([]string, 0, 4)
	for _, row := range assuranceTable(planText) {
		if filter && !wanted[row.component] {
			continue
		}
		for _, column := range columns {
			value := row.columns[column]
			if value != "" && value != "N/A" {
				commands = append(commands, value)
			}
		}
	}
	return commands
}

func globalGateCommands(planText string) []string {
	gates, _ := ParseGlobalGates(planText)
	commands := make([]string, 0, len(gates))
	for _, gate := range gates {
		if gate.Command != "" {
			commands = append(commands, gate.Command)
		}
	}
	return commands
}

func uniqueCommands(commands []string) []string {
	seen := make(map[string]bool, len(commands))
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		key := NormalizeCommand(command)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, command)
	}
	return result
}

// RegressionCommands devolve os comandos aceitos para o check REGRESSION: a
// coluna Regression dos componentes da task mais os gates globais.
func RegressionCommands(planText string, components []string) []string {
	return uniqueCommands(append(tableCommands(planText, []string{"regression"}, components), globalGateCommands(planText)...))
}

// AssuranceCommands devolve todos os comandos de gate do plano (colunas de
// garantia mais gates globais): nenhum deles é AC de task.
func AssuranceCommands(planText string, components []string) []string {
	return uniqueCommands(append(tableCommands(planText, assuranceColumns, components), globalGateCommands(planText)...))
}

// RequiredAuditChecks devolve os checks que a atestação de aceitação exige para
// a task.
func RequiredAuditChecks(task PlanTaskDefinition) []string {
	checks := make([]string, 0, len(task.ACs)+3)
	for index := range task.ACs {
		checks = append(checks, fmt.Sprintf("AC-%d", index+1))
	}
	if task.Visual.Required {
		checks = append(checks, "VISUAL")
	}
	if task.Documentation.Required {
		checks = append(checks, "DOCUMENTATION")
	}
	checks = append(checks, "REGRESSION")
	return checks
}

// AllowedCheckCommands devolve os comandos que o plano autoriza para um check
// do audit, ou o motivo de não haver nenhum.
func AllowedCheckCommands(planText string, task PlanTaskDefinition, name string) CheckBinding {
	empty := []string{}
	if match := checkACPattern.FindStringSubmatch(name); match != nil {
		index := atoi(match[1]) - 1
		if index < 0 || index >= len(task.ACs) {
			return CheckBinding{Commands: empty, Error: fmt.Sprintf("%s não existe no plano: a task %s declara %d AC(s)", name, task.ID, len(task.ACs))}
		}
		return CheckBinding{Commands: []string{task.ACs[index].Command}}
	}
	switch name {
	case "VISUAL":
		if !task.Visual.Required {
			return CheckBinding{Commands: empty, Error: fmt.Sprintf("a task %s não exige VISUAL", task.ID)}
		}
		if task.Visual.Command == "" {
			return CheckBinding{Commands: empty, Error: fmt.Sprintf("a task %s exige VISUAL mas não declara o comando em **Playwright:**", task.ID)}
		}
		return CheckBinding{Commands: []string{task.Visual.Command}}
	case "DOCUMENTATION":
		if !task.Documentation.Required {
			return CheckBinding{Commands: empty, Error: fmt.Sprintf("a task %s não exige DOCUMENTATION", task.ID)}
		}
		if task.Documentation.Command == "" {
			return CheckBinding{Commands: empty, Error: fmt.Sprintf("a task %s exige DOCUMENTATION mas não declara o comando em **Evidence:**", task.ID)}
		}
		return CheckBinding{Commands: []string{task.Documentation.Command}}
	case "REGRESSION":
		commands := RegressionCommands(planText, task.Components)
		if len(commands) == 0 {
			return CheckBinding{Commands: commands, Error: "o plano não declara comando de regressão (coluna Regression ou itens de ## Global gates)"}
		}
		return CheckBinding{Commands: commands}
	case "LOCAL-GATES":
		commands := AssuranceCommands(planText, task.Components)
		if len(commands) == 0 {
			return CheckBinding{Commands: commands, Error: "o plano não declara gates locais (colunas de garantia ou ## Global gates)"}
		}
		return CheckBinding{Commands: commands}
	}
	return CheckBinding{Commands: empty, Error: "check desconhecido: " + name}
}

// TaskDefinitionDigest devolve a impressão digital da definição da task: o bloco
// do plano sem o estado dos checkboxes mais os comandos de gate que se aplicam a
// ela. Congelada no baseline, impede trocar ACs, RED ou arquivos no meio do
// ciclo.
func TaskDefinitionDigest(planText string, task PlanTaskDefinition) string {
	normalized := NormalizeMarkers(strings.Join(task.Lines, "\n"))
	blockLines := strings.Split(normalized, "\n")
	for index, line := range blockLines {
		blockLines[index] = strings.TrimRightFunc(line, unicode.IsSpace)
	}
	block := strings.TrimSpace(strings.Join(blockLines, "\n"))

	gates := AssuranceCommands(planText, task.Components)
	normalizedGates := make([]string, len(gates))
	for index, gate := range gates {
		normalizedGates[index] = NormalizeCommand(gate)
	}

	payload := struct {
		Block string   `json:"block"`
		Gates []string `json:"gates"`
	}{Block: block, Gates: normalizedGates}
	return jsonx.SHA256Hex([]byte(canonicalJSON(payload)))
}
