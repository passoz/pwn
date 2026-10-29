package work

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
)

var (
	v3TaskHeading  = regexp.MustCompile(`^### \[([ x!])\] \[(\d+\.\d+)\] (.+)$`)
	v3Field        = regexp.MustCompile(`^\*\*([^:*]+):\*\*\s*(.*)$`)
	v3ListBullet   = regexp.MustCompile("^-\\s*(?:\\[([ xX!])\\]\\s*)?`([^`]+)`\\s*(.*)$")
	v3NumberedStep = regexp.MustCompile(`^\d+\.\s+(.*)$`)
	v3GateLine     = regexp.MustCompile(`^-\s*\[[ xX!]\]\s*(.+)$`)
	v3Requirement  = regexp.MustCompile(`^-\s*\*\*((?:FR|QR|EC|SC|A|US)-\d{3}):\*\*\s*(.*)$`)
	v3PromptHeader = regexp.MustCompile(`^(#{2,3})\s+(.*)$`)
	v3ActorBullet  = regexp.MustCompile(`^\*\*([^:*]+):\*\*\s*(.*)$`)
	v3InlineCode   = regexp.MustCompile("`([^`]+)`")
	v3TableDivider = regexp.MustCompile(`^\|[\s:|-]+\|$`)
)

// stripTicks remove os espaços e as crases das pontas.
func stripTicks(value string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(value), "`"))
}

// inlineCode devolve os trechos entre crases.
func inlineCode(value string) []string {
	matches := v3InlineCode.FindAllStringSubmatch(value, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		values = append(values, strings.TrimSpace(match[1]))
	}
	return values
}

// splitList divide uma lista separada por vírgula, removendo crases e "N/A".
func splitList(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		item := stripTicks(part)
		if item == "" || item == "N/A" {
			continue
		}
		values = append(values, item)
	}
	return values
}

// unique preserva a primeira ocorrência de cada valor.
func unique(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

// commandBullet é um item `- \`comando\` — descrição`.
type commandBullet struct {
	Command     string
	Description string
}

// parseCommandBullet lê um bullet de comando.
func parseCommandBullet(line string) *commandBullet {
	match := v3ListBullet.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	rest := strings.TrimSpace(match[3])
	rest = strings.TrimLeft(rest, "—–-")
	return &commandBullet{
		Command:     strings.TrimSpace(match[2]),
		Description: strings.TrimSpace(rest),
	}
}

// splitTableRow divide uma linha de tabela em células.
func splitTableRow(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	cells := strings.Split(trimmed, "|")
	for index := range cells {
		cells[index] = strings.TrimSpace(cells[index])
	}
	return cells
}

// tableAfter lê a primeira tabela que vem depois do heading.
func tableAfter(lines []string, heading string) ([]string, [][]string, bool) {
	start := -1
	for index, line := range lines {
		if line == heading {
			start = index
			break
		}
	}
	if start == -1 {
		return nil, nil, false
	}
	index := start + 1
	for index < len(lines) && !strings.HasPrefix(lines[index], "|") {
		if strings.HasPrefix(lines[index], "## ") {
			return nil, nil, false
		}
		index++
	}
	if index >= len(lines) {
		return nil, nil, false
	}
	headers := splitTableRow(lines[index])
	index++
	if index < len(lines) && v3TableDivider.MatchString(lines[index]) {
		index++
	}
	rows := make([][]string, 0)
	for ; index < len(lines) && strings.HasPrefix(lines[index], "|"); index++ {
		rows = append(rows, splitTableRow(lines[index]))
	}
	return headers, rows, true
}

// cell devolve a célula da coluna, ou "" quando a coluna ou a célula não existe.
func cell(row []string, column int) string {
	if column < 0 || column >= len(row) {
		return ""
	}
	return row[column]
}

// columnIndex devolve o índice do cabeçalho, sem distinguir maiúsculas.
func columnIndex(headers []string, name string) int {
	for index, header := range headers {
		if strings.EqualFold(header, name) {
			return index
		}
	}
	return -1
}

// parseV3Components lê a tabela `## Execution contract`.
func parseV3Components(lines []string) []plan.PlanComponent {
	headers, rows, ok := tableAfter(lines, "## Execution contract")
	if !ok {
		return []plan.PlanComponent{}
	}
	componentIndex := columnIndex(headers, "component")
	purposeIndex := columnIndex(headers, "purpose")
	assurance := []struct {
		key    string
		column int
	}{
		{"root", columnIndex(headers, "root")},
		{"regression", columnIndex(headers, "regression")},
		{"lint", columnIndex(headers, "lint")},
		{"build", columnIndex(headers, "build")},
		{"security", columnIndex(headers, "security")},
		{"dev", columnIndex(headers, "dev")},
		{"health", columnIndex(headers, "health")},
	}
	components := make([]plan.PlanComponent, 0, len(rows))
	for _, row := range rows {
		component := plan.PlanComponent{
			Name:    stripTicks(cell(row, componentIndex)),
			Purpose: stripTicks(cell(row, purposeIndex)),
		}
		if componentIndex < 0 {
			component.Name = stripTicks(cell(row, 0))
		}
		for _, entry := range assurance {
			if entry.column < 0 {
				continue
			}
			value := stripTicks(cell(row, entry.column))
			if value == "" {
				value = "N/A"
			}
			switch entry.key {
			case "root":
				component.Root = &value
			case "regression":
				component.Regression = &value
			case "lint":
				component.Lint = &value
			case "build":
				component.Build = &value
			case "security":
				component.Security = &value
			case "dev":
				component.Dev = &value
			case "health":
				component.Health = &value
			}
		}
		components = append(components, component)
	}
	return components
}

// parseV3GlobalGates lê os itens de `## Global gates`.
func parseV3GlobalGates(lines []string) []string {
	start := -1
	for index, line := range lines {
		if line == "## Global gates" {
			start = index
			break
		}
	}
	if start == -1 {
		return []string{}
	}
	gates := make([]string, 0)
	for index := start + 1; index < len(lines); index++ {
		line := lines[index]
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
			break
		}
		if match := v3GateLine.FindStringSubmatch(line); match != nil {
			gates = append(gates, strings.TrimSpace(match[1]))
		}
	}
	return gates
}

// collectBullets lê os bullets de comando consecutivos a partir de from.
func collectBullets(block []string, from int) []commandBullet {
	bullets := make([]commandBullet, 0)
	for index := from; index < len(block); index++ {
		line := block[index]
		if strings.TrimSpace(line) == "" {
			if len(bullets) > 0 {
				break
			}
			continue
		}
		bullet := parseCommandBullet(line)
		if bullet == nil {
			break
		}
		bullets = append(bullets, *bullet)
	}
	return bullets
}

// parseV3Tasks lê os blocos de task do markdown v3.
func parseV3Tasks(lines []string) []plan.PlanTask {
	type heading struct {
		index int
		match []string
	}
	headings := make([]heading, 0)
	for index, line := range lines {
		if match := v3TaskHeading.FindStringSubmatch(line); match != nil {
			headings = append(headings, heading{index: index, match: match})
		}
	}
	contractCounter := 0
	tasks := make([]plan.PlanTask, 0, len(headings))
	for position, entry := range headings {
		end := len(lines)
		if position+1 < len(headings) {
			end = headings[position+1].index
		}
		block := lines[entry.index+1 : end]

		fields := make(map[string]string)
		redIndex, implementationIndex, acsIndex := -1, -1, -1
		for index, line := range block {
			match := v3Field.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			name := strings.TrimSpace(match[1])
			if _, present := fields[name]; !present {
				fields[name] = strings.TrimSpace(match[2])
			}
			switch name {
			case "RED":
				redIndex = index
			case "Implementation":
				implementationIndex = index
			case "ACs":
				acsIndex = index
			}
		}

		var red *commandBullet
		if redIndex >= 0 {
			if bullets := collectBullets(block, redIndex+1); len(bullets) > 0 {
				red = &bullets[0]
			}
		}
		acceptance := []commandBullet{}
		if acsIndex >= 0 {
			acceptance = collectBullets(block, acsIndex+1)
		}
		steps := make([]string, 0)
		if implementationIndex >= 0 {
			for index := implementationIndex + 1; index < len(block); index++ {
				if match := v3NumberedStep.FindStringSubmatch(block[index]); match != nil {
					steps = append(steps, strings.TrimSpace(match[1]))
					continue
				}
				if len(steps) > 0 && strings.TrimSpace(block[index]) == "" {
					break
				}
			}
		}

		status := "pending"
		switch entry.match[1] {
		case "x":
			status = "done"
		case "!":
			status = "blocked"
		}
		contractCounter++
		acceptanceCriteria := make([]plan.PlanAC, 0, len(acceptance))
		if len(acceptance) > 0 {
			for _, bullet := range acceptance {
				acceptanceCriteria = append(acceptanceCriteria, plan.PlanAC{Command: bullet.Command, Description: bullet.Description})
			}
		} else {
			acceptanceCriteria = append(acceptanceCriteria, plan.PlanAC{
				Command:     "bun test",
				Description: "Aceitação de " + entry.match[2],
			})
		}

		requirement := stripTicks(fields["Requirement"])
		if requirement == "" {
			requirement = fmt.Sprintf("FR-%03d", contractCounter)
		}
		dependsValue := stripTicks(fields["Depends on"])
		dependsOn := []string{}
		if dependsValue != "" && dependsValue != "none" {
			dependsOn = splitList(strings.ReplaceAll(dependsValue, "`", ""))
		}
		if len(steps) == 0 {
			steps = []string{"Implementar o comportamento declarado"}
		}
		redCommand := "bun test"
		redDescription := "RED de " + entry.match[2]
		if red != nil {
			redCommand = red.Command
			redDescription = red.Description
		}
		visual := "N/A"
		if fields["Visual"] == "REQUIRED" {
			visual = "REQUIRED"
		}
		documentation := "N/A"
		if fields["Documentation"] == "REQUIRED" {
			documentation = "REQUIRED"
		}
		tasks = append(tasks, plan.PlanTask{
			ID:                  entry.match[2],
			Title:               strings.TrimSpace(entry.match[3]),
			RequirementID:       requirement,
			DependsOn:           nonNil(dependsOn),
			Behavior:            fields["Behavior"],
			Components:          nonNil(splitList(fields["Components"])),
			Files:               nonNil(splitList(fields["Files"])),
			ImplementationFiles: nonNil(splitList(fields["Implementation files"])),
			TestFiles:           nonNil(splitList(fields["Test files"])),
			Red:                 plan.PlanRed{Command: redCommand, Description: redDescription},
			ImplementationSteps: steps,
			AcceptanceCriteria:  acceptanceCriteria,
			Visual:              visual,
			Documentation:       documentation,
			SpecReference:       "",
			ContractID:          fmt.Sprintf("CTR-%03d", contractCounter),
			Complexity:          "standard",
			Status:              status,
		})
	}
	return tasks
}

// ParseV3PlanMarkdown converte o conjunto de tasks v3 no modelo canônico.
// workID é usado apenas como título alternativo.
func ParseV3PlanMarkdown(markdown, workID string) plan.Plan {
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")
	title := "Work " + workID
	for _, line := range lines {
		if strings.HasPrefix(line, "# Tasks: ") {
			title = strings.TrimSpace(strings.TrimPrefix(line, "# Tasks: "))
			break
		}
	}
	return plan.Plan{
		WorkID:      workID,
		Title:       title,
		Components:  nonNilComponents(parseV3Components(lines)),
		GlobalGates: nonNil(parseV3GlobalGates(lines)),
		Tasks:       nonNilTasks(parseV3Tasks(lines)),
	}
}

func nonNilComponents(values []plan.PlanComponent) []plan.PlanComponent {
	if values == nil {
		return []plan.PlanComponent{}
	}
	return values
}

func nonNilTasks(values []plan.PlanTask) []plan.PlanTask {
	if values == nil {
		return []plan.PlanTask{}
	}
	return values
}

// PromptDigest é o conteúdo autoral de um prompt v3.
type PromptDigest struct {
	Problem         string              `json:"problem"`
	Solution        string              `json:"solution"`
	Requirements    []PromptRequirement `json:"requirements"`
	InScope         []string            `json:"inScope"`
	OutOfScope      []string            `json:"outOfScope"`
	Actors          []string            `json:"actors"`
	SuccessCriteria []string            `json:"successCriteria"`
	Constraints     []string            `json:"constraints"`
}

// PromptRequirement é um requisito declarado no prompt.
type PromptRequirement struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

// parsePromptBullets lê os bullets até o próximo heading de seção.
func parsePromptBullets(lines []string, heading string) []string {
	start := -1
	for index, line := range lines {
		if line == heading {
			start = index
			break
		}
	}
	if start == -1 {
		return []string{}
	}
	values := make([]string, 0)
	for index := start + 1; index < len(lines); index++ {
		line := lines[index]
		if v3PromptHeader.MatchString(line) {
			break
		}
		if strings.HasPrefix(line, "- ") {
			values = append(values, strings.TrimSpace(line[2:]))
		}
	}
	return values
}

// promptField devolve o valor de `**Nome:**` do prompt.
func promptField(lines []string, name string) (string, bool) {
	prefix := "**" + name + ":**"
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):]), true
		}
	}
	return "", false
}

// ParsePromptDigest extrai o conteúdo autoral de um prompt de mudança v3.
// Todo valor vem do próprio prompt; nada é sintetizado.
func ParsePromptDigest(markdown string) PromptDigest {
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")
	requirements := make([]PromptRequirement, 0)
	for _, line := range lines {
		if match := v3Requirement.FindStringSubmatch(line); match != nil {
			requirements = append(requirements, PromptRequirement{ID: match[1], Statement: strings.TrimSpace(match[2])})
		}
	}
	successCriteria := make([]string, 0)
	constraints := make([]string, 0)
	for _, requirement := range requirements {
		switch {
		case strings.HasPrefix(requirement.ID, "SC-"):
			successCriteria = append(successCriteria, requirement.ID+": "+requirement.Statement)
		case strings.HasPrefix(requirement.ID, "QR-"):
			constraints = append(constraints, requirement.ID+": "+requirement.Statement)
		}
	}
	actors := make([]string, 0)
	for _, line := range parsePromptBullets(lines, "## Atores e valor") {
		if match := v3ActorBullet.FindStringSubmatch(line); match != nil {
			actors = append(actors, strings.TrimSpace(match[1]))
		}
	}
	problem, _ := promptField(lines, "Problema")
	solution, _ := promptField(lines, "Resultado esperado")
	return PromptDigest{
		Problem:         problem,
		Solution:        solution,
		Requirements:    nonNilPromptRequirements(requirements),
		InScope:         nonNil(parsePromptBullets(lines, "### Inclui")),
		OutOfScope:      nonNil(parsePromptBullets(lines, "### Não inclui")),
		Actors:          nonNil(actors),
		SuccessCriteria: nonNil(successCriteria),
		Constraints:     nonNil(constraints),
	}
}

func nonNilPromptRequirements(values []PromptRequirement) []PromptRequirement {
	if values == nil {
		return []PromptRequirement{}
	}
	return values
}

// Capability é uma capacidade da system spec.
type Capability struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Rules       []string `json:"rules"`
}

// CapabilityRule é uma regra da capability dependency.
type CapabilityRule struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

// CapabilityMap é o mapa de capabilities da system spec.
type CapabilityMap struct {
	Capabilities []Capability     `json:"capabilities"`
	Rules        []CapabilityRule `json:"rules"`
}

var (
	capabilityMapHeading = regexp.MustCompile(`^##\s+\d+\.\s+Capability Map`)
	capabilityDepHeading = regexp.MustCompile(`^###\s+[\d.]+\.?\s*Capability dependency`)
)

// ParseCapabilityMap lê o bloco "Capability Map" da system spec.
func ParseCapabilityMap(systemSpec string) CapabilityMap {
	lines := strings.Split(strings.ReplaceAll(systemSpec, "\r\n", "\n"), "\n")
	capabilities := make([]Capability, 0)
	rules := make([]CapabilityRule, 0)

	mapStart := -1
	for index, line := range lines {
		if capabilityMapHeading.MatchString(line) {
			mapStart = index
			break
		}
	}
	if mapStart != -1 {
		index := mapStart + 1
		for index < len(lines) && !strings.HasPrefix(lines[index], "```") {
			index++
		}
		index++
		counter := 0
		for ; index < len(lines) && !strings.HasPrefix(lines[index], "```"); index++ {
			name := strings.TrimSpace(lines[index])
			if name == "" {
				continue
			}
			counter++
			capabilities = append(capabilities, Capability{
				ID:          fmt.Sprintf("CAP-%03d", counter),
				Name:        name,
				Description: fmt.Sprintf("Capacidade \"%s\" definida na system spec do projeto.", name),
				Rules:       []string{},
			})
		}
	}

	depStart := -1
	for index, line := range lines {
		if capabilityDepHeading.MatchString(line) {
			depStart = index
			break
		}
	}
	if depStart != -1 {
		counter := 0
		for index := depStart + 1; index < len(lines); index++ {
			line := lines[index]
			if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
				break
			}
			if !strings.HasPrefix(line, "- ") {
				continue
			}
			counter++
			rules = append(rules, CapabilityRule{
				ID:        fmt.Sprintf("BR-%03d", counter),
				Statement: strings.TrimSpace(line[2:]),
			})
		}
	}
	return CapabilityMap{Capabilities: capabilities, Rules: rules}
}

// V3WorkFiles são os artefatos v3 localizados de um Work.
type V3WorkFiles struct {
	WorkID         string  `json:"workId"`
	ManifestPath   *string `json:"manifestPath"`
	PlanPath       string  `json:"planPath"`
	PromptPath     *string `json:"promptPath"`
	SourcePath     *string `json:"sourcePath"`
	SystemSpecPath *string `json:"systemSpecPath"`
}

// firstFileMatching devolve o primeiro arquivo do diretório que casa a expressão.
func firstFileMatching(directory string, expression *regexp.Regexp) (string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("work: ler %s: %w", directory, err)
	}
	for _, entry := range entries {
		if expression.MatchString(entry.Name()) {
			return filepath.Join(directory, entry.Name()), nil
		}
	}
	return "", nil
}

// FindV3Work localiza os artefatos v3 de um Work.
func FindV3Work(rootDir, workID string) (*V3WorkFiles, error) {
	planPath := filepath.Join(rootDir, ".todo", workID+"-tasks.md")
	if _, err := os.Stat(planPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("work: ler %s: %w", planPath, err)
	}
	manifestPath := filepath.Join(rootDir, ".work", workID+".json")
	systemSpec := filepath.Join(rootDir, ".specs", "system.md")
	files := &V3WorkFiles{WorkID: workID, PlanPath: planPath}
	if _, err := os.Stat(manifestPath); err == nil {
		files.ManifestPath = &manifestPath
	}
	promptPath, err := firstFileMatching(filepath.Join(rootDir, ".prompts"), regexp.MustCompile(`^`+regexp.QuoteMeta(workID)+`-.*\.md$`))
	if err != nil {
		return nil, err
	}
	if promptPath != "" {
		files.PromptPath = &promptPath
	}
	sourcePath, err := firstFileMatching(filepath.Join(rootDir, ".sources"), regexp.MustCompile(`^`+regexp.QuoteMeta(workID)+`-.*\.md$`))
	if err != nil {
		return nil, err
	}
	if sourcePath != "" {
		files.SourcePath = &sourcePath
	}
	if _, err := os.Stat(systemSpec); err == nil {
		files.SystemSpecPath = &systemSpec
	}
	return files, nil
}

// ListV3WorkIDs devolve os Work IDs presentes no layout v3.
func ListV3WorkIDs(rootDir string) []string {
	entries, err := os.ReadDir(filepath.Join(rootDir, ".todo"))
	if err != nil {
		return []string{}
	}
	ids := make([]string, 0)
	for _, entry := range entries {
		match := NumberedPlanPattern.FindStringSubmatch(entry.Name())
		if match != nil {
			ids = append(ids, match[1])
		}
	}
	sort.Strings(ids)
	return ids
}
