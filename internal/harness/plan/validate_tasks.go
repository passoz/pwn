package plan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Versões do contrato de task reconhecidas pelo validador.
const (
	LegacyTaskContractVersion   = 1
	PreviousTaskContractVersion = 2
	CurrentTaskContractVersion  = 3
)

// AnalyzeOptions ajusta AnalyzeTasks.
type AnalyzeOptions struct {
	// Strict promove cada aviso de compatibilidade a erro.
	Strict bool
	// PlanPath é o caminho do plano. A validação de dependências precisa dele.
	PlanPath string
}

// MigrateOptions ajusta MigrateTasksContent.
type MigrateOptions struct {
	// WorkID é o Work de quatro dígitos atribuído à migração.
	WorkID string
}

// ParsedTask é um heading de task reconhecido pelo validador.
type ParsedTask struct {
	Status string
	TaskID string
	Order  [2]int
	Title  string
	Start  int
	End    int
}

// TaskSummary é o resumo de uma task devolvido pela análise.
type TaskSummary struct {
	ID        string
	Status    string
	DependsOn string
}

// TaskAnalysis é o resultado da validação estrutural do markdown.
type TaskAnalysis struct {
	Errors                      []string
	Warnings                    []string
	Exceptions                  []string
	ContractVersion             *int
	ContractVersionSource       string
	MigratedFromContractVersion *int
	WorkID                      *string
	Tasks                       []TaskSummary
}

// MigrationResult é o resultado da migração de um plano para o contrato v3.
type MigrationResult struct {
	Content     string
	Changes     []string
	Errors      []string
	Warnings    []string
	FromVersion *int
	ToVersion   int
}

type issueReporter func(severity, message string)

var (
	validateTaskHeading   = regexp.MustCompile(`^### \[([ x!])\] \[([0-9]+)\.([0-9]+)\] (\S.*)$`)
	workIDDeclaration     = regexp.MustCompile(`^\*\*Work ID:\*\* ([0-9]{4})$`)
	contractVersionDecl   = regexp.MustCompile(`^\*\*Contract version:\*\* ([1-9][0-9]*)$`)
	migratedFromDecl      = regexp.MustCompile(`^\*\*Migrated from task contract:\*\* ([1-9][0-9]*)$`)
	placeholderMarker     = regexp.MustCompile(`(?i)<[^>\n]+>|\bTODO\b|\bTBD\b`)
	acConcrete            = regexp.MustCompile("^- \\[[ x!]\\] `([^`]+)`\\s+—\\s+\\S.*$")
	redConcrete           = regexp.MustCompile("^- `([^`]+)`\\s+—\\s+\\S.*$")
	docEvidence           = regexp.MustCompile("^- \\*\\*Evidence:\\*\\* `([^`]+)`\\s+—\\s+\\S.*$")
	dependencyDeclaration = regexp.MustCompile("(?i)^- `([^`]+)` — declared in `([^`]+)`\\.\\s*$")
	packageInstallation   = regexp.MustCompile(`\b(npm|pnpm|yarn) (install|add)\b|\b(pip|pip3) install\b|\bgo get\b|\bcargo add\b|\bapt(-get)? install\b|\bbrew install\b`)
	requirementID         = regexp.MustCompile(`^(FR|QR|EC|SC|SOURCE)-[0-9]{3}$`)
	localDependencyID     = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	qualifiedDependencyID = regexp.MustCompile(`^([0-9]{4})/([0-9]+\.[0-9]+)$`)
	implementationStep    = regexp.MustCompile(`^[0-9]+\.\s+\S`)
	legacyAllowanceEntry  = regexp.MustCompile(`^([a-z-]+)=([0-9]+)$`)
	specDependencyDecl    = regexp.MustCompile(`(?im)^\s*(-\s*)?\*\*(Dependencies|Dependency|Dependências|Dependência):\*\*\s+(.+)$`)
	traceBacktickValue    = regexp.MustCompile("`([^`]+)`")
	planFileName          = regexp.MustCompile(`^([0-9]{4})-tasks\.md$`)
	separatorCells        = regexp.MustCompile(`^[-:]+$`)
	workIDShape           = regexp.MustCompile(`^[0-9]{4}$`)
)

// incidentalRedPatterns descrevem falha incidental de ambiente ou ferramenta em
// vez de asserção de teste (BR-001).
var incidentalRedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bausente\b`),
	regexp.MustCompile(`(?i)\bnot found\b`),
	regexp.MustCompile(`(?i)\bcannot find\b`),
	regexp.MustCompile(`(?i)\bno such file\b`),
	regexp.MustCompile(`(?i)\bmissing module\b`),
	regexp.MustCompile(`(?i)\bno module\b`),
	regexp.MustCompile(`(?i)\bno required module\b`),
	regexp.MustCompile(`(?i)\bfile not found\b`),
	regexp.MustCompile(`(?i)\bmodule not found\b`),
	regexp.MustCompile(`(?i)\bsyntax\b`),
	regexp.MustCompile(`(?i)\bundefined\b`),
	regexp.MustCompile(`(?i)\bunresolved\b`),
	regexp.MustCompile(`(?i)\breferenceerror\b`),
	regexp.MustCompile(`(?i)\bparse error\b`),
	regexp.MustCompile(`(?i)\btype mismatch\b`),
}

type unsafeCommand struct {
	label   string
	pattern *regexp.Regexp
}

var unsafeCommands = []unsafeCommand{
	{"sudo", regexp.MustCompile(`(^|[;&|]\s*|\s)sudo(\s|$)`)},
	{"eval", regexp.MustCompile(`(^|[;&|]\s*|\s)eval(\s|$)`)},
	{"download piped to shell", regexp.MustCompile(`\b(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b`)},
	{"destructive git reset", regexp.MustCompile(`\bgit\s+reset\s+--hard\b`)},
	{"destructive git clean", regexp.MustCompile(`\bgit\s+clean\b`)},
	{"destructive removal", regexp.MustCompile(`(?i)\brm\s+(-[A-Za-z]*r[A-Za-z]*f|-rf|-fr)\b`)},
	{"migration rollback/reset", regexp.MustCompile(`\b(migrate\b.*\bdown|db:(drop|reset|rollback)|migration\s+(down|reset))\b`)},
	{"package installation", packageInstallation},
	{"deploy/publish", regexp.MustCompile(`\b(npm|pnpm|yarn|cargo)\s+publish\b|\bmake\s+(deploy|publish)\b|\b(kubectl|helm|fly|vercel|netlify|gcloud)\b[^\n;&|]*\bdeploy\b`)},
	{"environment disclosure", regexp.MustCompile(`\b(cat\s+\.env\b|printenv\b|env\s*$)`)},
}

var legacyAllowanceKeys = map[string]bool{
	"implementation-files": true, "red-commands": true, "ac-commands": true, "implementation-steps": true,
}

func validationSection(lines []string, heading string) (int, int, bool) {
	start := -1
	for index, line := range lines {
		if line == heading {
			start = index
			break
		}
	}
	if start == -1 {
		return 0, 0, false
	}
	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index], "## ") {
			end = index
			break
		}
	}
	return start, end, true
}

func contractComponents(lines []string) map[string]bool {
	components := make(map[string]bool)
	start, end, found := validationSection(lines, "## Execution contract")
	if !found {
		return components
	}
	for _, line := range lines[start+1 : end] {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := tableCells(line)
		if len(cells) == 0 || strings.ToLower(cells[0]) == "component" || separatorCells.MatchString(cells[0]) {
			continue
		}
		components[cells[0]] = true
	}
	return components
}

func parseTasks(lines []string, issue issueReporter) []ParsedTask {
	type found struct {
		index int
		match []string
	}
	headings := make([]found, 0, 4)
	for index, line := range lines {
		if !strings.HasPrefix(line, "### ") {
			continue
		}
		match := validateTaskHeading.FindStringSubmatch(line)
		if match == nil {
			issue("error", fmt.Sprintf("line %d: malformed task heading: %s", index+1, line))
			continue
		}
		headings = append(headings, found{index: index, match: match})
	}
	tasks := make([]ParsedTask, 0, len(headings))
	for index, heading := range headings {
		end := len(lines)
		if index+1 < len(headings) {
			end = headings[index+1].index
		}
		major, _ := strconv.Atoi(heading.match[2])
		minor, _ := strconv.Atoi(heading.match[3])
		tasks = append(tasks, ParsedTask{
			Status: heading.match[1],
			TaskID: fmt.Sprintf("%d.%d", major, minor),
			Order:  [2]int{major, minor},
			Title:  heading.match[4],
			Start:  heading.index,
			End:    end,
		})
	}
	return tasks
}

// pathValues devolve os caminhos na ordem de declaração e o conjunto para
// consulta.
func pathValues(value string) ([]string, map[string]bool) {
	values := make([]string, 0, 4)
	set := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		item := stripBackticks(strings.TrimSpace(part))
		if item == "" || item == "N/A" || set[item] {
			continue
		}
		set[item] = true
		values = append(values, item)
	}
	return values, set
}

func inlineCommands(line string) []string {
	matches := traceBacktickValue.FindAllStringSubmatch(line, -1)
	commands := make([]string, 0, len(matches))
	for _, match := range matches {
		commands = append(commands, match[1])
	}
	return commands
}

type lineCommand struct {
	line    int
	command string
}

func commandsIn(lines []string) []lineCommand {
	commands := make([]lineCommand, 0, 8)
	inContract := false
	commandPrefixes := []string{"- `", "- [ ] `", "- [x] `", "- [!] `", "- **Playwright:** `", "- **Evidence:** `"}

	for zeroBasedIndex, line := range lines {
		lineNumber := zeroBasedIndex + 1
		if line == "## Execution contract" {
			inContract = true
			continue
		}
		if inContract && strings.HasPrefix(line, "## ") {
			inContract = false
		}

		if inContract && strings.HasPrefix(line, "|") {
			cells := tableCells(line)
			if len(cells) > 0 && strings.ToLower(cells[0]) != "component" && !separatorCells.MatchString(cells[0]) {
				for index := 2; index < len(cells); index++ {
					if cells[index] != "N/A" {
						commands = append(commands, lineCommand{line: lineNumber, command: cells[index]})
					}
				}
			}
			continue
		}

		matched := false
		for _, prefix := range commandPrefixes {
			if strings.HasPrefix(line, prefix) {
				matched = true
				break
			}
		}
		if matched {
			for _, command := range inlineCommands(line) {
				commands = append(commands, lineCommand{line: lineNumber, command: command})
			}
		}
	}
	return commands
}

func compareOrder(left, right [2]int) int {
	if left[0] != right[0] {
		return left[0] - right[0]
	}
	return left[1] - right[1]
}

func packageNames(command string) []string {
	tokens := strings.Fields(strings.TrimSpace(command))
	manager := ""
	if len(tokens) > 0 {
		manager = strings.ToLower(tokens[0])
	}
	var packages []string
	switch {
	case manager == "npm" || manager == "pnpm" || manager == "yarn" || manager == "pip" || manager == "pip3" || manager == "cargo":
		if len(tokens) > 2 {
			packages = tokens[2:]
		}
	case manager == "go" && len(tokens) > 1 && strings.ToLower(tokens[1]) == "get":
		if len(tokens) > 2 {
			packages = tokens[2:]
		}
	case manager == "apt" || manager == "apt-get" || manager == "brew":
		if len(tokens) > 2 {
			packages = tokens[2:]
		}
	}
	for _, token := range packages {
		if token == "-g" || token == "--global" {
			return nil
		}
	}
	result := make([]string, 0, len(packages))
	for _, token := range packages {
		if token == "" || strings.HasPrefix(token, "-") {
			continue
		}
		switch {
		case manager == "go":
			result = append(result, strings.SplitN(token, "@", 2)[0])
		case strings.HasPrefix(token, "@"):
			if separator := strings.Index(token[1:], "@"); separator != -1 {
				result = append(result, token[:separator+1])
			} else {
				result = append(result, token)
			}
		default:
			result = append(result, firstSplit(token, "@=<>~!"))
		}
	}
	filtered := result[:0]
	for _, name := range result {
		if name != "" {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

// resolvePath resolve rel contra base, como path.resolve do Node: um caminho
// absoluto ignora a base.
func resolvePath(base, rel string) string {
	if filepath.IsAbs(rel) {
		return filepath.Clean(rel)
	}
	return filepath.Join(base, rel)
}

func firstSplit(value, separators string) string {
	if index := strings.IndexAny(value, separators); index != -1 {
		return value[:index]
	}
	return value
}

func specDependencies(specText string) map[string]bool {
	dependencies := make(map[string]bool)
	for _, match := range specDependencyDecl.FindAllStringSubmatch(specText, -1) {
		for _, value := range traceBacktickValue.FindAllStringSubmatch(match[3], -1) {
			dependencies[strings.ToLower(value[1])] = true
		}
	}
	return dependencies
}

func dependencyInstallations(lines []string, issue issueReporter, planPath string) map[int]bool {
	allowedLines := make(map[int]bool)
	repositoryRoot := ""
	if planPath != "" {
		absolute, err := filepath.Abs(planPath)
		if err != nil {
			absolute = planPath
		}
		repositoryRoot = filepath.Dir(filepath.Dir(absolute))
	}
	for _, task := range parseTasks(lines, func(string, string) {}) {
		if task.Status == "!" {
			continue
		}
		block := lines[task.Start+1 : task.End]
		start := -1
		for index, line := range block {
			if line == "**Dependency installations:**" {
				start = index
				break
			}
		}
		if start == -1 {
			continue
		}
		entries := fieldSection(block, "Dependency installations")
		if len(entries) == 0 {
			issue("error", fmt.Sprintf("task %s: Dependency installations needs at least one command and governing spec path", task.TaskID))
		}
		for index, entry := range entries {
			if strings.TrimSpace(entry) == "" {
				continue
			}
			lineNumber := task.Start + 2 + start + 1 + index
			match := dependencyDeclaration.FindStringSubmatch(entry)
			var packages []string
			if match != nil {
				packages = packageNames(match[1])
			}
			if match == nil || !packageInstallation.MatchString(strings.ToLower(match[1])) || len(packages) == 0 {
				issue("error", fmt.Sprintf("line %d: invalid dependency installation declaration", lineNumber))
				continue
			}
			if repositoryRoot == "" {
				issue("error", fmt.Sprintf("line %d: dependency installation validation requires a plan file path", lineNumber))
				continue
			}
			specPath := resolvePath(repositoryRoot, match[2])
			if specPath != repositoryRoot && !strings.HasPrefix(specPath, repositoryRoot+string(os.PathSeparator)) {
				issue("error", fmt.Sprintf("line %d: governing spec path escapes repository root: %s", lineNumber, match[2]))
				continue
			}
			specContent, err := os.ReadFile(specPath)
			if err != nil {
				issue("error", fmt.Sprintf("line %d: governing spec not found: %s", lineNumber, match[2]))
				continue
			}
			declared := specDependencies(string(specContent))
			missing := make([]string, 0, len(packages))
			for _, name := range packages {
				if !declared[strings.ToLower(name)] {
					missing = append(missing, name)
				}
			}
			if len(missing) > 0 {
				for _, name := range missing {
					issue("error", fmt.Sprintf("line %d: dependency %s is not declared in governing spec %s", lineNumber, name, match[2]))
				}
				continue
			}
			allowedLines[lineNumber] = true
		}
	}
	return allowedLines
}

func parseLegacyAllowances(block []string, taskID string, contractVersion int, migratedFrom *int, issue issueReporter) map[string]int {
	allowances := make(map[string]int)
	value, present := fieldValue(block, "Legacy allowances")
	if !present {
		return allowances
	}
	supported := migratedFrom != nil && (*migratedFrom == LegacyTaskContractVersion || *migratedFrom == PreviousTaskContractVersion)
	if contractVersion != CurrentTaskContractVersion || !supported {
		issue("error", fmt.Sprintf("task %s: Legacy allowances require a v%d plan marked as migrated from v1 or v2", taskID, CurrentTaskContractVersion))
		return allowances
	}

	entries := make([]string, 0, 2)
	for _, entry := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	if len(entries) == 0 {
		issue("error", fmt.Sprintf("task %s: Legacy allowances cannot be empty", taskID))
	}
	for _, entry := range entries {
		match := legacyAllowanceEntry.FindStringSubmatch(entry)
		if match == nil || !legacyAllowanceKeys[match[1]] {
			issue("error", fmt.Sprintf("task %s: invalid legacy allowance: %s", taskID, entry))
			continue
		}
		if _, exists := allowances[match[1]]; exists {
			issue("error", fmt.Sprintf("task %s: duplicate legacy allowance: %s", taskID, match[1]))
			continue
		}
		count, _ := strconv.Atoi(match[2])
		allowances[match[1]] = count
	}
	return allowances
}

func detectMigrationSource(lines []string, contractVersion int, issue issueReporter) *int {
	type declaration struct {
		line  string
		index int
	}
	declarations := make([]declaration, 0, 1)
	for index, line := range lines {
		if strings.HasPrefix(line, "**Migrated from task contract:**") {
			declarations = append(declarations, declaration{line: line, index: index})
		}
	}
	if len(declarations) == 0 {
		return nil
	}
	if len(declarations) > 1 {
		issue("error", "duplicate task contract migration source declaration")
	}
	match := migratedFromDecl.FindStringSubmatch(declarations[0].line)
	if match == nil {
		issue("error", fmt.Sprintf("line %d: invalid task contract migration source declaration", declarations[0].index+1))
		return nil
	}
	value, _ := strconv.Atoi(match[1])
	migratedFrom := value
	if contractVersion != CurrentTaskContractVersion || (migratedFrom != LegacyTaskContractVersion && migratedFrom != PreviousTaskContractVersion) {
		issue("error", fmt.Sprintf("unsupported task contract migration source: v%d -> v%d", migratedFrom, contractVersion))
	}
	return &migratedFrom
}

type contractVersion struct {
	version int
	source  string
}

func detectContractVersion(lines []string, issue issueReporter) contractVersion {
	type declaration struct {
		line  string
		index int
	}
	declarations := make([]declaration, 0, 1)
	for index, line := range lines {
		if strings.HasPrefix(line, "**Contract version:**") {
			declarations = append(declarations, declaration{line: line, index: index})
		}
	}
	if len(declarations) == 0 {
		issue("warning", fmt.Sprintf("task contract version is missing; assuming legacy version %d", LegacyTaskContractVersion))
		return contractVersion{version: LegacyTaskContractVersion, source: "inferred"}
	}
	if len(declarations) > 1 {
		issue("error", "duplicate task contract version declaration")
	}
	match := contractVersionDecl.FindStringSubmatch(declarations[0].line)
	if match == nil {
		issue("error", fmt.Sprintf("line %d: invalid task contract version declaration", declarations[0].index+1))
		return contractVersion{version: CurrentTaskContractVersion, source: "invalid"}
	}
	version, _ := strconv.Atoi(match[1])
	if version != LegacyTaskContractVersion && version != PreviousTaskContractVersion && version != CurrentTaskContractVersion {
		issue("error", fmt.Sprintf("unsupported task contract version: %d; supported versions are %d, %d, and %d", version, LegacyTaskContractVersion, PreviousTaskContractVersion, CurrentTaskContractVersion))
	} else if version < CurrentTaskContractVersion {
		issue("warning", fmt.Sprintf("task contract version %d is legacy; migrate to version %d", version, CurrentTaskContractVersion))
	}
	return contractVersion{version: version, source: "declared"}
}

// AnalyzeTasks valida estruturalmente o markdown de um plano.
func AnalyzeTasks(text string, options AnalyzeOptions) TaskAnalysis {
	lines := splitLines(text)
	errors := make([]string, 0, 4)
	warnings := make([]string, 0, 4)
	exceptions := make([]string, 0, 1)
	issue := func(severity, message string) {
		if severity == "warning" {
			warnings = append(warnings, message)
			return
		}
		errors = append(errors, message)
	}
	contract := detectContractVersion(lines, issue)
	migratedFrom := detectMigrationSource(lines, contract.version, issue)
	compatibility := contract.version < CurrentTaskContractVersion
	compatibilityIssue := func(message string) {
		if compatibility {
			issue("warning", message)
			return
		}
		issue("error", message)
	}

	type lineEntry struct {
		line  string
		index int
	}
	workDeclarations := make([]lineEntry, 0, 1)
	for index, line := range lines {
		if strings.HasPrefix(line, "**Work ID:**") {
			workDeclarations = append(workDeclarations, lineEntry{line: line, index: index})
		}
	}
	var declaredWorkID *string
	if len(workDeclarations) > 0 {
		if match := workIDDeclaration.FindStringSubmatch(workDeclarations[0].line); match != nil {
			value := match[1]
			declaredWorkID = &value
		}
	}
	if contract.version == CurrentTaskContractVersion {
		if len(workDeclarations) != 1 {
			if len(workDeclarations) > 0 {
				issue("error", "duplicate Work ID declaration")
			} else {
				issue("error", "missing declaration: **Work ID:** NNNN")
			}
		}
		if declaredWorkID == nil && len(workDeclarations) > 0 {
			issue("error", fmt.Sprintf("line %d: invalid Work ID declaration; expected four digits", workDeclarations[0].index+1))
		}
	}

	hasExecutionContract := false
	hasGlobalGates := false
	for _, line := range lines {
		switch line {
		case "## Execution contract":
			hasExecutionContract = true
		case "## Global gates":
			hasGlobalGates = true
		}
	}
	if !hasExecutionContract {
		issue("error", "missing section: ## Execution contract")
	}
	if !hasGlobalGates {
		issue("error", "missing section: ## Global gates")
	}

	for _, match := range placeholderMarker.FindAllStringIndex(text, -1) {
		line := strings.Count(text[:match[0]], "\n") + 1
		issue("error", fmt.Sprintf("line %d: unresolved marker: %s", line, text[match[0]:match[1]]))
	}

	if gates, _ := ParseGlobalGates(text); gates != nil {
		for _, gate := range gates {
			if gate.Command == "" {
				compatibilityIssue("global gate without an executable command in backticks: " + gate.Text)
			}
		}
	}

	components := contractComponents(lines)
	if len(components) == 0 {
		issue("error", "execution contract has no components")
	}

	tasks := parseTasks(lines, issue)
	if len(tasks) == 0 {
		issue("error", "no canonical task headings found")
	}

	seen := make(map[string]bool)
	primaryRequirements := make(map[string]string)
	var previous *[2]int
	required := []string{
		"Requirement", "Depends on", "Behavior", "Components", "Files",
		"Implementation files", "Test files", "RED", "Implementation", "ACs",
		"Visual", "Documentation",
	}
	legacyAdvisoryFields := map[string]bool{"Requirement": true, "Depends on": true}

	for _, task := range tasks {
		if seen[task.TaskID] {
			issue("error", fmt.Sprintf("task %s: duplicate ID", task.TaskID))
		}
		seen[task.TaskID] = true
		if previous != nil && compareOrder(task.Order, *previous) <= 0 {
			issue("error", fmt.Sprintf("task %s: IDs are not strictly increasing", task.TaskID))
		}
		order := task.Order
		previous = &order

		if task.Status == "!" {
			if !strings.Contains(strings.ToLower(task.Title), "bloquead") || !strings.Contains(task.Title, ":") {
				issue("error", fmt.Sprintf("task %s: blocked task must include a concrete reason", task.TaskID))
			}
			continue
		}

		block := lines[task.Start+1 : task.End]
		allowances := parseLegacyAllowances(block, task.TaskID, contract.version, migratedFrom, issue)
		consumedAllowances := make(map[string]bool)
		atomicityIssue := func(key string, actual int, valid bool, message string) {
			if valid {
				return
			}
			if compatibility {
				issue("warning", message)
				return
			}
			if allowed, present := allowances[key]; present && allowed == actual {
				consumedAllowances[key] = true
				exceptions = append(exceptions, fmt.Sprintf("task %s: preserved legacy allowance %s=%d", task.TaskID, key, actual))
				return
			}
			issue("error", message)
		}

		values := make(map[string]string, len(required))
		present := make(map[string]bool, len(required))
		for _, name := range required {
			values[name], present[name] = fieldValue(block, name)
		}
		for _, name := range required {
			if present[name] {
				continue
			}
			message := fmt.Sprintf("task %s: missing field **%s:**", task.TaskID, name)
			if compatibility && legacyAdvisoryFields[name] {
				issue("warning", message)
				continue
			}
			issue("error", message)
		}

		if present["Requirement"] {
			requirement := stripBackticks(values["Requirement"])
			if !requirementID.MatchString(requirement) {
				compatibilityIssue(fmt.Sprintf("task %s: Requirement must contain exactly one FR-*, QR-*, EC-*, SC-* or SOURCE-* ID", task.TaskID))
			} else if owner, exists := primaryRequirements[requirement]; exists {
				compatibilityIssue(fmt.Sprintf("task %s: primary Requirement %s already belongs to task %s; split the source requirement or use a distinct edge/success ID", task.TaskID, requirement, owner))
			} else {
				primaryRequirements[requirement] = task.TaskID
			}
		}

		if present["Depends on"] {
			dependencyValue := strings.ReplaceAll(values["Depends on"], "`", "")
			var dependencies []string
			if dependencyValue != "none" {
				for _, value := range strings.Split(dependencyValue, ",") {
					if trimmed := strings.TrimSpace(value); trimmed != "" {
						dependencies = append(dependencies, trimmed)
					}
				}
			}
			if dependencyValue != "none" && len(dependencies) == 0 {
				issue("error", fmt.Sprintf("task %s: Depends on must be none, previous local task IDs, or qualified NNNN/task IDs", task.TaskID))
			}
			for _, dependency := range dependencies {
				if localDependencyID.MatchString(dependency) {
					if !seen[dependency] {
						issue("error", fmt.Sprintf("task %s: local dependency must reference an earlier task: %s", task.TaskID, dependency))
					}
					if dependency == task.TaskID {
						issue("error", fmt.Sprintf("task %s: task cannot depend on itself", task.TaskID))
					}
					continue
				}
				qualified := qualifiedDependencyID.FindStringSubmatch(dependency)
				if qualified == nil {
					issue("error", fmt.Sprintf("task %s: invalid dependency ID: %s", task.TaskID, dependency))
					continue
				}
				if declaredWorkID != nil && qualified[1] == *declaredWorkID {
					if !seen[qualified[2]] {
						issue("error", fmt.Sprintf("task %s: same-work dependency must reference an earlier task: %s", task.TaskID, dependency))
					}
					if qualified[2] == task.TaskID {
						issue("error", fmt.Sprintf("task %s: task cannot depend on itself", task.TaskID))
					}
				}
			}
		}

		if present["Components"] {
			for _, name := range strings.Split(values["Components"], ",") {
				name = stripBackticks(strings.TrimSpace(name))
				if !components[name] {
					issue("error", fmt.Sprintf("task %s: unknown component: %s", task.TaskID, name))
				}
			}
		}

		_, files := pathValues(values["Files"])
		implementationFiles, _ := pathValues(values["Implementation files"])
		testFiles, testSet := pathValues(values["Test files"])
		overlap := make([]string, 0, len(implementationFiles))
		for _, value := range implementationFiles {
			if testSet[value] {
				overlap = append(overlap, value)
			}
		}
		sort.Strings(overlap)
		atomicityIssue(
			"implementation-files",
			len(implementationFiles),
			len(implementationFiles) <= 3,
			fmt.Sprintf("task %s: atomicity limit exceeded: %d implementation files (max 3)", task.TaskID, len(implementationFiles)),
		)
		if len(overlap) > 0 {
			issue("error", fmt.Sprintf("task %s: implementation/test files overlap: %s", task.TaskID, strings.Join(overlap, ", ")))
		}
		for _, declaredPath := range append(append([]string{}, implementationFiles...), testFiles...) {
			if reason := PlaceholderPathReason(declaredPath); reason != "" {
				compatibilityIssue(fmt.Sprintf("task %s: declared file %s %s; declare concrete files", task.TaskID, declaredPath, reason))
			}
		}
		taskComponents := make([]string, 0, 2)
		for _, name := range strings.Split(values["Components"], ",") {
			if trimmed := stripBackticks(strings.TrimSpace(name)); trimmed != "" {
				taskComponents = append(taskComponents, trimmed)
			}
		}
		gateCommands := AssuranceCommands(text, taskComponents)

		declaredFiles := make([]string, 0, len(implementationFiles)+len(testFiles))
		declaredSeen := make(map[string]bool)
		for _, value := range append(append([]string{}, implementationFiles...), testFiles...) {
			if !declaredSeen[value] {
				declaredSeen[value] = true
				declaredFiles = append(declaredFiles, value)
			}
		}
		sort.Strings(declaredFiles)
		for _, declaredPath := range declaredFiles {
			if !files[declaredPath] {
				issue("error", fmt.Sprintf("task %s: declared file missing from Files: %s", task.TaskID, declaredPath))
			}
		}

		redStart := indexOfLine(block, "**RED:**")
		acStart := indexOfLine(block, "**ACs:**")
		visualStart := indexOfPrefix(block, "**Visual:**")
		documentationStart := indexOfPrefix(block, "**Documentation:**")
		if redStart != -1 {
			redLines := make([]string, 0, 1)
			for _, line := range fieldSection(block, "RED") {
				if redConcrete.MatchString(line) {
					redLines = append(redLines, line)
				}
			}
			if len(redLines) == 0 {
				issue("error", fmt.Sprintf("task %s: RED needs a concrete command and expected failure", task.TaskID))
			}
			atomicityIssue(
				"red-commands",
				len(redLines),
				len(redLines) <= 1,
				fmt.Sprintf("task %s: atomicity limit exceeded: RED must contain exactly one focused command", task.TaskID),
			)
			for _, redLine := range redLines {
				description := stripRedPrefix(redLine)
				incidental := false
				for _, pattern := range incidentalRedPatterns {
					if pattern.MatchString(description) {
						incidental = true
						break
					}
				}
				if incidental {
					compatibilityIssue(fmt.Sprintf("task %s: RED description must not describe an incidental environment or toolchain failure as the primary mechanism; describe the assertion that fires instead", task.TaskID))
				}
				command := redConcrete.FindStringSubmatch(redLine)[1]
				if generic := GenericCommandReason(command, gateCommands); generic != "" {
					compatibilityIssue(fmt.Sprintf("task %s: RED `%s` %s; use the focused command of the task's own test", task.TaskID, command, generic))
				}
			}
		}
		if acStart != -1 {
			acLines := make([]string, 0, 3)
			for _, line := range fieldSection(block, "ACs") {
				if acConcrete.MatchString(line) {
					acLines = append(acLines, line)
				}
			}
			if len(acLines) == 0 {
				issue("error", fmt.Sprintf("task %s: ACs need at least one concrete command and expected result", task.TaskID))
			}
			for _, acLine := range acLines {
				command := acConcrete.FindStringSubmatch(acLine)[1]
				if generic := GenericCommandReason(command, gateCommands); generic != "" {
					compatibilityIssue(fmt.Sprintf("task %s: AC `%s` %s", task.TaskID, command, generic))
				}
			}
			atomicityIssue(
				"ac-commands",
				len(acLines),
				len(acLines) <= 3,
				fmt.Sprintf("task %s: atomicity limit exceeded: %d ACs (max 3)", task.TaskID, len(acLines)),
			)
		}

		implementationSteps := 0
		for _, line := range fieldSection(block, "Implementation") {
			if implementationStep.MatchString(line) {
				implementationSteps++
			}
		}
		stepMessage := fmt.Sprintf("task %s: Implementation needs at least one numbered step", task.TaskID)
		if implementationSteps > 0 {
			stepMessage = fmt.Sprintf("task %s: atomicity limit exceeded: %d implementation steps (max 2)", task.TaskID, implementationSteps)
		}
		atomicityIssue(
			"implementation-steps",
			implementationSteps,
			implementationSteps >= 1 && implementationSteps <= 2,
			stepMessage,
		)

		visual := values["Visual"]
		if present["Visual"] && visual != "N/A" && visual != "REQUIRED" {
			issue("error", fmt.Sprintf("task %s: Visual must be N/A or REQUIRED", task.TaskID))
		}
		if visual == "REQUIRED" && visualStart != -1 {
			visualEnd := len(block)
			if documentationStart != -1 {
				visualEnd = documentationStart
			}
			visualBlock := block[visualStart+1 : visualEnd]
			for _, name := range []string{"Route", "Selector", "Playwright", "Expected"} {
				if _, found := fieldValue(visualBlock, name); !found {
					issue("error", fmt.Sprintf("task %s: visual validation missing %s", task.TaskID, name))
				}
			}
		}

		documentation := values["Documentation"]
		if present["Documentation"] && documentation != "N/A" && documentation != "REQUIRED" {
			issue("error", fmt.Sprintf("task %s: Documentation must be N/A or REQUIRED", task.TaskID))
		}
		if documentation == "REQUIRED" && documentationStart != -1 {
			documentationBlock := block[documentationStart+1:]
			for _, name := range []string{"Audience", "Files", "Sections", "Sources", "Evidence"} {
				if _, found := fieldValue(documentationBlock, name); !found {
					issue("error", fmt.Sprintf("task %s: documentation missing %s", task.TaskID, name))
				}
			}
			concrete := false
			for _, line := range documentationBlock {
				if docEvidence.MatchString(line) {
					concrete = true
					break
				}
			}
			if !concrete {
				issue("error", fmt.Sprintf("task %s: documentation Evidence needs a concrete command and expected result", task.TaskID))
			}
		}

		for key, expected := range allowances {
			if !consumedAllowances[key] {
				issue("error", fmt.Sprintf("task %s: stale legacy allowance %s=%d; remove or update the task through an explicit replan", task.TaskID, key, expected))
			}
		}
	}

	allowedDependencyInstallations := dependencyInstallations(lines, issue, options.PlanPath)
	for _, entry := range commandsIn(lines) {
		lowered := strings.ToLower(entry.command)
		for _, unsafe := range unsafeCommands {
			if unsafe.label == "package installation" && allowedDependencyInstallations[entry.line] {
				continue
			}
			if unsafe.pattern.MatchString(lowered) {
				issue("error", fmt.Sprintf("line %d: unsafe command (%s): %s", entry.line, unsafe.label, entry.command))
			}
		}
	}

	if options.Strict && len(warnings) > 0 {
		for _, warning := range warnings {
			errors = append(errors, "compatibility warning treated as error: "+warning)
		}
		warnings = warnings[:0]
	}

	summaries := make([]TaskSummary, 0, len(tasks))
	for _, task := range tasks {
		dependsOn, hasDependsOn := fieldValue(lines[task.Start+1:task.End], "Depends on")
		if !hasDependsOn {
			dependsOn = "none"
		}
		summaries = append(summaries, TaskSummary{
			ID:        task.TaskID,
			Status:    task.Status,
			DependsOn: strings.ReplaceAll(dependsOn, "`", ""),
		})
	}

	version := contract.version
	var migrated *int
	if migratedFrom != nil {
		value := *migratedFrom
		migrated = &value
	}
	return TaskAnalysis{
		Errors:                      errors,
		Warnings:                    warnings,
		Exceptions:                  exceptions,
		ContractVersion:             &version,
		ContractVersionSource:       contract.source,
		MigratedFromContractVersion: migrated,
		WorkID:                      declaredWorkID,
		Tasks:                       summaries,
	}
}

func indexOfLine(lines []string, wanted string) int {
	for index, line := range lines {
		if line == wanted {
			return index
		}
	}
	return -1
}

func indexOfPrefix(lines []string, prefix string) int {
	for index, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return index
		}
	}
	return -1
}

var redPrefix = regexp.MustCompile("^- `[^`]+`\\s*—\\s*")

func stripRedPrefix(line string) string {
	return redPrefix.ReplaceAllString(line, "")
}

// ValidateTasksDetailed valida o plano e devolve os diagnósticos completos.
func ValidateTasksDetailed(filePath string, options AnalyzeOptions) TaskAnalysis {
	if _, err := os.Stat(filePath); err != nil {
		return TaskAnalysis{
			Errors:                []string{"file not found: " + filePath},
			Warnings:              []string{},
			Exceptions:            []string{},
			ContractVersion:       nil,
			ContractVersionSource: "absent",
			Tasks:                 []TaskSummary{},
		}
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return TaskAnalysis{
			Errors:                []string{"file not found: " + filePath},
			Warnings:              []string{},
			Exceptions:            []string{},
			ContractVersionSource: "absent",
			Tasks:                 []TaskSummary{},
		}
	}
	options.PlanPath = filePath
	return AnalyzeTasks(string(data), options)
}

// ValidateTasks devolve somente os erros do plano.
func ValidateTasks(filePath string, options AnalyzeOptions) []string {
	return ValidateTasksDetailed(filePath, options).Errors
}

type migrationBlock struct {
	Start  int
	End    int
	Status string
	ID     string
}

func migrationBlocks(lines []string) []migrationBlock {
	type found struct {
		index int
		match []string
	}
	headings := make([]found, 0, 4)
	for index, line := range lines {
		if match := validateTaskHeading.FindStringSubmatch(line); match != nil {
			headings = append(headings, found{index: index, match: match})
		}
	}
	blocks := make([]migrationBlock, 0, len(headings))
	for index, heading := range headings {
		end := len(lines)
		if index+1 < len(headings) {
			end = headings[index+1].index
		}
		major, _ := strconv.Atoi(heading.match[2])
		minor, _ := strconv.Atoi(heading.match[3])
		blocks = append(blocks, migrationBlock{
			Start:  heading.index,
			End:    end,
			Status: heading.match[1],
			ID:     fmt.Sprintf("%d.%d", major, minor),
		})
	}
	return blocks
}

func firstBodyLine(block []string) int {
	index := 1
	for index < len(block) && block[index] == "" {
		index++
	}
	return index
}

func legacyAtomicityAllowances(block []string) []string {
	allowances := make([]string, 0, 2)
	implementationValue, _ := fieldValue(block, "Implementation files")
	implementationFiles, _ := pathValues(implementationValue)
	redCommands := 0
	for _, line := range fieldSection(block, "RED") {
		if redConcrete.MatchString(line) {
			redCommands++
		}
	}
	acCommands := 0
	for _, line := range fieldSection(block, "ACs") {
		if acConcrete.MatchString(line) {
			acCommands++
		}
	}
	implementationSteps := 0
	for _, line := range fieldSection(block, "Implementation") {
		if implementationStep.MatchString(line) {
			implementationSteps++
		}
	}
	if len(implementationFiles) > 3 {
		allowances = append(allowances, fmt.Sprintf("implementation-files=%d", len(implementationFiles)))
	}
	if redCommands > 1 {
		allowances = append(allowances, fmt.Sprintf("red-commands=%d", redCommands))
	}
	if acCommands > 3 {
		allowances = append(allowances, fmt.Sprintf("ac-commands=%d", acCommands))
	}
	if implementationSteps < 1 || implementationSteps > 2 {
		allowances = append(allowances, fmt.Sprintf("implementation-steps=%d", implementationSteps))
	}
	return allowances
}

func migrateTaskBlock(block []string, taskIndex int, previousTaskID *string, changes *[]string) []string {
	if strings.HasPrefix(block[0], "### [!]") {
		return block
	}

	id := strconv.Itoa(taskIndex + 1)
	if match := validateTaskHeading.FindStringSubmatch(block[0]); match != nil {
		major, _ := strconv.Atoi(match[2])
		minor, _ := strconv.Atoi(match[3])
		id = fmt.Sprintf("%d.%d", major, minor)
	}
	if _, present := fieldValue(block, "Requirement"); !present {
		insertion := firstBodyLine(block)
		block = insertLine(block, insertion, fmt.Sprintf("**Requirement:** SOURCE-%03d", taskIndex+1))
		*changes = append(*changes, fmt.Sprintf("task %s: added a SOURCE-* requirement", id))
	}

	if _, present := fieldValue(block, "Depends on"); !present {
		requirementIndex := indexOfPrefix(block, "**Requirement:**")
		value := "none"
		if previousTaskID != nil {
			value = *previousTaskID
		}
		block = insertLine(block, requirementIndex+1, "**Depends on:** "+value)
		*changes = append(*changes, fmt.Sprintf("task %s: made the legacy serial dependency explicit", id))
	}

	allowances := legacyAtomicityAllowances(block)
	if len(allowances) > 0 {
		dependsOnIndex := indexOfPrefix(block, "**Depends on:**")
		block = insertLine(block, dependsOnIndex+1, "**Legacy allowances:** "+strings.Join(allowances, ", "))
		*changes = append(*changes, fmt.Sprintf("task %s: recorded exact legacy atomicity allowances (%s)", id, strings.Join(allowances, ", ")))
	}

	return block
}

// insertLine insere value em index e devolve a nova fatia.
func insertLine(lines []string, index int, value string) []string {
	if index < 0 {
		index = 0
	}
	if index > len(lines) {
		index = len(lines)
	}
	result := make([]string, 0, len(lines)+1)
	result = append(result, lines[:index]...)
	result = append(result, value)
	result = append(result, lines[index:]...)
	return result
}

// MigrateTasksContent migra um plano legado para o contrato v3.
func MigrateTasksContent(text string, options MigrateOptions) MigrationResult {
	before := AnalyzeTasks(text, AnalyzeOptions{})
	if len(before.Errors) > 0 {
		return MigrationResult{
			Content:     text,
			Changes:     []string{},
			Errors:      before.Errors,
			Warnings:    before.Warnings,
			FromVersion: before.ContractVersion,
			ToVersion:   CurrentTaskContractVersion,
		}
	}
	if before.ContractVersion != nil && *before.ContractVersion == CurrentTaskContractVersion {
		return MigrationResult{
			Content:     text,
			Changes:     []string{},
			Errors:      []string{},
			Warnings:    before.Warnings,
			FromVersion: before.ContractVersion,
			ToVersion:   CurrentTaskContractVersion,
		}
	}

	lines := splitLines(text)
	changes := make([]string, 0, 4)
	workID := options.WorkID
	if !workIDShape.MatchString(workID) {
		return MigrationResult{
			Content:     text,
			Changes:     changes,
			Errors:      []string{"migration to task contract v3 requires a four-digit Work ID"},
			Warnings:    before.Warnings,
			FromVersion: before.ContractVersion,
			ToVersion:   CurrentTaskContractVersion,
		}
	}
	versionIndex := indexOfPrefix(lines, "**Contract version:**")
	if versionIndex == -1 {
		titleIndex := indexOfPrefix(lines, "# Tasks:")
		if titleIndex == -1 {
			return MigrationResult{
				Content:     text,
				Changes:     changes,
				Errors:      []string{"migration requires a canonical # Tasks: title"},
				Warnings:    before.Warnings,
				FromVersion: before.ContractVersion,
				ToVersion:   CurrentTaskContractVersion,
			}
		}
		lines = insertLine(lines, titleIndex+1, fmt.Sprintf("**Contract version:** %d", CurrentTaskContractVersion))
		lines = insertLine(lines, titleIndex+2, fmt.Sprintf("**Migrated from task contract:** %d", *before.ContractVersion))
	} else {
		lines[versionIndex] = fmt.Sprintf("**Contract version:** %d", CurrentTaskContractVersion)
		lines = insertLine(lines, versionIndex+1, fmt.Sprintf("**Migrated from task contract:** %d", *before.ContractVersion))
	}
	changes = append(changes, fmt.Sprintf("set task contract version to %d with migration provenance from v%d", CurrentTaskContractVersion, *before.ContractVersion))

	existingWorkIndex := indexOfPrefix(lines, "**Work ID:**")
	if existingWorkIndex == -1 {
		contractIndex := indexOfPrefix(lines, "**Contract version:**")
		migrationIndex := indexOfPrefix(lines, "**Migrated from task contract:**")
		position := contractIndex
		if migrationIndex > position {
			position = migrationIndex
		}
		lines = insertLine(lines, position+1, "**Work ID:** "+workID)
		changes = append(changes, "assigned Work ID "+workID)
	} else if lines[existingWorkIndex] != "**Work ID:** "+workID {
		return MigrationResult{
			Content:     text,
			Changes:     changes,
			Errors:      []string{"migration Work ID conflicts with existing declaration: " + lines[existingWorkIndex]},
			Warnings:    before.Warnings,
			FromVersion: before.ContractVersion,
			ToVersion:   CurrentTaskContractVersion,
		}
	}

	blocks := migrationBlocks(lines)
	for index := len(blocks) - 1; index >= 0; index-- {
		blockInfo := blocks[index]
		block := append([]string{}, lines[blockInfo.Start:blockInfo.End]...)
		var previousTaskID *string
		if index > 0 {
			value := blocks[index-1].ID
			previousTaskID = &value
		}
		migrated := migrateTaskBlock(block, index, previousTaskID, &changes)
		replacement := make([]string, 0, len(lines)-(blockInfo.End-blockInfo.Start)+len(migrated))
		replacement = append(replacement, lines[:blockInfo.Start]...)
		replacement = append(replacement, migrated...)
		replacement = append(replacement, lines[blockInfo.End:]...)
		lines = replacement
	}

	content := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	after := AnalyzeTasks(content, AnalyzeOptions{Strict: true})
	return MigrationResult{
		Content:     content,
		Changes:     changes,
		Errors:      after.Errors,
		Warnings:    after.Warnings,
		FromVersion: before.ContractVersion,
		ToVersion:   CurrentTaskContractVersion,
	}
}

func validatePlanIdentity(filePath string, result TaskAnalysis) []string {
	if result.ContractVersion == nil || *result.ContractVersion != CurrentTaskContractVersion {
		return nil
	}
	base := filepath.Base(filePath)
	match := planFileName.FindStringSubmatch(base)
	if match == nil || filepath.Base(filepath.Dir(filePath)) != ".todo" {
		return []string{"current task contract requires canonical path .todo/NNNN-tasks.md: " + filePath}
	}
	declared := "missing"
	if result.WorkID != nil {
		declared = *result.WorkID
	}
	if match[1] != declared {
		return []string{fmt.Sprintf("plan filename Work ID %s does not match declaration %s", match[1], declared)}
	}
	return nil
}

func printIssues(writer io.Writer, label string, issues []string) {
	if len(issues) == 0 {
		return
	}
	fmt.Fprintf(writer, "%s (%d):\n", label, len(issues))
	for _, issue := range issues {
		fmt.Fprintf(writer, "- %s\n", issue)
	}
}

// ValidateTasksMain executa a interface de linha de comando do validador de
// plano e devolve o código de saída.
func ValidateTasksMain(args []string, stdout, stderr io.Writer) int {
	strict := false
	migrate := false
	write := false
	workID := ""
	withoutWork := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch argument {
		case "--strict":
			strict = true
			continue
		case "--migrate":
			migrate = true
			continue
		case "--write":
			write = true
			continue
		case "--work":
			if index+1 < len(args) {
				index++
				workID = args[index]
			}
			continue
		}
		withoutWork = append(withoutWork, argument)
	}
	unknownOptions := 0
	positionals := make([]string, 0, 1)
	for _, argument := range withoutWork {
		if strings.HasPrefix(argument, "--") {
			unknownOptions++
			continue
		}
		positionals = append(positionals, argument)
	}
	if len(positionals) != 1 || unknownOptions > 0 || (write && !migrate) || (strict && migrate) || (migrate && !workIDShape.MatchString(workID)) {
		fmt.Fprintln(stderr, "usage: validate_tasks.js [--strict] PATH | --migrate --work NNNN [--write] PATH")
		return 2
	}
	filePath := positionals[0]

	if migrate {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(stdout, "MIGRATION FAIL: %s\n", filePath)
			fmt.Fprintf(stdout, "- file not found: %s\n", filePath)
			return 1
		}
		original := string(data)
		initial := AnalyzeTasks(original, AnalyzeOptions{})
		if initial.ContractVersion != nil && *initial.ContractVersion == CurrentTaskContractVersion {
			if len(initial.Errors) > 0 {
				fmt.Fprintf(stdout, "MIGRATION BLOCKED: %s\n", filePath)
				printIssues(stdout, "Blocking issues", initial.Errors)
				return 1
			}
			fmt.Fprintf(stdout, "MIGRATION N/A: %s already uses task contract v%d\n", filePath, CurrentTaskContractVersion)
			return 0
		}
		result := MigrateTasksContent(original, MigrateOptions{WorkID: workID})
		if len(result.Errors) > 0 {
			fmt.Fprintf(stdout, "MIGRATION BLOCKED: %s\n", filePath)
			printIssues(stdout, "Blocking issues", result.Errors)
			if len(result.Warnings) > 0 {
				printIssues(stdout, "Compatibility warnings", result.Warnings)
			}
			return 1
		}
		fromVersion := 0
		if result.FromVersion != nil {
			fromVersion = *result.FromVersion
		}
		label := "MIGRATION PREVIEW"
		if write {
			label = "MIGRATED"
		}
		fmt.Fprintf(stdout, "%s: %s (v%d -> v%d)\n", label, filePath, fromVersion, result.ToVersion)
		printIssues(stdout, "Changes", result.Changes)
		if write {
			if err := os.WriteFile(filePath, []byte(result.Content), 0o644); err != nil {
				fmt.Fprintf(stderr, "%v\n", err)
				return 1
			}
			fmt.Fprintf(stdout, "PASS: %s is structurally valid under task contract v%d\n", filePath, CurrentTaskContractVersion)
		} else {
			fmt.Fprintln(stdout, "No file was changed. Migrated content follows:")
			fmt.Fprintln(stdout, "--- BEGIN MIGRATED FILE ---")
			fmt.Fprint(stdout, result.Content)
			if !strings.HasSuffix(result.Content, "\n") {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintln(stdout, "--- END MIGRATED FILE ---")
			fmt.Fprintln(stdout, "Apply by re-running the loaded validator with --migrate --write for the same file.")
		}
		return 0
	}

	result := ValidateTasksDetailed(filePath, AnalyzeOptions{Strict: strict})
	errors := append([]string{}, result.Errors...)
	errors = append(errors, validatePlanIdentity(filePath, result)...)
	if len(errors) > 0 {
		fmt.Fprintf(stdout, "FAIL: %s\n", filePath)
		printIssues(stdout, "Blocking issues", errors)
		return 1
	}
	version := 0
	if result.ContractVersion != nil {
		version = *result.ContractVersion
	}
	mode := "current"
	if version < CurrentTaskContractVersion {
		mode = "legacy compatibility"
	}
	fmt.Fprintf(stdout, "PASS: %s is executable under task contract v%d (%s)\n", filePath, version, mode)
	if len(result.Exceptions) > 0 {
		printIssues(stdout, "Preserved legacy exceptions", result.Exceptions)
	}
	if len(result.Warnings) > 0 {
		printIssues(stdout, "Compatibility warnings", result.Warnings)
		fmt.Fprintln(stdout, "Migration is optional: preview with --migrate, then apply with --migrate --write.")
	}
	return 0
}
