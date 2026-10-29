package work

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// Panorama de um plano. Os estados são parte do contrato observável da CLI e
// não mudam de nome.
const (
	PanoramaNotStarted       = "NOT STARTED"
	PanoramaInProgress       = "IN PROGRESS"
	PanoramaTasksComplete    = "TASKS COMPLETE"
	PanoramaComplete         = "COMPLETE"
	PanoramaInconsistent     = "INCONSISTENT STATE"
	PanoramaInconsistentSort = "INCONSISTENT ORDER"
	PanoramaBlocked          = "BLOCKED"
	PanoramaInvalidPlan      = "INVALID PLAN"
	PanoramaStaleEvidence    = "STALE EVIDENCE"
	PanoramaNoTasks          = "NO TASKS"
)

// acceptedStage é o único estágio que conta como task concluída: recibo do
// verificador independente sobre a árvore atual.
const acceptedStage = "ACCEPTED"

var taskHeading = regexp.MustCompile(`^### \[([ x!])\] \[(\d+\.\d+)\] (\S.*)$`)

// FileDigest é o hash de um arquivo no instante do instantâneo da evidência.
type FileDigest struct {
	Exists bool    `json:"exists"`
	SHA256 *string `json:"sha256"`
}

// EvidenceState é o estágio de evidência de uma task.
type EvidenceState struct {
	Stage string `json:"stage"`
	Stale bool   `json:"stale"`
	// Attestation explica por que uma evidência VERIFIED ainda não é aceita.
	Attestation string `json:"attestation,omitempty"`
}

// StatusTask é uma task lida do markdown com o estado da evidência.
type StatusTask struct {
	ID          string        `json:"id"`
	Marker      string        `json:"marker"`
	Title       string        `json:"title"`
	Requirement string        `json:"requirement"`
	DependsOn   string        `json:"dependsOn"`
	Evidence    EvidenceState `json:"evidence"`
}

// GlobalGates é o estado dos gates globais do plano.
type GlobalGates struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// PanoramaCounts são as contagens do panorama.
type PanoramaCounts struct {
	Total             int `json:"total"`
	Completed         int `json:"completed"`
	Pending           int `json:"pending"`
	Blocked           int `json:"blocked"`
	Stale             int `json:"stale"`
	UnverifiedChecked int `json:"unverifiedChecked"`
	VerifiedOpen      int `json:"verifiedOpen"`
}

// Panorama é o estado agregado do plano.
type Panorama struct {
	State                string         `json:"state"`
	StoppedAt            string         `json:"stoppedAt"`
	Counts               PanoramaCounts `json:"counts"`
	Progress             int            `json:"progress"`
	CompatibilityWarning int            `json:"compatibilityWarnings"`
}

// ArtifactState é o estado de um artefato do pipeline.
type ArtifactState struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// ArtifactsStatus são os artefatos do pipeline.
type ArtifactsStatus struct {
	SystemSpec ArtifactState `json:"systemSpec"`
	Prompt     ArtifactState `json:"prompt"`
	Tasks      ArtifactState `json:"tasks"`
}

// ProjectStatus é o relatório de um plano.
type ProjectStatus struct {
	Artifacts                   ArtifactsStatus `json:"artifacts"`
	Panorama                    Panorama        `json:"panorama"`
	GlobalGates                 GlobalGates     `json:"globalGates"`
	Tasks                       []StatusTask    `json:"tasks"`
	ValidationErrors            []string        `json:"validationErrors"`
	ValidationWarnings          []string        `json:"validationWarnings"`
	ValidationExceptions        []string        `json:"validationExceptions"`
	ContractVersion             *int            `json:"contractVersion"`
	ContractVersionSource       string          `json:"contractVersionSource"`
	MigratedFromContractVersion *int            `json:"migratedFromContractVersion"`
	WorkID                      *string         `json:"workId"`
}

// PlanStatus é o relatório de um plano com os bloqueios entre Works.
type PlanStatus struct {
	ProjectStatus
	CrossWorkBlockers map[string][]string `json:"crossWorkBlockers"`
}

// WorkIndexEntry é uma linha do índice de Works.
type WorkIndexEntry struct {
	WorkID          string              `json:"work_id"`
	State           string              `json:"state"`
	Origin          *WorkManifestOrigin `json:"origin,omitempty"`
	Plan            string              `json:"plan,omitempty"`
	PlanExists      bool                `json:"plan_exists,omitempty"`
	Error           string              `json:"error,omitempty"`
	Panorama        *Panorama           `json:"panorama"`
	GlobalGates     *GlobalGates        `json:"globalGates,omitempty"`
	ContractVersion *int                `json:"contractVersion,omitempty"`
}

// WorkIndexReport é a lista de Works com o panorama de cada um.
type WorkIndexReport struct {
	Works []WorkIndexEntry `json:"works"`
}

// evidenceStateFile é o estado TDD local de uma task, escrito pelo audit.
type evidenceStateFile struct {
	BaselineImplementation map[string]FileDigest  `json:"baseline_implementation"`
	BaselineTests          map[string]FileDigest  `json:"baseline_tests"`
	RedTests               *map[string]FileDigest `json:"red_tests"`
	GreenImplementation    map[string]FileDigest  `json:"green_implementation"`
	GreenTests             map[string]FileDigest  `json:"green_tests"`
}

// digestFile devolve o digest de um arquivo. Caminho ausente, diretório ou
// ilegível descreve o arquivo como inexistente, como o `digest` da referência.
func digestFile(path string) (FileDigest, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return FileDigest{Exists: false}, nil
		}
		return FileDigest{}, fmt.Errorf("work: ler estado de %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return FileDigest{Exists: false}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return FileDigest{}, fmt.Errorf("work: ler %s: %w", path, err)
	}
	sha := jsonx.SHA256Hex(data)
	return FileDigest{Exists: true, SHA256: &sha}, nil
}

// digestsEqual compara o digest esperado com o observado.
func digestsEqual(expected, actual FileDigest) bool {
	if expected.Exists != actual.Exists {
		return false
	}
	if (expected.SHA256 == nil) != (actual.SHA256 == nil) {
		return false
	}
	if expected.SHA256 == nil {
		return true
	}
	return *expected.SHA256 == *actual.SHA256
}

// snapshotChanged informa se algum arquivo do instantâneo mudou desde a
// captura. Caminhos do instantâneo são relativos à raiz do repositório.
func snapshotChanged(snapshot map[string]FileDigest, rootDir string) (bool, error) {
	for file, expected := range snapshot {
		// Caminho absoluto no instantâneo é usado como está, como o
		// `path.resolve(rootDir, filePath)` da referência.
		absolute := file
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(rootDir, file)
		}
		actual, err := digestFile(absolute)
		if err != nil {
			return false, err
		}
		if !digestsEqual(expected, actual) {
			return true, nil
		}
	}
	return false, nil
}

// fieldValue devolve o valor do campo `**Nome:**` de um bloco de task.
func fieldValue(lines []string, start, end int, name string) string {
	prefix := "**" + name + ":**"
	for index := start + 1; index < end && index < len(lines); index++ {
		if strings.HasPrefix(lines[index], prefix) {
			value := strings.TrimSpace(lines[index][len(prefix):])
			return strings.ReplaceAll(value, "`", "")
		}
	}
	return "—"
}

// parseStatusTasks lê os headings e campos das tasks do markdown.
func parseStatusTasks(text string) []StatusTask {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	type found struct {
		index int
		match []string
	}
	headings := make([]found, 0)
	for index, line := range lines {
		if match := taskHeading.FindStringSubmatch(line); match != nil {
			headings = append(headings, found{index: index, match: match})
		}
	}
	tasks := make([]StatusTask, 0, len(headings))
	for position, heading := range headings {
		end := len(lines)
		if position+1 < len(headings) {
			end = headings[position+1].index
		}
		tasks = append(tasks, StatusTask{
			ID:          heading.match[2],
			Marker:      heading.match[1],
			Title:       heading.match[3],
			Requirement: fieldValue(lines, heading.index, end, "Requirement"),
			DependsOn:   fieldValue(lines, heading.index, end, "Depends on"),
		})
	}
	return tasks
}

// evidenceFor calcula o estágio de evidência de uma task.
//
// `ACCEPTED` exige aceitação independente: aprovação vigente, recibo assinado
// pelo verificador e árvore atual idêntica à avaliada. Os estágios anteriores
// descrevem o loop local (RED/GREEN, `work audit`) — diagnóstico, não
// autorização.
func evidenceFor(taskID, todoDirectory string, workID *string) EvidenceState {
	rootDir := filepath.Dir(todoDirectory)
	evidenceRoot := filepath.Join(todoDirectory, "evidence")
	if workID != nil {
		evidenceRoot = filepath.Join(evidenceRoot, *workID)
	}
	var evaluation verify.AcceptanceEvaluation
	if workID != nil {
		evaluation = verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
			RootDir: rootDir,
			WorkID:  *workID,
			TaskID:  taskID,
		})
	} else {
		evaluation = verify.AcceptanceEvaluation{
			Accepted: false,
			Reason:   "plano sem Work ID: a aceitação independente exige um Work canônico",
		}
	}
	stateFile := filepath.Join(evidenceRoot, "state", taskID+".json")
	if _, err := os.Stat(stateFile); err != nil {
		if evaluation.Accepted {
			return EvidenceState{Stage: acceptedStage}
		}
		return EvidenceState{Stage: "not started", Attestation: evaluation.Reason}
	}
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
	}
	var state evidenceStateFile
	if err := unmarshalJSON(data, &state); err != nil {
		return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
	}
	if state.RedTests == nil {
		staleImplementation, err := snapshotChanged(state.BaselineImplementation, rootDir)
		if err != nil {
			return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
		}
		staleTests, err := snapshotChanged(state.BaselineTests, rootDir)
		if err != nil {
			return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
		}
		return EvidenceState{Stage: "BASELINE", Stale: staleImplementation || staleTests}
	}
	// Estado sem GREEN ainda está em RED.
	if state.GreenImplementation == nil {
		stale, err := snapshotChanged(*state.RedTests, rootDir)
		if err != nil {
			return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
		}
		return EvidenceState{Stage: "RED", Stale: stale}
	}
	staleImplementation, err := snapshotChanged(state.GreenImplementation, rootDir)
	if err != nil {
		return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
	}
	staleTests, err := snapshotChanged(state.GreenTests, rootDir)
	if err != nil {
		return EvidenceState{Stage: "invalid evidence: " + err.Error(), Stale: true}
	}
	stale := staleImplementation || staleTests
	verifyLog := filepath.Join(evidenceRoot, taskID+"-verify.log")
	logData, err := os.ReadFile(verifyLog)
	if err != nil || !verifyLogPass.Match(logData) {
		return EvidenceState{Stage: "GREEN", Stale: stale}
	}
	if evaluation.Accepted {
		return EvidenceState{Stage: acceptedStage}
	}
	return EvidenceState{Stage: "VERIFIED", Stale: stale, Attestation: evaluation.Reason}
}

var verifyLogPass = regexp.MustCompile(`(?m)VERDICT: PASS\s*$`)

// walkMarkdown devolve os arquivos .md sob directory, recursivamente.
func walkMarkdown(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("work: ler %s: %w", directory, err)
	}
	files := make([]string, 0)
	for _, entry := range entries {
		entryPath := filepath.Join(directory, entry.Name())
		if entry.IsDir() {
			nested, err := walkMarkdown(entryPath)
			if err != nil {
				return nil, err
			}
			files = append(files, nested...)
			continue
		}
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".md") {
			files = append(files, entryPath)
		}
	}
	return files, nil
}

// latestPrompt devolve o prompt mais recente em `.prompts/`.
func latestPrompt(rootDir string) (string, error) {
	files, err := walkMarkdown(filepath.Join(rootDir, ".prompts"))
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", nil
	}
	type candidate struct {
		path    string
		modTime int64
	}
	candidates := make([]candidate, 0, len(files))
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			return "", fmt.Errorf("work: ler %s: %w", file, err)
		}
		candidates = append(candidates, candidate{path: file, modTime: info.ModTime().UnixNano()})
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		if candidates[left].modTime != candidates[right].modTime {
			return candidates[left].modTime > candidates[right].modTime
		}
		return candidates[left].path < candidates[right].path
	})
	return candidates[0].path, nil
}

var (
	statusFieldPattern  = regexp.MustCompile(`(?m)^\*\*Status:\*\* (.+)$`)
	versionFieldPattern = regexp.MustCompile(`(?m)^\*\*Versão:\*\* (.+)$`)
)

// firstMatch devolve o primeiro grupo da expressão, ou "".
func firstMatch(text string, expression *regexp.Regexp) string {
	match := expression.FindStringSubmatch(text)
	if match == nil {
		return ""
	}
	return match[1]
}

// artifactStatus descreve os artefatos do pipeline para a raiz do repositório.
func artifactStatus(rootDir, tasksPath string, validation plan.TaskAnalysis) (ArtifactsStatus, error) {
	if absolute, err := filepath.Abs(tasksPath); err == nil {
		tasksPath = absolute
	}
	systemSpecPath := filepath.Join(rootDir, ".specs", "system.md")
	systemSpec := ArtifactState{Path: ".specs/system.md", State: "absent", Detail: "run /make-spec"}
	if data, err := os.ReadFile(systemSpecPath); err == nil {
		text := string(data)
		status := firstMatch(text, statusFieldPattern)
		if status == "" {
			status = "status unknown"
		}
		version := firstMatch(text, versionFieldPattern)
		if version == "" {
			version = "version unknown"
		}
		systemSpec = ArtifactState{Path: ".specs/system.md", State: "present", Detail: status + "; version " + version}
	} else if !os.IsNotExist(err) {
		return ArtifactsStatus{}, fmt.Errorf("work: ler system spec: %w", err)
	}

	prompt := ArtifactState{Path: ".prompts/", State: "absent", Detail: "run /make-prompt"}
	promptPath, err := latestPrompt(rootDir)
	if err != nil {
		return ArtifactsStatus{}, err
	}
	if promptPath != "" {
		data, err := os.ReadFile(promptPath)
		if err != nil {
			return ArtifactsStatus{}, fmt.Errorf("work: ler prompt %s: %w", promptPath, err)
		}
		status := firstMatch(string(data), statusFieldPattern)
		if status == "" {
			status = "status unknown"
		}
		relative, err := filepath.Rel(rootDir, promptPath)
		if err != nil {
			return ArtifactsStatus{}, fmt.Errorf("work: resolver %s: %w", promptPath, err)
		}
		prompt = ArtifactState{Path: normalizeWorkPath(relative), State: "present", Detail: status}
	}

	tasks := ArtifactState{Path: tasksPath, State: "absent", Detail: "run /make-todo"}
	if _, err := os.Stat(tasksPath); err == nil {
		version := "unknown"
		if validation.ContractVersion != nil {
			version = "v" + strconv.Itoa(*validation.ContractVersion)
		}
		switch {
		case len(validation.Errors) > 0:
			tasks = ArtifactState{
				Path:   tasksPath,
				State:  "invalid",
				Detail: fmt.Sprintf("%d blocking error(s); contract %s", len(validation.Errors), version),
			}
		case len(validation.Warnings) > 0 || len(validation.Exceptions) > 0:
			details := make([]string, 0, 2)
			if len(validation.Warnings) > 0 {
				details = append(details, fmt.Sprintf("%d compatibility warning(s)", len(validation.Warnings)))
			}
			if len(validation.Exceptions) > 0 {
				details = append(details, fmt.Sprintf("%d preserved legacy exception(s)", len(validation.Exceptions)))
			}
			tasks = ArtifactState{Path: tasksPath, State: "compatible", Detail: strings.Join(details, "; ") + "; contract " + version}
		default:
			tasks = ArtifactState{Path: tasksPath, State: "valid", Detail: "structural validation PASS; contract " + version}
		}
	}
	return ArtifactsStatus{SystemSpec: systemSpec, Prompt: prompt, Tasks: tasks}, nil
}

// globalGateShadow é um item de `## Global gates` com o marcador do checkbox.
type globalGateShadow struct {
	index  int
	marker string
}

var (
	globalGateNA       = regexp.MustCompile(`(?m)^\s*N/A\s*$`)
	globalGateCheckbox = regexp.MustCompile(`(?m)^- \[([ xX!])\]`)
)

// globalGateStatus avalia os gates globais. O checkbox não prova nada: um gate
// só conta quando existe recibo de aceitação independente para ele.
func globalGateStatus(text, rootDir string, workID *string) GlobalGates {
	start := strings.Index(text, "## Global gates")
	if start == -1 {
		return GlobalGates{State: "MISSING", Detail: "missing"}
	}
	after := text[start+len("## Global gates"):]
	boundaries := make([]int, 0, 2)
	if index := strings.Index(after, "\n## "); index != -1 {
		boundaries = append(boundaries, index)
	}
	if index := strings.Index(after, "\n### "); index != -1 {
		boundaries = append(boundaries, index)
	}
	end := len(after)
	for _, boundary := range boundaries {
		if boundary < end {
			end = boundary
		}
	}
	section := after[:end]
	if globalGateNA.MatchString(section) {
		return GlobalGates{State: "N/A", Detail: "N/A"}
	}
	matches := globalGateCheckbox.FindAllStringSubmatch(section, -1)
	if len(matches) == 0 {
		return GlobalGates{State: "UNTRACKED", Detail: "declared; no tracked checkbox state"}
	}
	items := make([]globalGateShadow, 0, len(matches))
	blocked := 0
	for index, match := range matches {
		items = append(items, globalGateShadow{index: index, marker: match[1]})
		if match[1] == "!" {
			blocked++
		}
	}
	proven := 0
	pending := make([]string, 0)
	for _, item := range items {
		name := "G-" + strconv.Itoa(item.index+1)
		var accepted bool
		reason := ""
		if workID == nil {
			reason = "plano sem Work ID"
		} else {
			evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
				RootDir: rootDir,
				WorkID:  *workID,
				TaskID:  name,
			})
			accepted = evaluation.Accepted
			reason = evaluation.Reason
		}
		if accepted {
			proven++
			continue
		}
		pending = append(pending, name+": "+reason)
	}
	detail := fmt.Sprintf("%d/%d with independent receipt", proven, len(items))
	if blocked > 0 {
		detail += fmt.Sprintf("; %d blocked", blocked)
	}
	if len(pending) > 0 {
		detail += " (" + strings.Join(pending, "; ") + ")"
	}
	switch {
	case blocked > 0:
		return GlobalGates{State: "BLOCKED", Detail: detail}
	case proven == len(items):
		return GlobalGates{State: "PASS", Detail: detail}
	default:
		return GlobalGates{State: "PENDING", Detail: detail}
	}
}

// panorama deriva o estado agregado do plano.
func panorama(tasks []StatusTask, validationErrors, validationWarnings []string, gates GlobalGates) Panorama {
	completed, pending, blocked, stale, unverifiedChecked, verifiedOpen := 0, 0, 0, 0, 0, 0
	var partial *StatusTask
	var firstBlocked *StatusTask
	var firstPending *StatusTask
	firstOpenIndex := -1
	for index := range tasks {
		task := &tasks[index]
		switch task.Marker {
		case "x":
			completed++
		case " ":
			pending++
		case "!":
			blocked++
		}
		if task.Evidence.Stale {
			stale++
		}
		if task.Marker == "x" && task.Evidence.Stage != acceptedStage {
			unverifiedChecked++
		}
		if task.Marker != "x" && task.Evidence.Stage == acceptedStage {
			verifiedOpen++
		}
		if partial == nil && task.Marker != "x" && task.Evidence.Stage != "not started" && task.Evidence.Stage != acceptedStage {
			partial = task
		}
		if firstBlocked == nil && task.Marker == "!" {
			firstBlocked = task
		}
		if firstPending == nil && task.Marker == " " {
			firstPending = task
		}
		if firstOpenIndex == -1 && task.Marker != "x" {
			firstOpenIndex = index
		}
	}
	var outOfOrder *StatusTask
	if firstOpenIndex != -1 {
		for index := firstOpenIndex + 1; index < len(tasks); index++ {
			if tasks[index].Marker == "x" {
				outOfOrder = &tasks[index]
				break
			}
		}
	}

	state := PanoramaNotStarted
	stoppedAt := "No task has started"
	switch {
	case len(validationErrors) > 0:
		state = PanoramaInvalidPlan
		stoppedAt = fmt.Sprintf("Structural validation failed with %d error(s)", len(validationErrors))
	case stale > 0:
		state = PanoramaStaleEvidence
		for index := range tasks {
			if tasks[index].Evidence.Stale {
				stoppedAt = "Evidence no longer matches files at " + tasks[index].ID
				break
			}
		}
	case firstBlocked != nil:
		state = PanoramaBlocked
		stoppedAt = "Blocked at " + firstBlocked.ID + ": " + firstBlocked.Title
	case unverifiedChecked > 0 || verifiedOpen > 0:
		state = PanoramaInconsistent
		var task *StatusTask
		for index := range tasks {
			if tasks[index].Marker == "x" && tasks[index].Evidence.Stage != acceptedStage {
				task = &tasks[index]
				break
			}
		}
		if task == nil {
			for index := range tasks {
				if tasks[index].Marker != "x" && tasks[index].Evidence.Stage == acceptedStage {
					task = &tasks[index]
					break
				}
			}
		}
		if task == nil {
			// Impossível: a condição do caso garante uma das duas tasks.
			stoppedAt = "Inconsistent evidence state"
			break
		}
		if task.Marker == "x" {
			stoppedAt = "Task " + task.ID + " is checked but evidence stage is " + task.Evidence.Stage
			if task.Evidence.Attestation != "" {
				stoppedAt += " (" + task.Evidence.Attestation + ")"
			}
		} else {
			stoppedAt = "Task " + task.ID + " has ACCEPTED evidence but marker is not checked"
		}
	case partial != nil:
		state = PanoramaInProgress
		stoppedAt = "Stopped during " + partial.ID + " at " + partial.Evidence.Stage
	case pending > 0 && completed > 0:
		if outOfOrder != nil {
			state = PanoramaInconsistentSort
			stoppedAt = "Task " + outOfOrder.ID + " is checked after open task " + tasks[firstOpenIndex].ID
		} else {
			state = PanoramaInProgress
			stoppedAt = "Next task: " + firstPending.ID + " — " + firstPending.Title
		}
	case pending > 0:
		stoppedAt = "Next task: " + firstPending.ID + " — " + firstPending.Title
	case len(tasks) > 0:
		if gates.State == "PASS" || gates.State == "N/A" {
			state = PanoramaComplete
			stoppedAt = "All tasks are checked and global gates are complete"
		} else {
			state = PanoramaTasksComplete
			stoppedAt = "All tasks are checked; global gates are " + gates.State + ": " + gates.Detail
		}
	default:
		state = PanoramaNoTasks
		stoppedAt = "No canonical tasks found"
	}

	progress := 0
	if len(tasks) > 0 {
		progress = completed * 100 / len(tasks)
	}
	return Panorama{
		State:                state,
		StoppedAt:            stoppedAt,
		Counts:               PanoramaCounts{Total: len(tasks), Completed: completed, Pending: pending, Blocked: blocked, Stale: stale, UnverifiedChecked: unverifiedChecked, VerifiedOpen: verifiedOpen},
		Progress:             progress,
		CompatibilityWarning: len(validationWarnings),
	}
}

// emptyTaskAnalysis é o diagnóstico de um plano ausente.
func emptyTaskAnalysis() plan.TaskAnalysis {
	return plan.TaskAnalysis{
		Errors:                []string{},
		Warnings:              []string{},
		Exceptions:            []string{},
		ContractVersion:       nil,
		ContractVersionSource: "absent",
		Tasks:                 []plan.TaskSummary{},
	}
}

// CollectProjectStatus monta o relatório de um plano markdown.
func CollectProjectStatus(tasksPath string) (ProjectStatus, error) {
	_, statErr := os.Stat(tasksPath)
	exists := statErr == nil
	text := ""
	if exists {
		data, err := os.ReadFile(tasksPath)
		if err != nil {
			return ProjectStatus{}, fmt.Errorf("work: ler plano %s: %w", tasksPath, err)
		}
		text = string(data)
	}
	validation := emptyTaskAnalysis()
	if exists {
		validation = plan.ValidateTasksDetailed(tasksPath, plan.AnalyzeOptions{PlanPath: tasksPath})
	}
	todoDirectory := filepath.Dir(tasksPath)
	rootDir := filepath.Dir(todoDirectory)
	var workID *string
	if validation.WorkID != nil && *validation.WorkID != "" {
		value := *validation.WorkID
		workID = &value
	}
	if workID != nil {
		canonicalPath := filepath.Join(rootDir, ".pwn", "work", *workID, "plan.json")
		if _, err := os.Stat(canonicalPath); err == nil {
			loaded := plan.LoadPlan(*workID, rootDir)
			if loaded == nil || !plan.PlanMatchesMarkdown(*loaded, text) {
				validation.Errors = append(validation.Errors,
					fmt.Sprintf("DRIFT: %s diverge de .pwn/work/%s/plan.json ou o plano canônico está ilegível", tasksPath, *workID))
			}
		}
	}
	tasks := parseStatusTasks(text)
	for index := range tasks {
		tasks[index].Evidence = evidenceFor(tasks[index].ID, todoDirectory, workID)
	}
	gates := globalGateStatus(text, rootDir, workID)
	artifacts, err := artifactStatus(rootDir, tasksPath, validation)
	if err != nil {
		return ProjectStatus{}, err
	}
	return ProjectStatus{
		Artifacts:                   artifacts,
		Panorama:                    panorama(tasks, validation.Errors, validation.Warnings, gates),
		GlobalGates:                 gates,
		Tasks:                       tasks,
		ValidationErrors:            nonNilStrings(validation.Errors),
		ValidationWarnings:          nonNilStrings(validation.Warnings),
		ValidationExceptions:        nonNilStrings(validation.Exceptions),
		ContractVersion:             validation.ContractVersion,
		ContractVersionSource:       validation.ContractVersionSource,
		MigratedFromContractVersion: validation.MigratedFromContractVersion,
		WorkID:                      workID,
	}, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// CollectWorkIndex monta o índice de Works com o panorama de cada plano.
func CollectWorkIndex(root string) (WorkIndexReport, error) {
	if root == "" {
		root = "."
	}
	works, err := ListWorks(root)
	if err != nil {
		return WorkIndexReport{}, err
	}
	entries := make([]WorkIndexEntry, 0, len(works))
	for _, summary := range works {
		entry := WorkIndexEntry{
			WorkID:     summary.WorkID,
			State:      summary.State,
			Origin:     summary.Origin,
			Plan:       summary.Plan,
			PlanExists: summary.PlanExists,
			Error:      summary.Error,
		}
		if !summary.PlanExists {
			entries = append(entries, entry)
			continue
		}
		report, err := CollectProjectStatus(filepath.Join(root, summary.Plan))
		if err != nil {
			return WorkIndexReport{}, err
		}
		reportPanorama := report.Panorama
		gates := report.GlobalGates
		entry.Panorama = &reportPanorama
		entry.GlobalGates = &gates
		entry.ContractVersion = report.ContractVersion
		entries = append(entries, entry)
	}
	return WorkIndexReport{Works: entries}, nil
}

var crossWorkDependency = regexp.MustCompile(`^(\d{4})/(\d+\.\d+)$`)

// crossWorkDependencyState devolve as dependências externas não concluídas.
func crossWorkDependencyState(root, workID, dependsOn string) ([]string, error) {
	if dependsOn == "" || dependsOn == "none" {
		return []string{}, nil
	}
	blockers := make([]string, 0)
	for _, raw := range strings.Split(dependsOn, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		match := crossWorkDependency.FindStringSubmatch(entry)
		if match == nil || match[1] == workID {
			continue
		}
		blocker, err := dependencyBlocked(root, match[1], match[2])
		if err != nil {
			// Manifest ausente ou plano ilegível é bloqueio observável, como no
			// `catch` da referência.
			blockers = append(blockers, entry)
			continue
		}
		if blocker {
			blockers = append(blockers, entry)
		}
	}
	return blockers, nil
}

// dependencyBlocked informa se a task dependente ainda não está aceita.
func dependencyBlocked(root, dependencyWorkID, dependencyTaskID string) (bool, error) {
	manifest, err := LoadManifest(root, dependencyWorkID)
	if err != nil {
		return true, err
	}
	report, err := CollectProjectStatus(filepath.Join(root, manifest.Artifacts.Plan))
	if err != nil {
		return true, err
	}
	for _, task := range report.Tasks {
		if task.ID != dependencyTaskID {
			continue
		}
		if task.Marker != "x" || task.Evidence.Stage != acceptedStage || task.Evidence.Stale {
			return true, nil
		}
		return false, nil
	}
	return true, nil
}

// CollectPlanStatus resolve o alvo e monta o relatório com bloqueios externos.
func CollectPlanStatus(target, root string) (PlanStatus, error) {
	if root == "" {
		root = "."
	}
	resolved, err := ResolvePlanTarget(root, target)
	if err != nil {
		return PlanStatus{}, err
	}
	report, err := CollectProjectStatus(resolved.Absolute)
	if err != nil {
		return PlanStatus{}, err
	}
	status := PlanStatus{ProjectStatus: report, CrossWorkBlockers: make(map[string][]string)}
	if resolved.WorkID == nil {
		return status, nil
	}
	for _, task := range report.Tasks {
		blockers, err := crossWorkDependencyState(root, *resolved.WorkID, task.DependsOn)
		if err != nil {
			return PlanStatus{}, err
		}
		if len(blockers) > 0 {
			status.CrossWorkBlockers[task.ID] = blockers
		}
	}
	return status, nil
}

// escapeCell neutraliza os separadores da célula de tabela.
func escapeCell(value string) string {
	value = strings.ReplaceAll(value, "|", `\|`)
	return strings.ReplaceAll(value, "\n", " ")
}

// RenderWorkIndex renderiza o índice de Works em markdown.
func RenderWorkIndex(report WorkIndexReport) string {
	lines := []string{
		"# Work index",
		"",
		"| Work | State | Plan | Progress | Panorama |",
		"|------|-------|------|----------|----------|",
	}
	for _, work := range report.Works {
		progress := "—"
		panorama := work.Error
		if panorama == "" {
			panorama = "no plan"
		}
		if work.Panorama != nil {
			progress = fmt.Sprintf("%d/%d", work.Panorama.Counts.Completed, work.Panorama.Counts.Total)
			panorama = work.Panorama.State
		}
		plan := work.Plan
		if plan == "" {
			plan = "—"
		}
		lines = append(lines, fmt.Sprintf("| `%s` | %s | `%s` | %s | %s |",
			work.WorkID, work.State, plan, progress, escapeCell(panorama)))
	}
	if len(report.Works) == 0 {
		lines = append(lines, "| — | — | — | — | No work artifacts found |")
	}
	return strings.Join(lines, "\n") + "\n"
}

// markerStatus descreve o marcador do heading.
func markerStatus(marker string) string {
	switch marker {
	case "x":
		return "[x] checked"
	case "!":
		return "[!] blocked"
	default:
		return "[ ] pending"
	}
}

// RenderMarkdown renderiza o relatório do plano em markdown.
func RenderMarkdown(report PlanStatus) string {
	contractVersion := "unknown"
	if report.ContractVersion != nil {
		contractVersion = "v" + strconv.Itoa(*report.ContractVersion)
	}
	migrated := ""
	if report.MigratedFromContractVersion != nil {
		migrated = fmt.Sprintf(" migrated from v%d", *report.MigratedFromContractVersion)
	}
	lines := []string{
		"# Project status",
		"",
		"## Pipeline artifacts",
		"",
		"| Artifact | Path | State | Detail |",
		"|----------|------|-------|--------|",
		fmt.Sprintf("| System spec | `%s` | %s | %s |", escapeCell(report.Artifacts.SystemSpec.Path), report.Artifacts.SystemSpec.State, escapeCell(report.Artifacts.SystemSpec.Detail)),
		fmt.Sprintf("| Change prompt | `%s` | %s | %s |", escapeCell(report.Artifacts.Prompt.Path), report.Artifacts.Prompt.State, escapeCell(report.Artifacts.Prompt.Detail)),
		fmt.Sprintf("| Task plan | `%s` | %s | %s |", escapeCell(report.Artifacts.Tasks.Path), report.Artifacts.Tasks.State, escapeCell(report.Artifacts.Tasks.Detail)),
		"",
		"## Panorama",
		"",
		"- **Project state:** " + report.Panorama.State,
		fmt.Sprintf("- **Progress:** %d/%d checked (%d%%)", report.Panorama.Counts.Completed, report.Panorama.Counts.Total, report.Panorama.Progress),
		fmt.Sprintf("- **Tasks:** %d pending | %d checked | %d blocked", report.Panorama.Counts.Pending, report.Panorama.Counts.Completed, report.Panorama.Counts.Blocked),
		fmt.Sprintf("- **Consistency:** %d checked without ACCEPTED evidence | %d ACCEPTED but open", report.Panorama.Counts.UnverifiedChecked, report.Panorama.Counts.VerifiedOpen),
		fmt.Sprintf("- **Task contract:** %s%s | %d compatibility warning(s) | %d preserved legacy exception(s)",
			contractVersion, migrated, report.Panorama.CompatibilityWarning, len(report.ValidationExceptions)),
		"- **Where it stopped:** " + escapeCell(report.Panorama.StoppedAt),
		"- **Global gates:** " + report.GlobalGates.State + " — " + escapeCell(report.GlobalGates.Detail),
		"",
		"## Tasks",
		"",
		"| ID | Status | Requirement | Depends on | Evidence | Task |",
		"|----|--------|-------------|------------|----------|------|",
	}
	if len(report.Tasks) == 0 {
		lines = append(lines, "| — | — | — | — | — | No tasks found |")
	}
	for _, task := range report.Tasks {
		evidence := task.Evidence.Stage
		if task.Evidence.Stale {
			evidence += " (STALE)"
		}
		if task.Evidence.Attestation != "" {
			evidence += " — " + task.Evidence.Attestation
		}
		lines = append(lines, fmt.Sprintf("| `%s` | %s | `%s` | %s | %s | %s |",
			task.ID, markerStatus(task.Marker), escapeCell(task.Requirement), escapeCell(task.DependsOn), escapeCell(evidence), escapeCell(task.Title)))
	}
	if len(report.CrossWorkBlockers) > 0 {
		lines = append(lines, "", "## Cross-work blockers", "")
		ids := make([]string, 0, len(report.CrossWorkBlockers))
		for id := range report.CrossWorkBlockers {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			rendered := make([]string, 0, len(report.CrossWorkBlockers[id]))
			for _, blocker := range report.CrossWorkBlockers[id] {
				rendered = append(rendered, "`"+blocker+"`")
			}
			lines = append(lines, fmt.Sprintf("- `%s`: %s", id, strings.Join(rendered, ", ")))
		}
	}
	if len(report.ValidationErrors) > 0 {
		lines = append(lines, "", "## Structural issues", "")
		for _, message := range report.ValidationErrors {
			lines = append(lines, "- "+message)
		}
	}
	if len(report.ValidationWarnings) > 0 {
		lines = append(lines, "", "## Compatibility warnings", "")
		for _, warning := range report.ValidationWarnings {
			lines = append(lines, "- "+warning)
		}
		lines = append(lines, "", "Migration is optional: use the loaded engineering-workflow validator with `--migrate` for preview and `--migrate --write` to apply.")
	}
	if len(report.ValidationExceptions) > 0 {
		lines = append(lines, "", "## Preserved legacy exceptions", "")
		for _, exception := range report.ValidationExceptions {
			lines = append(lines, "- "+exception)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
