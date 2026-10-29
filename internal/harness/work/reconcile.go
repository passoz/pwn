package work

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// ReconciliationFile é o nome do registro da conciliação dentro do Work.
const ReconciliationFile = "reconciliation.json"

// MaxImplementationFiles é o máximo de arquivos de implementação por task
// (limite de atomicidade do GATE-SPEC-PLAN).
const MaxImplementationFiles = 6

// governanceRoots são raízes da governança/dependências: nunca são "mudança não
// gerenciada".
var governanceRoots = map[string]bool{
	".git":          true,
	".pwn":          true,
	".todo":         true,
	".work":         true,
	".prompts":      true,
	".sources":      true,
	"queue":         true,
	".pwn-verifier": true,
	"node_modules":  true,
}

var testPathPattern = regexp.MustCompile(`(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py)$|(^|/)test_[^/]+\.py$`)

// ChangeStatus é o status git de uma mudança.
type ChangeStatus string

// Status possíveis de uma mudança.
const (
	ChangeAdded    ChangeStatus = "A"
	ChangeModified ChangeStatus = "M"
	ChangeDeleted  ChangeStatus = "D"
)

// ReconcileChange é um arquivo alterado fora do pwn.
type ReconcileChange struct {
	Path   string       `json:"path"`
	Status ChangeStatus `json:"status"`
	// SHA256 é nil para arquivo removido.
	SHA256 *string `json:"sha256"`
	Kind   string  `json:"kind"`
}

// ReconcileSkip é uma mudança ignorada com o motivo.
type ReconcileSkip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ReconcileOptions descreve a conciliação.
type ReconcileOptions struct {
	RootDir string
	// Since é a referência git de onde a mudança parte; vazia usa o HEAD.
	Since string
	// Paths restringe aos arquivos iguais ou abaixo destes prefixos.
	Paths []string
	// Tests são testes existentes que cobrem a mudança.
	Tests  []string
	Title  string
	WorkID string
	Risk   contract.RiskLevel
	Force  bool
	DryRun bool
}

// ReconcileTask é uma task derivada das mudanças.
type ReconcileTask struct {
	ID                  string   `json:"id"`
	ImplementationFiles []string `json:"implementationFiles"`
	TestFiles           []string `json:"testFiles"`
	// TestsToWrite é `true` quando a mudança não tem teste: TestFiles é o
	// caminho a escrever depois, sob o contrato.
	TestsToWrite bool `json:"testsToWrite"`
}

// PendingFreeze é uma task que ainda precisa congelar testes.
type PendingFreeze struct {
	Task   string `json:"task"`
	Reason string `json:"reason"`
}

// ReconcileResult é o resultado da conciliação.
type ReconcileResult struct {
	DryRun        bool              `json:"dryRun"`
	WorkID        *string           `json:"workId"`
	BaseCommit    string            `json:"baseCommit"`
	HeadCommit    string            `json:"headCommit"`
	Changes       []ReconcileChange `json:"changes"`
	Skipped       []ReconcileSkip   `json:"skipped"`
	Tasks         []ReconcileTask   `json:"tasks"`
	Generated     []string          `json:"generated"`
	Frozen        []string          `json:"frozen"`
	PendingFreeze []PendingFreeze   `json:"pendingFreeze"`
}

// ReconciliationFileEntry é uma linha de `files` no registro da conciliação.
type ReconciliationFileEntry struct {
	Path   string       `json:"path"`
	Status ChangeStatus `json:"status"`
	SHA256 *string      `json:"sha256"`
	Kind   string       `json:"kind"`
}

// Reconciliation é o registro persistido em reconciliation.json.
type Reconciliation struct {
	Version       int                       `json:"version"`
	WorkID        string                    `json:"work_id"`
	ReconciledAt  string                    `json:"reconciled_at"`
	BaseCommit    string                    `json:"base_commit"`
	HeadCommit    string                    `json:"head_commit"`
	Since         *string                   `json:"since"`
	Files         []ReconciliationFileEntry `json:"files"`
	DeclaredTests []string                  `json:"declared_tests"`
	Skipped       []ReconcileSkip           `json:"skipped"`
	Tasks         []ReconcileTask           `json:"tasks"`
	Note          string                    `json:"note"`
}

// Detected é a leitura das mudanças.
type Detected struct {
	BaseCommit string
	HeadCommit string
	Changes    []ReconcileChange
	Skipped    []ReconcileSkip
}

// runGit executa git e exige sucesso.
func runGit(ctx context.Context, rootDir string, args ...string) (string, error) {
	result, err := gitx.New(rootDir).Run(ctx, args, gitx.Options{})
	if err != nil {
		return "", err
	}
	if !result.OK() {
		detail := result.Stderr
		if detail == "" {
			detail = fmt.Sprintf("exit %d", result.Exit)
		}
		return "", fmt.Errorf("git %s falhou: %s", strings.Join(args, " "), detail)
	}
	return string(result.Stdout), nil
}

// gitSucceeds informa se o comando git terminou com sucesso.
func gitSucceeds(ctx context.Context, rootDir string, args ...string) bool {
	result, err := gitx.New(rootDir).Run(ctx, args, gitx.Options{})
	return err == nil && result.OK()
}

// normalizePrefix normaliza um prefixo de caminho para comparação POSIX.
func normalizePrefix(value string) string {
	normalized := path.Clean(strings.ReplaceAll(value, "\\", "/"))
	normalized = strings.TrimPrefix(normalized, "./")
	return strings.TrimRight(normalized, "/")
}

// reconciliationPath devolve o caminho do registro de conciliação.
func reconciliationPath(rootDir, workID string) string {
	return filepath.Join(GetWorkArtifactsPaths(workID, rootDir).WorkDir, ReconciliationFile)
}

// ReadReconciliation lê a conciliação registrada de um Work, ou nil quando o
// Work não nasceu de uma conciliação.
func ReadReconciliation(rootDir, workID string) *Reconciliation {
	file := reconciliationPath(rootDir, workID)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var record Reconciliation
	if err := unmarshalJSON(data, &record); err != nil {
		return nil
	}
	if record.Version != 1 || record.Files == nil {
		return nil
	}
	return &record
}

// alreadyReconciled mapeia caminho → conciliações anteriores, ignorando o Work
// informado.
func alreadyReconciled(rootDir, ignoreWorkID string) map[string][]struct {
	WorkID string
	SHA256 *string
} {
	known := make(map[string][]struct {
		WorkID string
		SHA256 *string
	})
	for _, workID := range GetExistingWorkIDs(rootDir) {
		if workID == ignoreWorkID {
			continue
		}
		record := ReadReconciliation(rootDir, workID)
		if record == nil {
			continue
		}
		for _, file := range record.Files {
			known[file.Path] = append(known[file.Path], struct {
				WorkID string
				SHA256 *string
			}{WorkID: workID, SHA256: file.SHA256})
		}
	}
	return known
}

// sha256Equal compara dois digests opcionais.
func sha256Equal(left, right *string) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	if left == nil {
		return true
	}
	return *left == *right
}

// DetectChanges lê o que mudou entre a referência e a árvore de trabalho
// (rastreados + novos não ignorados).
func DetectChanges(options ReconcileOptions) (Detected, error) {
	ctx := context.Background()
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	if !gitSucceeds(ctx, rootDir, "rev-parse", "--git-dir") {
		return Detected{}, fmt.Errorf("%s não é um repositório git", rootDir)
	}
	if !gitSucceeds(ctx, rootDir, "rev-parse", "--verify", "HEAD^{commit}") {
		return Detected{}, fmt.Errorf("o repositório não tem nenhum commit: conciliar exige um commit de referência")
	}
	headRaw, err := runGit(ctx, rootDir, "rev-parse", "HEAD")
	if err != nil {
		return Detected{}, err
	}
	headCommit := strings.TrimSpace(headRaw)

	baseCommit := headCommit
	if options.Since != "" {
		if !gitSucceeds(ctx, rootDir, "rev-parse", "--verify", options.Since+"^{commit}") {
			return Detected{}, fmt.Errorf("--since inválido: %s não é um commit", options.Since)
		}
		baseRaw, err := runGit(ctx, rootDir, "rev-parse", options.Since+"^{commit}")
		if err != nil {
			return Detected{}, err
		}
		baseCommit = strings.TrimSpace(baseRaw)
		isAncestor, err := gitx.New(rootDir).IsAncestor(ctx, baseCommit, headCommit)
		if err != nil {
			return Detected{}, err
		}
		if !isAncestor {
			return Detected{}, fmt.Errorf("--since %s não é ancestral do HEAD", options.Since)
		}
	}

	status := make(map[string]ChangeStatus)
	trackedRaw, err := runGit(ctx, rootDir, "diff", "--name-status", "--no-renames", "-z", baseCommit)
	if err != nil {
		return Detected{}, err
	}
	tracked := strings.Split(trackedRaw, "\x00")
	for index := 0; index+1 < len(tracked); index += 2 {
		code := tracked[index]
		if code == "" {
			continue
		}
		switch code[0] {
		case 'A':
			status[tracked[index+1]] = ChangeAdded
		case 'D':
			status[tracked[index+1]] = ChangeDeleted
		default:
			status[tracked[index+1]] = ChangeModified
		}
	}
	untracked, err := gitx.New(rootDir).LsFiles(ctx, gitx.LsFilesOptions{Others: true, ExcludeStandard: true})
	if err != nil {
		return Detected{}, err
	}
	for _, file := range untracked {
		status[file] = ChangeAdded
	}

	prefixes := make([]string, 0, len(options.Paths))
	for _, value := range options.Paths {
		prefixes = append(prefixes, normalizePrefix(value))
	}
	known := alreadyReconciled(rootDir, options.WorkID)
	paths := make([]string, 0, len(status))
	for file := range status {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	changes := make([]ReconcileChange, 0)
	skipped := make([]ReconcileSkip, 0)

	for _, file := range paths {
		changeStatus := status[file]
		firstSegment := strings.SplitN(file, "/", 2)[0]
		if governanceRoots[firstSegment] {
			continue
		}
		if len(prefixes) > 0 {
			matched := false
			for _, prefix := range prefixes {
				if file == prefix || strings.HasPrefix(file, prefix+"/") {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if strings.HasPrefix(path.Base(file), ".env") {
			skipped = append(skipped, ReconcileSkip{Path: file, Reason: "segredo (.env*): nunca é conciliado"})
			continue
		}
		if reason := plan.PlaceholderPathReason(file); reason != "" {
			skipped = append(skipped, ReconcileSkip{Path: file, Reason: fmt.Sprintf("caminho %s: o plano só declara arquivos concretos", reason)})
			continue
		}
		absolute := filepath.Join(rootDir, file)
		if changeStatus != ChangeDeleted {
			info, err := os.Stat(absolute)
			if err != nil || !info.Mode().IsRegular() {
				skipped = append(skipped, ReconcileSkip{Path: file, Reason: "não é um arquivo regular"})
				continue
			}
		}
		var sha *string
		if changeStatus != ChangeDeleted {
			data, err := os.ReadFile(absolute)
			if err != nil {
				return Detected{}, fmt.Errorf("work: ler %s: %w", file, err)
			}
			digest := jsonx.SHA256Hex(data)
			sha = &digest
		}
		reconciled := false
		for _, previous := range known[file] {
			if sha256Equal(previous.SHA256, sha) {
				skipped = append(skipped, ReconcileSkip{Path: file, Reason: "já conciliado no Work " + previous.WorkID})
				reconciled = true
				break
			}
		}
		if reconciled {
			continue
		}
		kind := "implementation"
		if testPathPattern.MatchString(file) {
			kind = "test"
		}
		changes = append(changes, ReconcileChange{Path: file, Status: changeStatus, SHA256: sha, Kind: kind})
	}
	return Detected{BaseCommit: baseCommit, HeadCommit: headCommit, Changes: changes, Skipped: skipped}, nil
}

// chunk divide values em grupos de tamanho fixo.
func chunk(values []string, size int) [][]string {
	groups := make([][]string, 0)
	for index := 0; index < len(values); index += size {
		end := index + size
		if end > len(values) {
			end = len(values)
		}
		groups = append(groups, values[index:end])
	}
	return groups
}

// uniqueSorted devolve os valores únicos em ordem.
func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// ReconcileChanges concilia as mudanças feitas fora do pwn: descobre o que
// mudou, cria o Work com contrato por task no escopo EXATO dos arquivos e grava
// reconciliation.json com o commit de referência. Não toca em arquivo do
// projeto além dos artefatos do pwn.
func ReconcileChanges(options ReconcileOptions) (ReconcileResult, error) {
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	risk := options.Risk
	if risk == "" {
		risk = contract.RiskL2
	}
	detected, err := DetectChanges(options)
	if err != nil {
		return ReconcileResult{}, err
	}
	baseCommit, headCommit, skipped := detected.BaseCommit, detected.HeadCommit, detected.Skipped
	changes := detected.Changes
	if len(changes) == 0 {
		if len(skipped) > 0 {
			reasons := make([]string, 0, len(skipped))
			for _, entry := range skipped {
				reasons = append(reasons, entry.Path+": "+entry.Reason)
			}
			return ReconcileResult{}, fmt.Errorf("nada a conciliar: todas as mudanças foram ignoradas (%s)", strings.Join(reasons, "; "))
		}
		return ReconcileResult{}, fmt.Errorf("nada a conciliar: nenhuma mudança fora da governança desde a referência")
	}

	implementation := make([]ReconcileChange, 0, len(changes))
	for _, change := range changes {
		if change.Kind == "implementation" {
			implementation = append(implementation, change)
		}
	}
	if len(implementation) == 0 {
		return ReconcileResult{}, fmt.Errorf("só há arquivos de teste alterados: não há implementação a conciliar (testes entram como cobertura da implementação)")
	}

	declared := make([]string, 0, len(options.Tests))
	for _, test := range options.Tests {
		declared = append(declared, normalizePrefix(test))
	}
	declared = unique(declared)
	for _, test := range declared {
		if reason := plan.PlaceholderPathReason(test); reason != "" {
			return ReconcileResult{}, fmt.Errorf("--tests %s %s", test, reason)
		}
		absolute := filepath.Join(rootDir, test)
		info, err := os.Stat(absolute)
		if err != nil || !info.Mode().IsRegular() {
			return ReconcileResult{}, fmt.Errorf("--tests %s não existe", test)
		}
	}
	testCandidates := make([]string, 0)
	for _, change := range changes {
		if change.Kind == "test" && change.Status != ChangeDeleted {
			testCandidates = append(testCandidates, change.Path)
		}
	}
	testCandidates = append(testCandidates, declared...)
	testFiles := uniqueSorted(testCandidates)

	title := options.Title
	if title == "" {
		title = fmt.Sprintf("Conciliação de %d arquivo(s) alterado(s) fora do pwn desde %s", len(changes), shortCommit(baseCommit))
	}
	implementationPaths := make([]string, 0, len(implementation))
	for _, change := range implementation {
		implementationPaths = append(implementationPaths, change.Path)
	}
	groups := chunk(implementationPaths, MaxImplementationFiles)
	denied := []string{".git/**", ".env*"}
	hasPackageJSON := false
	for _, change := range changes {
		if change.Path == "package.json" {
			hasPackageJSON = true
			break
		}
	}
	if !hasPackageJSON {
		denied = append(denied, "package.json")
	}

	// Sem teste algum, cada task declara o arquivo de teste a escrever depois, sob
	// o contrato (a write_allow já o autoriza). Nunca reaproveita um caminho que
	// já existe nem cria o arquivo.
	testsToWrite := len(testFiles) == 0
	reserved := make(map[string]bool, len(changes))
	for _, change := range changes {
		reserved[change.Path] = true
	}
	skeletonFor := func(files []string) (string, error) {
		stem := strings.ToLower(strings.TrimSuffix(filepath.Base(files[0]), filepath.Ext(files[0])))
		stem = strings.Trim(collapseDashes(strings.Map(func(character rune) rune {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				return character
			}
			return '-'
		}, stem)), "-")
		if stem == "" {
			stem = "task"
		}
		for attempt := 1; ; attempt++ {
			suffix := ""
			switch {
			case attempt == 2:
				suffix = "-reconcile"
			case attempt > 2:
				suffix = fmt.Sprintf("-reconcile-%d", attempt-1)
			}
			candidate := "tests/" + stem + suffix + ".test.ts"
			if reserved[candidate] {
				continue
			}
			if _, err := os.Stat(filepath.Join(rootDir, candidate)); err == nil {
				continue
			} else if !os.IsNotExist(err) {
				return "", fmt.Errorf("work: inspecionar %s: %w", candidate, err)
			}
			reserved[candidate] = true
			return candidate, nil
		}
	}

	specs := make([]ScaffoldTaskSpec, 0, len(groups))
	tasks := make([]ReconcileTask, 0, len(groups))
	for index, files := range groups {
		tests := testFiles
		if testsToWrite {
			skeleton, err := skeletonFor(files)
			if err != nil {
				return ReconcileResult{}, err
			}
			tests = []string{skeleton}
		}
		taskTitle := title
		if len(groups) > 1 {
			taskTitle = fmt.Sprintf("%s — parte %d/%d", title, index+1, len(groups))
		}
		specs = append(specs, ScaffoldTaskSpec{
			Title:               taskTitle,
			ImplementationFiles: files,
			TestFiles:           tests,
			Behavior:            fmt.Sprintf("registra e aceita a mudança feita fora do pwn em %d arquivo(s) de implementação", len(files)),
			WriteAllow:          append(append([]string{}, files...), tests...),
			WriteDeny:           denied,
		})
		tasks = append(tasks, ReconcileTask{
			ID:                  fmt.Sprintf("1.%d", index+1),
			ImplementationFiles: files,
			TestFiles:           tests,
			TestsToWrite:        testsToWrite,
		})
	}

	if options.DryRun {
		return ReconcileResult{
			DryRun:        true,
			Changes:       changes,
			Skipped:       nonNilSkippedReconcile(skipped),
			Tasks:         tasks,
			Generated:     []string{},
			Frozen:        []string{},
			PendingFreeze: []PendingFreeze{},
			BaseCommit:    baseCommit,
			HeadCommit:    headCommit,
		}, nil
	}

	if options.WorkID != "" && !options.Force {
		if _, err := os.Stat(GetWorkArtifactsPaths(options.WorkID, rootDir).WorkDir); err == nil {
			return ReconcileResult{}, fmt.Errorf("Work %s já existe (use --force para sobrescrever)", options.WorkID)
		}
	}

	scaffold, err := ScaffoldWork(ScaffoldOptions{
		RootDir: rootDir,
		Title:   title,
		WorkID:  options.WorkID,
		Risk:    risk,
		Force:   options.Force,
		Tasks:   specs,
		Narrative: &ScaffoldNarrative{
			Problem:   fmt.Sprintf("%d arquivo(s) foram alterados fora do pwn desde o commit %s e precisam entrar na governança com escopo e aceitação verificáveis.", len(changes), shortCommit(baseCommit)),
			Solution:  "Conciliar as mudanças em um Work cujo contrato V4 restringe a escrita aos arquivos alterados e cuja aceitação é o recibo independente sobre o teste congelado.",
			Objective: "Conciliar na governança a mudança feita fora do pwn sem alterar nenhum arquivo do projeto",
			Scenario:  "brownfield",
			Author:    "pwn-reconcile",
		},
	})
	if err != nil {
		return ReconcileResult{}, err
	}
	workID := scaffold.WorkID
	generated := append([]string{}, scaffold.Generated...)

	recordFiles := make([]ReconciliationFileEntry, 0, len(changes))
	for _, change := range changes {
		recordFiles = append(recordFiles, ReconciliationFileEntry{Path: change.Path, Status: change.Status, SHA256: change.SHA256, Kind: change.Kind})
	}
	var since *string
	if options.Since != "" {
		value := options.Since
		since = &value
	}
	record := Reconciliation{
		Version:       1,
		WorkID:        workID,
		ReconciledAt:  nowISO(),
		BaseCommit:    baseCommit,
		HeadCommit:    headCommit,
		Since:         since,
		Files:         recordFiles,
		DeclaredTests: declared,
		Skipped:       nonNilSkippedReconcile(skipped),
		Tasks:         tasks,
		Note:          "Conciliação pós-fato: sem RED/GREEN observado. A aceitação vem de `pwn verify` com a implementação revertida a base_commit.",
	}
	recordPath := reconciliationPath(rootDir, workID)
	if err := writeJSON(recordPath, record); err != nil {
		return ReconcileResult{}, err
	}
	relativeRecord, err := filepath.Rel(rootDir, recordPath)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("work: resolver %s: %w", recordPath, err)
	}
	generated = append(generated, normalizeWorkPath(relativeRecord))

	frozen := make([]string, 0)
	pendingFreeze := make([]PendingFreeze, 0)
	for _, task := range tasks {
		if task.TestsToWrite {
			pendingFreeze = append(pendingFreeze, PendingFreeze{
				Task:   task.ID,
				Reason: fmt.Sprintf("teste a escrever: %s ainda não existe", strings.Join(task.TestFiles, ", ")),
			})
			continue
		}
		_, err := plan.FreezeAcceptanceTests(context.Background(), plan.FreezeOptions{
			WorkID:  workID,
			TaskID:  task.ID,
			Paths:   task.TestFiles,
			RootDir: rootDir,
		})
		if err != nil {
			pendingFreeze = append(pendingFreeze, PendingFreeze{Task: task.ID, Reason: err.Error()})
			continue
		}
		frozen = append(frozen, task.ID)
	}

	resultWorkID := workID
	return ReconcileResult{
		DryRun:        false,
		WorkID:        &resultWorkID,
		BaseCommit:    baseCommit,
		HeadCommit:    headCommit,
		Changes:       changes,
		Skipped:       nonNilSkippedReconcile(skipped),
		Tasks:         tasks,
		Generated:     nonNil(generated),
		Frozen:        frozen,
		PendingFreeze: pendingFreeze,
	}, nil
}

// shortCommit devolve os sete primeiros caracteres do commit.
func shortCommit(commit string) string {
	if len(commit) <= 7 {
		return commit
	}
	return commit[:7]
}

// nonNilSkippedReconcile devolve a lista de ignorados sem nil.
func nonNilSkippedReconcile(values []ReconcileSkip) []ReconcileSkip {
	if values == nil {
		return []ReconcileSkip{}
	}
	return values
}
