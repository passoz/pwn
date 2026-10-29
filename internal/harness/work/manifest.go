package work

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/platform/fsx"
)

// WorkManifestVersion é a versão do manifest v3 suportada.
const WorkManifestVersion = 1

// WorkIDPattern exige quatro dígitos.
var WorkIDPattern = regexp.MustCompile(`^\d{4}$`)

// NumberedPlanPattern reconhece `.todo/<NNNN>-tasks.md`.
var NumberedPlanPattern = regexp.MustCompile(`^(\d{4})-tasks\.md$`)

// artifactPatterns são as trilhas que compartilham o espaço de Work IDs.
var artifactPatterns = []struct {
	directory string
	pattern   *regexp.Regexp
}{
	{".work", regexp.MustCompile(`^(\d{4})\.json$`)},
	{".sources", regexp.MustCompile(`^(\d{4})-.+\.md$`)},
	{".prompts", regexp.MustCompile(`^(\d{4})-change\.md$`)},
	{".todo", NumberedPlanPattern},
}

// WorkManifestState é um estado do vocabulário canônico do manifest.
type WorkManifestState string

// Vocabulário canônico do manifest. `manifest-sync` projeta o panorama do
// plano exatamente neste conjunto.
const (
	StateSourcePending WorkManifestState = "source_pending"
	StatePromptPending WorkManifestState = "prompt_pending"
	StatePlanPending   WorkManifestState = "plan_pending"
	StatePlanned       WorkManifestState = "planned"
	StateActive        WorkManifestState = "active"
	StateBlocked       WorkManifestState = "blocked"
	StateCompleted     WorkManifestState = "completed"
	StateAbandoned     WorkManifestState = "abandoned"
	StateInvalid       WorkManifestState = "invalid"
)

// WorkManifestStates é a lista ordenada dos estados válidos.
var WorkManifestStates = []WorkManifestState{
	StateSourcePending,
	StatePromptPending,
	StatePlanPending,
	StatePlanned,
	StateActive,
	StateBlocked,
	StateCompleted,
	StateAbandoned,
	StateInvalid,
}

var workManifestStateSet = func() map[WorkManifestState]bool {
	set := make(map[WorkManifestState]bool, len(WorkManifestStates))
	for _, state := range WorkManifestStates {
		set[state] = true
	}
	return set
}()

// IsWorkManifestState informa se value pertence ao vocabulário canônico.
func IsWorkManifestState(value string) bool {
	return workManifestStateSet[WorkManifestState(value)]
}

// WorkManifestOrigin descreve como o Work nasceu.
type WorkManifestOrigin struct {
	Type      string  `json:"type"`
	Reference *string `json:"reference"`
}

// WorkManifestArtifacts são os caminhos declarados no manifest.
type WorkManifestArtifacts struct {
	Manifest     string `json:"manifest"`
	Source       string `json:"source"`
	Prompt       string `json:"prompt"`
	Plan         string `json:"plan"`
	Evidence     string `json:"evidence"`
	Diagnostics  string `json:"diagnostics"`
	Screenshots  string `json:"screenshots"`
	Attestations string `json:"attestations"`
}

// WorkManifest é o manifest v3 de um Work.
type WorkManifest struct {
	Version   int                   `json:"version"`
	WorkID    string                `json:"work_id"`
	State     WorkManifestState     `json:"state"`
	Origin    WorkManifestOrigin    `json:"origin"`
	Artifacts WorkManifestArtifacts `json:"artifacts"`
	CreatedAt string                `json:"created_at"`
	UpdatedAt string                `json:"updated_at"`
}

// ReserveWorkOptions descreve a reserva de um Work ID.
type ReserveWorkOptions struct {
	WorkID          string
	OriginType      string
	OriginReference *string
	SourcePath      string
}

// WorkSummary é a linha de `pwn work list`.
type WorkSummary struct {
	WorkID     string              `json:"work_id"`
	State      string              `json:"state"`
	Origin     *WorkManifestOrigin `json:"origin,omitempty"`
	Plan       string              `json:"plan,omitempty"`
	PlanExists bool                `json:"plan_exists,omitempty"`
	Error      string              `json:"error,omitempty"`
}

// MigrationMove é um movimento da migração do layout legado.
type MigrationMove struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// LegacyMigration descreve a prévia ou o resultado da migração do plano legado.
type LegacyMigration struct {
	WorkID  string          `json:"work_id"`
	Moves   []MigrationMove `json:"moves"`
	Created string          `json:"manifest,omitempty"`
}

// PlanTarget é o alvo resolvido de um plano.
type PlanTarget struct {
	Root     string  `json:"root"`
	Target   *string `json:"target,omitempty"`
	WorkID   *string `json:"work_id,omitempty"`
	Legacy   bool    `json:"legacy"`
	Relative string  `json:"relative"`
	Absolute string  `json:"absolute"`
}

// assertRepositoryPath garante que candidate não escapa de root.
func assertRepositoryPath(root, candidate string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(filepath.Join(absoluteRoot, candidate))
	if err != nil {
		return "", err
	}
	if absolute != absoluteRoot && !strings.HasPrefix(absolute, absoluteRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root: %s", candidate)
	}
	return absolute, nil
}

// listIDs devolve todos os Work IDs conhecidos, em qualquer trilha.
func listIDs(root string) []string {
	root, err := filepath.Abs(root)
	if err != nil {
		return []string{}
	}
	seen := make(map[string]bool)
	for _, track := range artifactPatterns {
		directory := filepath.Join(root, track.directory)
		entries, err := os.ReadDir(directory)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			match := track.pattern.FindStringSubmatch(entry.Name())
			if match != nil {
				seen[match[1]] = true
			}
		}
	}
	// `.pwn/work/<NNNN>/` compartilha o espaço de IDs: um Work inicializado pela
	// CLI não pode ser reatribuído pela trilha do manifest, e vice-versa.
	workRoot := filepath.Join(root, workIDDirectory)
	if entries, err := os.ReadDir(workRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !WorkIDPattern.MatchString(entry.Name()) {
				continue
			}
			children, err := os.ReadDir(filepath.Join(workRoot, entry.Name()))
			if err != nil || len(children) == 0 {
				continue
			}
			seen[entry.Name()] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// nextID devolve o próximo Work ID livre.
func nextID(root string) (string, error) {
	ids := listIDs(root)
	highest := 0
	if len(ids) > 0 {
		// Um ID não numérico não desloca a numeração; `listIDs` só devolve as
		// formas de quatro dígitos, então o erro é impossível por construção.
		number, err := strconv.Atoi(ids[len(ids)-1])
		if err != nil {
			return "", fmt.Errorf("work: Work ID não numérico na trilha: %s", ids[len(ids)-1])
		}
		highest = number
	}
	if highest >= 9999 {
		return "", fmt.Errorf("work ID space exhausted at 9999")
	}
	return padWorkID(highest + 1), nil
}

// ManifestPath devolve o caminho relativo do manifest do Work.
func ManifestPath(workID string) (string, error) {
	if !WorkIDPattern.MatchString(workID) {
		return "", fmt.Errorf("invalid Work ID: %s; expected four digits", workID)
	}
	return filepath.Join(".work", workID+".json"), nil
}

// CanonicalArtifacts devolve os caminhos canônicos do Work.
func CanonicalArtifacts(workID, sourceKind string) (WorkManifestArtifacts, error) {
	if !WorkIDPattern.MatchString(workID) {
		return WorkManifestArtifacts{}, fmt.Errorf("invalid Work ID: %s; expected four digits", workID)
	}
	safeKind := sanitizeSourceKind(sourceKind)
	return WorkManifestArtifacts{
		Manifest:     filepath.Join(".work", workID+".json"),
		Source:       filepath.Join(".sources", workID+"-"+safeKind+".md"),
		Prompt:       filepath.Join(".prompts", workID+"-change.md"),
		Plan:         filepath.Join(".todo", workID+"-tasks.md"),
		Evidence:     filepath.Join(".todo", "evidence", workID),
		Diagnostics:  filepath.Join(".todo", "diagnostics", workID),
		Screenshots:  filepath.Join(".todo", "screenshots", workID),
		Attestations: filepath.Join(".todo", "attestations", workID),
	}, nil
}

var sourceKindUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeSourceKind reproduz o slug do TypeScript.
func sanitizeSourceKind(value string) string {
	slug := sourceKindUnsafe.ReplaceAllString(strings.ToLower(value), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "request"
	}
	return slug
}

// LoadManifest lê e valida o manifest do Work.
//
// Um estado fora do vocabulário atual (por exemplo o antigo `in_progress`) é
// exposto como `invalid` em vez de ser aceito.
func LoadManifest(root, workID string) (WorkManifest, error) {
	relative, err := ManifestPath(workID)
	if err != nil {
		return WorkManifest{}, err
	}
	absolute, err := assertRepositoryPath(root, relative)
	if err != nil {
		return WorkManifest{}, err
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return WorkManifest{}, fmt.Errorf("work manifest not found: %s", normalizeWorkPath(relative))
	}
	var manifest WorkManifest
	if err := unmarshalJSON(data, &manifest); err != nil {
		return WorkManifest{}, fmt.Errorf("work: ler %s: %w", normalizeWorkPath(relative), err)
	}
	if manifest.Version != WorkManifestVersion {
		return WorkManifest{}, fmt.Errorf("unsupported work manifest version: %d", manifest.Version)
	}
	if manifest.WorkID != workID {
		return WorkManifest{}, fmt.Errorf("manifest Work ID mismatch: expected %s, found %s", workID, manifest.WorkID)
	}
	if !IsWorkManifestState(string(manifest.State)) {
		manifest.State = StateInvalid
	}
	return manifest, nil
}

// ReserveWork reserva um Work ID e grava o manifest.
func ReserveWork(root string, options ReserveWorkOptions) (WorkManifest, error) {
	if root == "" {
		root = "."
	}
	repositoryRoot, err := filepath.Abs(root)
	if err != nil {
		return WorkManifest{}, err
	}
	requested := options.WorkID
	if requested != "" && !WorkIDPattern.MatchString(requested) {
		return WorkManifest{}, fmt.Errorf("invalid Work ID: %s; expected four digits", requested)
	}
	// O tipo de origem padrão é `local` e o nome do snapshot usa `request`,
	// como no `reserveWork` de referência.
	manifestOriginType := options.OriginType
	if manifestOriginType == "" {
		manifestOriginType = "local"
	}
	sourceKind := options.OriginType
	if sourceKind == "" {
		sourceKind = "request"
	}

	for {
		workID := requested
		if workID == "" {
			workID, err = nextID(repositoryRoot)
			if err != nil {
				return WorkManifest{}, err
			}
		}
		artifacts, err := CanonicalArtifacts(workID, sourceKind)
		if err != nil {
			return WorkManifest{}, err
		}
		absoluteManifest, err := assertRepositoryPath(repositoryRoot, artifacts.Manifest)
		if err != nil {
			return WorkManifest{}, err
		}
		if err := os.MkdirAll(filepath.Dir(absoluteManifest), 0o755); err != nil {
			return WorkManifest{}, fmt.Errorf("work: criar diretório do manifest: %w", err)
		}
		descriptor, err := os.OpenFile(absoluteManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsExist(err) {
				if requested == "" {
					continue
				}
				return WorkManifest{}, fmt.Errorf("Work ID already reserved: %s", workID)
			}
			return WorkManifest{}, fmt.Errorf("work: reservar manifest: %w", err)
		}
		now := nowISO()
		manifest := WorkManifest{
			Version: WorkManifestVersion,
			WorkID:  workID,
			State:   StateSourcePending,
			Origin: WorkManifestOrigin{
				Type:      manifestOriginType,
				Reference: options.OriginReference,
			},
			Artifacts: artifacts,
			CreatedAt: now,
			UpdatedAt: now,
		}
		content, err := marshalDocument(manifest)
		if err != nil {
			_ = descriptor.Close()
			return WorkManifest{}, err
		}
		if _, err := descriptor.WriteString(content); err != nil {
			_ = descriptor.Close()
			return WorkManifest{}, fmt.Errorf("work: gravar manifest: %w", err)
		}
		if err := descriptor.Close(); err != nil {
			return WorkManifest{}, fmt.Errorf("work: fechar manifest: %w", err)
		}

		if options.SourcePath != "" {
			sourceAbsolute, err := assertRepositoryPath(repositoryRoot, options.SourcePath)
			if err != nil {
				return WorkManifest{}, err
			}
			info, err := os.Stat(sourceAbsolute)
			if err != nil || info.IsDir() {
				return WorkManifest{}, fmt.Errorf("source file not found: %s", options.SourcePath)
			}
			snapshotAbsolute, err := assertRepositoryPath(repositoryRoot, artifacts.Source)
			if err != nil {
				return WorkManifest{}, err
			}
			if err := os.MkdirAll(filepath.Dir(snapshotAbsolute), 0o755); err != nil {
				return WorkManifest{}, fmt.Errorf("work: criar diretório do snapshot: %w", err)
			}
			if _, err := os.Stat(snapshotAbsolute); err == nil {
				return WorkManifest{}, fmt.Errorf("source snapshot already exists: %s", normalizeWorkPath(artifacts.Source))
			}
			data, err := os.ReadFile(sourceAbsolute)
			if err != nil {
				return WorkManifest{}, fmt.Errorf("work: ler fonte %s: %w", options.SourcePath, err)
			}
			if err := writeFileAtomic(snapshotAbsolute, string(data)); err != nil {
				return WorkManifest{}, err
			}
			if _, err := UpdateManifest(repositoryRoot, workID, ManifestChanges{State: new(StatePromptPending)}); err != nil {
				return WorkManifest{}, err
			}
		}
		return LoadManifest(repositoryRoot, workID)
	}
}

// ManifestChanges são as mudanças aceitas por UpdateManifest.
type ManifestChanges struct {
	State     *WorkManifestState
	Artifacts *WorkManifestArtifacts
	Origin    *WorkManifestOrigin
}

// UpdateManifest lê-modifica-grava o manifest sob trava.
func UpdateManifest(root, workID string, changes ManifestChanges) (WorkManifest, error) {
	repositoryRoot, err := filepath.Abs(root)
	if err != nil {
		return WorkManifest{}, err
	}
	relative, err := ManifestPath(workID)
	if err != nil {
		return WorkManifest{}, err
	}
	absolute, err := assertRepositoryPath(repositoryRoot, relative)
	if err != nil {
		return WorkManifest{}, err
	}
	var updated WorkManifest
	err = fsx.WithFileLock(absolute, func() error {
		manifest, err := LoadManifest(repositoryRoot, workID)
		if err != nil {
			return err
		}
		if changes.State != nil {
			if !IsWorkManifestState(string(*changes.State)) {
				return fmt.Errorf("invalid work state: %s", *changes.State)
			}
			manifest.State = *changes.State
		}
		if changes.Artifacts != nil {
			manifest.Artifacts = *changes.Artifacts
		}
		if changes.Origin != nil {
			manifest.Origin = *changes.Origin
		}
		manifest.UpdatedAt = nowISO()
		content, err := marshalDocument(manifest)
		if err != nil {
			return err
		}
		if err := fsx.WriteFileAtomic(absolute, content); err != nil {
			return err
		}
		// O rename troca o inode: restaura o 0600 da reserva.
		if err := os.Chmod(absolute, 0o600); err != nil {
			return fmt.Errorf("work: restaurar modo do manifest: %w", err)
		}
		updated = manifest
		return nil
	}, fsx.LockOptions{})
	if err != nil {
		return WorkManifest{}, err
	}
	return updated, nil
}

// ResolvePlanTarget resolve `NNNN`, um caminho canônico de plano ou `legacy`.
func ResolvePlanTarget(root, target string) (PlanTarget, error) {
	if root == "" {
		root = "."
	}
	repositoryRoot, err := filepath.Abs(root)
	if err != nil {
		return PlanTarget{}, err
	}
	if target == "" {
		return PlanTarget{}, fmt.Errorf("explicit plan target required; use NNNN, a canonical plan path, or legacy")
	}
	var relative string
	var workID string
	legacy := false
	switch {
	case target == "legacy":
		relative = filepath.Join(".todo", "tasks.md")
		legacy = true
	case WorkIDPattern.MatchString(target):
		workID = target
		relative = filepath.Join(".todo", target+"-tasks.md")
	case regexp.MustCompile(`^\d+$`).MatchString(target):
		return PlanTarget{}, fmt.Errorf("invalid Work ID: %s; preserve four digits", target)
	default:
		absoluteTarget, err := assertRepositoryPath(repositoryRoot, target)
		if err != nil {
			return PlanTarget{}, err
		}
		relative, err = filepath.Rel(repositoryRoot, absoluteTarget)
		if err != nil {
			return PlanTarget{}, err
		}
		match := NumberedPlanPattern.FindStringSubmatch(filepath.Base(relative))
		if match != nil && filepath.Dir(relative) == ".todo" {
			workID = match[1]
		} else if relative == filepath.Join(".todo", "tasks.md") {
			legacy = true
		} else {
			return PlanTarget{}, fmt.Errorf("not a canonical plan target: %s", target)
		}
	}
	absolute, err := assertRepositoryPath(repositoryRoot, relative)
	if err != nil {
		return PlanTarget{}, err
	}
	if _, err := os.Stat(absolute); err != nil {
		return PlanTarget{}, fmt.Errorf("plan not found: %s", normalizeWorkPath(relative))
	}
	if !legacy {
		if workID == "" {
			return PlanTarget{}, fmt.Errorf("canonical plan target requires a Work ID: %s", target)
		}
		// O manifest v3 é opcional no layout canônico. Quando existe, o plano
		// declarado nele precisa concordar com o alvo.
		manifestRelative, err := ManifestPath(workID)
		if err != nil {
			return PlanTarget{}, err
		}
		manifestAbsolute, err := assertRepositoryPath(repositoryRoot, manifestRelative)
		if err != nil {
			return PlanTarget{}, err
		}
		if _, err := os.Stat(manifestAbsolute); err == nil {
			manifest, err := LoadManifest(repositoryRoot, workID)
			if err != nil {
				return PlanTarget{}, err
			}
			if manifest.Artifacts.Plan != filepath.FromSlash(normalizeWorkPath(relative)) {
				return PlanTarget{}, fmt.Errorf("manifest plan mismatch for Work ID %s: %s", workID, manifest.Artifacts.Plan)
			}
		}
	}
	targetCopy := target
	result := PlanTarget{
		Root:     repositoryRoot,
		Target:   &targetCopy,
		Legacy:   legacy,
		Relative: relative,
		Absolute: absolute,
	}
	if workID != "" {
		result.WorkID = &workID
	}
	return result, nil
}

// ListWorkIDs devolve todos os Work IDs conhecidos, ordenados.
func ListWorkIDs(root string) []string {
	if root == "" {
		root = "."
	}
	return listIDs(root)
}

// ListWorks devolve o resumo de cada Work conhecido.
func ListWorks(root string) ([]WorkSummary, error) {
	if root == "" {
		root = "."
	}
	repositoryRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	works := make([]WorkSummary, 0)
	for _, workID := range listIDs(repositoryRoot) {
		relative, err := ManifestPath(workID)
		if err != nil {
			works = append(works, WorkSummary{WorkID: workID, State: "invalid", Error: err.Error()})
			continue
		}
		manifestFile := filepath.Join(repositoryRoot, relative)
		if _, err := os.Stat(manifestFile); err != nil {
			// Sem manifest v3, o Work só existe se nasceu pelo layout canônico.
			canonicalDirectory := filepath.Join(repositoryRoot, workIDDirectory, workID)
			if _, err := os.Stat(canonicalDirectory); err != nil {
				works = append(works, WorkSummary{
					WorkID: workID,
					State:  "invalid",
					Error:  "missing " + normalizeWorkPath(relative),
				})
				continue
			}
			plan := filepath.Join(".todo", workID+"-tasks.md")
			_, planErr := os.Stat(filepath.Join(repositoryRoot, plan))
			planExists := planErr == nil
			summary := WorkSummary{WorkID: workID, State: "plan_pending", Plan: plan, PlanExists: planExists}
			if planExists {
				summary.State = "planned"
			}
			works = append(works, summary)
			continue
		}
		manifest, err := LoadManifest(repositoryRoot, workID)
		if err != nil {
			works = append(works, WorkSummary{WorkID: workID, State: "invalid", Error: err.Error()})
			continue
		}
		_, planErr := os.Stat(filepath.Join(repositoryRoot, manifest.Artifacts.Plan))
		origin := manifest.Origin
		works = append(works, WorkSummary{
			WorkID:     workID,
			State:      string(manifest.State),
			Origin:     &origin,
			Plan:       manifest.Artifacts.Plan,
			PlanExists: planErr == nil,
		})
	}
	legacyPlan := filepath.Join(repositoryRoot, ".todo", "tasks.md")
	if _, err := os.Stat(legacyPlan); err == nil {
		works = append(works, WorkSummary{
			WorkID:     "legacy",
			State:      "legacy",
			Plan:       filepath.Join(".todo", "tasks.md"),
			PlanExists: true,
		})
	}
	return works, nil
}

// migrationMoves calcula os movimentos do layout legado.
func migrationMoves(root, workID string) ([]MigrationMove, error) {
	moves := make([]MigrationMove, 0)
	if _, err := os.Stat(filepath.Join(root, ".todo", "tasks.md")); err == nil {
		moves = append(moves, MigrationMove{From: filepath.Join(".todo", "tasks.md"), To: filepath.Join(".todo", workID+"-tasks.md")})
	}
	for _, directory := range []string{"evidence", "diagnostics", "screenshots"} {
		base := filepath.Join(root, ".todo", directory)
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Name() == workID || WorkIDPattern.MatchString(entry.Name()) {
				continue
			}
			moves = append(moves, MigrationMove{
				From: filepath.Join(".todo", directory, entry.Name()),
				To:   filepath.Join(".todo", directory, workID, entry.Name()),
			})
		}
	}
	for _, move := range moves {
		if _, err := os.Stat(filepath.Join(root, move.To)); err == nil {
			return nil, fmt.Errorf("legacy migration destination already exists: %s", normalizeWorkPath(move.To))
		}
	}
	return moves, nil
}

// PreviewLegacyMigration descreve a migração do plano legado sem escrever.
func PreviewLegacyMigration(root string) (LegacyMigration, error) {
	if root == "" {
		root = "."
	}
	repositoryRoot, err := filepath.Abs(root)
	if err != nil {
		return LegacyMigration{}, err
	}
	if _, err := os.Stat(filepath.Join(repositoryRoot, ".todo", "tasks.md")); err != nil {
		return LegacyMigration{}, fmt.Errorf("legacy plan not found: .todo/tasks.md")
	}
	workID, err := nextID(repositoryRoot)
	if err != nil {
		return LegacyMigration{}, err
	}
	moves, err := migrationMoves(repositoryRoot, workID)
	if err != nil {
		return LegacyMigration{}, err
	}
	return LegacyMigration{WorkID: workID, Moves: moves}, nil
}

// ApplyLegacyMigration reserva o Work e move os artefatos legados.
func ApplyLegacyMigration(root string) (LegacyMigration, error) {
	if root == "" {
		root = "."
	}
	repositoryRoot, err := filepath.Abs(root)
	if err != nil {
		return LegacyMigration{}, err
	}
	preview, err := PreviewLegacyMigration(repositoryRoot)
	if err != nil {
		return LegacyMigration{}, err
	}
	reference := ".todo/tasks.md"
	if _, err := ReserveWork(repositoryRoot, ReserveWorkOptions{
		WorkID:          preview.WorkID,
		OriginType:      "legacy-migration",
		OriginReference: &reference,
	}); err != nil {
		return LegacyMigration{}, err
	}
	for _, move := range preview.Moves {
		destination := filepath.Join(repositoryRoot, move.To)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return LegacyMigration{}, fmt.Errorf("work: criar destino %s: %w", normalizeWorkPath(move.To), err)
		}
		if err := os.Rename(filepath.Join(repositoryRoot, move.From), destination); err != nil {
			return LegacyMigration{}, fmt.Errorf("work: mover %s: %w", normalizeWorkPath(move.From), err)
		}
	}
	if _, err := UpdateManifest(repositoryRoot, preview.WorkID, ManifestChanges{State: new(StatePlanned)}); err != nil {
		return LegacyMigration{}, err
	}
	result := preview
	created, err := ManifestPath(preview.WorkID)
	if err != nil {
		return LegacyMigration{}, err
	}
	result.Created = normalizeWorkPath(created)
	return result, nil
}
