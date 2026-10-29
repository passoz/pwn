// Package batch porta src/core/batch.ts: lotes paralelos de tasks de um Work.
//
// Cada task do lote recebe um worktree próprio nascido do mesmo commit (`base`);
// um agente implementa e roda o audit local ali. IntegrateBatch aplica cada
// entrega na árvore principal, um commit por task, e traz a evidência local.
//
// Invariantes que evitam retrabalho de evidência:
//   - tasks do mesmo lote têm write_allow disjuntos, nenhum componente em comum
//     e nenhuma dependência entre si: a evidência local (snapshot por arquivo
//     declarado) continua válida depois que as outras entregas entram;
//   - a aprovação independente precisa existir ANTES do lote: o baseline
//     aprovado é anterior à implementação, então o AC continua causal depois
//     da integração;
//   - o recibo independente amarra a árvore inteira: a verificação roda uma
//     vez, na árvore integrada, depois do último lote.
package batch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

const manifestPath = ".pwn/batch.json"

// patchSuffix é o patch de referência da entrega original, ao lado do worktree
// refeito por RebaseTask.
const patchSuffix = ".delivery.patch"

// integratedStages são os estágios locais em que a implementação já está na
// árvore (GREEN em diante).
var integratedStages = map[string]bool{"GREEN": true, "VERIFIED": true, "ACCEPTED": true}

// integrableStages é a evidência local mínima para integrar: GREEN com mutation
// e verify PASS.
var integrableStages = map[string]bool{"VERIFIED": true, "ACCEPTED": true}

// lockOptions cobre a integração, que faz várias operações git e coleta status:
// o lock não pode ser tomado por "velho" no meio.
func lockOptions() fsx.LockOptions {
	return fsx.LockOptions{Timeout: 5 * time.Second, Stale: 10 * time.Minute}
}

// SchedulableTask é uma task do plano com o estado necessário para o scheduler.
type SchedulableTask struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	DependsOn         []string `json:"dependsOn"`
	Components        []string `json:"components"`
	WriteAllow        []string `json:"writeAllow"`
	Risk              string   `json:"risk"`
	Marker            string   `json:"marker"`
	Stage             string   `json:"stage"`
	CrossWorkBlockers []string `json:"crossWorkBlockers"`
	// Approved indica aprovação independente vigente cujo baseline é ancestral
	// do HEAD.
	Approved bool `json:"approved"`
}

// Deferral explica por que uma task ficou fora do lote.
type Deferral struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Schedule é o próximo lote com os motivos das retenções.
type Schedule struct {
	Batch      []SchedulableTask `json:"batch"`
	Deferred   []Deferral        `json:"deferred"`
	Integrated []string          `json:"integrated"`
}

// BatchTask é uma task preparada em worktree.
type BatchTask struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	RunID    string `json:"run_id"`
	Worktree string `json:"worktree"`
	Branch   string `json:"branch"`
	GitDir   string `json:"git_dir"`
	// Injected são os artefatos que o harness injetou no worktree (node_modules,
	// bunfig.toml) com a assinatura: nunca são entrega.
	Injected run.HarnessArtifacts `json:"injected"`
	// Base é o commit em que o worktree foi refeito por RebaseTask; ausente = base
	// do lote.
	Base string `json:"base,omitempty"`
}

// BatchManifest é o manifesto `.pwn/batch.json`.
type BatchManifest struct {
	Version   int         `json:"version"`
	BatchID   string      `json:"batch_id"`
	WorkID    string      `json:"work_id"`
	Base      string      `json:"base"`
	Head      string      `json:"head"`
	CreatedAt string      `json:"created_at"`
	Tasks     []BatchTask `json:"tasks"`
}

// HoldKind é o motivo da retenção de uma entrega.
//
// clash e stale_base se resolvem refazendo a task sobre o HEAD integrado
// (RebaseTask); os demais exigem o agente (ou o operador).
type HoldKind string

const (
	HoldDelivery    HoldKind = "delivery"
	HoldClash       HoldKind = "clash"
	HoldStaleBase   HoldKind = "stale_base"
	HoldRegression  HoldKind = "regression"
	HoldCommit      HoldKind = "commit"
	HoldInterrupted HoldKind = "interrupted"
)

// IntegratedTask é uma entrega integrada com o commit criado.
type IntegratedTask struct {
	ID     string   `json:"id"`
	Commit string   `json:"commit"`
	Files  []string `json:"files"`
}

// HeldTask é uma entrega que ficou no lote.
type HeldTask struct {
	ID      string   `json:"id"`
	Kind    HoldKind `json:"kind"`
	Reasons []string `json:"reasons"`
}

// IntegrationResult é o resultado de IntegrateBatch.
type IntegrationResult struct {
	BatchID    string           `json:"batchId"`
	WorkID     string           `json:"workId"`
	Integrated []IntegratedTask `json:"integrated"`
	Failed     []HeldTask       `json:"failed"`
	Warnings   []string         `json:"warnings"`
	Remaining  []string         `json:"remaining"`
}

var (
	harnessStatePattern = regexp.MustCompile(`^(?:\.todo|\.work|queue)/`)
	workCachePattern    = regexp.MustCompile(`^\.pwn/work/[^/]+/\.pwn/`)
)

// isHarnessState informa se o arquivo é estado do harness que pode estar sujo
// sem afetar o lote.
//
// Artefatos de governança versionados (`.pwn/work/NNNN/*`) não entram aqui: o
// worktree os recebe pelo HEAD, então precisam estar commitados. Caches dentro
// deles (`.pwn/work/NNNN/.pwn/`) entram.
func isHarnessState(file string) bool {
	if harnessStatePattern.MatchString(file) {
		return true
	}
	if !strings.HasPrefix(file, ".pwn/") {
		return false
	}
	return !strings.HasPrefix(file, ".pwn/work/") || workCachePattern.MatchString(file)
}

// BlockingChanges devolve as alterações não commitadas que impedem o lote:
// worktrees nascem do HEAD e a integração aplica diffs sobre ele.
func BlockingChanges(ctx context.Context, root string) ([]string, error) {
	entries, err := gitx.New(root).StatusPorcelain(ctx, gitx.StatusOptions{})
	if err != nil {
		return nil, fmt.Errorf("batch: ler o status de %s: %w", root, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Path == "" || isHarnessState(entry.Path) {
			continue
		}
		files = append(files, entry.Path)
	}
	return files, nil
}

// soloReason devolve o motivo pelo qual a task exige um lote próprio.
func soloReason(task SchedulableTask) string {
	if task.Risk == "L4" {
		return "risco L4 (revisão humana)"
	}
	for _, pattern := range task.WriteAllow {
		for _, file := range verify.DependencyManifests {
			if run.GlobsMayOverlap(pattern, file) {
				return fmt.Sprintf("escopo alcança manifesto de dependências (%s); node_modules é compartilhado", pattern)
			}
		}
	}
	return ""
}

// PlanNextBatch monta o próximo lote, em ordem de plano.
//
// Uma task entra quando está pronta (dependências integradas, aprovação vigente,
// nada em andamento na árvore principal) e não conflita com nenhuma task já
// escolhida. Conflito = write_allow que pode sobrepor (heurística conservadora),
// componente em comum, ou necessidade de execução isolada.
func PlanNextBatch(tasks []SchedulableTask, maxJobs int, workID string, only map[string]bool) Schedule {
	byID := make(map[string]SchedulableTask, len(tasks))
	for _, task := range tasks {
		byID[task.ID] = task
	}
	isIntegrated := func(task SchedulableTask) bool {
		return task.Marker == "x" || integratedStages[task.Stage]
	}

	batch := make([]SchedulableTask, 0, len(tasks))
	deferred := make([]Deferral, 0)
	integrated := make([]string, 0)
	prefix := workID + "/"

	for _, task := range tasks {
		if isIntegrated(task) {
			integrated = append(integrated, task.ID)
			continue
		}
		if only != nil && !only[task.ID] {
			continue
		}
		deferTask := func(reason string) {
			deferred = append(deferred, Deferral{ID: task.ID, Reason: reason})
		}

		if task.Marker == "!" {
			deferTask("bloqueada no plano ([!])")
			continue
		}
		if task.Stage != "not started" {
			deferTask(fmt.Sprintf("já iniciada na árvore principal (evidência local: %s); termine-a fora do lote", task.Stage))
			continue
		}
		pendingDependency := ""
		for _, raw := range task.DependsOn {
			id := raw
			if strings.HasPrefix(raw, prefix) {
				id = raw[len(prefix):]
			}
			// Dependências de outro Work (NNNN/x.y) são resolvidas por crossWorkBlockers.
			if fourDigitWorkPattern.MatchString(id) {
				continue
			}
			target, ok := byID[id]
			if !ok {
				pendingDependency = fmt.Sprintf("depende de %s, que não existe no plano", raw)
				break
			}
			if !isIntegrated(target) {
				pendingDependency = fmt.Sprintf("depende de %s, ainda não integrada", raw)
				break
			}
		}
		if pendingDependency != "" {
			deferTask(pendingDependency)
			continue
		}
		if len(task.CrossWorkBlockers) > 0 {
			deferTask(fmt.Sprintf("dependência entre Works sem aceitação independente: %s", strings.Join(task.CrossWorkBlockers, ", ")))
			continue
		}
		if !task.Approved {
			deferTask("sem aprovação vigente: rode pwn verify approve ANTES de implementar (aprovada depois, o baseline já contém a implementação e o AC falha como vácuo)")
			continue
		}

		solo := soloReason(task)
		soloMember := ""
		for _, member := range batch {
			if reason := soloReason(member); reason != "" {
				soloMember = member.ID
				break
			}
		}
		if soloMember != "" {
			deferTask(fmt.Sprintf("aguarda: %s exige execução isolada", soloMember))
			continue
		}
		if solo != "" && len(batch) > 0 {
			deferTask(fmt.Sprintf("exige execução isolada (%s); entra num lote próprio", solo))
			continue
		}

		conflict := ""
		for _, member := range batch {
			pair := ""
			for _, a := range task.WriteAllow {
				for _, b := range member.WriteAllow {
					if run.GlobsMayOverlap(a, b) {
						pair = fmt.Sprintf("%s × %s", a, b)
						break
					}
				}
				if pair != "" {
					break
				}
			}
			if pair != "" {
				conflict = fmt.Sprintf("escopo pode sobrepor %s (%s)", member.ID, pair)
				break
			}
			for _, name := range task.Components {
				if contains(member.Components, name) {
					conflict = fmt.Sprintf("componente compartilhado com %s: %s", member.ID, name)
					break
				}
			}
			if conflict != "" {
				break
			}
		}
		if conflict != "" {
			deferTask(conflict)
			continue
		}
		if len(batch) >= maxJobs {
			deferTask(fmt.Sprintf("limite de %d task(s) por lote", maxJobs))
			continue
		}
		batch = append(batch, task)
	}
	return Schedule{Batch: batch, Deferred: deferred, Integrated: integrated}
}

var fourDigitWorkPattern = regexp.MustCompile(`^\d{4}/`)

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// CollectSchedulableTasks monta as entradas do scheduler a partir do plano, dos
// contratos, do status local e das aprovações.
func CollectSchedulableTasks(ctx context.Context, workID, root string) ([]SchedulableTask, error) {
	workPlan := plan.LoadPlan(workID, root)
	if workPlan == nil {
		return nil, fmt.Errorf("batch: plan.json ausente para o Work %s", workID)
	}
	markdownPath := plan.TasksMarkdownPath(workID, root)
	relative, err := filepath.Rel(root, markdownPath)
	if err != nil {
		relative = markdownPath
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		return nil, fmt.Errorf("batch: plano derivado ausente: %s (rode pwn work plan --work %s)", relative, workID)
	}
	if !plan.PlanMatchesMarkdown(*workPlan, string(markdown)) {
		return nil, fmt.Errorf("batch: DRIFT: %s diverge de plan.json; regenere com pwn work plan --work %s --force", relative, workID)
	}
	status, err := work.CollectPlanStatus(workID, root)
	if err != nil {
		return nil, err
	}
	head, err := gitx.New(root).Head(ctx)
	if err != nil {
		return nil, err
	}
	verifierRoot, err := verify.Root()
	if err != nil {
		return nil, err
	}

	tasks := make([]SchedulableTask, 0, len(workPlan.Tasks))
	for _, task := range workPlan.Tasks {
		taskContract, err := plan.LoadTaskContract(workID, task.ID, root)
		if err != nil {
			return nil, err
		}
		stage := "not started"
		marker := " "
		for _, row := range status.Tasks {
			if row.ID == task.ID {
				marker = row.Marker
				stage = row.Evidence.Stage
				break
			}
		}
		approved := false
		if approval := verify.CurrentApproval(workID, task.ID, verifierRoot); approval != nil {
			ancestor, err := gitx.New(root).IsAncestor(ctx, approval.BaselineCommit, head)
			if err != nil {
				return nil, err
			}
			approved = ancestor
		}
		tasks = append(tasks, SchedulableTask{
			ID:                task.ID,
			Title:             task.Title,
			DependsOn:         task.DependsOn,
			Components:        task.Components,
			WriteAllow:        taskContract.ScopeContract.WriteAllow,
			Risk:              string(taskContract.Risk.Level),
			Marker:            marker,
			Stage:             stage,
			CrossWorkBlockers: status.CrossWorkBlockers[task.ID],
			Approved:          approved,
		})
	}
	return tasks, nil
}

// ReadBatch lê o manifesto do lote ativo. Devolve nil quando não existe.
func ReadBatch(root string) (*BatchManifest, error) {
	file := manifestFile(root)
	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("batch: ler %s: %w", file, err)
	}
	var manifest BatchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("batch: manifesto de lote inválido: %s", file)
	}
	if manifest.Version != 1 {
		return nil, fmt.Errorf("batch: manifesto de lote inválido: %s", file)
	}
	return &manifest, nil
}

func manifestFile(root string) string {
	return filepath.Join(root, manifestPath)
}

func writeManifest(root string, manifest BatchManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("batch: serializar o manifesto: %w", err)
	}
	return fsx.WriteFileAtomic(manifestFile(root), string(data)+"\n")
}

func sessionOf(task BatchTask) sandbox.Session {
	return sandbox.Session{
		RunID:        task.RunID,
		WorktreePath: task.Worktree,
		BranchName:   task.Branch,
		Created:      true,
		GitDir:       task.GitDir,
	}
}

func preview(files []string) string {
	if len(files) > 5 {
		return strings.Join(files[:5], ", ") + fmt.Sprintf(" … +%d", len(files)-5)
	}
	return strings.Join(files, ", ")
}

// PrepareOptions são as entradas de PrepareBatch.
type PrepareOptions struct {
	Root   string
	WorkID string
	Jobs   int
	// Only restringe o lote a estas tasks; cada uma precisa estar pronta e
	// compatível.
	Only []string
}

// PrepareResult é o lote criado e o agendamento que o produziu.
type PrepareResult struct {
	Manifest *BatchManifest
	Schedule Schedule
}

// PrepareBatch cria um worktree por task do próximo lote. Lote vazio devolve
// Manifest nil com os motivos no schedule.
func PrepareBatch(ctx context.Context, options PrepareOptions) (PrepareResult, error) {
	root := options.Root
	workID := options.WorkID
	var result PrepareResult
	err := fsx.WithFileLock(manifestFile(root), func() error {
		active, err := ReadBatch(root)
		if err != nil {
			return err
		}
		if active != nil {
			ids := make([]string, 0, len(active.Tasks))
			for _, task := range active.Tasks {
				ids = append(ids, task.ID)
			}
			return fmt.Errorf(
				"já existe um lote ativo (%s, Work %s: %s); integre com 'pwn work batch integrate' ou descarte com 'pwn work batch abort'",
				active.BatchID, active.WorkID, strings.Join(ids, ", "),
			)
		}
		dirty, err := BlockingChanges(ctx, root)
		if err != nil {
			return err
		}
		if len(dirty) > 0 {
			return fmt.Errorf("a árvore principal tem alterações não commitadas (%s): os worktrees nascem do HEAD e a integração aplica diffs sobre ele — commite ou descarte antes", preview(dirty))
		}

		tasks, err := CollectSchedulableTasks(ctx, workID, root)
		if err != nil {
			return err
		}
		var only map[string]bool
		if options.Only != nil {
			only = make(map[string]bool, len(options.Only))
			for _, id := range options.Only {
				only[id] = true
			}
			unknown := make([]string, 0)
			for _, id := range options.Only {
				found := false
				for _, task := range tasks {
					if task.ID == id {
						found = true
						break
					}
				}
				if !found {
					unknown = append(unknown, id)
				}
			}
			if len(unknown) > 0 {
				return fmt.Errorf("task(s) fora do plano do Work %s: %s", workID, strings.Join(unknown, ", "))
			}
		}
		schedule := PlanNextBatch(tasks, options.Jobs, workID, only)
		if only != nil {
			problems := make([]string, 0)
			for _, id := range options.Only {
				if contains(schedule.Integrated, id) {
					problems = append(problems, id+": já integrada")
				}
			}
			for _, entry := range schedule.Deferred {
				problems = append(problems, entry.ID+": "+entry.Reason)
			}
			if len(problems) > 0 {
				return fmt.Errorf("--tasks não forma um lote válido:\n  %s", strings.Join(problems, "\n  "))
			}
		}
		if len(schedule.Batch) == 0 {
			result = PrepareResult{Manifest: nil, Schedule: schedule}
			return nil
		}

		base, err := gitx.New(root).Head(ctx)
		if err != nil {
			return err
		}
		markdownPath := plan.TasksMarkdownPath(workID, root)
		batchID := newBatchID()
		entries := make([]BatchTask, 0, len(schedule.Batch))
		cleanup := func() {
			for _, entry := range entries {
				_ = sandbox.CleanupGitWorktreeSandbox(ctx, sessionOf(entry), root)
			}
		}
		for _, task := range schedule.Batch {
			session, err := sandbox.CreateGitWorktreeSandbox(ctx, batchID+"-"+task.ID, root)
			if err != nil {
				cleanup()
				return err
			}
			entry := BatchTask{
				ID:       task.ID,
				Title:    task.Title,
				RunID:    session.RunID,
				Worktree: session.WorktreePath,
				Branch:   session.BranchName,
				GitDir:   session.GitDir,
				Injected: run.HarnessArtifacts{},
			}
			entries = append(entries, entry)
			injected, err := run.PrepareSandbox(session.WorktreePath, root)
			if err != nil {
				cleanup()
				return err
			}
			entries[len(entries)-1].Injected = injected
			// `.todo/` não é versionado: o audit do worktree precisa do plano
			// derivado.
			relative, err := filepath.Rel(root, markdownPath)
			if err != nil {
				cleanup()
				return err
			}
			target := filepath.Join(session.WorktreePath, relative)
			if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
				cleanup()
				return fmt.Errorf("batch: criar %s: %w", filepath.Dir(target), err)
			}
			content, err := os.ReadFile(markdownPath)
			if err != nil {
				cleanup()
				return fmt.Errorf("batch: ler %s: %w", markdownPath, err)
			}
			if err := os.WriteFile(target, content, 0o644); err != nil {
				cleanup()
				return fmt.Errorf("batch: copiar o plano para %s: %w", target, err)
			}
		}

		manifest := BatchManifest{
			Version:   1,
			BatchID:   batchID,
			WorkID:    workID,
			Base:      base,
			Head:      base,
			CreatedAt: isoNow(),
			Tasks:     entries,
		}
		if err := writeManifest(root, manifest); err != nil {
			cleanup()
			return err
		}
		result = PrepareResult{Manifest: &manifest, Schedule: schedule}
		return nil
	}, lockOptions())
	if err != nil {
		return PrepareResult{}, err
	}
	return result, nil
}

func newBatchID() string {
	var buffer [4]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "BATCH-" + strconv.FormatInt(time.Now().UnixMilli(), 36) + "-0"
	}
	return "BATCH-" + strconv.FormatInt(time.Now().UnixMilli(), 36) + "-" + hex.EncodeToString(buffer[:])
}

func isoNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// localEvidence devolve o estágio e o STALE da evidência local de UMA task na
// árvore indicada.
func localEvidence(treeRoot, workID, taskID string) (work.EvidenceState, error) {
	status, err := work.CollectProjectStatus(plan.TasksMarkdownPath(workID, treeRoot))
	if err != nil {
		return work.EvidenceState{}, err
	}
	for _, row := range status.Tasks {
		if row.ID == taskID {
			return row.Evidence, nil
		}
	}
	return work.EvidenceState{Stage: "ausente do plano"}, nil
}

// copyTaskEvidence copia a evidência local de UMA task (estado, logs, cadeia,
// atestações): nomes `<task>.json` ou `<task>-*`.
func copyTaskEvidence(fromRoot, toRoot, workID, taskID string) error {
	directories := []string{
		filepath.Join(".todo", "evidence", workID),
		filepath.Join(".todo", "evidence", workID, "state"),
		filepath.Join(".todo", "attestations", workID),
	}
	for _, directory := range directories {
		source := filepath.Join(fromRoot, directory)
		entries, err := os.ReadDir(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("batch: ler %s: %w", source, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if entry.Name() != taskID+".json" && !strings.HasPrefix(entry.Name(), taskID+"-") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(source, entry.Name()))
			if err != nil {
				return fmt.Errorf("batch: ler %s: %w", entry.Name(), err)
			}
			targetDirectory := filepath.Join(toRoot, directory)
			if err := os.MkdirAll(targetDirectory, 0o777); err != nil {
				return fmt.Errorf("batch: criar %s: %w", targetDirectory, err)
			}
			if err := os.WriteFile(filepath.Join(targetDirectory, entry.Name()), data, 0o644); err != nil {
				return fmt.Errorf("batch: copiar %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

// baseOf devolve a base de uma task: a do lote, ou o HEAD em que ela foi refeita
// por RebaseTask.
func baseOf(manifest BatchManifest, task BatchTask) string {
	if task.Base != "" {
		return task.Base
	}
	return manifest.Base
}

// dropTask remove o worktree, o branch e o patch de referência de uma task.
func dropTask(ctx context.Context, task BatchTask, root string) error {
	if err := sandbox.CleanupGitWorktreeSandbox(ctx, sessionOf(task), root); err != nil {
		return err
	}
	if err := os.Remove(task.Worktree + patchSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("batch: remover %s: %w", task.Worktree+patchSuffix, err)
	}
	return nil
}

// sortedKeys devolve as chaves do mapa em ordem, para mensagens determinísticas.
func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
