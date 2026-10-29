package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// delivery é o que o agente entregou num worktree: arquivos alterados e o diff
// contra a base da task.
type delivery struct {
	Task  BatchTask
	Files []string
	Patch []byte
}

// capture é o inventário e o diff da entrega, commitada ou não, contra a base.
type capture struct {
	Files []string
	Patch []byte
	// Harness são alterações em artefatos do harness: ignoradas, não são entrega.
	Harness []string
}

var conflictMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^<{7} `),
	regexp.MustCompile(`(?m)^={7}\r?$`),
	regexp.MustCompile(`(?m)^>{7} `),
}

// unresolvedConflicts devolve os arquivos da entrega que ainda têm os três
// marcadores de conflito.
func unresolvedConflicts(treeRoot string, files []string) []string {
	result := make([]string, 0)
	for _, file := range files {
		target := filepath.Join(treeRoot, file)
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 5*1024*1024 {
			continue
		}
		data, err := os.ReadFile(target)
		if err != nil {
			continue
		}
		matches := true
		for _, marker := range conflictMarkers {
			if !marker.Match(data) {
				matches = false
				break
			}
		}
		if matches {
			result = append(result, file)
		}
	}
	return result
}

// gitDetail extrai o detalhe curto de uma falha do gitx.
func gitDetail(err error) string {
	var exitErr *gitx.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Result.Stderr != "" {
			return exitErr.Result.Stderr
		}
		return fmt.Sprintf("exit %d", exitErr.Result.Exit)
	}
	return err.Error()
}

func splitNUL(data []byte) []string {
	raw := strings.Split(string(data), "\x00")
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func excludeSpecs(paths []string) []string {
	args := make([]string, 0, len(paths))
	for _, entry := range paths {
		args = append(args, ":(exclude)"+entry)
	}
	return args
}

// captureDelivery ancora o worktree e monta o inventário e o diff da entrega
// contra base.
func captureDelivery(ctx context.Context, task BatchTask, base string) (capture, []string) {
	if _, err := os.Stat(task.Worktree); err != nil {
		return capture{}, []string{fmt.Sprintf("worktree ausente: %s", task.Worktree)}
	}
	// Âncora: sem o `.git` do worktree o Git subiria para o repositório principal
	// e o `add -A` abaixo encenaria a árvore errada.
	gitDir, ok := sandbox.ResolveGitDir(ctx, task.Worktree)
	if !ok || filepath.Clean(gitDir) != filepath.Clean(task.GitDir) {
		resolved := gitDir
		if !ok {
			resolved = "nenhum"
		}
		return capture{}, []string{fmt.Sprintf(
			"worktree %s não aponta mais para o repositório do lote (%s); árvore substituída — descarte o lote",
			task.Worktree, resolved,
		)}
	}
	replaced := make([]string, 0)
	for _, relative := range sortedKeys(task.Injected) {
		if run.PathFingerprint(filepath.Join(task.Worktree, relative)) != task.Injected[relative] {
			replaced = append(replaced, relative)
		}
	}
	if len(replaced) > 0 {
		return capture{}, []string{fmt.Sprintf(
			"artefato do harness substituído no worktree: %s (instalar dependências exige lote isolado, com o manifesto no write_allow)",
			strings.Join(replaced, ", "),
		)}
	}

	excludes := make([]string, 0, len(verify.HarnessStatePaths)+len(verify.DependencyPaths)+len(task.Injected))
	excludes = append(excludes, verify.HarnessStatePaths...)
	excludes = append(excludes, verify.DependencyPaths...)
	excludes = append(excludes, sortedKeys(task.Injected)...)

	runner := gitx.New(task.Worktree)
	addArgs := append([]string{"add", "-A", "--", "."}, excludeSpecs(excludes)...)
	added, err := runner.Run(ctx, addArgs, gitx.Options{})
	if err != nil {
		return capture{}, []string{fmt.Sprintf("git add no worktree falhou: %s", gitDetail(err))}
	}
	if !added.OK() {
		return capture{}, []string{fmt.Sprintf("git add no worktree falhou: %s", detailOf(added))}
	}
	filesDiff, err := runner.Diff(ctx, gitx.DiffOptions{
		Base:           base,
		Cached:         true,
		NameOnly:       true,
		NoRenames:      true,
		NullTerminated: true,
		Paths:          []string{"."},
		Excludes:       excludes,
	})
	if err != nil {
		return capture{}, []string{fmt.Sprintf("git diff no worktree falhou: %s", gitDetail(err))}
	}
	harnessDiff, err := runner.Diff(ctx, gitx.DiffOptions{
		Base:           base,
		NameOnly:       true,
		NoRenames:      true,
		NullTerminated: true,
		Paths:          []string{".pwn/work", ".work"},
	})
	if err != nil {
		return capture{}, []string{fmt.Sprintf("git diff no worktree falhou: %s", gitDetail(err))}
	}
	patch, err := runner.Diff(ctx, gitx.DiffOptions{
		Base:      base,
		Cached:    true,
		Binary:    true,
		NoRenames: true,
		Paths:     []string{"."},
		Excludes:  excludes,
	})
	if err != nil {
		return capture{}, []string{fmt.Sprintf("git diff no worktree falhou: %s", gitDetail(err))}
	}
	return capture{Files: splitNUL(filesDiff), Patch: patch, Harness: splitNUL(harnessDiff)}, nil
}

func detailOf(result gitx.Result) string {
	if result.Stderr != "" {
		return result.Stderr
	}
	return fmt.Sprintf("exit %d", result.Exit)
}

// inspectDelivery monta o inventário de uma entrega e as checagens de
// integração.
func inspectDelivery(ctx context.Context, root string, manifest BatchManifest, task BatchTask, warnings *[]string) (*delivery, []string, error) {
	capture, reasons := captureDelivery(ctx, task, baseOf(manifest, task))
	if len(reasons) > 0 {
		return nil, reasons, nil
	}
	if len(capture.Harness) > 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"%s: alterações em artefatos do harness ignoradas (não são entrega): %s",
			task.ID, preview(capture.Harness),
		))
	}
	if len(capture.Files) == 0 {
		return nil, []string{"nenhuma alteração em relação ao base da task"}, nil
	}

	reasons = make([]string, 0)
	if unresolved := unresolvedConflicts(task.Worktree, capture.Files); len(unresolved) > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"conflito não resolvido (marcadores <<<<<<< / ======= / >>>>>>>): %s", preview(unresolved),
		))
	}
	taskContract, err := plan.LoadTaskContract(manifest.WorkID, task.ID, root)
	if err != nil {
		return nil, nil, err
	}
	scope, err := contract.CheckDiffAgainstContract(
		capture.Files,
		taskContract.ScopeContract.WriteAllow,
		taskContract.ScopeContract.WriteDeny,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("batch: verificar o escopo de %s: %w", task.ID, err)
	}
	for _, violation := range scope.Violations {
		reason := violation.Reason
		if reason == "" {
			reason = string(violation.ViolationType)
		}
		reasons = append(reasons, fmt.Sprintf("DIFF VIOLATION %s: %s", violation.File, reason))
	}

	evidence, err := localEvidence(task.Worktree, manifest.WorkID, task.ID)
	if err != nil {
		return nil, nil, err
	}
	if !integrableStages[evidence.Stage] || evidence.Stale {
		stale := ""
		if evidence.Stale {
			stale = " (STALE)"
		}
		reasons = append(reasons, fmt.Sprintf(
			"evidência local insuficiente: %s%s — no worktree rode baseline → red → green → verify",
			evidence.Stage, stale,
		))
	} else {
		// O green/check posteriores leem o conteúdo do baseline nesse commit: ele
		// precisa existir na árvore principal, não só num commit local do branch
		// que a limpeza apaga.
		stateFile := filepath.Join(task.Worktree, ".todo", "evidence", manifest.WorkID, "state", task.ID+".json")
		data, err := os.ReadFile(stateFile)
		if err != nil {
			return nil, nil, fmt.Errorf("batch: ler %s: %w", stateFile, err)
		}
		var state struct {
			BaselineCommit string `json:"baseline_commit"`
		}
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, nil, fmt.Errorf("batch: ler %s: %w", stateFile, err)
		}
		ancestor := false
		if state.BaselineCommit != "" {
			ancestor, err = gitx.New(root).IsAncestor(ctx, state.BaselineCommit, manifest.Head)
			if err != nil {
				ancestor = false
			}
		}
		if !ancestor {
			shown := state.BaselineCommit
			if shown == "" {
				shown = "(nenhum commit)"
			}
			reasons = append(reasons, fmt.Sprintf(
				"baseline do audit capturado sobre %s, que não está na árvore principal; refaça o baseline a partir do base do lote",
				shown,
			))
		}
	}
	if len(reasons) > 0 {
		return nil, reasons, nil
	}
	return &delivery{Task: task, Files: capture.Files, Patch: capture.Patch}, nil, nil
}

// RegressionOptions é o gate de regressão da integração: o comando vem do
// operador e precisa ser o declarado no plano.
type RegressionOptions struct {
	Command        []string
	TimeoutSeconds int
}

// runRegression executa a regressão numa árvore (sob bwrap quando disponível,
// sem rede e sem a chave do verificador).
func runRegression(treeRoot string, regression RegressionOptions) (bool, string) {
	executable := regression.Command[0]
	args := regression.Command[1:]
	if sandbox.IsBwrapSupported() {
		executable, args = sandbox.WrapWithBwrap(executable, args, treeRoot, sandbox.BwrapOptions{})
	}

	ctx := context.Background()
	cancel := func() {}
	if regression.TimeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(regression.TimeoutSeconds)*time.Second)
	}
	defer cancel()

	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = treeRoot
	command.Env = withoutVerifierEnvironment(os.Environ())
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()

	output := strings.TrimRight(stdout.String()+stderr.String(), " \t\r\n")
	lines := strings.Split(output, "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	detail := strings.Join(lines, "\n")
	timedOut := ctx.Err() == context.DeadlineExceeded
	if detail == "" {
		switch {
		case runErr == nil:
			detail = "exit 0"
		default:
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				detail = fmt.Sprintf("exit %d", exitErr.ExitCode())
			} else {
				detail = runErr.Error()
			}
		}
	}
	if timedOut {
		detail = fmt.Sprintf("excedeu %ds\n%s", regression.TimeoutSeconds, detail)
	}
	return runErr == nil && !timedOut, detail
}

func withoutVerifierEnvironment(environment []string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		if strings.HasPrefix(entry, "PWN_VERIFIER_KEY=") || strings.HasPrefix(entry, "PWN_VERIFIER_HOME=") {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// assertDeclaredRegression recusa um comando de regressão que o plano não
// declara: o harness nunca executa comando lido de fora do plano.
func assertDeclaredRegression(root, workID string, command []string) error {
	planText, err := os.ReadFile(plan.TasksMarkdownPath(workID, root))
	if err != nil {
		return fmt.Errorf("batch: ler o plano do Work %s: %w", workID, err)
	}
	declared := plan.RegressionCommands(string(planText), nil)
	for _, planned := range declared {
		if plan.CommandMatches(planned, command) {
			return nil
		}
	}
	shown := "nenhum declarado na coluna Regression nem em ## Global gates"
	if len(declared) > 0 {
		quoted := make([]string, 0, len(declared))
		for _, entry := range declared {
			quoted = append(quoted, "`"+entry+"`")
		}
		shown = strings.Join(quoted, " | ")
	}
	return fmt.Errorf(
		"comando de regressão diverge do plano (operador: `%s`; plano: %s)",
		plan.DisplayCommand(command), shown,
	)
}

// IntegrateOptions são as entradas de IntegrateBatch.
type IntegrateOptions struct {
	Root string
	// WorkID vazio usa o Work do lote ativo.
	WorkID     string
	Regression *RegressionOptions
}

// IntegrateBatch integra as entregas prontas do lote ativo: um commit por task,
// em ordem de plano, e a evidência local copiada para a árvore principal.
//
// Tasks reprovadas continuam no lote (worktree intacto) para correção; as demais
// entram mesmo assim — seus arquivos são disjuntos, então o diff de cada uma
// aplica sobre o HEAD já avançado.
//
// Com Regression, cada entrega é aplicada primeiro num worktree temporário que
// já contém as anteriores do lote e roda o comando ali. Só passa para a árvore
// principal quem passa: a task que quebra a suíte integrada é identificada na
// hora e nada é commitado por ela.
func IntegrateBatch(ctx context.Context, options IntegrateOptions) (IntegrationResult, error) {
	root := options.Root
	regression := options.Regression
	var result IntegrationResult
	err := fsx.WithFileLock(manifestFile(root), func() error {
		manifest, err := ReadBatch(root)
		if err != nil {
			return err
		}
		if manifest == nil {
			return errors.New("nenhum lote ativo: prepare um com 'pwn work batch prepare'")
		}
		if options.WorkID != "" && options.WorkID != manifest.WorkID {
			return fmt.Errorf("o lote ativo é do Work %s, não do %s", manifest.WorkID, options.WorkID)
		}
		head, err := gitx.New(root).Head(ctx)
		if err != nil {
			return err
		}
		if head != manifest.Head {
			return fmt.Errorf(
				"HEAD mudou fora do lote (esperado %s, atual %s): commits externos durante o lote não são integráveis com segurança — desfaça-os ou descarte o lote",
				short(head), short(manifest.Head),
			)
		}
		dirty, err := BlockingChanges(ctx, root)
		if err != nil {
			return err
		}
		if len(dirty) > 0 {
			return fmt.Errorf("a árvore principal tem alterações não commitadas (%s); a integração commita sobre ela — commite ou descarte antes", preview(dirty))
		}
		if regression != nil {
			if len(regression.Command) == 0 {
				return errors.New("comando de regressão vazio")
			}
			if err := assertDeclaredRegression(root, manifest.WorkID, regression.Command); err != nil {
				return err
			}
		}

		warnings := make([]string, 0)
		if regression == nil {
			warnings = append(warnings,
				"nenhuma regressão executada na árvore integrada: conflitos de comportamento entre tasks só aparecem no 'pwn verify run-all' final (use: pwn work batch integrate -- <comando de regressão do plano>)",
			)
		}
		failed := make([]HeldTask, 0)
		deliveries := make([]delivery, 0, len(manifest.Tasks))
		for _, task := range manifest.Tasks {
			delivery, reasons, err := inspectDelivery(ctx, root, *manifest, task, &warnings)
			if err != nil {
				return err
			}
			if delivery != nil {
				deliveries = append(deliveries, *delivery)
				continue
			}
			failed = append(failed, HeldTask{ID: task.ID, Kind: HoldDelivery, Reasons: reasons})
		}

		// Escopos disjuntos garantem arquivos disjuntos; a checagem real protege
		// contra falso negativo da heurística de globs. A primeira em ordem de plano
		// entra; a(s) seguinte(s) ficam retidas e precisam de RebaseTask.
		owners := make(map[string]string)
		clashes := make(map[string][]string)
		for _, delivery := range deliveries {
			for _, file := range delivery.Files {
				owner, taken := owners[file]
				if !taken {
					owners[file] = delivery.Task.ID
					continue
				}
				clashes[delivery.Task.ID] = append(clashes[delivery.Task.ID], fmt.Sprintf(
					"%s também alterado por %s, que vem antes no plano; integre %s e rode 'pwn work batch rebase %s'",
					file, owner, owner, delivery.Task.ID,
				))
			}
		}

		integrated := make([]IntegratedTask, 0, len(deliveries))
		interrupted := ""
		var gateTree *sandbox.Session
		if regression != nil {
			session, err := sandbox.CreateGitWorktreeSandbox(ctx, manifest.BatchID+"-regression", root)
			if err != nil {
				return err
			}
			gateTree = &session
			if _, err := run.PrepareSandbox(session.WorktreePath, root); err != nil {
				_ = sandbox.CleanupGitWorktreeSandbox(ctx, session, root)
				return err
			}
		}
		if gateTree != nil {
			defer func() {
				_ = sandbox.CleanupGitWorktreeSandbox(context.Background(), *gateTree, root)
			}()
		}

		for _, delivery := range deliveries {
			task := delivery.Task
			if clash, ok := clashes[task.ID]; ok {
				failed = append(failed, HeldTask{ID: task.ID, Kind: HoldClash, Reasons: clash})
				continue
			}
			if interrupted != "" {
				failed = append(failed, HeldTask{ID: task.ID, Kind: HoldInterrupted, Reasons: []string{
					fmt.Sprintf("não aplicada: integração interrompida em %s", interrupted),
				}})
				continue
			}
			if gateTree != nil && regression != nil {
				gate := gitx.New(gateTree.WorktreePath)
				if err := gate.Apply(ctx, delivery.Patch, gitx.ApplyOptions{Index: true}); err != nil {
					failed = append(failed, HeldTask{ID: task.ID, Kind: HoldStaleBase, Reasons: []string{
						fmt.Sprintf("o diff não aplica sobre o HEAD integrado: %s", gitDetail(err)),
						fmt.Sprintf("refaça a task sobre o HEAD atual: pwn work batch rebase %s", task.ID),
					}})
					continue
				}
				ok, tail := runRegression(gateTree.WorktreePath, *regression)
				if !ok {
					_ = gate.Apply(ctx, delivery.Patch, gitx.ApplyOptions{Index: true, Revert: true})
					reasons := []string{fmt.Sprintf(
						"regressão falhou com a entrega aplicada sobre o HEAD integrado (`%s`); a árvore principal não foi tocada:",
						plan.DisplayCommand(regression.Command),
					)}
					for _, line := range strings.Split(tail, "\n") {
						reasons = append(reasons, "  | "+line)
					}
					failed = append(failed, HeldTask{ID: task.ID, Kind: HoldRegression, Reasons: reasons})
					continue
				}
			}
			if err := gitx.New(root).Apply(ctx, delivery.Patch, gitx.ApplyOptions{Index: true}); err != nil {
				if gateTree != nil {
					_ = gitx.New(gateTree.WorktreePath).Apply(ctx, delivery.Patch, gitx.ApplyOptions{Index: true, Revert: true})
				}
				failed = append(failed, HeldTask{ID: task.ID, Kind: HoldStaleBase, Reasons: []string{
					fmt.Sprintf("o diff não aplica sobre o HEAD: %s", gitDetail(err)),
					fmt.Sprintf("refaça a task sobre o HEAD atual: pwn work batch rebase %s", task.ID),
				}})
				continue
			}
			subject := fmt.Sprintf("pwn batch %s/%s: %s", manifest.WorkID, task.ID, task.Title)
			body := fmt.Sprintf("Lote %s; base %s.", manifest.BatchID, baseOf(*manifest, task))
			commit, err := gitx.New(root).Run(ctx, []string{"commit", "-q", "-m", subject, "-m", body}, gitx.Options{})
			if err != nil || !commit.OK() {
				_ = gitx.New(root).Apply(ctx, delivery.Patch, gitx.ApplyOptions{Index: true, Revert: true})
				if gateTree != nil {
					_ = gitx.New(gateTree.WorktreePath).Apply(ctx, delivery.Patch, gitx.ApplyOptions{Index: true, Revert: true})
				}
				detail := ""
				if err != nil {
					detail = gitDetail(err)
				} else {
					detail = detailOf(commit)
				}
				failed = append(failed, HeldTask{ID: task.ID, Kind: HoldCommit, Reasons: []string{
					fmt.Sprintf("git commit falhou: %s", detail),
				}})
				interrupted = task.ID
				continue
			}
			if err := copyTaskEvidence(task.Worktree, root, manifest.WorkID, task.ID); err != nil {
				return err
			}
			after, err := localEvidence(root, manifest.WorkID, task.ID)
			if err != nil {
				return err
			}
			if !integrableStages[after.Stage] || after.Stale {
				stale := ""
				if after.Stale {
					stale = " (STALE)"
				}
				warnings = append(warnings, fmt.Sprintf(
					"%s: evidência local na árvore principal ficou %s%s após integrar; refaça o audit da task",
					task.ID, after.Stage, stale,
				))
			}
			if err := dropTask(ctx, task, root); err != nil {
				return err
			}
			commitHash, err := gitx.New(root).Head(ctx)
			if err != nil {
				return err
			}
			integrated = append(integrated, IntegratedTask{ID: task.ID, Commit: commitHash, Files: delivery.Files})
		}

		done := make(map[string]bool, len(integrated))
		for _, entry := range integrated {
			done[entry.ID] = true
		}
		remainingTasks := make([]BatchTask, 0, len(manifest.Tasks))
		for _, task := range manifest.Tasks {
			if !done[task.ID] {
				remainingTasks = append(remainingTasks, task)
			}
		}
		remaining := make([]string, 0, len(remainingTasks))
		for _, task := range remainingTasks {
			remaining = append(remaining, task.ID)
		}
		if len(remainingTasks) > 0 {
			finalHead, err := gitx.New(root).Head(ctx)
			if err != nil {
				return err
			}
			updated := *manifest
			updated.Head = finalHead
			updated.Tasks = remainingTasks
			if err := writeManifest(root, updated); err != nil {
				return err
			}
		} else if err := os.Remove(manifestFile(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("batch: remover o manifesto: %w", err)
		}

		ordered := make([]HeldTask, 0, len(failed))
		for _, task := range manifest.Tasks {
			for _, entry := range failed {
				if entry.ID == task.ID {
					ordered = append(ordered, entry)
				}
			}
		}
		result = IntegrationResult{
			BatchID:    manifest.BatchID,
			WorkID:     manifest.WorkID,
			Integrated: integrated,
			Failed:     ordered,
			Warnings:   warnings,
			Remaining:  remaining,
		}
		return nil
	}, lockOptions())
	if err != nil {
		return IntegrationResult{}, err
	}
	return result, nil
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
