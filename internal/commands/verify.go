package commands

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/decider"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/jsonx"
	"github.com/passoz/pwn/internal/platform/proc"
)

// Verify porta `pwn verify <subcomando>` de src/commands/verify.ts.
func (r *Runner) Verify(subcommand string, args []string) int {
	if subcommand == "run-all" {
		return r.verifyRunAll(args)
	}
	return r.verifySync(subcommand, args)
}

// verifyUsage é o texto de uso da referência.
var verifyUsage = strings.Join([]string{
	"pwn verify init                            Inicializa a raiz protegida do verificador (chaves Ed25519, runtime, isolamento)",
	"pwn verify approve --work NNNN --task T [--by NOME]",
	"                                           Aprova os critérios de uma task (exige testes de aceitação congelados);",
	"                                           sem --by, o decisor do projeto decide (pwn decider)",
	"pwn verify approve --work NNNN --global G-1 [--by NOME]",
	"                                           Aprova um item de ## Global gates",
	"pwn verify run --work NNNN --task T        Executa a aceitação independente e emite o recibo assinado",
	"pwn verify run --work NNNN --global G-1    Executa a aceitação independente de um gate global",
	"pwn verify run-all --work NNNN [--jobs N] [--timeout-seconds S]",
	"                                           Executa em paralelo (subprocessos) todas as aprovações vigentes do Work",
	"pwn verify status --work NNNN --task T     Informa se a árvore atual tem aceitação independente válida",
	"pwn verify show --work NNNN [--task T]     Mostra a aprovação vigente e o último recibo",
}, "\n")

// verifySync executa os subcomandos síncronos e traduz o erro no código da
// referência: 2 para pré-requisito ausente do verificador, 1 para o restante.
func (r *Runner) verifySync(subcommand string, args []string) int {
	code, err := r.verifyAction(subcommand, args)
	if err != nil {
		return r.reportVerifyError(err)
	}
	return code
}

// reportVerifyError escreve o erro do verificador com o código da referência.
func (r *Runner) reportVerifyError(err error) int {
	var unavailable *verify.VerificationUnavailable
	if errors.As(err, &unavailable) {
		fmt.Fprintf(r.errOut(), "[VERIFICATION BLOCKED] %s\n", unavailable.Message)
		fmt.Fprintf(r.errOut(), "  %s\n", unavailable.Detail)
		return 2
	}
	fmt.Fprintf(r.errOut(), "[VERIFY ERROR] %s\n", err.Error())
	return 1
}

// verifyAction despacha um subcomando síncrono.
func (r *Runner) verifyAction(subcommand string, args []string) (int, error) {
	switch subcommand {
	case "init":
		return r.verifyInit()
	case "approve":
		return r.verifyApprove(args)
	case "run":
		return r.verifyRun(args)
	case "status":
		return r.verifyStatus(args)
	case "show":
		return r.verifyShow(args)
	default:
		fmt.Fprintf(r.errOut(), "Subcomando desconhecido para 'pwn verify': %s\n", showOrEmpty(subcommand))
		fmt.Fprintf(r.errOut(), "\nUso:\n%s\n", verifyUsage)
		return 1, nil
	}
}

// showOrEmpty usa "(vazio)" para o subcomando ausente, como a referência.
func showOrEmpty(value string) string {
	if value == "" {
		return "(vazio)"
	}
	return value
}

// requireWorkID devolve --work ou o último Work conhecido.
func (r *Runner) requireWorkID(args []string) (string, error) {
	if workID := flagValue(args, "--work"); workID != "" {
		return workID, nil
	}
	workID := work.GetLatestWorkID(r.rootDir())
	if workID == "" {
		return "", fmt.Errorf("informe --work NNNN (nenhum Work encontrado)")
	}
	return workID, nil
}

// verifyInit inicializa a raiz protegida do verificador.
func (r *Runner) verifyInit() (int, error) {
	root, err := verify.Root()
	if err != nil {
		return 0, err
	}
	initialization, err := verify.InitializeVerifierHome(root)
	if err != nil {
		return 0, err
	}
	config := initialization.Config

	state := "já existia"
	if initialization.Created {
		state = "criada agora"
	}
	bwrap := "(não encontrado — aceitação ficará bloqueada)"
	if config.Isolation.Bwrap != nil {
		bwrap = *config.Isolation.Bwrap
	}

	fmt.Fprint(r.out(), "=== [pwn verify init] Raiz protegida do verificador ===\n")
	fmt.Fprintf(r.out(), "  Raiz:      %s\n", initialization.Root)
	fmt.Fprintf(r.out(), "  Estado:    %s\n", state)
	fmt.Fprintf(r.out(), "  Verifier:  %s\n", config.VerifierID)
	fmt.Fprintf(r.out(), "  Runtime:   %s\n", config.Runtime.Bun)
	fmt.Fprintf(r.out(), "  bwrap:     %s\n", bwrap)

	readiness, err := verify.RequireVerifierReady(root)
	if err != nil {
		fmt.Fprintf(r.errOut(), "\n[VERIFICATION BLOCKED] %s\n", err.Error())
		return 2, nil
	}
	policy, err := jsonx.Insertion(verify.BuildSandboxPolicy(readiness.Runtime, nil, nil))
	if err != nil {
		return 0, err
	}
	fmt.Fprint(r.out(), "  Isolamento: bwrap disponível; política de sandbox:\n")
	fmt.Fprintf(r.out(), "    %s\n", policy)
	fmt.Fprintf(r.out(), "  Chave pública (fingerprint): %s\n", readiness.PublicKeyFingerprint)
	fmt.Fprint(r.out(), "\nVerificador pronto. O código avaliado nunca recebe esta raiz.\n")
	return 0, nil
}

// verifyApprove aprova os critérios de uma task ou de um gate global.
func (r *Runner) verifyApprove(args []string) (int, error) {
	workID, err := r.requireWorkID(args)
	if err != nil {
		return 0, err
	}
	global := flagValue(args, "--global")
	taskID := flagValue(args, "--task")
	if global == "" && taskID == "" {
		return 0, fmt.Errorf("informe --task T ou --global G-n")
	}
	rootDir := r.rootDir()
	approvedBy := flagValue(args, "--by")

	if approvedBy == "" {
		// Sem --by: o decisor do projeto aprova, se houver um configurado (senão,
		// como sempre, exige --by).
		root, err := verify.Root()
		if err != nil {
			return 0, err
		}
		subject := taskID
		if global != "" {
			subject = global
		}
		options := decider.DecideOptions{
			Context:      contextBackground(),
			RootDir:      rootDir,
			WorkID:       workID,
			TaskID:       subject,
			VerifierRoot: root,
		}
		if global != "" {
			options.Policy = decider.GlobalApprovalPolicy
			options.Request = func() (decider.Request, error) {
				return decider.GlobalApprovalRequest(rootDir, workID, global)
			}
		} else {
			taskContract, err := plan.LoadTaskContract(workID, taskID, rootDir)
			if err != nil {
				return 0, err
			}
			risk := taskContract.Risk.Level
			options.Risk = &risk
			options.Policy = decider.TaskApprovalPolicy
			options.Request = func() (decider.Request, error) {
				return decider.TaskApprovalRequest(rootDir, workID, taskID)
			}
		}
		result, err := decider.Decide(options)
		if err != nil {
			return 0, err
		}
		if result.Kind == decider.ResultHuman {
			reason := ""
			if result.Reason != nil {
				reason = "; " + *result.Reason
			}
			return 0, fmt.Errorf("informe --by <responsável> (a aprovação é ato do operador%s)", reason)
		}
		if result.Record == nil {
			return 0, fmt.Errorf("o decisor não devolveu registro para %s/%s", workID, subject)
		}
		record := result.Record
		for _, line := range decider.DescribeDecision(*record) {
			fmt.Fprintln(r.out(), line)
		}
		target := "--task " + taskID
		if global != "" {
			target = "--global " + global
		}
		if record.Outcome == decider.OutcomeReject {
			fmt.Fprint(r.errOut(), "\n[NOT APPROVED] o decisor rejeitou os critérios: corrija os testes congelados ou o plano e peça de novo.\n")
			fmt.Fprintf(r.errOut(), "Para decidir você mesmo: pwn verify approve --work %s %s --by <nome>\n", workID, target)
			return 1, nil
		}
		if record.Outcome == decider.OutcomeEscalate {
			fmt.Fprintf(r.errOut(), "\n[OPERADOR] o decisor não decidiu: pwn verify approve --work %s %s --by <nome>\n", workID, target)
			return run.ExitSuspended, nil
		}
		approvedBy = decider.DecisionReference(*record)
	}

	// Work nascido de `pwn work reconcile`: a implementação é revertida ao commit
	// anterior à mudança.
	var reconciliation *work.Reconciliation
	if global == "" {
		reconciliation = work.ReadReconciliation(rootDir, workID)
	}
	baselineCommit := ""
	if reconciliation != nil {
		baselineCommit = reconciliation.BaseCommit
	}

	approvalTaskID := taskID
	if global != "" {
		approvalTaskID = verify.GlobalTaskID
	}
	approval, err := verify.CreateApproval(verify.CreateApprovalOptions{
		Ctx:            contextBackground(),
		RootDir:        rootDir,
		WorkID:         workID,
		TaskID:         approvalTaskID,
		ApprovedBy:     approvedBy,
		Global:         global,
		BaselineCommit: baselineCommit,
	})
	if err != nil {
		return 0, err
	}

	fmt.Fprint(r.out(), "=== [pwn verify approve] Critérios aprovados ===\n")
	fmt.Fprint(r.out(), describeApproval(approval))
	if reconciliation != nil {
		fmt.Fprintf(r.out(), "\nWork conciliado: baseline = %s (commit anterior à mudança feita fora do pwn).\n", truncate(approval.BaselineCommit, 12))
	}
	fmt.Fprint(r.out(), "\nA avaliação executará EXATAMENTE isso. O agente não pode alterar o pacote.\n")
	return 0, nil
}

// describeApproval monta o texto do pacote de aceitação.
func describeApproval(approval verify.Approval) string {
	contractID := "(nenhum)"
	if approval.ContractID != nil {
		contractID = *approval.ContractID
	}
	lines := []string{
		fmt.Sprintf("Aprovação %s… (%s)", truncate(approval.ApprovalID, 16), approval.Kind),
		fmt.Sprintf("  Work/task:    %s/%s", approval.WorkID, approval.TaskID),
		fmt.Sprintf("  Aprovada por: %s em %s", approval.ApprovedBy, approval.CreatedAt),
		fmt.Sprintf("  Baseline:     %s", truncate(approval.BaselineCommit, 12)),
		fmt.Sprintf("  Plano sha256: %s…", truncate(approval.PlanSHA256, 16)),
		fmt.Sprintf("  Contrato:     %s", contractID),
		fmt.Sprintf("  Arquivos de aceitação aprovados: %d", len(approval.ApprovedFiles)),
	}
	for _, entry := range approval.ApprovedFiles {
		lines = append(lines, fmt.Sprintf("    = %s", entry.Path))
	}
	lines = append(lines, "  Checks:")
	for _, check := range approval.Checks {
		baseline := ""
		if check.RequireBaselineFailure {
			baseline = "  [exige falha no baseline]"
		}
		lines = append(lines, fmt.Sprintf("    %s %s%s", padEnd(check.ID, 13), strings.Join(check.Command, " "), baseline))
	}
	return strings.Join(lines, "\n") + "\n"
}

// verifyRun executa a aceitação independente e grava o recibo assinado.
func (r *Runner) verifyRun(args []string) (int, error) {
	workID, err := r.requireWorkID(args)
	if err != nil {
		return 0, err
	}
	global := flagValue(args, "--global")
	taskID := global
	if taskID == "" {
		taskID = flagValue(args, "--task")
	}
	if taskID == "" {
		return 0, fmt.Errorf("informe --task T ou --global G-n")
	}
	timeoutSeconds := timeoutSecondsValue(args)
	rootDir := r.rootDir()

	root, err := verify.Root()
	if err != nil {
		return 0, err
	}
	approval := verify.CurrentApproval(workID, taskID, root)
	if approval == nil {
		fmt.Fprintf(r.errOut(), "[VERIFICATION BLOCKED] não existe aprovação vigente para %s/%s.\n", workID, taskID)
		target := "--task " + taskID
		if global != "" {
			target = "--global " + global
		}
		fmt.Fprintf(r.errOut(), "Aprove antes: pwn verify approve --work %s %s --by <nome>\n", workID, target)
		return 2, nil
	}

	fmt.Fprintf(r.out(), "=== [pwn verify run] Aceitação independente de %s/%s ===\n", workID, taskID)
	result, err := verify.RunVerification(verify.RunVerificationOptions{
		Ctx:             contextBackground(),
		RootDir:         rootDir,
		Approval:        *approval,
		TimeoutSeconds:  timeoutSeconds,
		VerifierRootDir: root,
	})
	if err != nil {
		return 0, err
	}
	for _, check := range result.Checks {
		baseline := ""
		if check.Baseline != nil {
			baseline = fmt.Sprintf(" | baseline exit %d", check.Baseline.ExitCode)
			if check.Baseline.SuspectEnvironmental {
				baseline += " (suspeito de ambiente)"
			}
		}
		fmt.Fprintf(r.out(), "  %s %s exit %d%s\n", padEnd(upper(check.Outcome), 7), padEnd(check.ID, 13), check.ExitCode, baseline)
		if check.Reason != "" {
			fmt.Fprintf(r.out(), "          → %s\n", check.Reason)
		}
	}

	receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{
		Approval:        *approval,
		Result:          result,
		VerifierRootDir: root,
	})
	if err != nil {
		return 0, err
	}
	written, err := verify.StoreReceipt(receipt, rootDir, root)
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(r.out(), "\nRecibo: %s (%s)\n", receipt.ReceiptID, receipt.Outcome)
	for _, file := range written {
		fmt.Fprintf(r.out(), "  gravado: %s\n", file)
	}
	if receipt.Outcome != "pass" {
		fmt.Fprintf(r.errOut(), "\n[NOT ACCEPTED] %s: a entrega não satisfez a aceitação independente.\n", receipt.Outcome)
		return 1, nil
	}
	fmt.Fprint(r.out(), "\n[ACCEPTED] entrega verificada independentemente; o status conta esta task como concluída.\n")
	return 0, nil
}

// verifyStatus informa se a árvore atual tem aceitação válida.
func (r *Runner) verifyStatus(args []string) (int, error) {
	workID, err := r.requireWorkID(args)
	if err != nil {
		return 0, err
	}
	global := flagValue(args, "--global")
	taskID := global
	if taskID == "" {
		taskID = flagValue(args, "--task")
	}
	if taskID == "" {
		return 0, fmt.Errorf("informe --task T ou --global G-n")
	}
	root, err := verify.Root()
	if err != nil {
		return 0, err
	}
	evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{
		RootDir:         r.rootDir(),
		WorkID:          workID,
		TaskID:          taskID,
		VerifierRootDir: root,
	})
	if evaluation.Accepted {
		receiptID := ""
		if evaluation.Receipt != nil {
			receiptID = evaluation.Receipt.ReceiptID
		}
		fmt.Fprintf(r.out(), "ACCEPTED %s/%s — recibo %s\n", workID, taskID, receiptID)
		return 0, nil
	}
	fmt.Fprintf(r.out(), "NOT ACCEPTED %s/%s — %s\n", workID, taskID, evaluation.Reason)
	return 1, nil
}

// verifyShow mostra a aprovação vigente e o último recibo.
func (r *Runner) verifyShow(args []string) (int, error) {
	workID, err := r.requireWorkID(args)
	if err != nil {
		return 0, err
	}
	taskID := flagValue(args, "--task")
	root, err := verify.Root()
	if err != nil {
		return 0, err
	}
	approvals := verify.ListApprovals(root)
	fmt.Fprintf(r.out(), "=== [pwn verify show] Verificador em %s ===\n", root)
	if len(approvals) == 0 {
		fmt.Fprint(r.out(), "  (nenhuma aprovação registrada para este Work)\n")
	}
	for _, approval := range approvals {
		if approval.WorkID != workID {
			continue
		}
		if taskID != "" && approval.TaskID != taskID {
			continue
		}
		fmt.Fprint(r.out(), "\n")
		fmt.Fprint(r.out(), describeApproval(approval))
		receipt := verify.LatestReceipt(workID, approval.TaskID, root)
		if receipt != nil {
			fmt.Fprintf(r.out(), "  Último recibo: %s (%s) em %s\n", receipt.ReceiptID, receipt.Outcome, receipt.CreatedAt)
			fmt.Fprintf(r.out(), "    snapshot avaliado: %s…\n", truncate(receipt.CandidateSnapshotDigest, 16))
			continue
		}
		fmt.Fprint(r.out(), "  Último recibo: (nenhum)\n")
	}
	return 0, nil
}

// ── run-all: um subprocesso `verify run` por aprovação vigente ──────────────

// verifyVerdict é o veredicto de uma aceitação, como no resumo da referência.
type verifyVerdict string

const (
	verdictAccepted    verifyVerdict = "ACCEPTED"
	verdictNotAccepted verifyVerdict = "NOT ACCEPTED"
	verdictBlocked     verifyVerdict = "BLOCKED"
)

// verdictOf traduz o resultado de um subprocesso em veredicto.
func verdictOf(result proc.Result) verifyVerdict {
	if result.Status == 0 && !result.TimedOut {
		return verdictAccepted
	}
	if result.Status == 2 {
		return verdictBlocked
	}
	return verdictNotAccepted
}

// aggregateVerifyExit devolve 0 se todas passaram, 2 se alguma ficou BLOCKED e
// 1 nos demais casos.
func aggregateVerifyExit(results []proc.Result) int {
	blocked := false
	notAccepted := false
	for _, result := range results {
		switch verdictOf(result) {
		case verdictBlocked:
			blocked = true
		case verdictNotAccepted:
			notAccepted = true
		}
	}
	if blocked {
		return 2
	}
	if notAccepted {
		return 1
	}
	return 0
}

// buildVerifyJobs monta um job `verify run` por aprovação vigente do Work.
func buildVerifyJobs(
	approvals []verify.Approval,
	workID string,
	executable string,
	timeoutSeconds int,
	isCurrent func(taskID string) bool,
) []proc.Job {
	seen := make(map[string]struct{}, len(approvals))
	jobs := make([]proc.Job, 0, len(approvals))
	for _, approval := range approvals {
		if approval.WorkID != workID {
			continue
		}
		if _, ok := seen[approval.TaskID]; ok {
			continue
		}
		if isCurrent != nil && !isCurrent(approval.TaskID) {
			continue
		}
		seen[approval.TaskID] = struct{}{}
		target := "--task"
		if globalTaskPattern.MatchString(approval.TaskID) {
			target = "--global"
		}
		jobs = append(jobs, proc.Job{
			ID: approval.TaskID,
			Command: []string{
				executable,
				"verify",
				"run",
				"--work",
				workID,
				target,
				approval.TaskID,
				"--timeout-seconds",
				strconv.Itoa(timeoutSeconds),
			},
		})
	}
	return jobs
}

// globalTaskPattern reconhece um item de `## Global gates` (G-1, G-2, ...).
var globalTaskPattern = regexp.MustCompile(`^G-\d+$`)

// verifyTimeoutSeconds valida --timeout-seconds para o run-all.
func verifyTimeoutSeconds(args []string) (int, error) {
	raw := flagValue(args, "--timeout-seconds")
	if raw == "" {
		return 600, nil
	}
	value, err := parsePositiveNumber(raw)
	if err != nil {
		return 0, fmt.Errorf("--timeout-seconds inválido")
	}
	seconds := int(value)
	if seconds < 1 {
		seconds = 1
	}
	return seconds, nil
}

// verifyRunAll executa em paralelo as aprovações vigentes do Work.
func (r *Runner) verifyRunAll(args []string) int {
	code, err := r.verifyRunAllAction(args)
	if err != nil {
		return r.reportVerifyError(err)
	}
	return code
}

// verifyRunAllAction executa o pool de subprocessos.
func (r *Runner) verifyRunAllAction(args []string) (int, error) {
	workID, err := r.requireWorkID(args)
	if err != nil {
		return 0, err
	}
	timeoutSeconds, err := verifyTimeoutSeconds(args)
	if err != nil {
		return 0, err
	}
	concurrency := proc.DefaultConcurrency()
	if raw := flagValue(args, "--jobs"); raw != "" {
		jobs, err := parsePositiveInt(raw)
		if err != nil {
			return 0, fmt.Errorf("--jobs deve ser inteiro >= 1")
		}
		concurrency = jobs
	}

	root, err := verify.Root()
	if err != nil {
		return 0, err
	}
	executable, err := selfExecutable()
	if err != nil {
		return 0, err
	}
	jobs := buildVerifyJobs(
		verify.ListApprovals(root),
		workID,
		executable,
		timeoutSeconds,
		func(taskID string) bool { return verify.CurrentApproval(workID, taskID, root) != nil },
	)

	fmt.Fprintf(r.out(), "=== [pwn verify run-all] Work %s: %d task(s), jobs=%d ===\n", workID, len(jobs), concurrency)
	if len(jobs) == 0 {
		fmt.Fprintf(r.errOut(), "[VERIFICATION BLOCKED] nenhuma aprovação vigente para o Work %s.\n", workID)
		return 2, nil
	}

	results := proc.RunPool(jobs, proc.Options{
		Concurrency: concurrency,
		Timeout:     secondsToDuration(float64(timeoutSeconds+60)) * 2,
		OnResult: func(result proc.Result) {
			timeoutMark := ""
			if result.TimedOut {
				timeoutMark = " (timeout)"
			}
			fmt.Fprintf(r.out(), "  %s %s %ss%s\n",
				padEnd(string(verdictOf(result)), 12), padEnd(result.ID, 8), secondsText(result.Duration), timeoutMark)
		},
	})

	counts := map[verifyVerdict]int{}
	for _, result := range results {
		counts[verdictOf(result)]++
	}
	fmt.Fprintf(r.out(), "\nResumo: %d accepted, %d not accepted, %d blocked\n",
		counts[verdictAccepted], counts[verdictNotAccepted], counts[verdictBlocked])
	for _, result := range results {
		if verdictOf(result) == verdictAccepted {
			continue
		}
		detail := result.Stderr
		if detail == "" {
			detail = result.Stdout
		}
		fmt.Fprintf(r.errOut(), "\n--- %s ---\n%s\n", result.ID, strings.TrimSpace(detail))
	}
	return aggregateVerifyExit(results), nil
}
