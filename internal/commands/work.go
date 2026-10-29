package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/harness/audit"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/proc"
)

// Work porta `pwn work <subcomando>` de src/commands/work.ts.
//
// `pwn work batch` ainda não foi portado: o pacote internal/harness/batch está
// em port paralelo. O subcomando responde com o código 1 e a mensagem de não
// portado.
func (r *Runner) Work(subcommand string, args []string) int {
	switch subcommand {
	case "init":
		return r.workInit(args)
	case "gate":
		return r.workGate(args)
	case "specify":
		fmt.Fprint(r.out(), "=== [pwn work specify] Especificando mudança / baseline ===\n")
		return plan.ValidatePromptMain(args, r.out(), r.errOut())
	case "contract":
		return r.workContract(args)
	case "import":
		return r.workImport(args)
	case "scaffold":
		return r.workScaffold(args)
	case "reconcile":
		return r.workReconcile(args)
	case "plan":
		return r.workPlan(args)
	case "run":
		return r.workRun(args)
	case "run-all":
		return r.workRunAll(args)
	case "audit":
		fmt.Fprint(r.out(), "=== [pwn work audit] Auditando Evidências e Aceitação ===\n")
		return audit.Main(workAuditArgs(args), r.out(), r.errOut())
	case "status":
		return r.workStatus(args)
	case "sync":
		return r.workSync(args)
	case "batch":
		fmt.Fprint(r.errOut(), "✗ pwn work batch: comando ainda não portado para Go\n")
		return 1
	default:
		fmt.Fprintf(r.errOut(), "Subcomando desconhecido para 'pwn work': %s\n", subcommand)
		fmt.Fprint(r.out(), "\nUso:\n")
		fmt.Fprint(r.out(), "  pwn work init <id>  Inicializa diretório de artefatos sob .pwn/work/<id>/\n")
		fmt.Fprint(r.out(), "  pwn work import    Importa Works do layout v3 (.work/, .todo/) para o layout canônico\n")
		fmt.Fprint(r.out(), "  pwn work scaffold  Cria um Work novo com cadeia completa (discovery→prd→spec→plan+CTR)\n")
		fmt.Fprint(r.out(), "  pwn work gate <id>  Executa gate determinístico (GATE-DISC-REQ, GATE-REQ-PRD, GATE-PRD-SPEC)\n")
		fmt.Fprint(r.out(), "  pwn work gate --all [--work NNNN] [--no-cache]  Executa os 5 gates e resume por gate\n")
		fmt.Fprint(r.out(), "  pwn work gate --clear-cache  Remove o cache de veredictos (.pwn/gate-cache/)\n")
		fmt.Fprint(r.out(), "  pwn work specify   Especifica mudanças no baseline\n")
		fmt.Fprint(r.out(), "  pwn work contract  Valida os contratos V4 congelados (.pwn/work/<id>/CTR-*.json)\n")
		fmt.Fprint(r.out(), "  pwn work contract --task <t> --freeze-tests <arquivos>  Congela testes de aceitação antes da implementação\n")
		fmt.Fprint(r.out(), "  pwn work plan      Valida o grafo e o plano de tarefas\n")
		fmt.Fprint(r.out(), "  pwn work run       Executa tarefas do work de forma autônoma (--no-gate, --no-isolation, --no-sync, --dry-run)\n")
		fmt.Fprint(r.out(), "  pwn work run-all   Executa vários Works em paralelo, um subprocesso `work run` por Work (--works 0001,0002 --jobs N --timeout-seconds S --no-gate -- <comando>)\n")
		fmt.Fprint(r.out(), "  pwn work batch     Lotes paralelos de tasks de um Work em worktrees: plan|prepare|integrate|rebase|abort (--work NNNN --jobs N --tasks 1.2,1.3 -- <regressão do plano>)\n")
		fmt.Fprint(r.out(), "  pwn work audit     Diagnóstico TDD local: baseline|red|green|verify|check (NÃO conclui a task — a aceitação é do pwn verify)\n")
		fmt.Fprint(r.out(), "  pwn work status    Exibe o status do progresso do projeto\n")
		fmt.Fprint(r.out(), "  pwn work sync      Sincroniza o estado do manifest .work/NNNN.json com o plano\n")
		return 1
	}
}

// workInit cria o diretório do Work e os modelos de artefato.
func (r *Runner) workInit(args []string) int {
	rootDir := r.rootDir()
	requestedID := work.GetNextWorkID(rootDir)
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		requestedID = args[0]
	}
	paths, err := work.InitWorkDirectory(requestedID, rootDir)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	resolvedID := filepath.Base(paths.WorkDir)
	fmt.Fprintf(r.out(), "=== [pwn work init] Inicializando estrutura de artefatos para Work %s ===\n", resolvedID)
	fmt.Fprintf(r.out(), "✓ Estrutura criada em: %s\n", paths.WorkDir)
	fmt.Fprint(r.out(), "Artefatos gerados: intake.json, discovery.json, requirements.json, prd.json, traceability-matrix.json\n")
	return 0
}

// gateEvaluators é o mapa canônico gate → avaliador determinístico.
var gateEvaluators = map[string]func(workID, workDir string) gates.GateOutput{
	"GATE-DISC-REQ":      gates.EvaluateGateDiscReq,
	"GATE-REQ-PRD":       gates.EvaluateGateReqPrd,
	"GATE-PRD-SPEC":      gates.EvaluateGatePrdSpec,
	"GATE-SPEC-PLAN":     gates.EvaluateGateSpecPlan,
	"GATE-PLAN-CONTRACT": gates.EvaluateGatePlanContract,
}

// knownGates mantém a ordem de declaração do mapa da referência.
var knownGates = []string{
	"GATE-DISC-REQ",
	"GATE-REQ-PRD",
	"GATE-PRD-SPEC",
	"GATE-SPEC-PLAN",
	"GATE-PLAN-CONTRACT",
}

// workGate executa um gate, todos os gates ou limpa o cache.
func (r *Runner) workGate(args []string) int {
	rootDir := r.rootDir()
	noCache := hasFlag(args, "--no-cache")
	workID := flagValue(args, "--work")
	if workID == "" {
		workID = work.GetLatestWorkID(rootDir)
	}
	paths := work.GetWorkArtifactsPaths(workID, rootDir)

	if hasFlag(args, "--clear-cache") {
		fmt.Fprint(r.out(), "=== [pwn work gate] Limpando cache de gates ===\n")
		removed := gates.ClearGateCache(rootDir)
		fmt.Fprintf(r.out(), "✓ %d arquivo(s) de cache removido(s) de .pwn/gate-cache/.\n", removed)
		return 0
	}

	if hasFlag(args, "--all") {
		fmt.Fprintf(r.out(), "=== [pwn work gate] Executando todos os gates para Work %s ===\n", workID)
		outputs := gates.EvaluateAllGates(workID, paths.WorkDir)

		for _, gate := range outputs {
			fmt.Fprintf(r.out(), "\n── %s ──\n", gate.Gate)
			if len(gate.Findings) == 0 {
				fmt.Fprint(r.out(), "  (nenhum finding)\n")
				continue
			}
			for _, finding := range gate.Findings {
				fmt.Fprintf(r.out(), "  [%s] %s · %s · %s\n", finding.Severity, finding.ID, finding.Type, finding.Status)
				fmt.Fprintf(r.out(), "      %s\n", finding.Description)
				fmt.Fprintf(r.out(), "      resolução: %s (owner: %s)\n", finding.RequiredResolution, finding.ResolutionOwner)
			}
		}

		fmt.Fprint(r.out(), "\n── Resumo por gate ──\n")
		blocked := make([]string, 0, len(outputs))
		for _, gate := range outputs {
			fmt.Fprintf(r.out(), "%s: %s (%d findings)\n", gate.Gate, gate.Result, len(gate.Findings))
			if gate.Result == gates.ResultBlocked {
				blocked = append(blocked, gate.Gate)
			}
		}
		if len(blocked) > 0 {
			fmt.Fprintf(r.errOut(), "\n[GATE RESULT]: BLOCKED — %d gate(s) bloqueado(s): %s.\n", len(blocked), strings.Join(blocked, ", "))
			return 1
		}
		fmt.Fprint(r.out(), "\n[GATE RESULT]: PASS — todos os gates aprovados.\n")
		return 0
	}

	gateID := "GATE-DISC-REQ"
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		gateID = args[0]
	}
	evaluator, ok := gateEvaluators[gateID]
	if !ok {
		fmt.Fprintf(r.errOut(), "Gate desconhecido: %s. Opções: %s\n", gateID, strings.Join(knownGates, ", "))
		return 1
	}

	// A chave do cache deriva do próprio GateOutput (input_versions), portanto a
	// avaliação antecede a consulta; um hit reutiliza o veredicto gravado.
	fresh := evaluator(workID, paths.WorkDir)
	var cached *gates.GateOutput
	if !noCache {
		cached = gates.ReadGateCache(gateID, rootDir, fresh.InputVersions)
	}
	output := fresh
	if cached != nil {
		output = *cached
	}

	cacheMark := ""
	if cached != nil {
		cacheMark = " (cache)"
	}
	fmt.Fprintf(r.out(), "=== [pwn work gate] Executando Gate %s para Work %s%s ===\n", gateID, workID, cacheMark)
	r.printGate(output)

	if cached == nil && !noCache {
		// O cache é otimização: uma falha de IO não interrompe o gate.
		_ = gates.WriteGateCache(fresh, rootDir)
	}

	if output.Result == gates.ResultBlocked {
		fmt.Fprintf(r.errOut(), "\n[GATE RESULT]: BLOCKED — Existem lacunas ou conflitos materiais no Work %s.\n", workID)
		return 1
	}
	fmt.Fprintf(r.out(), "\n[GATE RESULT]: %s — Gate aprovado.\n", upper(string(output.Result)))
	return 0
}

// printGate escreve o GateOutput com a forma de JSON.stringify(gate, null, 2).
func (r *Runner) printGate(output gates.GateOutput) {
	compact, err := gates.MarshalOutput(output)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return
	}
	fmt.Fprintln(r.out(), pretty.String())
}

// workContract valida os contratos V4 ou congela testes de aceitação.
func (r *Runner) workContract(args []string) int {
	rootDir := r.rootDir()
	if hasFlag(args, "--freeze-tests") {
		fmt.Fprint(r.out(), "=== [pwn work contract --freeze-tests] Congelando testes de aceitação no contrato ===\n")
		workID := flagValue(args, "--work")
		if workID == "" {
			workID = work.GetLatestWorkID(rootDir)
		}
		taskID := flagValue(args, "--task")
		paths := flagListAfter(args, "--freeze-tests")
		if taskID == "" {
			fmt.Fprint(r.errOut(), "Uso: pwn work contract --work NNNN --task 1.1 --freeze-tests <arquivo-de-teste>...\n")
			return 1
		}
		result, err := plan.FreezeAcceptanceTests(contextBackground(), plan.FreezeOptions{
			WorkID:  workID,
			TaskID:  taskID,
			Paths:   paths,
			RootDir: rootDir,
		})
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
		fmt.Fprintf(r.out(), "✓ %d teste(s) congelado(s) em %s:\n", len(result.Frozen), result.ContractID)
		for _, entry := range result.Frozen {
			fmt.Fprintf(r.out(), "  %s  %s\n", truncate(entry.SHA256, 12), entry.Path)
		}
		fmt.Fprint(r.out(), "\nAo menos um AC da task precisa exercitar cada arquivo; o audit recusa a atestação se algum deles mudar.\n")
		return 0
	}

	fmt.Fprint(r.out(), "=== [pwn work contract] Validando contratos V4 congelados do Work ===\n")
	workID := flagValue(args, "--work")
	if workID == "" {
		workID = work.GetLatestWorkID(rootDir)
	}
	tasksPlan := plan.LoadPlan(workID, rootDir)
	if tasksPlan == nil {
		fmt.Fprintf(r.errOut(), "Nenhum plan.json encontrado em .pwn/work/%s/. Rode 'pwn work init %s' e defina as tasks antes de validar os contratos.\n", workID, workID)
		return 1
	}

	fmt.Fprintf(r.out(), "Work %s — %d task(s) no plano\n\n", workID, len(tasksPlan.Tasks))
	failures := 0
	for _, task := range tasksPlan.Tasks {
		taskContract, err := plan.LoadTaskContract(workID, task.ID, rootDir)
		if err == nil {
			err = validateFrozenContract(taskContract)
		}
		if err != nil {
			failures++
			fmt.Fprintf(r.errOut(), "✗ %s — %s\n", task.ID, err.Error())
			continue
		}
		fmt.Fprintf(r.out(), "✓ %s — %s | risco %s | %s\n",
			task.ID, task.ContractID, taskContract.Risk.Level, taskContract.ValidationStrategy)
		fmt.Fprintf(r.out(), "    write_allow: %s\n", strings.Join(taskContract.ScopeContract.WriteAllow, ", "))
		fmt.Fprintf(r.out(), "    aceitação:   %s\n", strings.Join(taskContract.AcceptanceContract.Commands, " ; "))
		if len(taskContract.AcceptanceContract.FrozenTests) > 0 {
			frozen := make([]string, 0, len(taskContract.AcceptanceContract.FrozenTests))
			for _, entry := range taskContract.AcceptanceContract.FrozenTests {
				frozen = append(frozen, entry.Path)
			}
			fmt.Fprintf(r.out(), "    congelados:  %s\n", strings.Join(frozen, ", "))
		}
	}

	if failures > 0 {
		fmt.Fprintf(r.errOut(), "\n[CONTRACT RESULT]: FAIL — %d contrato(s) inválido(s) ou ausente(s). A execução ficaria bloqueada.\n", failures)
		return 1
	}
	fmt.Fprint(r.out(), "\n[CONTRACT RESULT]: PASS — todos os contratos V4 estão congelados e utilizáveis.\n")
	return 0
}

// validateFrozenContract recusa um contrato sem os campos que a execução exige.
func validateFrozenContract(taskContract *contract.TaskContractV4) error {
	if taskContract.Risk.Level == "" {
		return fmt.Errorf("risk.level ausente no contrato")
	}
	if len(taskContract.ScopeContract.WriteAllow) == 0 {
		return fmt.Errorf("scope_contract.write_allow vazio")
	}
	if len(taskContract.AcceptanceContract.Commands) == 0 {
		return fmt.Errorf("acceptance_contract.commands vazio (fail-closed: nenhuma execução seria autorizada)")
	}
	return nil
}

// validRisks são os níveis aceitos por scaffold e reconcile.
var validRisks = []string{"L0", "L1", "L2", "L3", "L4"}

// workImport importa Works do layout v3 para o layout canônico.
func (r *Runner) workImport(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work import] Importando Works do layout v3 para o layout canônico ===\n")
	rootDir := r.resolvedDir(args)
	requested := flagValue(args, "--work")
	all := hasFlag(args, "--all")
	force := hasFlag(args, "--force")
	gateChain := hasFlag(args, "--gate-chain")
	riskArg := flagValue(args, "--risk")
	if riskArg == "" {
		riskArg = "L2"
	}

	validImportRisks := append([]string{"auto"}, validRisks...)
	if !containsString(validImportRisks, riskArg) {
		fmt.Fprintf(r.errOut(), "--risk inválido: %s. Opções: %s\n", riskArg, strings.Join(validImportRisks, ", "))
		return 1
	}

	available := work.ListV3WorkIDs(rootDir)
	if len(available) == 0 {
		fmt.Fprintf(r.errOut(), "Nenhum Work v3 encontrado em %s (esperado NNNN-tasks.md).\n", filepath.Join(rootDir, ".todo"))
		return 1
	}

	targets := available
	if requested != "" {
		targets = []string{requested}
		if !containsString(available, requested) && !all {
			fmt.Fprintf(r.errOut(), "⚠  Work %s não está em .todo/ (%s); tentando mesmo assim.\n", requested, strings.Join(available, ", "))
		}
	}

	gateChainMark := "não"
	if gateChain {
		gateChainMark = "sim"
	}
	forceMark := "não"
	if force {
		forceMark = "sim"
	}
	fmt.Fprintf(r.out(), "Raiz: %s\n", rootDir)
	fmt.Fprintf(r.out(), "Works: %s | risco: %s | gate-chain: %s | force: %s\n\n", strings.Join(targets, ", "), riskArg, gateChainMark, forceMark)

	for _, workID := range targets {
		fmt.Fprintf(r.out(), "── Work %s ──\n", workID)
		result, err := work.ImportV3Work(work.V3ImportOptions{
			RootDir:   rootDir,
			WorkID:    workID,
			Force:     force,
			Risk:      riskArg,
			GateChain: gateChain,
		})
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ Work %s: %s\n", workID, err.Error())
			return 1
		}
		fmt.Fprintf(r.out(), "✓ %d artefato(s) em .pwn/work/%s/: %s\n", len(result.Generated), workID, strings.Join(result.Generated, ", "))
		for _, skip := range result.Skipped {
			fmt.Fprintf(r.out(), "  · ignorado %s: %s\n", skip.File, skip.Reason)
		}
		for _, warning := range result.Warnings {
			fmt.Fprintf(r.errOut(), "  ! %s\n", warning)
		}
		mapped := make([]string, 0, len(result.CapabilityMapping))
		for _, entry := range result.CapabilityMapping {
			if entry.Score > 0 {
				mapped = append(mapped, entry.Task+"→"+entry.Capability)
			}
		}
		if len(mapped) > 0 {
			fmt.Fprintf(r.out(), "  capability mapping: %s\n", strings.Join(mapped, ", "))
		}
		if riskArg == "auto" {
			perTask := make([]string, 0, len(result.RiskMapping))
			for _, entry := range result.RiskMapping {
				perTask = append(perTask, entry.Task+"="+string(entry.Risk))
			}
			fmt.Fprintf(r.out(), "  risco por task: %s\n", strings.Join(perTask, ", "))
		} else {
			risks := make([]string, 0, len(result.RiskMapping))
			seen := make(map[string]struct{}, len(result.RiskMapping))
			for _, entry := range result.RiskMapping {
				value := string(entry.Risk)
				if _, ok := seen[value]; ok {
					continue
				}
				seen[value] = struct{}{}
				risks = append(risks, value)
			}
			sort.Strings(risks)
			fmt.Fprintf(r.out(), "  risco congelado: %s\n", strings.Join(risks, ", "))
		}
		fmt.Fprint(r.out(), "\n")
	}

	fmt.Fprint(r.out(), "ℹ  Os artefatos v3 (.work/, .todo/, .prompts/, .sources/, .specs/) não foram alterados.\n")
	fmt.Fprint(r.out(), "   Próximos passos: pwn work contract --work <id> | pwn work plan --work <id> | pwn validate\n")
	return 0
}

// workScaffold cria um Work com a cadeia documental completa.
func (r *Runner) workScaffold(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work scaffold] Criando cadeia completa e válida de Work ===\n")
	rootDir := r.resolvedDir(args)
	title := flagValue(args, "--title")
	workID := flagValue(args, "--work")
	sourcePath := flagValue(args, "--source")
	force := hasFlag(args, "--force")
	risk := flagValue(args, "--risk")
	if risk == "" {
		risk = "L2"
	}

	if title == "" {
		fmt.Fprint(r.errOut(), "Uso: pwn work scaffold --title \"<titulo>\" [--work NNNN] [--source spec.md] [--risk Lx] [--dir PATH] [--force]\n")
		return 1
	}
	if !containsString(validRisks, risk) {
		fmt.Fprintf(r.errOut(), "--risk inválido: %s. Opções: %s\n", risk, strings.Join(validRisks, ", "))
		return 1
	}

	result, err := work.ScaffoldWork(work.ScaffoldOptions{
		RootDir:    rootDir,
		Title:      title,
		WorkID:     workID,
		SourcePath: sourcePath,
		Risk:       contract.RiskLevel(risk),
		Force:      force,
	})
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	fmt.Fprintf(r.out(), "✓ Work %s criado em %s\n", result.WorkID, result.WorkDir)
	fmt.Fprintf(r.out(), "Artefatos gerados (%d):\n", len(result.Generated))
	for _, file := range result.Generated {
		fmt.Fprintf(r.out(), "  + %s\n", file)
	}
	for _, skip := range result.Skipped {
		fmt.Fprintf(r.out(), "  · ignorado %s: %s\n", skip.File, skip.Reason)
	}
	fmt.Fprint(r.out(), "\nRevisão obrigatória antes de implementar:\n")
	for _, note := range result.Review {
		fmt.Fprintf(r.out(), "  ! %s\n", note)
	}
	fmt.Fprintf(r.out(), "\nPróximos passos:\n  pwn work contract --work %s\n  pwn work gate GATE-PLAN-CONTRACT --work %s\n  pwn validate --work %s\n  pwn task capsule 1.1 %s\n",
		result.WorkID, result.WorkID, result.WorkID, result.WorkID)
	return 0
}

// workReconcile concilia mudanças feitas fora do pwn.
func (r *Runner) workReconcile(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work reconcile] Conciliando mudanças feitas fora do pwn ===\n")
	rootDir := r.resolvedDir(args)
	risk := flagValue(args, "--risk")
	if risk == "" {
		risk = "L2"
	}
	dryRun := hasFlag(args, "--dry-run")
	list := func(name string) []string {
		raw := flagValue(args, name)
		if raw == "" {
			return nil
		}
		items := make([]string, 0)
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				items = append(items, item)
			}
		}
		return items
	}

	if !containsString(validRisks, risk) {
		fmt.Fprintf(r.errOut(), "--risk inválido: %s. Opções: %s\n", risk, strings.Join(validRisks, ", "))
		return 1
	}

	result, err := work.ReconcileChanges(work.ReconcileOptions{
		RootDir: rootDir,
		Since:   flagValue(args, "--since"),
		Paths:   list("--paths"),
		Tests:   list("--tests"),
		Title:   flagValue(args, "--title"),
		WorkID:  flagValue(args, "--work"),
		Risk:    contract.RiskLevel(risk),
		Force:   hasFlag(args, "--force"),
		DryRun:  dryRun,
	})
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}

	fmt.Fprintf(r.out(), "Referência: %s | HEAD: %s\n", truncate(result.BaseCommit, 12), truncate(result.HeadCommit, 12))
	fmt.Fprintf(r.out(), "Mudanças a conciliar (%d):\n", len(result.Changes))
	for _, change := range result.Changes {
		kind := "código"
		if change.Kind == "test" {
			kind = "teste "
		}
		fmt.Fprintf(r.out(), "  %s %s %s\n", change.Status, kind, change.Path)
	}
	for _, skip := range result.Skipped {
		fmt.Fprintf(r.out(), "  · ignorado %s: %s\n", skip.Path, skip.Reason)
	}
	tasks := make([]string, 0, len(result.Tasks))
	for _, task := range result.Tasks {
		tasks = append(tasks, fmt.Sprintf("%s [%d arquivo(s)]", task.ID, len(task.ImplementationFiles)))
	}
	fmt.Fprintf(r.out(), "Tasks (%d): %s\n", len(result.Tasks), strings.Join(tasks, ", "))

	if result.DryRun {
		fmt.Fprint(r.out(), "\n(--dry-run) nada foi criado. Rode sem --dry-run para criar o Work.\n")
		return 0
	}

	workID := ""
	if result.WorkID != nil {
		workID = *result.WorkID
	}
	fmt.Fprintf(r.out(), "\n✓ Work %s criado em .pwn/work/%s/ (%d artefato(s))\n", workID, workID, len(result.Generated))
	if len(result.Frozen) > 0 {
		fmt.Fprintf(r.out(), "✓ Testes congelados no contrato: task(s) %s\n", strings.Join(result.Frozen, ", "))
	}
	for _, pending := range result.PendingFreeze {
		var task *work.ReconcileTask
		for i := range result.Tasks {
			if result.Tasks[i].ID == pending.Task {
				task = &result.Tasks[i]
				break
			}
		}
		if task != nil && task.TestsToWrite {
			fmt.Fprintf(r.errOut(), "! task %s: a mudança não tem teste — escrever depois: %s\n", task.ID, strings.Join(task.TestFiles, " "))
			fmt.Fprintf(r.errOut(), "  O contrato já autoriza esse arquivo. O teste deve FALHAR com %s no commit-base %s.\n",
				strings.Join(task.ImplementationFiles, ", "), truncate(result.BaseCommit, 7))
			fmt.Fprintf(r.errOut(), "  Escreva e commite o teste; depois: pwn work contract --work %s --task %s --freeze-tests %s\n",
				workID, task.ID, strings.Join(task.TestFiles, " "))
			continue
		}
		fmt.Fprintf(r.errOut(), "! task %s: testes ainda não congelados — %s\n", pending.Task, pending.Reason)
		if task != nil {
			fmt.Fprintf(r.errOut(), "  Comite os testes e rode: pwn work contract --work %s --task %s --freeze-tests %s\n",
				workID, task.ID, strings.Join(task.TestFiles, " "))
		}
	}
	fmt.Fprint(r.out(), "\nA conciliação não conclui nada: sem RED/GREEN observado, a prova é o recibo do verificador.\n")
	fmt.Fprint(r.out(), "Próximos passos:\n")
	fmt.Fprintf(r.out(), "  pwn work gate --all --work %s\n", workID)
	for _, task := range result.Tasks {
		fmt.Fprintf(r.out(), "  pwn verify approve --work %s --task %s --by <nome> && pwn verify run --work %s --task %s\n",
			workID, task.ID, workID, task.ID)
	}
	return 0
}

// workPlan renderiza e valida o plano de tarefas.
func (r *Runner) workPlan(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work plan] Planejando / Validando Grafo de Tarefas ===\n")
	rootDir := r.rootDir()
	hasForce := hasFlag(args, "--force")
	flagWorkID := flagValue(args, "--work")

	var pathArg string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") || (flagWorkID != "" && arg == flagWorkID) {
			continue
		}
		pathArg = arg
		break
	}

	workID := flagWorkID
	if workID == "" {
		if pathArg != "" && work.NumberedPlanPattern.MatchString(filepath.Base(pathArg)) {
			workID = work.NumberedPlanPattern.FindStringSubmatch(filepath.Base(pathArg))[1]
		} else {
			workID = work.GetLatestWorkID(rootDir)
		}
	}

	if tasksPlan := plan.LoadPlan(workID, rootDir); tasksPlan != nil {
		rendered := plan.RenderTasksMarkdown(*tasksPlan)
		target := pathArg
		if target == "" {
			target = plan.TasksMarkdownPath(workID, rootDir)
		}

		_, statErr := os.Stat(target)
		switch {
		case os.IsNotExist(statErr):
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
				return 1
			}
			if err := os.WriteFile(target, []byte(rendered), 0o644); err != nil {
				fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
				return 1
			}
			fmt.Fprintf(r.out(), "✓ Plano gerado a partir de plan.json em: %s\n", target)
		case hasForce:
			if err := os.WriteFile(target, []byte(rendered), 0o644); err != nil {
				fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
				return 1
			}
			fmt.Fprintf(r.out(), "✓ Plano regenerado (--force) em: %s\n", target)
		default:
			existing, readErr := os.ReadFile(target)
			if readErr != nil {
				fmt.Fprintf(r.errOut(), "✗ %s\n", readErr.Error())
				return 1
			}
			if !plan.PlanMatchesMarkdown(*tasksPlan, string(existing)) {
				fmt.Fprint(r.errOut(), "⚠  DRIFT: o markdown diverge de plan.json (edição manual ou fora de sincronia).\n")
				fmt.Fprintf(r.errOut(), "   Regenere com: pwn work plan --work %s --force\n", workID)
			}
		}

		return plan.ValidateTasksMain([]string{target}, r.out(), r.errOut())
	}

	if pathArg == "" {
		fmt.Fprintf(r.errOut(), "Nenhum plan.json encontrado para o Work %s. Rode 'pwn work init' e crie .pwn/work/%s/plan.json, ou informe um caminho de plano markdown.\n", workID, workID)
		return 1
	}
	return plan.ValidateTasksMain([]string{pathArg}, r.out(), r.errOut())
}

// workRun executa o Work via pipeline governado.
func (r *Runner) workRun(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work run] Executando Work via Pipeline ===\n")
	rootDir := r.rootDir()
	hasNoGate := hasFlag(args, "--no-gate")
	noIsolation := hasFlag(args, "--no-isolation")
	noSync := hasFlag(args, "--no-sync")
	workID := flagValue(args, "--work")
	if workID == "" {
		workID = work.GetLatestWorkID(rootDir)
	}
	taskID := flagValue(args, "--task")
	timeoutSeconds := timeoutSecondsValue(args)
	command := commandAfterSeparator(args)

	if hasFlag(args, "--dry-run") {
		return r.workRunDryRun(rootDir, workID, taskID, command)
	}

	// ── Pré-condição obrigatória: cadeia determinística de 5 gates ──
	if !hasNoGate {
		paths := work.GetWorkArtifactsPaths(workID, rootDir)
		if _, err := os.Stat(paths.WorkDir); os.IsNotExist(err) {
			fmt.Fprintf(r.errOut(), "\n[GATE BLOCKED] Work %s não existe em %s. Rode 'pwn work init %s' e complete a cadeia de artefatos antes de 'pwn work run'.\n", workID, paths.WorkDir, workID)
			return 1
		}

		gateChain := []struct {
			id   string
			eval func() gates.GateOutput
		}{
			{"GATE-DISC-REQ", func() gates.GateOutput { return gates.EvaluateGateDiscReq(workID, paths.WorkDir) }},
			{"GATE-REQ-PRD", func() gates.GateOutput { return gates.EvaluateGateReqPrd(workID, paths.WorkDir) }},
			{"GATE-PRD-SPEC", func() gates.GateOutput { return gates.EvaluateGatePrdSpec(workID, paths.WorkDir) }},
			{"GATE-SPEC-PLAN", func() gates.GateOutput { return gates.EvaluateGateSpecPlan(workID, paths.WorkDir) }},
			{"GATE-PLAN-CONTRACT", func() gates.GateOutput { return gates.EvaluateGatePlanContract(workID, paths.WorkDir) }},
		}

		blocked := false
		for _, entry := range gateChain {
			gate := entry.eval()
			r.printGate(gate)
			if gate.Result == gates.ResultBlocked {
				fmt.Fprintf(r.errOut(), "\n[GATE BLOCKED] %s bloqueou o Work %s. Resolva os findings ou use --no-gate somente se o risco for aceito por humano.\n", entry.id, workID)
				blocked = true
				break
			}
			fmt.Fprintf(r.out(), "✓ %s: %s\n", entry.id, gate.Result)
		}
		if blocked {
			return 1
		}

		// ── Guarda de drift: plan.json é a fonte única; o markdown derivado não pode divergir ──
		if runPlan := plan.LoadPlan(workID, rootDir); runPlan != nil {
			mdPath := plan.TasksMarkdownPath(workID, rootDir)
			if _, err := os.Stat(mdPath); err == nil {
				existing, readErr := os.ReadFile(mdPath)
				if readErr == nil && !plan.PlanMatchesMarkdown(*runPlan, string(existing)) {
					fmt.Fprintf(r.errOut(), "\n[DRIFT BLOCKED] .todo/%s-tasks.md diverge de plan.json. Regenere com 'pwn work plan --work %s --force' ou resolva a divergência.\n", workID, workID)
					return 1
				}
			}
		}

		fmt.Fprint(r.out(), "✓ Todos os gates determinísticos aprovados — Work elegível para execução.\n")
	} else {
		fmt.Fprint(r.errOut(), "⚠  Gates bypassados (--no-gate): execução sem validação da cadeia determinística.\n")
	}

	if noIsolation {
		fmt.Fprint(r.errOut(), "⚠  Sandbox desabilitado (--no-isolation): execução no diretório de trabalho, sem diff guard.\n")
	}

	if len(command) == 0 {
		fmt.Fprint(r.errOut(), "Nenhum comando informado. Uso: pwn work run --work NNNN --timeout-seconds N -- <comando>\n")
		return 1
	}

	isolated := !noIsolation
	result := run.Run(contextBackground(), run.Options{
		WorkID:   workID,
		TaskID:   taskID,
		Command:  command,
		Timeout:  secondsToDuration(float64(timeoutSeconds)),
		RootDir:  rootDir,
		Isolated: &isolated,
		Log:      r.errOut(),
	})
	if result.Stdout != "" {
		fmt.Fprintf(r.out(), "%s\n", result.Stdout)
	}
	if result.Stderr != "" {
		fmt.Fprintf(r.errOut(), "%s\n", result.Stderr)
	}
	if len(result.DiffViolations) > 0 {
		fmt.Fprint(r.errOut(), "\n[DIFF VIOLATION] Arquivos fora do escopo do contrato:\n")
		for _, violation := range result.DiffViolations {
			fmt.Fprintf(r.errOut(), "  - %s\n", violation)
		}
	}
	if taskID != "" && result.Status != 0 && !result.Suspended {
		fmt.Fprintf(r.errOut(), "[RUN FAILED] Execução terminou com status %d para a task %s (work %s).\n", result.Status, taskID, workID)
	}

	var verification *verify.AutoVerification
	if result.Suspended {
		subject := taskID
		if subject == "" {
			subject = "(work)"
		}
		fmt.Fprintf(r.errOut(), "\n[SUSPENDED] A task %s do Work %s não foi executada: aguarda decisão humana na fila AFK.\n", subject, workID)
		fmt.Fprintf(r.errOut(), "Use 'pwn queue approve %s' para destravar (exit code %d).\n", result.RunID, result.Status)
	} else if taskID == "" {
		fmt.Fprint(r.out(), "· Aceitação independente exige --task (ou use: pwn verify run --work NNNN --task T).\n")
	} else if result.Status == 0 {
		// A execução terminou: a aceitação independente roda SEM depender do agente.
		auto, err := verify.AfterRun(verify.AfterRunOptions{
			RootDir:        rootDir,
			WorkID:         workID,
			TaskID:         taskID,
			TimeoutSeconds: timeoutSeconds,
		})
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
		verification = &auto
		verify.ReportAutoVerification(auto, r.out(), r.errOut())
	}

	if result.Suspended {
		// Suspensão L4 não altera estado de governança.
	} else if noSync {
		fmt.Fprintf(r.out(), "· Manifest .work/%s.json não sincronizado (--no-sync).\n", workID)
	} else if state, err := work.SyncWorkManifest(workID, rootDir); err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	} else if state != work.ManifestAbsent {
		fmt.Fprintf(r.out(), "✓ Manifest .work/%s.json → state: %s\n", workID, state)
	}

	if verification != nil && verification.Attempted && verification.Outcome != "pass" {
		return 1
	}
	return result.Status
}

// workRunDryRun valida a cadeia inteira e reporta impedimentos sem executar nada.
func (r *Runner) workRunDryRun(rootDir, workID, taskID string, command []string) int {
	fmt.Fprintf(r.out(), "=== [pwn work run] Simulação (--dry-run) do Work %s — nada será executado ===\n", workID)
	paths := work.GetWorkArtifactsPaths(workID, rootDir)
	impediments := make([]string, 0)

	fmt.Fprint(r.out(), "\n── Gates ──\n")
	for _, gate := range gates.EvaluateAllGates(workID, paths.WorkDir) {
		fmt.Fprintf(r.out(), "%s: %s (%d findings)\n", gate.Gate, gate.Result, len(gate.Findings))
		if gate.Result != gates.ResultBlocked {
			continue
		}
		material := make([]string, 0)
		for _, finding := range gate.Findings {
			if finding.Status == contract.FindingStatusOpen &&
				(finding.Severity == contract.SeverityCritical || finding.Severity == contract.SeverityHigh) {
				material = append(material, finding.ID)
			}
		}
		detail := fmt.Sprintf("%d finding(s)", len(gate.Findings))
		if len(material) > 0 {
			detail = strings.Join(material, ", ")
		}
		impediments = append(impediments, fmt.Sprintf("%s: blocked — %s", gate.Gate, detail))
	}

	fmt.Fprint(r.out(), "\n── Contratos ──\n")
	dryPlan := plan.LoadPlan(workID, rootDir)
	if dryPlan == nil {
		fmt.Fprint(r.out(), "  (plan.json ausente)\n")
		impediments = append(impediments, fmt.Sprintf("plan.json ausente para o Work %s.", workID))
	} else {
		for _, task := range dryPlan.Tasks {
			taskContract, err := plan.LoadTaskContract(workID, task.ID, rootDir)
			if err != nil {
				impediments = append(impediments, fmt.Sprintf("Task %s: %s", task.ID, err.Error()))
				fmt.Fprintf(r.errOut(), "✗ %s — %s\n", task.ID, err.Error())
				continue
			}
			problems := make([]string, 0)
			if taskContract.Risk.Level == "" {
				problems = append(problems, "risk.level ausente")
			}
			if len(taskContract.ScopeContract.WriteAllow) == 0 {
				problems = append(problems, "scope_contract.write_allow vazio")
			}
			if len(taskContract.AcceptanceContract.Commands) == 0 {
				problems = append(problems, "acceptance_contract.commands vazio")
			}
			if len(problems) > 0 {
				for _, problem := range problems {
					impediments = append(impediments, fmt.Sprintf("Task %s (%s): %s", task.ID, task.ContractID, problem))
				}
				fmt.Fprintf(r.errOut(), "✗ %s — %s\n", task.ID, strings.Join(problems, "; "))
				continue
			}
			fmt.Fprintf(r.out(), "✓ %s — %s | risco %s | %d write_allow | %d comando(s)\n",
				task.ID, task.ContractID, taskContract.Risk.Level,
				len(taskContract.ScopeContract.WriteAllow), len(taskContract.AcceptanceContract.Commands))
		}
	}

	fmt.Fprint(r.out(), "\n── Impedimentos ──\n")
	if len(impediments) == 0 {
		fmt.Fprint(r.out(), "(nenhum) — Work elegível para execução.\n")
		return 0
	}
	for _, impediment := range impediments {
		fmt.Fprintf(r.errOut(), "  - %s\n", impediment)
	}
	fmt.Fprintf(r.errOut(), "\n[DRY-RUN]: %d impedimento(s). A execução ficaria bloqueada.\n", len(impediments))
	return 1
}

// workAuditArgs aplica a compatibilidade do audit: sem ação explícita, roda a
// verificação de evidência (verify).
func workAuditArgs(args []string) []string {
	knownActions := []string{"baseline", "red", "green", "verify", "check"}
	if len(args) > 0 && containsString(knownActions, args[0]) {
		return args
	}
	return append([]string{"verify"}, args...)
}

// workStatus escreve o status do projeto ou a cobertura do Work.
func (r *Runner) workStatus(args []string) int {
	rootDir := r.rootDir()
	if hasFlag(args, "--coverage") {
		workID := flagValue(args, "--work")
		if workID == "" {
			for _, arg := range args {
				if workIDPattern.MatchString(arg) {
					workID = arg
					break
				}
			}
		}
		if workID == "" {
			workID = work.GetLatestWorkID(rootDir)
		}
		paths := work.GetWorkArtifactsPaths(workID, rootDir)
		if _, err := os.Stat(paths.WorkDir); os.IsNotExist(err) {
			fmt.Fprintf(r.errOut(), "Work %s não encontrado em %s.\n", workID, paths.WorkDir)
			return 1
		}
		cov := gates.ComputeWorkCoverage(paths.WorkDir)
		fmt.Fprintf(r.out(), "=== [pwn work status --coverage] Cobertura do Work %s ===\n\n", workID)
		line := func(label string, value, total int) {
			mark := "·"
			if total != 0 {
				mark = "⚠"
				if value == total {
					mark = "✓"
				}
			}
			fmt.Fprintf(r.out(), "  %s %s %d/%d\n", mark, padEnd(label, 34), value, total)
		}
		line("requisitos aceitos", cov.AcceptedRequirements, cov.Requirements)
		line("capabilities com regras", cov.CapabilitiesWithRules, cov.Capabilities)
		line("tasks com contrato congelado", cov.TasksWithContract, cov.Tasks)
		line("tasks com critérios de aceite", cov.TasksWithACs, cov.Tasks)
		gaps := (cov.Requirements - cov.AcceptedRequirements) +
			(cov.Capabilities - cov.CapabilitiesWithRules) +
			(cov.Tasks - cov.TasksWithContract) +
			(cov.Tasks - cov.TasksWithACs)
		if gaps == 0 {
			fmt.Fprint(r.out(), "\n[COVERAGE RESULT]: COMPLETO\n")
			return 0
		}
		fmt.Fprintf(r.out(), "\n[COVERAGE RESULT]: %d lacuna(s)\n", gaps)
		return 1
	}

	fmt.Fprint(r.out(), "=== [pwn work status] Relatório de Status do Work ===\n")
	jsonOutput := hasFlag(args, "--json")
	positional := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--json" {
			positional = append(positional, arg)
		}
	}
	if len(positional) > 1 {
		fmt.Fprint(r.errOut(), "usage: project_status.js [NNNN | CANONICAL_PLAN_PATH | legacy] [--json]\n")
		return 2
	}

	if len(positional) == 0 {
		report, err := work.CollectWorkIndex(rootDir)
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
		if jsonOutput {
			r.printJSON(report)
			return 0
		}
		fmt.Fprintln(r.out(), work.RenderWorkIndex(report))
		return 0
	}

	report, err := work.CollectPlanStatus(positional[0], rootDir)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if jsonOutput {
		r.printJSON(report)
		return 0
	}
	fmt.Fprintln(r.out(), work.RenderMarkdown(report))
	return 0
}

// workSync projeta o estado real do Work no manifest v3.
func (r *Runner) workSync(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work sync] Sincronizando estado do manifest .work/NNNN.json ===\n")
	rootDir := r.rootDir()
	workID := flagValue(args, "--work")
	if workID == "" {
		workID = work.GetLatestWorkID(rootDir)
	}
	state, err := work.SyncWorkManifest(workID, rootDir)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	if state == work.ManifestAbsent {
		fmt.Fprintf(r.errOut(), "Manifest .work/%s.json não encontrado. Nada a sincronizar.\n", workID)
		return 1
	}
	fmt.Fprintf(r.out(), "✓ Manifest .work/%s.json → state: %s\n", workID, state)
	return 0
}

// ── run-all: pool de subprocessos `pwn work run`, um por Work ────────────────

// selfExecutableEnv aponta o binário que o run-all deve executar. Sem ela vale
// o executável do processo atual.
const selfExecutableEnv = "PWN_SELF_EXECUTABLE"

// exitTimeout é o código agregado de um subprocesso encerrado por timeout.
const exitTimeout = 124

// runAllOptions são as flags de `pwn work run-all`.
type runAllOptions struct {
	works          []string
	jobs           int
	timeoutSeconds float64
	noGate         bool
	command        []string
}

// flagValuePresent devolve o valor da flag e informa se ele não é nulo, com a
// mesma semântica do flagValue da referência: a flag ausente ou seguida de
// outra flag não tem valor.
func flagValuePresent(args []string, name string) (string, bool) {
	for i, arg := range args {
		if arg != name {
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return "", false
		}
		return args[i+1], true
	}
	return "", false
}

// parseRunAllArgs interpreta os argumentos de `pwn work run-all`.
func parseRunAllArgs(args []string) (runAllOptions, error) {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	own := args
	command := []string{}
	if separator != -1 {
		own = args[:separator]
		command = args[separator+1:]
	}

	options := runAllOptions{timeoutSeconds: 600, command: command}

	worksRaw, worksOK := flagValuePresent(own, "--works")
	if hasFlag(own, "--works") && !worksOK {
		return runAllOptions{}, fmt.Errorf("--works exige uma lista separada por vírgula (ex.: --works 0001,0002)")
	}
	if worksOK {
		seen := make(map[string]struct{})
		works := make([]string, 0)
		for _, id := range strings.Split(worksRaw, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			works = append(works, id)
		}
		if len(works) == 0 {
			return runAllOptions{}, fmt.Errorf("--works está vazio")
		}
		options.works = works
	}

	jobsRaw, jobsOK := flagValuePresent(own, "--jobs")
	if hasFlag(own, "--jobs") && !jobsOK {
		return runAllOptions{}, fmt.Errorf("--jobs exige um inteiro positivo")
	}
	if jobsOK {
		jobs, err := parsePositiveInt(jobsRaw)
		if err != nil {
			return runAllOptions{}, fmt.Errorf("--jobs inválido: '%s' (esperado inteiro >= 1)", jobsRaw)
		}
		options.jobs = jobs
	}

	timeoutRaw, timeoutOK := flagValuePresent(own, "--timeout-seconds")
	if hasFlag(own, "--timeout-seconds") && !timeoutOK {
		return runAllOptions{}, fmt.Errorf("--timeout-seconds exige um número positivo")
	}
	if timeoutOK {
		timeout, err := parsePositiveNumber(timeoutRaw)
		if err != nil {
			return runAllOptions{}, fmt.Errorf("--timeout-seconds inválido: '%s' (esperado número > 0)", timeoutRaw)
		}
		options.timeoutSeconds = timeout
	}

	options.noGate = hasFlag(own, "--no-gate")
	return options, nil
}

// parsePositiveInt aceita inteiros positivos, inclusive na forma decimal
// ("2.0"), como Number.isInteger da referência.
func parsePositiveInt(raw string) (int, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value != float64(int(value)) || value < 1 {
		return 0, fmt.Errorf("valor inválido")
	}
	return int(value), nil
}

// parsePositiveNumber aceita números finitos maiores que zero.
func parsePositiveNumber(raw string) (float64, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("valor inválido")
	}
	return value, nil
}

// formatNumber escreve o número como String(number) do JavaScript.
func formatNumber(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// buildRunAllJobs monta um job `work run` por Work, repassando flags e o `--`.
func buildRunAllJobs(args []string, works []string, executable string) ([]proc.Job, error) {
	options, err := parseRunAllArgs(args)
	if err != nil {
		return nil, err
	}
	jobs := make([]proc.Job, 0, len(works))
	for _, workID := range works {
		command := []string{executable, "work", "run", "--work", workID}
		if options.noGate {
			command = append(command, "--no-gate")
		}
		command = append(command, "--timeout-seconds", formatNumber(options.timeoutSeconds), "--")
		command = append(command, options.command...)
		jobs = append(jobs, proc.Job{ID: workID, Command: command})
	}
	return jobs, nil
}

// scopeOverlap descreve globs de `write_allow` que podem casar o mesmo arquivo.
type scopeOverlap struct {
	works    [2]string
	patterns [][2]string
}

// findScopeOverlaps detecta, para cada par de Works, globs de `write_allow`
// (união dos contratos) que se sobrepõem. A ordem dos Works é a da lista dada.
func findScopeOverlaps(workIDs []string, contractsByWork map[string][]contract.TaskContractV4) []scopeOverlap {
	type union struct {
		workID   string
		patterns []string
	}
	unions := make([]union, 0, len(workIDs))
	for _, workID := range workIDs {
		seen := make(map[string]struct{})
		patterns := make([]string, 0)
		for _, taskContract := range contractsByWork[workID] {
			for _, pattern := range taskContract.ScopeContract.WriteAllow {
				if _, ok := seen[pattern]; ok {
					continue
				}
				seen[pattern] = struct{}{}
				patterns = append(patterns, pattern)
			}
		}
		unions = append(unions, union{workID: workID, patterns: patterns})
	}

	overlaps := make([]scopeOverlap, 0)
	for i := range len(unions) {
		for j := i + 1; j < len(unions); j++ {
			patterns := make([][2]string, 0)
			for _, a := range unions[i].patterns {
				for _, b := range unions[j].patterns {
					if run.GlobsMayOverlap(a, b) {
						patterns = append(patterns, [2]string{a, b})
					}
				}
			}
			if len(patterns) > 0 {
				overlaps = append(overlaps, scopeOverlap{
					works:    [2]string{unions[i].workID, unions[j].workID},
					patterns: patterns,
				})
			}
		}
	}
	return overlaps
}

// aggregateExitCodes devolve 0 só quando todos os jobs terminaram em 0; senão o
// maior código não-zero, com timeout valendo 124.
func aggregateExitCodes(results []proc.Result) int {
	worst := 0
	for _, result := range results {
		code := result.Status
		if result.TimedOut {
			code = exitTimeout
		}
		if code != 0 && code > worst {
			worst = code
		}
	}
	return worst
}

// prefixLines prefixa cada linha com o Work, descartando as quebras finais.
func prefixLines(workID, text string) []string {
	trimmed := strings.TrimRight(text, "\n")
	lines := strings.Split(trimmed, "\n")
	prefixed := make([]string, 0, len(lines))
	for _, line := range lines {
		prefixed = append(prefixed, "["+workID+"] "+line)
	}
	return prefixed
}

// runIDPattern extrai o RUN-<id> da saída de um Work.
var runIDPattern = regexp.MustCompile(`\bRUN-[A-Za-z0-9_-]+`)

// parseRunID devolve o RUN-<id> citado na saída do subprocesso.
func parseRunID(result proc.Result) string {
	return runIDPattern.FindString(result.Stdout + "\n" + result.Stderr)
}

// selfExecutable devolve o binário que o run-all executa.
func selfExecutable() (string, error) {
	if override := os.Getenv(selfExecutableEnv); override != "" {
		return override, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("não foi possível localizar o executável do pwn: %w", err)
	}
	return executable, nil
}

// workRunAll executa um subprocesso `work run` por Work.
func (r *Runner) workRunAll(args []string) int {
	fmt.Fprint(r.out(), "=== [pwn work run-all] Executando Works em paralelo (um subprocesso por Work) ===\n")
	options, err := parseRunAllArgs(args)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		fmt.Fprint(r.errOut(), "Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando de aceitação>\n")
		return 1
	}
	if len(options.command) == 0 {
		fmt.Fprint(r.errOut(), "Nenhum comando informado. Uso: pwn work run-all [--works 0001,0002] [--jobs N] [--timeout-seconds S] [--no-gate] -- <comando>\n")
		return 1
	}

	rootDir := r.rootDir()
	works := options.works
	if works == nil {
		summaries, err := work.ListWorks(rootDir)
		if err != nil {
			fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
			return 1
		}
		works = make([]string, 0, len(summaries))
		for _, summary := range summaries {
			if summary.WorkID == "legacy" || !summary.PlanExists {
				continue
			}
			works = append(works, summary.WorkID)
		}
	}
	if len(works) == 0 {
		fmt.Fprint(r.errOut(), "Nenhum Work com plano encontrado. Informe --works NNNN,NNNN ou rode `pwn work scaffold`.\n")
		return 1
	}

	// Pré-checagem (não bloqueia): escopos sobrepostos entre Works podem conflitar no merge.
	contractsByWork := make(map[string][]contract.TaskContractV4, len(works))
	for _, workID := range works {
		loaded, err := plan.LoadWorkContracts(workID, rootDir)
		if err != nil {
			fmt.Fprintf(r.errOut(), "⚠  Work %s: contratos não carregados para a checagem de escopo (%s).\n", workID, err.Error())
			continue
		}
		values := make([]contract.TaskContractV4, 0, len(loaded))
		for _, taskContract := range loaded {
			if taskContract == nil {
				continue
			}
			values = append(values, *taskContract)
		}
		contractsByWork[workID] = values
	}
	for _, overlap := range findScopeOverlaps(works, contractsByWork) {
		sample := make([]string, 0, min(3, len(overlap.patterns)))
		for _, pair := range overlap.patterns[:min(3, len(overlap.patterns))] {
			sample = append(sample, pair[0]+" ↔ "+pair[1])
		}
		ellipsis := ""
		if len(overlap.patterns) > 3 {
			ellipsis = "; …"
		}
		fmt.Fprintf(r.errOut(), "⚠  Possível conflito de merge entre Works %s e %s: write_allow sobreposto (%s%s). Cada um roda em worktree isolado.\n",
			overlap.works[0], overlap.works[1], strings.Join(sample, "; "), ellipsis)
	}

	executable, err := selfExecutable()
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	jobs, err := buildRunAllJobs(args, works, executable)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		return 1
	}
	concurrency := options.jobs
	if concurrency == 0 {
		concurrency = proc.DefaultConcurrency()
	}
	running := concurrency
	if len(jobs) < running {
		running = len(jobs)
	}
	fmt.Fprintf(r.out(), "· %d Work(s): %s | jobs=%d\n", len(jobs), strings.Join(works, ", "), running)

	results := proc.RunPool(jobs, proc.Options{
		Concurrency: concurrency,
		// Rede de segurança acima do timeout do comando (gates + sandbox + verificação).
		Timeout: secondsToDuration(options.timeoutSeconds) + time.Minute,
		OnResult: func(result proc.Result) {
			for _, line := range prefixLines(result.ID, result.Stdout) {
				fmt.Fprintln(r.out(), line)
			}
			for _, line := range prefixLines(result.ID, result.Stderr) {
				fmt.Fprintln(r.errOut(), line)
			}
			if result.TimedOut {
				fmt.Fprintf(r.errOut(), "[%s] ✗ Subprocesso excedeu o tempo limite e foi encerrado.\n", result.ID)
			}
		},
	})

	fmt.Fprint(r.out(), "\n── Resumo run-all ──\n")
	failed := 0
	for _, result := range results {
		code := result.Status
		if result.TimedOut {
			code = exitTimeout
		}
		mark := "✓"
		if code != 0 {
			mark = "✗"
			failed++
		}
		timeoutMark := ""
		if result.TimedOut {
			timeoutMark = " (timeout)"
		}
		runIDMark := ""
		if runID := parseRunID(result); runID != "" {
			runIDMark = " | " + runID
		}
		fmt.Fprintf(r.out(), "%s Work %s: exit %d%s | %ss%s\n",
			mark, result.ID, code, timeoutMark, secondsText(result.Duration), runIDMark)
	}
	exitCode := aggregateExitCodes(results)
	if exitCode == 0 {
		fmt.Fprintf(r.out(), "[RUN-ALL]: %d Work(s) concluído(s) com sucesso.\n", len(results))
	} else {
		fmt.Fprintf(r.out(), "[RUN-ALL]: %d/%d Work(s) falharam (exit %d).\n", failed, len(results), exitCode)
	}
	return exitCode
}
