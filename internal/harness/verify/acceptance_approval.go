package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// GlobalTaskID identifica a aprovação de um item de `## Global gates`.
const GlobalTaskID = "GLOBAL"

// ApprovedCheck é um check congelado no pacote de aceitação.
type ApprovedCheck struct {
	// ID é `AC-n`, `VISUAL`, `DOCUMENTATION`, `REGRESSION` ou `G-n`.
	ID string `json:"id"`
	// Command é o argv executado no sandbox.
	Command []string `json:"command"`
	// ExpectOutput precisa aparecer na saída do candidato; nil quando não
	// declarado.
	ExpectOutput *string `json:"expect_output"`
	// RequireBaselineFailure exige que o check falhe com a implementação
	// revertida ao baseline.
	RequireBaselineFailure bool `json:"require_baseline_failure"`
}

// ApprovedFile é um arquivo de aceitação guardado na raiz protegida.
type ApprovedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ApprovalContent é o pacote de aceitação sem o identificador calculado.
type ApprovalContent struct {
	Version             int             `json:"version"`
	WorkID              string          `json:"work_id"`
	TaskID              string          `json:"task_id"`
	Kind                string          `json:"kind"`
	ApprovedBy          string          `json:"approved_by"`
	CreatedAt           string          `json:"created_at"`
	PlanPath            string          `json:"plan_path"`
	PlanSHA256          string          `json:"plan_sha256"`
	ContractID          *string         `json:"contract_id"`
	ContractSHA256      *string         `json:"contract_sha256"`
	BaselineCommit      string          `json:"baseline_commit"`
	ImplementationFiles []string        `json:"implementation_files"`
	Checks              []ApprovedCheck `json:"checks"`
	ApprovedFiles       []ApprovedFile  `json:"approved_files"`
}

// Approval é o pacote de aceitação aprovado.
//
// É o que o agente NÃO pode alterar: os comandos avaliados, a árvore de
// referência e o conteúdo dos testes de aceitação aprovados, guardado na raiz
// protegida do verificador.
type Approval struct {
	ApprovalID string `json:"approval_id"`
	ApprovalContent
}

// ApprovalIndex mapeia Work:task para a aprovação vigente.
type ApprovalIndex struct {
	Version int               `json:"version"`
	Current map[string]string `json:"current"`
}

func approvalIndexPath(root string) string {
	return filepath.Join(ApprovalsDir(root), "index.json")
}

func readApprovalIndex(root string) ApprovalIndex {
	empty := ApprovalIndex{Version: 1, Current: map[string]string{}}
	data, err := os.ReadFile(approvalIndexPath(root))
	if err != nil {
		return empty
	}
	var index ApprovalIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return empty
	}
	if index.Version != 1 || index.Current == nil {
		return empty
	}
	return index
}

// ApprovalPath devolve o caminho do pacote de aprovação.
func ApprovalPath(approvalID, root string) string {
	return filepath.Join(ApprovalsDir(root), approvalID+".json")
}

// ReadApproval lê um pacote de aprovação. Devolve nil quando ausente, inválido
// ou de versão diferente de 1.
func ReadApproval(approvalID, root string) *Approval {
	data, err := os.ReadFile(ApprovalPath(approvalID, root))
	if err != nil {
		return nil
	}
	var approval Approval
	if err := json.Unmarshal(data, &approval); err != nil {
		return nil
	}
	if approval.Version != 1 {
		return nil
	}
	return &approval
}

// CurrentApproval devolve a aprovação vigente de um par Work/task, ou nil
// quando nunca houve aprovação.
func CurrentApproval(workID, taskID, root string) *Approval {
	index := readApprovalIndex(root)
	id, ok := index.Current[fmt.Sprintf("%s:%s", workID, taskID)]
	if !ok || id == "" {
		return nil
	}
	return ReadApproval(id, root)
}

// ListApprovals devolve as aprovações vigentes em ordem de chave Work:task.
func ListApprovals(root string) []Approval {
	index := readApprovalIndex(root)
	keys := make([]string, 0, len(index.Current))
	for key := range index.Current {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	approvals := make([]Approval, 0, len(keys))
	for _, key := range keys {
		if approval := ReadApproval(index.Current[key], root); approval != nil {
			approvals = append(approvals, *approval)
		}
	}
	return approvals
}

// ApprovedFileContent devolve o conteúdo aprovado de um arquivo de aceitação,
// lido da raiz protegida.
func ApprovedFileContent(approval Approval, relative, root string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(ApprovalFilesDir(approval.ApprovalID, root), relative))
	if err != nil {
		return "", false
	}
	return string(data), true
}

// CreateApprovalOptions são as entradas de CreateApproval.
type CreateApprovalOptions struct {
	// Ctx limita os comandos de git. Nil usa context.Background.
	Ctx        context.Context
	RootDir    string
	WorkID     string
	TaskID     string
	ApprovedBy string
	// Global aprova um item de `## Global gates` em vez de uma task.
	Global string
	// VerifierRootDir é a raiz protegida. Vazio usa Root.
	VerifierRootDir string
	// BaselineCommit é o commit de referência (revert da implementação).
	// Vazio usa HEAD.
	BaselineCommit string
}

func commandTokens(command string) ([]string, error) {
	tokens, ok := plan.SplitCommandLine(command)
	if !ok {
		tokens = strings.Fields(command)
	}
	if len(tokens) == 0 || tokens[0] == "" {
		return nil, errors.New("comando vazio no plano")
	}
	return tokens, nil
}

func checksForTask(planText string, task plan.PlanTaskDefinition) ([]ApprovedCheck, error) {
	checks := make([]ApprovedCheck, 0, len(task.ACs)+3)
	for _, name := range plan.RequiredAuditChecks(task) {
		allowed := plan.AllowedCheckCommands(planText, task, name)
		if allowed.Error != "" {
			return nil, fmt.Errorf("%s: %s", name, allowed.Error)
		}
		if len(allowed.Commands) == 0 {
			return nil, fmt.Errorf("%s: comando vazio no plano", name)
		}
		tokens, err := commandTokens(allowed.Commands[0])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		checks = append(checks, ApprovedCheck{
			ID:                     name,
			Command:                tokens,
			ExpectOutput:           nil,
			RequireBaselineFailure: strings.HasPrefix(name, "AC-"),
		})
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("a task %s não declara checks de aceitação no plano", task.ID)
	}
	return checks, nil
}

func checksForGlobal(planText, gateName string) ([]ApprovedCheck, error) {
	gates, _ := plan.ParseGlobalGates(planText)
	index := -1
	if number, err := strconv.Atoi(strings.TrimPrefix(gateName, "G-")); err == nil {
		index = number - 1
	}
	if index < 0 || index >= len(gates) {
		return nil, fmt.Errorf(
			"%s não existe no plano: ## Global gates declara %d item(ns)",
			gateName, len(gates),
		)
	}
	gate := gates[index]
	if gate.Command == "" {
		return nil, fmt.Errorf("%s não declara comando executável em ## Global gates", gateName)
	}
	tokens, err := commandTokens(gate.Command)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", gateName, err)
	}
	return []ApprovedCheck{{
		ID:                     gateName,
		Command:                tokens,
		ExpectOutput:           nil,
		RequireBaselineFailure: false,
	}}, nil
}

func gitError(args []string, result gitx.Result) error {
	detail := result.Stderr
	if detail == "" {
		detail = fmt.Sprintf("exit %d", result.Exit)
	}
	return fmt.Errorf("git %s falhou: %s", strings.Join(args, " "), detail)
}

// CreateApproval cria e registra o pacote aprovado.
//
// Exige plano e contrato presentes, árvore de aceitação commitada e limpa, e
// testes de aceitação congelados no contrato — é o conteúdo que a avaliação
// restaura, então uma aprovação sem eles não teria o que proteger.
func CreateApproval(options CreateApprovalOptions) (Approval, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := resolveRoot(options.VerifierRootDir)
	if err != nil {
		return Approval{}, err
	}
	rootDir := options.RootDir
	isGlobal := options.Global != ""
	taskID := options.TaskID
	if isGlobal {
		taskID = options.Global
	}
	if strings.TrimSpace(options.ApprovedBy) == "" {
		return Approval{}, errors.New("a aprovação exige --by <responsável>")
	}
	if _, err := InitializeVerifierHome(root); err != nil {
		return Approval{}, err
	}
	if err := AssertProtectedOutsideRepository(root, rootDir); err != nil {
		return Approval{}, err
	}

	planPath := plan.TasksMarkdownPath(options.WorkID, rootDir)
	planData, err := os.ReadFile(planPath)
	if err != nil {
		return Approval{}, fmt.Errorf("plano não encontrado: %s", planPath)
	}
	planText := string(planData)

	runner := gitx.New(rootDir)
	headArgs := []string{"rev-parse", "HEAD"}
	head, err := runner.Run(ctx, headArgs, gitx.Options{})
	if err != nil {
		return Approval{}, err
	}
	if !head.OK() {
		return Approval{}, gitError(headArgs, head)
	}
	baselineCommit := strings.TrimSpace(string(head.Stdout))
	if options.BaselineCommit != "" {
		// Conciliação pós-fato: o baseline é o commit ANTERIOR à mudança, não o
		// HEAD que já a contém.
		verifyArgs := []string{"rev-parse", "--verify", options.BaselineCommit + "^{commit}"}
		requested, err := runner.Run(ctx, verifyArgs, gitx.Options{})
		if err != nil {
			return Approval{}, err
		}
		if !requested.OK() {
			return Approval{}, gitError(verifyArgs, requested)
		}
		commit := strings.TrimSpace(string(requested.Stdout))
		isAncestor, err := runner.IsAncestor(ctx, commit, baselineCommit)
		if err != nil {
			return Approval{}, err
		}
		if !isAncestor {
			return Approval{}, fmt.Errorf("o commit de referência %s não é ancestral do HEAD", options.BaselineCommit)
		}
		baselineCommit = commit
	}
	if baselineCommit == "" {
		return Approval{}, errors.New("não foi possível resolver o commit de referência da aprovação")
	}

	implementationFiles := []string{}
	var checks []ApprovedCheck
	approvedFiles := make([]ApprovedFile, 0)
	var contractID *string
	var contractSHA *string
	approvedContents := make(map[string]string)

	if isGlobal {
		checks, err = checksForGlobal(planText, options.Global)
		if err != nil {
			return Approval{}, err
		}
	} else {
		task := plan.ParsePlanTask(planText, options.TaskID)
		if task == nil {
			return Approval{}, fmt.Errorf("task %s não encontrada em %s", options.TaskID, planPath)
		}
		implementationFiles = task.ImplementationFiles
		checks, err = checksForTask(planText, *task)
		if err != nil {
			return Approval{}, err
		}
		if len(implementationFiles) == 0 {
			return Approval{}, fmt.Errorf("a task %s não declara arquivos de implementação", options.TaskID)
		}

		canonicalPlan := plan.LoadPlan(options.WorkID, rootDir)
		boundID := ""
		if canonicalPlan != nil {
			for _, entry := range canonicalPlan.Tasks {
				if entry.ID == options.TaskID {
					boundID = entry.ContractID
					break
				}
			}
		}
		if boundID == "" {
			return Approval{}, fmt.Errorf(
				"a task %s não vincula contract_id no plan.json do Work %s",
				options.TaskID, options.WorkID,
			)
		}
		taskContract, err := plan.LoadTaskContract(options.WorkID, options.TaskID, rootDir)
		if err != nil {
			return Approval{}, err
		}
		contractID = new(boundID)
		contractPath, err := filepath.Abs(filepath.Join(rootDir, ".pwn", "work", options.WorkID, boundID+".json"))
		if err != nil {
			return Approval{}, fmt.Errorf("verifier: resolver o contrato %s: %w", boundID, err)
		}
		digest, err := DigestOfFile(contractPath)
		if err != nil {
			return Approval{}, err
		}
		contractSHA = new(digest)

		frozen := taskContract.AcceptanceContract.FrozenTests
		if len(frozen) == 0 {
			return Approval{}, fmt.Errorf(
				"a task %s não tem testes de aceitação congelados; congele-os antes de aprovar "+
					"('pwn work contract --work %s --task %s --freeze-tests <arquivo>)",
				options.TaskID, options.WorkID, options.TaskID,
			)
		}
		for _, entry := range frozen {
			absolute, err := filepath.Abs(filepath.Join(rootDir, entry.Path))
			if err != nil {
				return Approval{}, fmt.Errorf("verifier: resolver %s: %w", entry.Path, err)
			}
			info, err := os.Stat(absolute)
			if err != nil || !info.Mode().IsRegular() {
				return Approval{}, fmt.Errorf("teste de aceitação aprovado ausente no repositório: %s", entry.Path)
			}
			current, err := DigestOfFile(absolute)
			if err != nil {
				return Approval{}, err
			}
			if current != entry.SHA256 {
				return Approval{}, fmt.Errorf(
					"teste de aceitação aprovado diverge do congelado no contrato: %s",
					entry.Path,
				)
			}
			data, err := os.ReadFile(absolute)
			if err != nil {
				return Approval{}, fmt.Errorf("verifier: ler %s: %w", absolute, err)
			}
			// A versão aprovada vive na raiz protegida: a avaliação restaura este
			// conteúdo por cima da entrega candidata.
			approvedContents[entry.Path] = string(data)
			approvedFiles = append(approvedFiles, ApprovedFile{Path: entry.Path, SHA256: current})
		}
	}

	planRelative, err := filepath.Rel(rootDir, planPath)
	if err != nil {
		return Approval{}, fmt.Errorf("verifier: resolver o caminho relativo do plano: %w", err)
	}
	kind := "task"
	if isGlobal {
		kind = "global"
	}
	content := ApprovalContent{
		Version:             1,
		WorkID:              options.WorkID,
		TaskID:              taskID,
		Kind:                kind,
		ApprovedBy:          strings.TrimSpace(options.ApprovedBy),
		CreatedAt:           isoNow(),
		PlanPath:            planRelative,
		PlanSHA256:          DigestOfText(planText),
		ContractID:          contractID,
		ContractSHA256:      contractSHA,
		BaselineCommit:      baselineCommit,
		ImplementationFiles: implementationFiles,
		Checks:              checks,
		ApprovedFiles:       approvedFiles,
	}
	canonical, err := jsonx.Canonical(content)
	if err != nil {
		return Approval{}, fmt.Errorf("verifier: serializar a aprovação: %w", err)
	}
	approval := Approval{ApprovalID: digestBytes(canonical), ApprovalContent: content}

	for relative, body := range approvedContents {
		target := filepath.Join(ApprovalFilesDir(approval.ApprovalID, root), relative)
		if err := WriteFileAtomic(target, body, 0o600); err != nil {
			return Approval{}, err
		}
	}
	if err := WriteJSONAtomic(ApprovalPath(approval.ApprovalID, root), approval); err != nil {
		return Approval{}, err
	}

	index := readApprovalIndex(root)
	index.Current[fmt.Sprintf("%s:%s", options.WorkID, taskID)] = approval.ApprovalID
	if err := WriteJSONAtomic(approvalIndexPath(root), index); err != nil {
		return Approval{}, err
	}
	return approval, nil
}
