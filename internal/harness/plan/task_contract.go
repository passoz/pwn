package plan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/cryptox"
	"github.com/passoz/pwn/internal/platform/gitx"
)

// LoadTaskContract lê o contrato V4 congelado de uma task de um Work. O
// plan.json mapeia o id da task para o id do contrato; o contrato fica em
// `<contract_id>.json`.
func LoadTaskContract(workID, taskID, rootDir string) (*contract.TaskContractV4, error) {
	if rootDir == "" {
		rootDir = "."
	}
	workPlan := LoadPlan(workID, rootDir)
	if workPlan == nil {
		return nil, fmt.Errorf("plan.json não encontrado para o Work %s em .pwn/work/%s/", workID, workID)
	}

	var task *PlanTask
	for index := range workPlan.Tasks {
		if workPlan.Tasks[index].ID == taskID {
			task = &workPlan.Tasks[index]
			break
		}
	}
	if task == nil {
		return nil, fmt.Errorf("Task %s não encontrada no plano do Work %s", taskID, workID)
	}
	if task.ContractID == "" {
		return nil, fmt.Errorf("Task %s não vincula contract_id no plano do Work %s", taskID, workID)
	}

	contractPath := filepath.Join(rootDir, ".pwn", "work", workID, task.ContractID+".json")
	data, err := os.ReadFile(contractPath)
	if err != nil {
		return nil, fmt.Errorf("Contrato %s não encontrado em %s", task.ContractID, contractPath)
	}
	var parsed contract.TaskContractV4
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("Erro ao ler o contrato %s: %v", task.ContractID, err)
	}
	if parsed.ContractVersion != contract.ContractVersionV4 {
		version := parsed.ContractVersion
		if version == "" {
			version = "ausente"
		}
		return nil, fmt.Errorf("Contrato %s não é V4 (contract_version: %s)", task.ContractID, version)
	}
	return &parsed, nil
}

// FreezeOptions são as entradas de FreezeAcceptanceTests.
type FreezeOptions struct {
	WorkID  string
	TaskID  string
	Paths   []string
	RootDir string
}

// FreezeResult é o contrato atualizado e os testes congelados.
type FreezeResult struct {
	ContractID string
	Frozen     []contract.FrozenTest
}

// FreezeAcceptanceTests congela testes de aceitação no contrato da task.
//
// O ponto é a ordem: os testes precisam existir, estar commitados e limpos
// ANTES do baseline da task. Quem implementa não consegue mais ajustá-los ao
// código, porque o audit recusa a atestação se algum hash mudar.
func FreezeAcceptanceTests(ctx context.Context, options FreezeOptions) (FreezeResult, error) {
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	workPlan := LoadPlan(options.WorkID, rootDir)
	var task *PlanTask
	if workPlan != nil {
		for index := range workPlan.Tasks {
			if workPlan.Tasks[index].ID == options.TaskID {
				task = &workPlan.Tasks[index]
				break
			}
		}
	}
	if workPlan == nil || task == nil {
		return FreezeResult{}, fmt.Errorf("Task %s não encontrada no plan.json do Work %s", options.TaskID, options.WorkID)
	}
	if task.ContractID == "" {
		return FreezeResult{}, fmt.Errorf("Task %s não vincula contract_id", options.TaskID)
	}
	if len(options.Paths) == 0 {
		return FreezeResult{}, fmt.Errorf("informe ao menos um arquivo de teste após --freeze-tests")
	}

	evidenceState := filepath.Join(rootDir, ".todo", "evidence", options.WorkID, "state", options.TaskID+".json")
	if _, err := os.Stat(evidenceState); err == nil {
		relative, relErr := filepath.Rel(rootDir, evidenceState)
		if relErr != nil {
			relative = evidenceState
		}
		return FreezeResult{}, fmt.Errorf("a task %s já tem baseline (%s): testes de aceitação se congelam antes da implementação", options.TaskID, relative)
	}

	implementationFiles := make(map[string]bool, len(task.ImplementationFiles))
	for _, path := range task.ImplementationFiles {
		implementationFiles[path] = true
	}

	frozen := make([]contract.FrozenTest, 0, len(options.Paths))
	seen := make(map[string]bool, len(options.Paths))
	for _, filePath := range options.Paths {
		if seen[filePath] {
			continue
		}
		seen[filePath] = true
		if reason := PlaceholderPathReason(filePath); reason != "" {
			return FreezeResult{}, fmt.Errorf("%s %s", filePath, reason)
		}
		if implementationFiles[filePath] {
			return FreezeResult{}, fmt.Errorf("%s é arquivo de implementação da task, não teste de aceitação", filePath)
		}
		absolute := filePath
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(rootDir, filePath)
		}
		info, err := os.Stat(absolute)
		if err != nil || info.IsDir() {
			return FreezeResult{}, fmt.Errorf("teste de aceitação não encontrado: %s", filePath)
		}
		runner := gitx.New(rootDir)
		tracked, err := runner.Run(ctx, []string{"ls-files", "--error-unmatch", "--", filePath}, gitx.Options{})
		if err != nil {
			return FreezeResult{}, fmt.Errorf("%s precisa estar commitado e sem alterações para ser congelado (a versão aprovada fica no histórico)", filePath)
		}
		status, statusErr := runner.Run(ctx, []string{"status", "--porcelain=v1", "--", filePath}, gitx.Options{})
		if statusErr != nil || !tracked.OK() || !status.OK() || strings.TrimSpace(string(status.Stdout)) != "" {
			return FreezeResult{}, fmt.Errorf("%s precisa estar commitado e sem alterações para ser congelado (a versão aprovada fica no histórico)", filePath)
		}
		content, err := os.ReadFile(absolute)
		if err != nil {
			return FreezeResult{}, fmt.Errorf("teste de aceitação não encontrado: %s", filePath)
		}
		frozen = append(frozen, contract.FrozenTest{Path: filePath, SHA256: cryptox.SHA256Hex(content)})
	}

	contractPath := filepath.Join(rootDir, ".pwn", "work", options.WorkID, task.ContractID+".json")
	loaded, err := LoadTaskContract(options.WorkID, options.TaskID, rootDir)
	if err != nil {
		return FreezeResult{}, err
	}
	loaded.AcceptanceContract.FrozenTests = frozen
	if err := writeContractFile(contractPath, loaded); err != nil {
		return FreezeResult{}, err
	}
	return FreezeResult{ContractID: task.ContractID, Frozen: frozen}, nil
}

// writeContractFile grava o contrato com indentação de dois espaços, como
// JSON.stringify(value, null, 2), sem escapar HTML.
func writeContractFile(path string, value *contract.TaskContractV4) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o644)
}

// LoadWorkContracts lê todos os contratos congelados referenciados pelo plano,
// na ordem do plano.
func LoadWorkContracts(workID, rootDir string) ([]*contract.TaskContractV4, error) {
	workPlan := LoadPlan(workID, rootDir)
	if workPlan == nil {
		return nil, fmt.Errorf("plan.json não encontrado para o Work %s", workID)
	}
	contracts := make([]*contract.TaskContractV4, 0, len(workPlan.Tasks))
	for _, task := range workPlan.Tasks {
		loaded, err := LoadTaskContract(workID, task.ID, rootDir)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, loaded)
	}
	return contracts, nil
}
