package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/passoz/pwn/internal/harness/contract"
)

// planTaskRef é o mínimo do plan.json necessário para resolver contratos.
type planTaskRef struct {
	ID         string `json:"id"`
	ContractID string `json:"contract_id"`
}

type planRef struct {
	Tasks []planTaskRef `json:"tasks"`
}

// loadPlanRef lê o plano canônico de um Work. Devolve nil quando o arquivo não
// existe, não é JSON ou não declara a lista de tasks, como o original.
func loadPlanRef(workID, rootDir string) *planRef {
	data, err := os.ReadFile(filepath.Join(rootDir, ".pwn", "work", workID, "plan.json"))
	if err != nil {
		return nil
	}
	var plan planRef
	if json.Unmarshal(data, &plan) != nil {
		return nil
	}
	if plan.Tasks == nil {
		return nil
	}
	return &plan
}

// loadTaskContractWithDocument devolve o contrato tipado e o documento JSON
// original. O vínculo de aprovação L4 usa o documento, porque o hash do
// contrato precisa ser o mesmo do JSON.parse do original — um contrato tipado
// perderia chaves desconhecidas e a diferença entre campo ausente e campo zerado.
func loadTaskContractWithDocument(workID, taskID, rootDir string) (contract.TaskContractV4, any, error) {
	plan := loadPlanRef(workID, rootDir)
	if plan == nil {
		return contract.TaskContractV4{}, nil, fmt.Errorf(
			"plan.json não encontrado para o Work %s em .pwn/work/%s/", workID, workID,
		)
	}

	var contractID string
	found := false
	for _, task := range plan.Tasks {
		if task.ID == taskID {
			contractID = task.ContractID
			found = true
			break
		}
	}
	if !found {
		return contract.TaskContractV4{}, nil, fmt.Errorf("Task %s não encontrada no plano do Work %s", taskID, workID)
	}
	if contractID == "" {
		return contract.TaskContractV4{}, nil, fmt.Errorf("Task %s não vincula contract_id no plano do Work %s", taskID, workID)
	}

	contractPath := filepath.Join(rootDir, ".pwn", "work", workID, contractID+".json")
	data, err := os.ReadFile(contractPath)
	if err != nil {
		return contract.TaskContractV4{}, nil, fmt.Errorf("Contrato %s não encontrado em %s", contractID, contractPath)
	}
	var taskContract contract.TaskContractV4
	if err := json.Unmarshal(data, &taskContract); err != nil {
		return contract.TaskContractV4{}, nil, fmt.Errorf("Erro ao ler o contrato %s: %v", contractID, err)
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return contract.TaskContractV4{}, nil, fmt.Errorf("Erro ao ler o contrato %s: %v", contractID, err)
	}

	if taskContract.ContractVersion != contract.ContractVersionV4 {
		version := taskContract.ContractVersion
		if version == "" {
			version = "ausente"
		}
		return contract.TaskContractV4{}, nil, fmt.Errorf(
			"Contrato %s não é V4 (contract_version: %s)", contractID, version,
		)
	}
	return taskContract, document, nil
}

// loadWorkContractsWithDocuments carrega os contratos do plano e os documentos
// JSON originais, na ordem do plano.
func loadWorkContractsWithDocuments(workID, rootDir string) ([]contract.TaskContractV4, []any, error) {
	plan := loadPlanRef(workID, rootDir)
	if plan == nil {
		return nil, nil, fmt.Errorf("plan.json não encontrado para o Work %s", workID)
	}
	contracts := make([]contract.TaskContractV4, 0, len(plan.Tasks))
	documents := make([]any, 0, len(plan.Tasks))
	for _, task := range plan.Tasks {
		taskContract, document, err := loadTaskContractWithDocument(workID, task.ID, rootDir)
		if err != nil {
			return nil, nil, err
		}
		contracts = append(contracts, taskContract)
		documents = append(documents, document)
	}
	return contracts, documents, nil
}
