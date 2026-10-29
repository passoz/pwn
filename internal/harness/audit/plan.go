package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
)

// incompleteError marca pré-requisito ausente: vira EXIT_INCOMPLETE em vez de
// violação.
type incompleteError struct {
	items []string
}

func (e *incompleteError) Error() string {
	return strings.Join(e.items, "; ")
}

// loadedPlan é o plano lido e a definição da task.
type loadedPlan struct {
	path string
	text string
	task plan.PlanTaskDefinition
}

var contractVersionPattern = regexp.MustCompile(`(?m)^\*\*Contract version:\*\* ([1-9]\d*)$`)

// planPathFor devolve o markdown do plano. O Work `legacy` usa o caminho antigo.
func planPathFor(workID string) string {
	if workID == "legacy" {
		return filepath.Join(".todo", "tasks.md")
	}
	return plan.TasksMarkdownPath(workID, ".")
}

// contractVersionOf lê a versão do contrato do plano; plano sem a linha é v1.
func contractVersionOf(planText string) int {
	match := contractVersionPattern.FindStringSubmatch(planText)
	if match == nil {
		return 1
	}
	version := 0
	for _, digit := range match[1] {
		version = version*10 + int(digit-'0')
	}
	return version
}

// loadPlanTask lê o plano e a definição da task. Plano ou task ausente é
// pré-requisito faltando.
func loadPlanTask(workID, taskID string) (loadedPlan, error) {
	planPath := planPathFor(workID)
	data, err := os.ReadFile(planPath)
	if err != nil {
		if os.IsNotExist(err) {
			return loadedPlan{}, &incompleteError{items: []string{
				fmt.Sprintf("plano do Work (plan not found: %s) — o audit amarra comandos e arquivos ao plano", planPath),
			}}
		}
		return loadedPlan{}, err
	}
	text := string(data)
	task := plan.ParsePlanTask(text, taskID)
	if task == nil {
		return loadedPlan{}, &incompleteError{items: []string{
			fmt.Sprintf("task %s no plano %s", taskID, planPath),
		}}
	}
	return loadedPlan{path: planPath, text: text, task: *task}, nil
}

// planDrift compara o markdown derivado com o plano canônico. ACs ou RED
// editados em um só dos lados invalidam a evidência.
func planDrift(workID, planText string) (string, error) {
	if workID == "legacy" {
		return "", nil
	}
	canonicalPath, err := filepath.Abs(filepath.Join(".pwn", "work", workID, "plan.json"))
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(canonicalPath); err != nil {
		return "", nil
	}
	model := plan.LoadPlan(workID, ".")
	if model == nil {
		return fmt.Sprintf("DRIFT: .pwn/work/%s/plan.json está ilegível ou inválido", workID), nil
	}
	if plan.PlanMatchesMarkdown(*model, planText) {
		return "", nil
	}
	return fmt.Sprintf(
		"DRIFT: %s diverge de .pwn/work/%s/plan.json; regenere com 'pwn work plan --work %s --force'",
		planPathFor(workID), workID, workID,
	), nil
}

// contractInfo é o contrato V4 da task com o hash do arquivo bruto.
type contractInfo struct {
	ID          string
	SHA256      string
	FrozenTests []FrozenTest
}

var frozenSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// loadContractInfo lê o contrato V4. Devolve nil quando o plano não declara
// contrato para a task.
func loadContractInfo(workID, taskID string) (*contractInfo, error) {
	if workID == "legacy" {
		return nil, nil
	}
	model := plan.LoadPlan(workID, ".")
	if model == nil {
		return nil, nil
	}
	contractID := ""
	found := false
	for _, task := range model.Tasks {
		if task.ID == taskID {
			contractID = task.ContractID
			found = true
			break
		}
	}
	if !found || contractID == "" {
		return nil, nil
	}
	contractPath, err := filepath.Abs(filepath.Join(".pwn", "work", workID, contractID+".json"))
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("contrato %s da task %s não encontrado em %s", contractID, taskID, contractPath)
		}
		return nil, err
	}

	var parsed struct {
		AcceptanceContract *struct {
			FrozenTests json.RawMessage `json:"frozen_tests"`
		} `json:"acceptance_contract"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("contrato %s ilegível: %v", contractID, err)
	}

	frozenTests := make([]FrozenTest, 0)
	if parsed.AcceptanceContract != nil && len(parsed.AcceptanceContract.FrozenTests) > 0 {
		field := bytes.TrimSpace(parsed.AcceptanceContract.FrozenTests)
		if string(field) == "null" {
			return nil, fmt.Errorf("contrato %s: acceptance_contract.frozen_tests deve ser uma lista", contractID)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(field, &items); err != nil {
			return nil, fmt.Errorf("contrato %s: acceptance_contract.frozen_tests deve ser uma lista", contractID)
		}
		for _, item := range items {
			var candidate struct {
				Path   *string `json:"path"`
				SHA256 *string `json:"sha256"`
			}
			if err := json.Unmarshal(item, &candidate); err != nil ||
				candidate.Path == nil || candidate.SHA256 == nil ||
				!frozenSHA256Pattern.MatchString(*candidate.SHA256) {
				return nil, fmt.Errorf(
					"contrato %s: frozen_tests com entrada inválida (%s)",
					contractID, compactJSON(item),
				)
			}
			frozenTests = append(frozenTests, FrozenTest{Path: *candidate.Path, SHA256: *candidate.SHA256})
		}
	}

	return &contractInfo{ID: contractID, SHA256: sha256Hex(raw), FrozenTests: frozenTests}, nil
}

func compactJSON(raw []byte) string {
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		return string(raw)
	}
	return buffer.String()
}

// frozenTestViolations devolve os testes congelados alterados ou ausentes.
func frozenTestViolations(frozen []FrozenTest) ([]string, error) {
	violations := make([]string, 0, len(frozen))
	for _, entry := range frozen {
		current, err := digest(entry.Path)
		if err != nil {
			return nil, err
		}
		if current.SHA256 == nil || *current.SHA256 != entry.SHA256 {
			violations = append(violations, fmt.Sprintf("teste de aceitação congelado alterado ou ausente: %s", entry.Path))
		}
	}
	return violations, nil
}

// guardDefinition confere que definição e contrato da task são os mesmos
// congelados no baseline.
func guardDefinition(state *State, workID, taskID string) (loadedPlan, error) {
	if state.StateVersion != stateVersion || state.TaskDefinitionSHA256 == "" {
		return loadedPlan{}, &incompleteError{items: []string{
			fmt.Sprintf("baseline amarrado ao plano (estado da task %s é anterior ao amarramento; refaça o baseline)", taskID),
		}}
	}
	loaded, err := loadPlanTask(workID, taskID)
	if err != nil {
		return loadedPlan{}, err
	}
	drift, err := planDrift(workID, loaded.text)
	if err != nil {
		return loadedPlan{}, err
	}
	if drift != "" {
		return loadedPlan{}, fmt.Errorf("%s", drift)
	}
	if plan.TaskDefinitionDigest(loaded.text, loaded.task) != state.TaskDefinitionSHA256 {
		return loadedPlan{}, fmt.Errorf(
			"a definição da task %s no plano mudou depois do baseline (RED, ACs, arquivos ou gates); refaça o baseline",
			taskID,
		)
	}
	contract, err := loadContractInfo(workID, taskID)
	if err != nil {
		return loadedPlan{}, err
	}
	recorded := state.Contract
	contractID := ""
	contractSHA := ""
	if contract != nil {
		contractID = contract.ID
		contractSHA = contract.SHA256
	}
	recordedID := ""
	recordedSHA := ""
	if recorded != nil {
		recordedID = recorded.ID
		recordedSHA = recorded.SHA256
	}
	if contractID != recordedID || contractSHA != recordedSHA {
		return loadedPlan{}, fmt.Errorf("o contrato da task %s mudou depois do baseline; refaça o baseline", taskID)
	}
	return loaded, nil
}

// sameSet informa se duas listas têm o mesmo conjunto de valores.
func sameSet(left, right []string) bool {
	leftSet := uniqueSorted(left)
	rightSet := uniqueSorted(right)
	if len(leftSet) != len(rightSet) {
		return false
	}
	for index := range leftSet {
		if leftSet[index] != rightSet[index] {
			return false
		}
	}
	return true
}

// greenDigest identifica o snapshot GREEN sobre o qual um check rodou.
func greenDigest(state *State) string {
	payload, err := jsonCanonical(map[string]any{
		"implementation": state.GreenImplementation,
		"tests":          state.GreenTests,
	})
	if err != nil {
		return ""
	}
	return sha256Hex(payload)
}
