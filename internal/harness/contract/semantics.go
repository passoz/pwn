package contract

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/platform/shellwords"
)

// Severity é o peso de um achado semântico. Os valores são os mesmos de
// src/core/gates.ts.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// FindingType classifica o achado.
type FindingType string

const (
	FindingCoverageGap            FindingType = "coverage_gap"
	FindingConflict               FindingType = "conflict"
	FindingAmbiguity              FindingType = "ambiguity"
	FindingUnverifiableAcceptance FindingType = "unverifiable_acceptance"
	FindingTraceabilityGap        FindingType = "traceability_gap"
)

// FindingStatus é o estado inicial de um achado.
type FindingStatus string

const FindingStatusOpen FindingStatus = "open"

// PlanFileName é a referência do plano usada nos achados.
const PlanFileName = "plan.json"

// Finding é o achado semântico. Os campos e os nomes JSON são os mesmos de
// GateFinding, para que o pacote gates reutilize o tipo.
type Finding struct {
	ID                 string        `json:"id"`
	Severity           Severity      `json:"severity"`
	Type               FindingType   `json:"type"`
	SourceRefs         []string      `json:"source_refs"`
	TargetRefs         []string      `json:"target_refs"`
	Description        string        `json:"description"`
	RequiredResolution string        `json:"required_resolution"`
	ResolutionOwner    string        `json:"resolution_owner"`
	Status             FindingStatus `json:"status"`
}

// FrozenTestsRequiredFromRisk é o risco a partir do qual o contrato precisa de
// testes de aceitação congelados antes da implementação.
const FrozenTestsRequiredFromRisk = RiskL3

// FrozenTestsRequired informa se o risco exige testes congelados.
func FrozenTestsRequired(risk RiskLevel) bool {
	return risk.AtLeast(FrozenTestsRequiredFromRisk)
}

// SemanticTask é a parte do plano que a validação semântica do contrato lê.
type SemanticTask struct {
	ID                 string
	Complexity         string
	AcceptanceCriteria []string
}

// SemanticInput reúne o contrato e o contexto da task.
type SemanticInput struct {
	Contract     TaskContractV4
	ContractID   string
	ContractPath string
	Task         SemanticTask
}

// ValidateSemantics porta a parte pura de validateContractSemantics.
//
// A verificação roda sobre o contrato já carregado: existência e leitura do
// arquivo pertencem ao pacote de gates. As cinco checagens e as mensagens são as
// do TypeScript:
//
//  1. write_allow não pode ser vazio;
//  2. o budget precisa declarar tokens, custo ou duração;
//  3. complexidade alta não aceita risco L0/L1;
//  4. o contrato precisa autorizar cada AC do plano;
//  5. os testes congelados precisam ser válidos, exigidos pelo risco e
//     exercitados por um AC.
func ValidateSemantics(input SemanticInput) []Finding {
	taskContract := input.Contract
	contractPath := input.ContractPath
	contractID := input.ContractID
	taskID := input.Task.ID
	findings := make([]Finding, 0)

	if len(taskContract.ScopeContract.WriteAllow) == 0 {
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-SCOPE-" + contractID,
			Severity:           SeverityMedium,
			Type:               FindingCoverageGap,
			SourceRefs:         []string{contractPath, PlanFileName},
			TargetRefs:         []string{taskID},
			Description:        "Contrato " + contractID + " não declara nenhum arquivo em write_allow — impossível verificar escopo",
			RequiredResolution: "Adicionar padrões de arquivo ao scope.write_allow",
			ResolutionOwner:    "architect",
			Status:             FindingStatusOpen,
		})
	}

	budget := taskContract.BudgetContract
	if !positiveInt(budget.MaxTokens) && !positiveFloat(budget.MaxCostUSD) && !positiveInt(budget.MaxDurationMinutes) {
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-BUDGET-" + contractID,
			Severity:           SeverityMedium,
			Type:               FindingCoverageGap,
			SourceRefs:         []string{contractPath},
			TargetRefs:         []string{taskID},
			Description:        "Contrato " + contractID + " não define limites de budget — sem enforcement de custo/tempo",
			RequiredResolution: "Adicionar max_tokens, max_cost_usd ou max_duration_minutes",
			ResolutionOwner:    "architect",
			Status:             FindingStatusOpen,
		})
	}

	risk := taskContract.Risk.Level
	if risk == "" {
		risk = RiskL1
	}
	complexity := input.Task.Complexity
	if complexity == "" {
		complexity = "medium"
	}
	if highComplexity[complexity] && (risk == RiskL0 || risk == RiskL1) {
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-RISK-" + contractID,
			Severity:           SeverityMedium,
			Type:               FindingConflict,
			SourceRefs:         []string{contractPath, PlanFileName},
			TargetRefs:         []string{taskID},
			Description:        "Task " + taskID + " é de alta complexidade mas o contrato é risco " + string(risk) + " — sub-classificação de risco",
			RequiredResolution: "Reavaliar o risco da task ou decompor em tasks menores",
			ResolutionOwner:    "architect",
			Status:             FindingStatusOpen,
		})
	}

	commands := make([]string, 0, len(input.Task.AcceptanceCriteria))
	for _, raw := range input.Task.AcceptanceCriteria {
		if command := strings.TrimSpace(raw); command != "" {
			commands = append(commands, command)
		}
	}
	for index, command := range commands {
		if contractAuthorizes(taskContract.AcceptanceContract.Commands, command) {
			continue
		}
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-AC-" + taskID + "-" + strconv.Itoa(index+1),
			Severity:           SeverityHigh,
			Type:               FindingConflict,
			SourceRefs:         []string{contractPath, PlanFileName},
			TargetRefs:         []string{taskID},
			Description:        "AC-" + strconv.Itoa(index+1) + " da task " + taskID + " (`" + command + "`) não é autorizado por acceptance_contract.commands do " + contractID,
			RequiredResolution: "Incluir o comando (ou um prefixo estrutural dele) nos comandos de aceitação do contrato",
			ResolutionOwner:    "architect",
			Status:             FindingStatusOpen,
		})
	}

	frozen, invalidFrozen := validFrozenTests(taskContract.AcceptanceContract.FrozenTests)
	if taskContract.AcceptanceContract.FrozenTests != nil && invalidFrozen {
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-FROZEN-INVALID-" + taskID,
			Severity:           SeverityHigh,
			Type:               FindingAmbiguity,
			SourceRefs:         []string{contractPath},
			TargetRefs:         []string{taskID},
			Description:        "acceptance_contract.frozen_tests do " + contractID + " tem entradas sem { path, sha256 } válidos",
			RequiredResolution: "Regenerar com pwn work contract --freeze-tests",
			ResolutionOwner:    "architect",
			Status:             FindingStatusOpen,
		})
	}
	if FrozenTestsRequired(risk) && len(frozen) == 0 {
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-FROZEN-REQUIRED-" + taskID,
			Severity:           SeverityHigh,
			Type:               FindingUnverifiableAcceptance,
			SourceRefs:         []string{contractPath},
			TargetRefs:         []string{taskID},
			Description:        "Task " + taskID + " é risco " + string(risk) + ": exige testes de aceitação escritos e congelados antes da implementação",
			RequiredResolution: "Commitar os testes de aceitação e rodar 'pwn work contract --work <id> --task " + taskID + " --freeze-tests <arquivos>'",
			ResolutionOwner:    "architect",
			Status:             FindingStatusOpen,
		})
	}
	for _, entry := range frozen {
		if anyReferencesPath(commands, entry.Path) {
			continue
		}
		findings = append(findings, Finding{
			ID:                 "FIND-SEM-CTR-FROZEN-UNUSED-" + taskID + "-" + entry.Path,
			Severity:           SeverityHigh,
			Type:               FindingUnverifiableAcceptance,
			SourceRefs:         []string{contractPath, PlanFileName},
			TargetRefs:         []string{taskID, entry.Path},
			Description:        "Teste congelado " + entry.Path + " não é exercitado por nenhum AC da task " + taskID,
			RequiredResolution: "Apontar um AC da task para o teste congelado (arquivo ou diretório)",
			ResolutionOwner:    "planner",
			Status:             FindingStatusOpen,
		})
	}

	return findings
}

var highComplexity = map[string]bool{
	"high":          true,
	"critical":      true,
	"architectural": true,
}

var frozenSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func positiveInt(value *int) bool { return value != nil && *value > 0 }

func positiveFloat(value *float64) bool { return value != nil && *value > 0 }

// validFrozenTests separa as entradas com path e sha256 válidos. O segundo
// resultado informa se alguma entrada ficou de fora.
func validFrozenTests(entries []FrozenTest) (valid []FrozenTest, invalid bool) {
	valid = make([]FrozenTest, 0, len(entries))
	for _, entry := range entries {
		if entry.Path == "" || !frozenSHA256.MatchString(entry.SHA256) {
			invalid = true
			continue
		}
		valid = append(valid, entry)
	}
	return valid, invalid
}

// commandTokens usa a mesma leitura estrutural da política de shell, com queda
// para Fields quando as aspas não fecham.
func commandTokens(command string) []string {
	trimmed := strings.TrimSpace(command)
	if tokens, ok := shellwords.Split(trimmed); ok {
		return tokens
	}
	return strings.Fields(trimmed)
}

// contractAuthorizes informa se algum comando do contrato é prefixo estrutural
// do comando do AC.
func contractAuthorizes(contractCommands []string, command string) bool {
	tokens := commandTokens(command)
	if len(tokens) == 0 {
		return false
	}
	for _, raw := range contractCommands {
		planned := commandTokens(raw)
		if len(planned) == 0 || planned[0] != tokens[0] {
			continue
		}
		matches := true
		for index, argument := range planned[1:] {
			if index+1 >= len(tokens) || tokens[index+1] != argument {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func anyReferencesPath(commands []string, filePath string) bool {
	for _, command := range commands {
		if referencesPath(command, filePath) {
			return true
		}
	}
	return false
}

// referencesPath informa se o comando cita o arquivo ou um diretório que o contém.
func referencesPath(command, filePath string) bool {
	target := path.Clean(filePath)
	for _, token := range commandTokens(command) {
		if strings.HasPrefix(token, "-") {
			continue
		}
		candidate := strings.TrimSuffix(path.Clean(token), "/")
		if candidate == target || strings.HasPrefix(target, candidate+"/") {
			return true
		}
	}
	return false
}
