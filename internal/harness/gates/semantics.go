package gates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
)

// FrozenTestsRequiredFromRisk é o risco a partir do qual a task só executa com
// testes de aceitação congelados antes da implementação.
const FrozenTestsRequiredFromRisk = contract.FrozenTestsRequiredFromRisk

// FrozenTestsRequired informa se o risco exige testes congelados.
func FrozenTestsRequired(risk contract.RiskLevel) bool {
	return contract.FrozenTestsRequired(risk)
}

var (
	observableCommand   = regexp.MustCompile("`[^`]+`")
	observableDash      = regexp.MustCompile(`\S\s+—\s+\S`)
	observableNormative = regexp.MustCompile(`(?i)deve|deveria|should|must|shall|verificável|observável|testável|mensurável`)
	atomicSpecReference = regexp.MustCompile(`(?i)[,+]| e | and `)
)

// isObservableCriterion informa se o critério é checável: comando executável
// (com resultado esperado) ou verbo normativo.
func isObservableCriterion(value any) bool {
	criterion, ok := value.(string)
	if !ok {
		return false
	}
	return observableCommand.MatchString(criterion) ||
		observableDash.MatchString(criterion) ||
		observableNormative.MatchString(criterion)
}

// validatePRDSemantics exige critério observável para requisito aceito e
// justificativa para requisito rejeitado.
func validatePRDSemantics(workDir string) []contract.Finding {
	findings := make([]contract.Finding, 0)
	reqData, reqOK := isJSONObject(readArtifactJSON(filepath.Join(workDir, "requirements.json")))
	prdData, prdOK := isJSONObject(readArtifactJSON(filepath.Join(workDir, "prd.json")))
	if !reqOK || !prdOK {
		return findings
	}

	accepted := make(map[string]bool)
	for _, value := range asJSONArray(prdData["accepted_requirements"]) {
		accepted[jsScalarString(value)] = true
	}

	for _, rawReq := range asJSONArray(reqData["requirements"]) {
		req := objectOrEmpty(rawReq)
		reqID := asJSONString(req["id"])
		if reqID == "" {
			continue
		}
		isAccepted := accepted[reqID]

		if isAccepted && !someCriterion(asJSONArray(req["acceptance_criteria"])) {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-SEM-PRD-AC-" + reqID,
				Severity:           contract.SeverityMedium,
				Type:               contract.FindingUnverifiableAcceptance,
				SourceRefs:         []string{"requirements.json", "prd.json"},
				TargetRefs:         []string{reqID},
				Description:        "Requisito aceito " + reqID + " não possui critério de aceite observável/testável",
				RequiredResolution: "Reformular critérios de aceite com o comando que os verifica ou linguagem observável (deve, verificável, etc.)",
				ResolutionOwner:    "product-owner",
				Status:             contract.FindingStatusOpen,
			})
		}

		if !isAccepted && asJSONString(req["status"]) == "rejected" && !jsTruthy(req["rejection_rationale"]) {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-SEM-PRD-REJ-" + reqID,
				Severity:           contract.SeverityLow,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{"requirements.json", "prd.json"},
				TargetRefs:         []string{reqID},
				Description:        "Requisito rejeitado " + reqID + " não possui justificativa documentada",
				RequiredResolution: "Documentar por que o requisito foi rejeitado",
				ResolutionOwner:    "product-owner",
				Status:             contract.FindingStatusOpen,
			})
		}
	}

	return findings
}

func someCriterion(criteria []any) bool {
	for _, criterion := range criteria {
		if isObservableCriterion(criterion) {
			return true
		}
	}
	return false
}

// requirementCoverageFindings lista requisitos aceitos que nenhuma capability
// cobre, nem por covered_requirements nem pela matriz de rastreabilidade.
func requirementCoverageFindings(workDir string) []contract.Finding {
	findings := make([]contract.Finding, 0)
	prdData, prdOK := isJSONObject(readArtifactJSON(filepath.Join(workDir, "prd.json")))
	specData, specOK := isJSONObject(readArtifactJSON(filepath.Join(workDir, "spec.json")))
	if !prdOK || !specOK {
		return findings
	}

	capabilityIDs := make(map[string]bool)
	covered := make(map[string]bool)
	for _, rawCapability := range asJSONArray(specData["capabilities"]) {
		capability, ok := isJSONObject(rawCapability)
		if !ok {
			continue
		}
		if id := asJSONString(capability["id"]); id != "" {
			capabilityIDs[id] = true
		}
		for _, reqID := range asJSONArray(capability["covered_requirements"]) {
			covered[jsScalarString(reqID)] = true
		}
	}
	if matrix := loadTraceabilityMatrixRaw(workDir); matrix != nil {
		for _, rawEntry := range asJSONArray(matrix["matrix"]) {
			entry := objectOrEmpty(rawEntry)
			if !jsTruthy(entry["requirement_id"]) {
				continue
			}
			if capabilityIDs[jsScalarString(entry["spec_section"])] {
				covered[jsScalarString(entry["requirement_id"])] = true
			}
		}
	}

	for _, value := range asJSONArray(prdData["accepted_requirements"]) {
		reqID := jsScalarString(value)
		if covered[reqID] {
			continue
		}
		findings = append(findings, contract.Finding{
			ID:                 "FIND-SEM-SPEC-COVER-" + reqID,
			Severity:           contract.SeverityHigh,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"prd.json", "spec.json", "traceability-matrix.json"},
			TargetRefs:         []string{reqID},
			Description:        "Requisito aceito " + reqID + " não é coberto por nenhuma capacidade técnica no spec.json",
			RequiredResolution: "Vincular uma capacidade ao requisito " + reqID + " (covered_requirements ou matriz) ou removê-lo do escopo aceito",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	}

	return findings
}

// validateSpecCoversPRD valida que a spec cobre o PRD e que a capability é mais
// que um título.
func validateSpecCoversPRD(workDir string) []contract.Finding {
	findings := requirementCoverageFindings(workDir)
	specData, ok := isJSONObject(readArtifactJSON(filepath.Join(workDir, "spec.json")))
	if !ok {
		return findings
	}

	for _, rawCapability := range asJSONArray(specData["capabilities"]) {
		capability, ok := isJSONObject(rawCapability)
		if !ok {
			continue
		}
		capabilityID := asJSONString(capability["id"])
		if capabilityID == "" {
			continue
		}
		hasImplementation := len(asJSONArray(capability["rules"])) > 0 ||
			len(asJSONArray(capability["api_endpoints"])) > 0 ||
			len(asJSONArray(capability["data_models"])) > 0
		if hasImplementation {
			continue
		}
		findings = append(findings, contract.Finding{
			ID:                 "FIND-SEM-SPEC-IMPL-" + capabilityID,
			Severity:           contract.SeverityMedium,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"spec.json"},
			TargetRefs:         []string{capabilityID},
			Description:        "Capacidade " + capabilityID + " não possui regras, endpoints ou modelos de dados — é apenas um título",
			RequiredResolution: "Especificar como a capacidade será implementada",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	}

	return findings
}

// ValidatePlanAcceptance valida a aceitação verificável por task: RED focado,
// ACs com comando executável e específico e listas de arquivos concretas. Toda
// violação é high.
func ValidatePlanAcceptance(workDir string) []contract.Finding {
	planData, ok := isJSONObject(readArtifactJSON(filepath.Join(workDir, "plan.json")))
	if !ok {
		return []contract.Finding{}
	}

	findings := make([]contract.Finding, 0)
	add := func(id, taskID, description, resolution string, findingType contract.FindingType) {
		findings = append(findings, contract.Finding{
			ID:                 id,
			Severity:           contract.SeverityHigh,
			Type:               findingType,
			SourceRefs:         []string{"plan.json"},
			TargetRefs:         []string{taskID},
			Description:        description,
			RequiredResolution: resolution,
			ResolutionOwner:    "planner",
			Status:             contract.FindingStatusOpen,
		})
	}

	for index, rawTask := range asJSONArray(planData["tasks"]) {
		task := objectOrEmpty(rawTask)
		taskID := asJSONString(task["id"])
		if taskID == "" {
			taskID = strconv.Itoa(index + 1)
		}
		gateCommands := planGateCommands(planData, stringList(task["components"]))

		acceptanceCriteria := asJSONArray(task["acceptance_criteria"])
		if len(acceptanceCriteria) == 0 {
			add("FIND-AC-MISSING-"+taskID, taskID,
				"Task "+taskID+" não declara critérios de aceite",
				"Declarar ao menos um AC { command, description } que prove o comportamento da task",
				contract.FindingUnverifiableAcceptance)
		}
		for acIndex, rawAC := range acceptanceCriteria {
			command := ""
			if ac, ok := isJSONObject(rawAC); ok {
				command = strings.TrimSpace(asJSONString(ac["command"]))
			}
			label := "AC-" + strconv.Itoa(acIndex+1)
			if command == "" {
				add("FIND-AC-COMMAND-"+taskID+"-"+strconv.Itoa(acIndex+1), taskID,
					label+" da task "+taskID+" não tem comando executável",
					"Declarar o AC como { command, description }: texto livre não é verificável",
					contract.FindingUnverifiableAcceptance)
				continue
			}
			if generic := plan.GenericCommandReason(command, gateCommands); generic != "" {
				add("FIND-AC-GENERIC-"+taskID+"-"+strconv.Itoa(acIndex+1), taskID,
					label+" da task "+taskID+" (`"+command+"`) "+generic,
					"Usar um comando focado no comportamento da task (arquivo de teste, filtro de nome ou probe do observável)",
					contract.FindingUnverifiableAcceptance)
			}
		}

		redCommand := ""
		if red, ok := isJSONObject(task["red"]); ok {
			redCommand = strings.TrimSpace(asJSONString(red["command"]))
		}
		if redCommand == "" {
			add("FIND-RED-MISSING-"+taskID, taskID,
				"Task "+taskID+" não declara comando RED",
				"Declarar o comando focado que falha antes da implementação",
				contract.FindingUnverifiableAcceptance)
		} else if generic := plan.GenericCommandReason(redCommand, gateCommands); generic != "" {
			add("FIND-RED-GENERIC-"+taskID, taskID,
				"RED da task "+taskID+" (`"+redCommand+"`) "+generic,
				"Usar o comando focado no teste novo da task",
				contract.FindingUnverifiableAcceptance)
		}

		for _, field := range []struct{ name, label string }{
			{"implementation_files", "Implementation files"},
			{"test_files", "Test files"},
		} {
			files := stringList(task[field.name])
			if len(files) == 0 {
				add("FIND-FILES-MISSING-"+taskID+"-"+field.name, taskID,
					"Task "+taskID+" não declara "+field.label,
					"Declarar os arquivos concretos que o audit congela no baseline",
					contract.FindingCoverageGap)
			}
			for _, file := range files {
				if reason := plan.PlaceholderPathReason(file); reason != "" {
					add("FIND-FILES-PLACEHOLDER-"+taskID+"-"+file, taskID,
						field.label+" da task "+taskID+": "+file+" "+reason,
						"Substituir pelo caminho do arquivo concreto",
						contract.FindingCoverageGap)
				}
			}
		}
	}

	return findings
}

// validateContractSemantics exige que o contrato congelado da task exista, seja
// legível e passe na validação semântica do pacote contract.
func validateContractSemantics(workDir string) []contract.Finding {
	findings := make([]contract.Finding, 0)
	planData, ok := isJSONObject(readArtifactJSON(filepath.Join(workDir, "plan.json")))
	if !ok {
		return findings
	}

	for _, rawTask := range asJSONArray(planData["tasks"]) {
		task, ok := isJSONObject(rawTask)
		if !ok {
			continue
		}
		taskID := asJSONString(task["id"])
		contractID := asJSONString(task["contract_id"])
		if contractID == "" {
			continue
		}
		contractPath := filepath.Join(workDir, contractID+".json")

		if _, err := os.Stat(contractPath); err != nil {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-SEM-CTR-MISSING-" + taskID,
				Severity:           contract.SeverityHigh,
				Type:               contract.FindingTraceabilityGap,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         []string{contractID},
				Description:        "Contrato " + contractID + " referenciado pela task " + taskID + " não existe",
				RequiredResolution: "Criar o contrato ou corrigir o contract_id",
				ResolutionOwner:    "architect",
				Status:             contract.FindingStatusOpen,
			})
			continue
		}

		rawContract, ok := isJSONObject(readArtifactJSON(contractPath))
		if !ok {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-SEM-CTR-UNREADABLE-" + taskID,
				Severity:           contract.SeverityHigh,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{contractPath},
				TargetRefs:         []string{contractID},
				Description:        "Contrato " + contractID + " da task " + taskID + " não é um JSON legível",
				RequiredResolution: "Corrigir o JSON do contrato",
				ResolutionOwner:    "architect",
				Status:             contract.FindingStatusOpen,
			})
			continue
		}

		taskContract, ok := contractForValidation(rawContract)
		if !ok {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-SEM-CTR-UNREADABLE-" + taskID,
				Severity:           contract.SeverityHigh,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{contractPath},
				TargetRefs:         []string{contractID},
				Description:        "Contrato " + contractID + " da task " + taskID + " não é um JSON legível",
				RequiredResolution: "Corrigir o JSON do contrato",
				ResolutionOwner:    "architect",
				Status:             contract.FindingStatusOpen,
			})
			continue
		}

		acceptanceCriteria := make([]string, 0)
		for _, rawAC := range asJSONArray(task["acceptance_criteria"]) {
			if ac, ok := isJSONObject(rawAC); ok {
				if command := strings.TrimSpace(asJSONString(ac["command"])); command != "" {
					acceptanceCriteria = append(acceptanceCriteria, command)
				}
			}
		}

		findings = append(findings, contract.ValidateSemantics(contract.SemanticInput{
			Contract:     taskContract,
			ContractID:   contractID,
			ContractPath: contractPath,
			Task: contract.SemanticTask{
				ID:                 taskID,
				Complexity:         asJSONString(task["complexity"]),
				AcceptanceCriteria: acceptanceCriteria,
			},
		})...)
	}

	return findings
}

// contractForValidation normaliza os aliases legados de escopo e budget
// (`scope` e `budget`) e decodifica o contrato V4.
func contractForValidation(raw map[string]any) (contract.TaskContractV4, bool) {
	merged := make(map[string]any, len(raw)+2)
	for key, value := range raw {
		merged[key] = value
	}
	merged["scope_contract"] = firstObject(raw["scope_contract"], raw["scope"])
	merged["budget_contract"] = firstObject(raw["budget_contract"], raw["budget"])

	data, err := json.Marshal(merged)
	if err != nil {
		return contract.TaskContractV4{}, false
	}
	var taskContract contract.TaskContractV4
	if err := json.Unmarshal(data, &taskContract); err != nil {
		return contract.TaskContractV4{}, false
	}
	return taskContract, true
}

// firstObject devolve o primeiro valor que é objeto JSON, ou um objeto vazio.
func firstObject(values ...any) map[string]any {
	for _, value := range values {
		if object, ok := value.(map[string]any); ok {
			return object
		}
	}
	return map[string]any{}
}

// ValidateSemanticTraceability roda todas as validações semânticas de um Work,
// as mesmas que os gates aplicam.
func ValidateSemanticTraceability(workDir, workID string) []contract.Finding {
	findings := make([]contract.Finding, 0)
	findings = append(findings, validatePRDSemantics(workDir)...)
	findings = append(findings, validateSpecCoversPRD(workDir)...)
	findings = append(findings, ValidatePlanAcceptance(workDir)...)
	findings = append(findings, validateContractSemantics(workDir)...)
	return findings
}
