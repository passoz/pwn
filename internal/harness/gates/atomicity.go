package gates

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
)

// ValidateTaskAtomicity verifica que uma task mapeia para uma capability, um
// componente e um conjunto pequeno de arquivos. Os achados são advisory
// (medium/low) e nunca bloqueiam o gate.
func ValidateTaskAtomicity(workDir string) []contract.Finding {
	planData, ok := isJSONObject(readArtifactJSON(filepath.Join(workDir, "plan.json")))
	if !ok {
		return []contract.Finding{}
	}

	findings := make([]contract.Finding, 0)
	for index, rawTask := range asJSONArray(planData["tasks"]) {
		task := objectOrEmpty(rawTask)
		taskID := asJSONString(task["id"])
		if taskID == "" {
			taskID = strconv.Itoa(index + 1)
		}

		specReference := strings.TrimSpace(asJSONString(task["spec_reference"]))
		if specReference != "" && atomicSpecReference.MatchString(specReference) {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-ATOMIC-SPEC-" + taskID,
				Severity:           contract.SeverityMedium,
				Type:               contract.FindingCoverageGap,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         []string{specReference},
				Description:        "Task " + taskID + " referencia múltiplas capabilities em spec_reference (\"" + specReference + "\")",
				RequiredResolution: "Dividir a task para referenciar uma única capability",
				ResolutionOwner:    "planner",
				Status:             contract.FindingStatusOpen,
			})
		}

		components := stringList(task["components"])
		if len(components) > 1 {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-ATOMIC-COMP-" + taskID,
				Severity:           contract.SeverityLow,
				Type:               contract.FindingCoverageGap,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         components,
				Description:        "Task " + taskID + " cobre " + strconv.Itoa(len(components)) + " componentes (" + strings.Join(components, ", ") + ")",
				RequiredResolution: "Dividir a task por componente ou justificar o acoplamento",
				ResolutionOwner:    "planner",
				Status:             contract.FindingStatusOpen,
			})
		}

		implementationFiles := stringList(task["implementation_files"])
		if len(implementationFiles) > 6 {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-ATOMIC-FILES-" + taskID,
				Severity:           contract.SeverityLow,
				Type:               contract.FindingCoverageGap,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         implementationFiles,
				Description:        "Task " + taskID + " declara " + strconv.Itoa(len(implementationFiles)) + " arquivos de implementação (> 6)",
				RequiredResolution: "Dividir a task em unidades menores",
				ResolutionOwner:    "planner",
				Status:             contract.FindingStatusOpen,
			})
		}

		behavior := asJSONString(task["behavior"])
		conjunctions := strings.Count(behavior, " e ") + strings.Count(behavior, " and ")
		if conjunctions > 3 {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-ATOMIC-BEHAVIOR-" + taskID,
				Severity:           contract.SeverityLow,
				Type:               contract.FindingCoverageGap,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         []string{},
				Description:        "Task " + taskID + " descreve múltiplos comportamentos encadeados (" + strconv.Itoa(conjunctions) + " conjunções)",
				RequiredResolution: "Decompor o comportamento em tasks atômicas",
				ResolutionOwner:    "planner",
				Status:             contract.FindingStatusOpen,
			})
		}
	}

	return findings
}

// WorkCoverage é a cobertura agregada de um Work.
type WorkCoverage struct {
	Requirements          int `json:"requirements"`
	AcceptedRequirements  int `json:"accepted_requirements"`
	Capabilities          int `json:"capabilities"`
	CapabilitiesWithRules int `json:"capabilities_with_rules"`
	Tasks                 int `json:"tasks"`
	TasksWithContract     int `json:"tasks_with_contract"`
	TasksWithACs          int `json:"tasks_with_acs"`
}

// ComputeWorkCoverage conta quantos requisitos, capabilities, tasks e
// contratos existem e estão vinculados.
func ComputeWorkCoverage(workDir string) WorkCoverage {
	requirementsData, _ := isJSONObject(readArtifactJSON(filepath.Join(workDir, "requirements.json")))
	prdData, _ := isJSONObject(readArtifactJSON(filepath.Join(workDir, "prd.json")))
	specData, _ := isJSONObject(readArtifactJSON(filepath.Join(workDir, "spec.json")))
	planData, _ := isJSONObject(readArtifactJSON(filepath.Join(workDir, "plan.json")))

	requirements := asJSONArray(requirementsData["requirements"])
	acceptedRequirements := asJSONArray(prdData["accepted_requirements"])
	capabilities := asJSONArray(specData["capabilities"])
	tasks := asJSONArray(planData["tasks"])

	coverage := WorkCoverage{
		Requirements:         len(requirements),
		AcceptedRequirements: len(acceptedRequirements),
		Capabilities:         len(capabilities),
		Tasks:                len(tasks),
	}
	for _, rawCapability := range capabilities {
		capability, ok := isJSONObject(rawCapability)
		if ok && len(asJSONArray(capability["rules"])) > 0 {
			coverage.CapabilitiesWithRules++
		}
	}
	for _, rawTask := range tasks {
		task, ok := isJSONObject(rawTask)
		if !ok {
			continue
		}
		if len(asJSONString(task["contract_id"])) > 0 {
			coverage.TasksWithContract++
		}
		if len(asJSONArray(task["acceptance_criteria"])) > 0 {
			coverage.TasksWithACs++
		}
	}
	return coverage
}
