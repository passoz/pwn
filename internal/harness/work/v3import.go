package work

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
)

// V3ImportOptions descreve a importação de um Work v3.
type V3ImportOptions struct {
	RootDir string
	WorkID  string
	// Force sobrescreve artefatos existentes em `.pwn/work/<id>`.
	Force bool
	// Risk congela o risco nos contratos derivados. `auto` classifica por task;
	// vazio usa L2.
	Risk string
	// GateChain também deriva a cadeia documental
	// (discovery/requirements/prd/spec/traceability).
	GateChain bool
	// Decider eleva o risco determinístico no modo `auto`. Nil usa a heurística.
	Decider RiskDecider
}

// CapabilityMappingEntry é o resultado do mapeamento task → capability.
type CapabilityMappingEntry struct {
	Task       string `json:"task"`
	Capability string `json:"capability"`
	Score      int    `json:"score"`
}

// RiskMappingEntry é o risco congelado de uma task importada.
type RiskMappingEntry struct {
	Task string             `json:"task"`
	Risk contract.RiskLevel `json:"risk"`
}

// V3ImportResult é o resultado da importação.
type V3ImportResult struct {
	WorkID            string                   `json:"workId"`
	WorkDir           string                   `json:"workDir"`
	Generated         []string                 `json:"generated"`
	Skipped           []SkippedFile            `json:"skipped"`
	Warnings          []string                 `json:"warnings"`
	CapabilityMapping []CapabilityMappingEntry `json:"capabilityMapping"`
	RiskMapping       []RiskMappingEntry       `json:"riskMapping"`
	Plan              plan.Plan                `json:"plan"`
}

// writeImportJSON grava value, ou registra o arquivo preservado.
func writeImportJSON(filePath string, value any, generated *[]string, skipped *[]SkippedFile, force bool) error {
	if _, err := os.Stat(filePath); err == nil && !force {
		*skipped = append(*skipped, SkippedFile{
			File:   filepath.Base(filePath),
			Reason: "já existe (use --force para sobrescrever)",
		})
		return nil
	}
	if err := writeJSON(filePath, value); err != nil {
		return err
	}
	*generated = append(*generated, filepath.Base(filePath))
	return nil
}

var prdRequirementPrefix = regexp.MustCompile(`^(FR|QR|EC|SC)`)
var nonDigits = regexp.MustCompile(`\D`)

// ImportV3Work traduz um Work v3 para os artefatos canônicos em
// `.pwn/work/<id>/`. Só lê os artefatos v3; nunca os apaga ou reescreve.
func ImportV3Work(options V3ImportOptions) (V3ImportResult, error) {
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	workID := options.WorkID
	riskChoice := options.Risk
	if riskChoice == "" {
		riskChoice = string(contract.RiskL2)
	}

	files, err := FindV3Work(rootDir, workID)
	if err != nil {
		return V3ImportResult{}, err
	}
	if files == nil {
		return V3ImportResult{}, fmt.Errorf("Work v3 %s não encontrado: falta .todo/%s-tasks.md em %s", workID, workID, rootDir)
	}

	planData, err := os.ReadFile(files.PlanPath)
	if err != nil {
		return V3ImportResult{}, fmt.Errorf("work: ler %s: %w", files.PlanPath, err)
	}
	planValue := ParseV3PlanMarkdown(string(planData), workID)
	if len(planValue.Tasks) == 0 {
		return V3ImportResult{}, fmt.Errorf("Nenhuma task canônica encontrada em %s", files.PlanPath)
	}

	systemSpec := ""
	if files.SystemSpecPath != nil {
		data, err := os.ReadFile(*files.SystemSpecPath)
		if err != nil {
			return V3ImportResult{}, fmt.Errorf("work: ler %s: %w", *files.SystemSpecPath, err)
		}
		systemSpec = string(data)
	}
	capabilityMap := ParseCapabilityMap(systemSpec)

	var prompt *PromptDigest
	if files.PromptPath != nil {
		data, err := os.ReadFile(*files.PromptPath)
		if err != nil {
			return V3ImportResult{}, fmt.Errorf("work: ler %s: %w", *files.PromptPath, err)
		}
		digest := ParsePromptDigest(string(data))
		prompt = &digest
	}
	source := ""
	if files.SourcePath != nil {
		data, err := os.ReadFile(*files.SourcePath)
		if err != nil {
			return V3ImportResult{}, fmt.Errorf("work: ler %s: %w", *files.SourcePath, err)
		}
		source = string(data)
	}

	warnings := make([]string, 0)
	capabilityMapping := make([]CapabilityMappingEntry, 0, len(planValue.Tasks))
	riskMapping := make([]RiskMappingEntry, 0, len(planValue.Tasks))
	for index := range planValue.Tasks {
		task := &planValue.Tasks[index]
		capabilityID, score := MapTaskToCapability(*task, capabilityMap)
		task.SpecReference = capabilityID
		capabilityMapping = append(capabilityMapping, CapabilityMappingEntry{Task: task.ID, Capability: capabilityID, Score: score})
		if score == 0 {
			warnings = append(warnings, fmt.Sprintf("Task %s: nenhuma capability casou por palavra-chave; usando %s — revise o spec_reference.", task.ID, capabilityID))
		}
		level := contract.RiskLevel(riskChoice)
		if riskChoice == "auto" {
			level = DeriveTaskRisk(*task)
		} else {
			parsed, err := contract.ParseRiskLevel(riskChoice)
			if err != nil {
				return V3ImportResult{}, fmt.Errorf("work: --risk: %w", err)
			}
			level = parsed
		}
		riskMapping = append(riskMapping, RiskMappingEntry{Task: task.ID, Risk: level})
	}
	if riskChoice == "auto" {
		if err := applyRiskDecider(context.Background(), options.Decider, workID, planValue.Tasks, riskMapping, &warnings); err != nil {
			return V3ImportResult{}, err
		}
	}

	workDir := filepath.Join(rootDir, ".pwn", "work", workID)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return V3ImportResult{}, fmt.Errorf("work: criar %s: %w", workDir, err)
	}
	generated := make([]string, 0)
	skipped := make([]SkippedFile, 0)
	write := func(name string, value any) error {
		return writeImportJSON(filepath.Join(workDir, name), value, &generated, &skipped, options.Force)
	}

	// 1. Plano canônico (schema plan.schema.json).
	if err := write("plan.json", planDocument{Schema: "../../../schemas/plan.schema.json", Plan: planValue}); err != nil {
		return V3ImportResult{}, err
	}

	// 2. Contratos V4 congelados (risco por task no modo `auto`).
	for index := range planValue.Tasks {
		task := planValue.Tasks[index]
		taskRisk := contract.RiskL2
		for _, entry := range riskMapping {
			if entry.Task == task.ID {
				taskRisk = entry.Risk
				break
			}
		}
		derived, err := DeriveContract(planValue, task, workID, taskRisk)
		if err != nil {
			return V3ImportResult{}, err
		}
		if err := write(task.ContractID+".json", derived); err != nil {
			return V3ImportResult{}, err
		}
	}

	result := V3ImportResult{
		WorkID:            workID,
		WorkDir:           normalizeWorkPath(workDir),
		Generated:         generated,
		Skipped:           skipped,
		Warnings:          warnings,
		CapabilityMapping: capabilityMapping,
		RiskMapping:       riskMapping,
		Plan:              planValue,
	}
	if !options.GateChain {
		return result, nil
	}

	// 3. Cadeia documental derivada do prompt/plano/system spec.
	requirementEntries := make([]requirementEntry, 0, len(planValue.Tasks))
	accepted := make([]string, 0, len(planValue.Tasks))
	for _, task := range planValue.Tasks {
		criteria := make([]string, 0, len(task.AcceptanceCriteria))
		for _, entry := range task.AcceptanceCriteria {
			criteria = append(criteria, entry.Command+" — "+entry.Description)
		}
		requirementEntries = append(requirementEntries, requirementEntry{
			ID:                 task.RequirementID,
			Title:              task.Title,
			AcceptanceCriteria: criteria,
		})
		accepted = append(accepted, task.RequirementID)
	}
	accepted = unique(accepted)

	problem := fmt.Sprintf("O Work %s (\"%s\") precisa ser executado sob governança determinística do PWN.", workID, planValue.Title)
	solution := fmt.Sprintf("Executar o plano \"%s\" com contratos V4 congelados, sandbox e diff guard.", planValue.Title)
	actors := []string{"Operador humano"}
	inScope := make([]string, 0, len(planValue.Tasks))
	for _, task := range planValue.Tasks {
		inScope = append(inScope, task.Title)
	}
	outOfScope := []string{"Itens não declarados no plano importado"}
	if prompt != nil {
		if len([]rune(prompt.Problem)) >= 20 {
			problem = prompt.Problem
		}
		if len([]rune(prompt.Solution)) >= 20 {
			solution = prompt.Solution
		}
		if len(prompt.Actors) > 0 {
			actors = prompt.Actors
		}
		if len(prompt.InScope) > 0 {
			inScope = prompt.InScope
		}
		if len(prompt.OutOfScope) > 0 {
			outOfScope = prompt.OutOfScope
		}
	}

	importedFrom, err := filepath.Rel(rootDir, files.PlanPath)
	if err != nil {
		return V3ImportResult{}, fmt.Errorf("work: resolver %s: %w", files.PlanPath, err)
	}
	objectives := inScope
	constraints := planValue.GlobalGates
	if prompt != nil {
		if len(prompt.SuccessCriteria) > 0 {
			objectives = prompt.SuccessCriteria
		}
		if len(prompt.Constraints) > 0 {
			constraints = prompt.Constraints
		}
	}
	if err := write("discovery.json", discoveryDocument{
		WorkID:        workID,
		Title:         planValue.Title,
		GrillingDepth: "medium",
		Problem:       problem,
		Actors:        nonNil(actors),
		Objectives:    nonNil(objectives),
		Constraints:   nonNil(constraints),
		ImportedFrom:  normalizeWorkPath(importedFrom),
	}); err != nil {
		return V3ImportResult{}, err
	}

	if err := write("requirements.json", requirementDocument{
		WorkID:       workID,
		Requirements: requirementEntries,
	}); err != nil {
		return V3ImportResult{}, err
	}

	prdStatus := "draft"
	allDone := true
	for _, task := range planValue.Tasks {
		if task.Status != "done" {
			allDone = false
			break
		}
	}
	if allDone {
		prdStatus = "approved"
	}
	prdRequirements := make([]prdRequirement, 0, len(requirementEntries))
	for _, entry := range requirementEntries {
		requirementID := entry.ID
		if !prdRequirementPrefix.MatchString(requirementID) {
			requirementID = "FR-" + nonDigits.ReplaceAllString(requirementID, "")
		}
		prdRequirements = append(prdRequirements, prdRequirement{
			ID:                 requirementID,
			Type:               "functional",
			Statement:          entry.ID + ": " + entry.Title,
			AcceptanceCriteria: entry.AcceptanceCriteria,
		})
	}
	stakeholders := make([]prdStakeholder, 0, len(actors))
	for _, name := range actors {
		stakeholders = append(stakeholders, prdStakeholder{Name: name, Role: "stakeholder"})
	}
	if len(stakeholders) == 0 {
		stakeholders = append(stakeholders, prdStakeholder{Name: "Operador humano", Role: "operator"})
	}
	prdTitle := planValue.Title
	if len([]rune(prdTitle)) > 100 {
		prdTitle = string([]rune(prdTitle)[:100])
	}
	if err := write("prd.json", prdDocument{
		Schema:   "../../../schemas/prd.schema.json",
		ID:       "PRD-" + workID,
		Meta:     prdMeta{Version: "1.0", CreatedAt: nowISO(), Author: "pwn-import"},
		Title:    prdTitle,
		Status:   prdStatus,
		Scenario: "brownfield",
		Problem:  prdStatement{Statement: problem},
		Solution: prdStatement{Statement: solution},
		Decisions: []prdDecision{{
			ID:        "DEC-001",
			Statement: fmt.Sprintf("Governar o Work %s pelo PWN com contratos V4 congelados derivados do plano v3.", workID),
			Status:    "accepted",
			MadeBy:    "pwn-import",
		}},
		Requirements:         prdRequirements,
		Stakeholders:         stakeholders,
		Scope:                prdScope{InScope: nonNil(inScope), OutOfScope: nonNil(outOfScope)},
		AcceptedRequirements: nonNil(accepted),
	}); err != nil {
		return V3ImportResult{}, err
	}

	capabilityIDs := make([]string, 0, len(planValue.Tasks))
	for _, task := range planValue.Tasks {
		capabilityIDs = append(capabilityIDs, task.SpecReference)
	}
	usedCapabilities := unique(capabilityIDs)
	capabilityRows := make([]capability, 0, len(usedCapabilities))
	for _, id := range usedCapabilities {
		var found *Capability
		for index := range capabilityMap.Capabilities {
			if capabilityMap.Capabilities[index].ID == id {
				found = &capabilityMap.Capabilities[index]
				break
			}
		}
		row := capability{
			ID:          id,
			Name:        fmt.Sprintf("Capacidade do Work %s", workID),
			Description: fmt.Sprintf("Capacidade implementada pelo Work %s: %s.", workID, planValue.Title),
			Rules:       []string{"BR-001"},
		}
		if found != nil {
			row.Name = found.Name
			row.Description = found.Description
		}
		if len(capabilityMap.Rules) > 0 {
			rules := make([]string, 0, len(capabilityMap.Rules))
			for _, rule := range capabilityMap.Rules {
				rules = append(rules, rule.ID)
			}
			row.Rules = rules
		}
		capabilityRows = append(capabilityRows, row)
	}
	rules := make([]specRule, 0, len(capabilityMap.Rules))
	if len(capabilityMap.Rules) > 0 {
		for _, rule := range capabilityMap.Rules {
			rules = append(rules, specRule{ID: rule.ID, Statement: rule.Statement})
		}
	} else {
		rules = append(rules, specRule{ID: "BR-001", Statement: "A execução deve permanecer dentro do escopo congelado nos contratos V4."})
	}
	if err := write("spec.json", specDocument{
		WorkID:       workID,
		Title:        planValue.Title,
		Capabilities: capabilityRows,
		Rules:        rules,
	}); err != nil {
		return V3ImportResult{}, err
	}

	matrix := make([]traceabilityEntry, 0, len(planValue.Tasks))
	for index, task := range planValue.Tasks {
		status := "planned"
		if task.Status == "done" {
			status = "done"
		}
		matrix = append(matrix, traceabilityEntry{
			Origin:        "DISC-001",
			RequirementID: task.RequirementID,
			DecisionID:    "DEC-001",
			SpecSection:   task.SpecReference,
			TaskID:        task.ID,
			ContractID:    task.ContractID,
			EvidenceID:    fmt.Sprintf("EVD-%03d", index+1),
			Status:        status,
		})
	}
	if err := write("traceability-matrix.json", traceabilityDocument{WorkID: workID, Matrix: matrix}); err != nil {
		return V3ImportResult{}, err
	}

	if strings.TrimSpace(source) == "" {
		result.Warnings = append(result.Warnings, "Nenhum .sources/NNNN-*.md encontrado: discovery.json derivado apenas do prompt/plano.")
	}
	result.Generated = generated
	result.Skipped = skipped
	return result, nil
}
