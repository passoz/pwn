// Package work porta os artefatos de governança de um Work do pwn:
// src/core/work-artifacts.ts, work-manifest.ts, manifest-sync.ts,
// project_status.ts, scaffold.ts, reconcile.ts e v3-import.ts.
//
// O pacote lê e escreve os arquivos do Work (`.pwn/work/<NNNN>/`, `.work/`,
// `.todo/`, `.pwn`, `.sources/`, `.prompts/`) e deriva o estado do projeto
// deles. Nenhuma decisão de conclusão nasce aqui: a aceitação de uma task vem
// de `verify.EvaluateAcceptance`, com recibo assinado pelo verificador
// independente.
package work

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WorkArtifactsPaths são os caminhos canônicos de um Work.
type WorkArtifactsPaths struct {
	WorkDir            string `json:"work_dir"`
	Intake             string `json:"intake"`
	Discovery          string `json:"discovery"`
	Requirements       string `json:"requirements"`
	PRD                string `json:"prd"`
	TechnicalDecisions string `json:"technical_decisions"`
	Spec               string `json:"spec"`
	Enrichment         string `json:"enrichment"`
	WorkGovernance     string `json:"work_governance"`
	Plan               string `json:"plan"`
	Progress           string `json:"progress"`
	TraceabilityMatrix string `json:"traceability_matrix"`
}

// workIDDirectory é a trilha canônica de diretórios de Work ID, compartilhada
// com a CLI (`pwn work init`).
const workIDDirectory = ".pwn/work"

// GetExistingWorkIDs devolve os Work IDs com diretório canônico não vazio.
// Diretório vazio não é um Work existente e não desloca a numeração.
func GetExistingWorkIDs(rootDir string) []string {
	if rootDir == "" {
		rootDir = "."
	}
	baseDir := filepath.Join(rootDir, workIDDirectory)
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return []string{}
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		children, err := os.ReadDir(filepath.Join(baseDir, entry.Name()))
		if err != nil || len(children) == 0 {
			continue
		}
		ids = append(ids, entry.Name())
	}
	return ids
}

// GetLatestWorkID devolve o maior Work ID conhecido, ou "0001" quando não há
// nenhum. Um ID não numérico devolve o último da lista ordenada.
func GetLatestWorkID(rootDir string) string {
	ids := ListWorkIDs(rootDir)
	if len(ids) == 0 {
		return "0001"
	}
	maxNum := 0
	for _, id := range ids {
		if number, err := strconv.Atoi(id); err == nil && number > maxNum {
			maxNum = number
		}
	}
	if maxNum == 0 {
		return ids[len(ids)-1]
	}
	return padWorkID(maxNum)
}

// GetNextWorkID devolve o próximo Work ID livre.
func GetNextWorkID(rootDir string) string {
	ids := ListWorkIDs(rootDir)
	if len(ids) == 0 {
		return "0001"
	}
	maxNum := 0
	for _, id := range ids {
		if number, err := strconv.Atoi(id); err == nil && number > maxNum {
			maxNum = number
		}
	}
	return padWorkID(maxNum + 1)
}

// padWorkID formata o número com quatro dígitos.
func padWorkID(value int) string {
	return fmt.Sprintf("%04d", value)
}

// GetWorkArtifactsPaths devolve os caminhos dos artefatos do Work.
func GetWorkArtifactsPaths(workID, rootDir string) WorkArtifactsPaths {
	if rootDir == "" {
		rootDir = "."
	}
	workDir := filepath.Join(rootDir, workIDDirectory, workID)
	return WorkArtifactsPaths{
		WorkDir:            workDir,
		Intake:             filepath.Join(workDir, "intake.json"),
		Discovery:          filepath.Join(workDir, "discovery.json"),
		Requirements:       filepath.Join(workDir, "requirements.json"),
		PRD:                filepath.Join(workDir, "prd.json"),
		TechnicalDecisions: filepath.Join(workDir, "technical-decisions.json"),
		Spec:               filepath.Join(workDir, "spec.json"),
		Enrichment:         filepath.Join(workDir, "enrichment.json"),
		WorkGovernance:     filepath.Join(workDir, "work-governance.json"),
		Plan:               filepath.Join(workDir, "plan.json"),
		Progress:           filepath.Join(workDir, "progress.json"),
		TraceabilityMatrix: filepath.Join(workDir, "traceability-matrix.json"),
	}
}

// InitWorkDirectory cria o diretório do Work e os modelos que ainda não
// existem. `workID` vazio ou "auto" usa o próximo ID livre.
func InitWorkDirectory(workID, rootDir string) (WorkArtifactsPaths, error) {
	if rootDir == "" {
		rootDir = "."
	}
	resolvedWorkID := workID
	if resolvedWorkID == "" || resolvedWorkID == "auto" {
		resolvedWorkID = GetNextWorkID(rootDir)
	}
	paths := GetWorkArtifactsPaths(resolvedWorkID, rootDir)
	if err := os.MkdirAll(paths.WorkDir, 0o755); err != nil {
		return WorkArtifactsPaths{}, fmt.Errorf("work: criar %s: %w", paths.WorkDir, err)
	}
	now := nowISO()
	templates := []struct {
		path  string
		value map[string]any
	}{
		{paths.Intake, map[string]any{
			"work_id":    resolvedWorkID,
			"created_at": now,
			"objective":  "Objetivo do pedido bruto",
			"requester":  "operator",
			"status":     "draft",
		}},
		{paths.Discovery, map[string]any{
			"work_id":     resolvedWorkID,
			"problem":     "Descrição do problema",
			"actors":      []string{"ACT-001"},
			"objectives":  []string{"Objetivo principal"},
			"constraints": []string{"Restrição de tecnologia/tempo"},
		}},
		{paths.Requirements, map[string]any{
			"work_id": resolvedWorkID,
			"requirements": []any{
				map[string]any{
					"id":                  "FR-001",
					"title":               "Primeiro Requisito Funcional",
					"user_story":          "Como operador, quero funcionalidade X para beneficio Y",
					"acceptance_criteria": []string{"Critério 1 observável"},
				},
			},
		}},
		{paths.PRD, map[string]any{
			"$schema": "https://pwn.dev/schemas/prd.schema.json",
			"id":      "PRD-" + resolvedWorkID,
			"meta": map[string]any{
				"version":    "1.0",
				"created_at": now,
				"author":     "operator",
			},
			"title":    "PRD do Work " + resolvedWorkID,
			"status":   "draft",
			"scenario": "greenfield",
			"problem":  map[string]any{"statement": "Problema resolvido pelo PRD — descreva o problema em detalhe"},
			"solution": map[string]any{"statement": "Solucao proposta — descreva a abordagem"},
			"decisions": []any{
				map[string]any{"id": "DEC-001", "statement": "Decisao inicial do produto", "status": "proposed"},
			},
			"requirements": []any{
				map[string]any{"id": "FR-001", "type": "functional", "statement": "Primeiro requisito funcional"},
			},
			"stakeholders":          []any{map[string]any{"name": "operator", "role": "ACT-001"}},
			"scope":                 map[string]any{"in_scope": []string{"Escopo incluido"}, "out_of_scope": []string{"Nao-objetivos"}},
			"accepted_requirements": []string{"FR-001"},
		}},
		{paths.TraceabilityMatrix, map[string]any{
			"work_id": resolvedWorkID,
			"matrix": []any{
				map[string]any{
					"origin":         "DISC-001",
					"requirement_id": "FR-001",
					"decision_id":    "TD-001",
					"spec_section":   "SPEC-001",
					"task_id":        "T-001",
					"contract_id":    "CTR-001",
					"evidence_id":    "EVD-001",
					"status":         "planned",
				},
			},
		}},
	}
	for _, template := range templates {
		if _, err := os.Stat(template.path); err == nil {
			continue
		}
		content, err := marshalIndent(template.value)
		if err != nil {
			return WorkArtifactsPaths{}, err
		}
		if err := writeFileAtomic(template.path, content); err != nil {
			return WorkArtifactsPaths{}, err
		}
	}
	return paths, nil
}

// normalizeWorkPath devolve o caminho relativo com separadores POSIX.
func normalizeWorkPath(value string) string {
	return strings.ReplaceAll(filepath.ToSlash(value), "\\", "/")
}
