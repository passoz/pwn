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

	"github.com/passoz/pwn/internal/platform/jsonx"
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
	// Os modelos usam jsonx.Fields: a ordem das chaves é a de JSON.stringify na
	// referência. Um map de Go sairia em ordem alfabética.
	templates := []struct {
		path  string
		value jsonx.Fields
	}{
		{paths.Intake, jsonx.Fields{
			{Key: "work_id", Value: resolvedWorkID},
			{Key: "created_at", Value: now},
			{Key: "objective", Value: "Objetivo do pedido bruto"},
			{Key: "requester", Value: "operator"},
			{Key: "status", Value: "draft"},
		}},
		{paths.Discovery, jsonx.Fields{
			{Key: "work_id", Value: resolvedWorkID},
			{Key: "problem", Value: "Descrição do problema"},
			{Key: "actors", Value: []string{"ACT-001"}},
			{Key: "objectives", Value: []string{"Objetivo principal"}},
			{Key: "constraints", Value: []string{"Restrição de tecnologia/tempo"}},
		}},
		{paths.Requirements, jsonx.Fields{
			{Key: "work_id", Value: resolvedWorkID},
			{Key: "requirements", Value: []any{
				jsonx.Fields{
					{Key: "id", Value: "FR-001"},
					{Key: "title", Value: "Primeiro Requisito Funcional"},
					{Key: "user_story", Value: "Como operador, quero funcionalidade X para beneficio Y"},
					{Key: "acceptance_criteria", Value: []string{"Critério 1 observável"}},
				},
			}},
		}},
		{paths.PRD, jsonx.Fields{
			{Key: "$schema", Value: "https://pwn.dev/schemas/prd.schema.json"},
			{Key: "id", Value: "PRD-" + resolvedWorkID},
			{Key: "meta", Value: jsonx.Fields{
				{Key: "version", Value: "1.0"},
				{Key: "created_at", Value: now},
				{Key: "author", Value: "operator"},
			}},
			{Key: "title", Value: "PRD do Work " + resolvedWorkID},
			{Key: "status", Value: "draft"},
			{Key: "scenario", Value: "greenfield"},
			{Key: "problem", Value: jsonx.Fields{{Key: "statement", Value: "Problema resolvido pelo PRD — descreva o problema em detalhe"}}},
			{Key: "solution", Value: jsonx.Fields{{Key: "statement", Value: "Solucao proposta — descreva a abordagem"}}},
			{Key: "decisions", Value: []any{
				jsonx.Fields{
					{Key: "id", Value: "DEC-001"},
					{Key: "statement", Value: "Decisao inicial do produto"},
					{Key: "status", Value: "proposed"},
				},
			}},
			{Key: "requirements", Value: []any{
				jsonx.Fields{
					{Key: "id", Value: "FR-001"},
					{Key: "type", Value: "functional"},
					{Key: "statement", Value: "Primeiro requisito funcional"},
				},
			}},
			{Key: "stakeholders", Value: []any{
				jsonx.Fields{{Key: "name", Value: "operator"}, {Key: "role", Value: "ACT-001"}},
			}},
			{Key: "scope", Value: jsonx.Fields{
				{Key: "in_scope", Value: []string{"Escopo incluido"}},
				{Key: "out_of_scope", Value: []string{"Nao-objetivos"}},
			}},
			{Key: "accepted_requirements", Value: []string{"FR-001"}},
		}},
		{paths.TraceabilityMatrix, jsonx.Fields{
			{Key: "work_id", Value: resolvedWorkID},
			{Key: "matrix", Value: []any{
				jsonx.Fields{
					{Key: "origin", Value: "DISC-001"},
					{Key: "requirement_id", Value: "FR-001"},
					{Key: "decision_id", Value: "TD-001"},
					{Key: "spec_section", Value: "SPEC-001"},
					{Key: "task_id", Value: "T-001"},
					{Key: "contract_id", Value: "CTR-001"},
					{Key: "evidence_id", Value: "EVD-001"},
					{Key: "status", Value: "planned"},
				},
			}},
		}},
	}
	for _, template := range templates {
		if _, err := os.Stat(template.path); err == nil {
			continue
		}
		content, err := marshalOrdered(template.value)
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
