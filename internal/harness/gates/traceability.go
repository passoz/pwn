package gates

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
)

// TraceabilityEntry é uma linha da matriz de rastreabilidade.
type TraceabilityEntry struct {
	Origin        string `json:"origin"`
	RequirementID string `json:"requirement_id"`
	DecisionID    string `json:"decision_id"`
	SpecSection   string `json:"spec_section"`
	TaskID        string `json:"task_id"`
	ContractID    string `json:"contract_id"`
	EvidenceID    string `json:"evidence_id"`
	Status        string `json:"status"`
}

// TraceabilityMatrix é a matriz de rastreabilidade de um Work.
type TraceabilityMatrix struct {
	WorkID string              `json:"work_id"`
	Matrix []TraceabilityEntry `json:"matrix"`
}

// LoadTraceabilityMatrix carrega a matriz de um diretório de Work. Devolve nil
// quando o arquivo está ausente ou é inválido.
func LoadTraceabilityMatrix(workDir string) *TraceabilityMatrix {
	raw := loadTraceabilityMatrixRaw(workDir)
	if raw == nil {
		return nil
	}
	matrix := &TraceabilityMatrix{WorkID: asJSONString(raw["work_id"])}
	for _, rawEntry := range asJSONArray(raw["matrix"]) {
		entry := objectOrEmpty(rawEntry)
		matrix.Matrix = append(matrix.Matrix, TraceabilityEntry{
			Origin:        asJSONString(entry["origin"]),
			RequirementID: asJSONString(entry["requirement_id"]),
			DecisionID:    asJSONString(entry["decision_id"]),
			SpecSection:   asJSONString(entry["spec_section"]),
			TaskID:        asJSONString(entry["task_id"]),
			ContractID:    asJSONString(entry["contract_id"]),
			EvidenceID:    asJSONString(entry["evidence_id"]),
			Status:        asJSONString(entry["status"]),
		})
	}
	return matrix
}

// loadTraceabilityMatrixRaw lê a matriz como objeto JSON cru. A validação
// semântica precisa dos valores originais, sem a tipagem antecipada.
func loadTraceabilityMatrixRaw(workDir string) map[string]any {
	matrixPath := filepath.Join(workDir, "traceability-matrix.json")
	if _, err := os.Stat(matrixPath); err != nil {
		return nil
	}
	value := readArtifactJSON(matrixPath)
	matrix, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return matrix
}

// validateTraceability valida os vínculos exigidos pelo gate. A ausência da
// matriz e a matriz vazia geram achados próprios.
func validateTraceability(matrix map[string]any, gateName string, requiredFields []string, _ string) []contract.Finding {
	findings := make([]contract.Finding, 0)

	if matrix == nil {
		return append(findings, contract.Finding{
			ID:                 "FIND-TRACE-" + gateName + "-001",
			Severity:           contract.SeverityHigh,
			Type:               contract.FindingTraceabilityGap,
			SourceRefs:         []string{"traceability-matrix.json"},
			TargetRefs:         []string{},
			Description:        "Matriz de rastreabilidade ausente para gate " + gateName,
			RequiredResolution: "Criar traceability-matrix.json com links entre artefatos",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	}

	entries := asJSONArray(matrix["matrix"])
	if len(entries) == 0 {
		return append(findings, contract.Finding{
			ID:                 "FIND-TRACE-" + gateName + "-002",
			Severity:           contract.SeverityHigh,
			Type:               contract.FindingTraceabilityGap,
			SourceRefs:         []string{"traceability-matrix.json"},
			TargetRefs:         []string{},
			Description:        "Matriz de rastreabilidade vazia para gate " + gateName,
			RequiredResolution: "Adicionar entradas à matriz de rastreabilidade",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	}

	for index, rawEntry := range entries {
		entry := objectOrEmpty(rawEntry)
		for _, field := range requiredFields {
			value := entry[field]
			if jsTruthy(value) && jsScalarString(value) != "PLACEHOLDER-"+field {
				continue
			}
			target := ""
			if jsTruthy(value) {
				target = jsScalarString(value)
			}
			findings = append(findings, contract.Finding{
				ID:                 "FIND-TRACE-" + gateName + "-" + strconv.Itoa(index) + "-" + field,
				Severity:           contract.SeverityMedium,
				Type:               contract.FindingTraceabilityGap,
				SourceRefs:         []string{"matrix[" + strconv.Itoa(index) + "]"},
				TargetRefs:         []string{target},
				Description:        "Entrada " + strconv.Itoa(index+1) + " da matriz: campo \"" + field + "\" não preenchido ou é placeholder",
				RequiredResolution: "Preencher " + field + " com o ID real do artefato vinculado",
				ResolutionOwner:    "architect",
				Status:             contract.FindingStatusOpen,
			})
		}
	}

	return findings
}

// ValidateFullTraceability valida a cadeia completa de proveniência:
// DISC → REQ → PRD → CAP → TASK → CONTRACT → EVIDENCE.
func ValidateFullTraceability(workDir, workID string) []contract.Finding {
	matrix := loadTraceabilityMatrixRaw(workDir)
	findings := make([]contract.Finding, 0)

	if matrix == nil {
		return append(findings, contract.Finding{
			ID:                 "FIND-TRACE-FULL-001",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingTraceabilityGap,
			SourceRefs:         []string{"traceability-matrix.json"},
			TargetRefs:         []string{},
			Description:        "Matriz de rastreabilidade ausente — cadeia de proveniência não verificável",
			RequiredResolution: "Criar traceability-matrix.json antes de finalizar o Work",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	}

	findings = append(findings, validateTraceability(
		matrix,
		"FULL-CHAIN",
		[]string{"origin", "requirement_id", "decision_id", "spec_section", "task_id", "contract_id", "evidence_id"},
		workID,
	)...)

	verifyFile := func(artifactID string, expectedPattern *regexp.Regexp) {
		if artifactID == "" {
			return
		}
		entries, err := os.ReadDir(workDir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), artifactID) || expectedPattern.MatchString(entry.Name()) {
				return
			}
		}
		findings = append(findings, contract.Finding{
			ID:                 "FIND-TRACE-VERIFY-" + artifactID,
			Severity:           contract.SeverityMedium,
			Type:               contract.FindingTraceabilityGap,
			SourceRefs:         []string{"traceability-matrix.json"},
			TargetRefs:         []string{artifactID},
			Description:        "Artefato referenciado \"" + artifactID + "\" não encontrado no diretório do Work",
			RequiredResolution: "Verificar se o artefato " + artifactID + " foi criado corretamente",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	}

	requirementsPattern := regexp.MustCompile("requirements")
	contractPattern := regexp.MustCompile("contract|plan")
	evidencePattern := regexp.MustCompile("evidence|test")
	for _, rawEntry := range asJSONArray(matrix["matrix"]) {
		entry := objectOrEmpty(rawEntry)
		if requirementID := asJSONString(entry["requirement_id"]); requirementID != "" {
			verifyFile(requirementID, requirementsPattern)
		}
		if contractID := asJSONString(entry["contract_id"]); contractID != "" {
			verifyFile(contractID, contractPattern)
		}
		if evidenceID := asJSONString(entry["evidence_id"]); evidenceID != "" {
			verifyFile(evidenceID, evidencePattern)
		}
	}

	return findings
}
