// Package gates porta src/core/gates.ts: os cinco gates de verificação de um
// Work, a validação semântica dos artefatos e a cobertura agregada.
//
// Cada gate lê o diretório do Work, produz achados com os mesmos IDs,
// severidades, tipos, mensagens e ordem do TypeScript e conclui com pass,
// pass_with_notes ou blocked.
package gates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// ResultStatus é o veredito de um gate.
type ResultStatus string

const (
	// ResultPass indica ausência de achados.
	ResultPass ResultStatus = "pass"
	// ResultPassWithNotes indica achados que não bloqueiam.
	ResultPassWithNotes ResultStatus = "pass_with_notes"
	// ResultBlocked indica achado open de severidade high ou critical.
	ResultBlocked ResultStatus = "blocked"
)

// Summary conta os achados por categoria. A ordem dos campos é a do
// TypeScript, para que o JSON serializado mantenha a mesma forma.
type Summary struct {
	Covered          int `json:"covered"`
	Gaps             int `json:"gaps"`
	Conflicts        int `json:"conflicts"`
	Ambiguities      int `json:"ambiguities"`
	TraceabilityGaps int `json:"traceability_gaps"`
}

// InputVersions são os hashes dos artefatos de entrada na ordem de inserção do
// TypeScript. A ordem importa: o JSON.stringify do objeto preserva a ordem em
// que as chaves foram escritas.
type InputVersions []jsonx.Field

// Get devolve o hash de um artefato.
func (v InputVersions) Get(key string) (string, bool) {
	for _, field := range v {
		if field.Key == key {
			value, ok := field.Value.(string)
			return value, ok
		}
	}
	return "", false
}

// MarshalJSON emite o objeto na ordem de inserção.
func (v InputVersions) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return jsonx.Insertion(jsonx.Fields(v))
}

// UnmarshalJSON lê o objeto preservando a ordem do documento.
func (v *InputVersions) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("gates: input_versions não é um objeto")
	}
	fields := make(InputVersions, 0, 4)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("gates: chave de input_versions não é string")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		fields = append(fields, jsonx.Field{Key: key, Value: value})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*v = fields
	return nil
}

// GateOutput é o resultado de um gate. A ordem dos campos é a do TypeScript.
type GateOutput struct {
	Gate          string             `json:"gate"`
	WorkID        string             `json:"work_id"`
	InputVersions InputVersions      `json:"input_versions"`
	Result        ResultStatus       `json:"result"`
	Summary       Summary            `json:"summary"`
	Findings      []contract.Finding `json:"findings"`
}

// gateOutputJSON é a forma serializável de GateOutput: InputVersions vira
// jsonx.Fields para que o objeto saia na ordem de inserção, sem escapar HTML.
type gateOutputJSON struct {
	Gate          string             `json:"gate"`
	WorkID        string             `json:"work_id"`
	InputVersions jsonx.Fields       `json:"input_versions"`
	Result        ResultStatus       `json:"result"`
	Summary       Summary            `json:"summary"`
	Findings      []contract.Finding `json:"findings"`
}

// MarshalOutput devolve o GateOutput com os mesmos bytes do JSON.stringify do
// TypeScript: ordem de campos declarada e sem escapar <, > e &.
//
// encoding/json escapa HTML e reescapa o resultado de um Marshaler, por isso a
// serialização canônica não usa json.Marshal.
func MarshalOutput(output GateOutput) ([]byte, error) {
	return jsonx.Insertion(gateOutputJSON{
		Gate:          output.Gate,
		WorkID:        output.WorkID,
		InputVersions: jsonx.Fields(output.InputVersions),
		Result:        output.Result,
		Summary:       output.Summary,
		Findings:      output.Findings,
	})
}

// shortHash devolve o SHA-256 do arquivo truncado em 12 caracteres. Um arquivo
// ausente ou ilegível vira "absent".
func shortHash(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "absent"
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])[:12]
}

// contractsHash é a versão combinada dos contratos referenciados pelo plano.
// Ela entra na chave do cache do GATE-PLAN-CONTRACT: o gate lê os contratos,
// então um contrato editado não pode continuar servindo o veredito antigo.
func contractsHash(workDir string) string {
	planData, ok := readArtifactJSON(filepath.Join(workDir, "plan.json")).(map[string]any)
	if !ok {
		return "absent"
	}
	var ids []string
	for _, raw := range asJSONArray(planData["tasks"]) {
		task, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if id := asJSONString(task["contract_id"]); id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	hasher := sha256.New()
	for _, id := range ids {
		hasher.Write([]byte(id + ":" + shortHash(filepath.Join(workDir, id+".json")) + ";"))
	}
	return hex.EncodeToString(hasher.Sum(nil))[:12]
}

// blocked informa se existe achado open de severidade high ou critical.
func blocked(findings []contract.Finding) bool {
	for _, finding := range findings {
		if (finding.Severity == contract.SeverityCritical || finding.Severity == contract.SeverityHigh) &&
			finding.Status == contract.FindingStatusOpen {
			return true
		}
	}
	return false
}

// summarize monta o resumo de um gate.
func summarize(findings []contract.Finding, covered int) Summary {
	summary := Summary{Covered: covered}
	for _, finding := range findings {
		switch finding.Type {
		case contract.FindingCoverageGap:
			summary.Gaps++
		case contract.FindingConflict:
			summary.Conflicts++
		case contract.FindingAmbiguity:
			summary.Ambiguities++
		case contract.FindingTraceabilityGap:
			summary.TraceabilityGaps++
		}
	}
	return summary
}

// newOutput monta o GateOutput com as mesmas regras de resultado do TypeScript.
func newOutput(gate, workID string, versions InputVersions, covered int, findings []contract.Finding) GateOutput {
	if findings == nil {
		findings = []contract.Finding{}
	}
	result := ResultPass
	if blocked(findings) {
		result = ResultBlocked
	} else if len(findings) > 0 {
		result = ResultPassWithNotes
	}
	return GateOutput{
		Gate:          gate,
		WorkID:        workID,
		InputVersions: versions,
		Result:        result,
		Summary:       summarize(findings, covered),
		Findings:      findings,
	}
}

// ── Helpers de artefato ────────────────────────────────────────────

// readArtifactJSON lê um JSON do Work sem lançar: devolve nil quando o arquivo
// está ausente ou ilegível.
func readArtifactJSON(filePath string) any {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil
	}
	return value
}

// decodeArtifactJSON lê um JSON e devolve o erro de leitura. Usado quando o
// gate precisa da mensagem do erro no achado.
func decodeArtifactJSON(filePath string) (any, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func isJSONObject(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

// asJSONArray normaliza a forma de um dado externo: só um array JSON é array.
func asJSONArray(value any) []any {
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	return array
}

func asJSONString(value any) string {
	text, _ := value.(string)
	return text
}

// isEmptyLength reproduz `!value || value.length === 0`: verdadeiro para valor
// falsy, array vazio e valor com propriedade length igual a zero.
func isEmptyLength(value any) bool {
	if !jsTruthy(value) {
		return true
	}
	switch typed := value.(type) {
	case []any:
		return len(typed) == 0
	case string:
		return len(typed) == 0
	case map[string]any:
		if length, ok := typed["length"].(float64); ok {
			return length == 0
		}
		return false
	default:
		return false
	}
}

// jsonArrayForMap reproduz `(value || []).map(...)`: um valor ausente ou falsy
// vira array vazio; um valor truthy que não é array não é iterável e aborta a
// checagem. O segundo resultado informa se a checagem pode seguir.
func jsonArrayForMap(value any) ([]any, bool) {
	if !jsTruthy(value) {
		return nil, true
	}
	array, ok := value.([]any)
	return array, ok
}

func objectOrEmpty(value any) map[string]any {
	if object, ok := value.(map[string]any); ok {
		return object
	}
	return map[string]any{}
}

// jsTruthy reproduz a conversão de valor para booleano do JavaScript.
func jsTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case float64:
		return typed != 0 && !math.IsNaN(typed)
	default:
		return true
	}
}

// jsScalarString reproduz String(valor) do JavaScript para valores escalares.
func jsScalarString(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return formatJSNumber(typed)
	default:
		data, err := jsonx.Insertion(value)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

// formatJSNumber aproxima Number.prototype.toString para os inteiros pequenos
// usados nos identificadores.
func formatJSNumber(value float64) string {
	if value == math.Trunc(value) && math.Abs(value) < 1e21 {
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	return strconv.FormatFloat(value, 'g', -1, 64)
}

// jsID devolve o identificador do item como o TypeScript o interpola: o valor
// quando ele é truthy, senão o fallback.
func jsID(value any, fallback string) string {
	if jsTruthy(value) {
		return jsScalarString(value)
	}
	return fallback
}

// ── Gate 1: DISC → REQ ─────────────────────────────────────────────

// EvaluateGateDiscReq avalia o GATE-DISC-REQ.
func EvaluateGateDiscReq(workID, workDir string) GateOutput {
	discoveryPath := filepath.Join(workDir, "discovery.json")
	requirementsPath := filepath.Join(workDir, "requirements.json")

	findings := make([]contract.Finding, 0)
	covered := 0

	if _, err := os.Stat(discoveryPath); err != nil {
		findings = append(findings, contract.Finding{
			ID:                 "FIND-001",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"discovery.json"},
			TargetRefs:         []string{},
			Description:        "Artefato discovery.json ausente no Work",
			RequiredResolution: "Criar e preencher discovery.json antes de derivar requisitos",
			ResolutionOwner:    "product-owner",
			Status:             contract.FindingStatusOpen,
		})
	}

	if _, err := os.Stat(requirementsPath); err != nil {
		findings = append(findings, contract.Finding{
			ID:                 "FIND-002",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"requirements.json"},
			TargetRefs:         []string{},
			Description:        "Artefato requirements.json ausente no Work",
			RequiredResolution: "Criar requisitos observáveis a partir do Discovery",
			ResolutionOwner:    "product-owner",
			Status:             contract.FindingStatusOpen,
		})
	}

	if len(findings) == 0 {
		value, err := decodeArtifactJSON(requirementsPath)
		if err != nil {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-ERR-01",
				Severity:           contract.SeverityCritical,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{"requirements.json"},
				TargetRefs:         []string{},
				Description:        "Erro ao ler JSON de requisitos: " + err.Error(),
				RequiredResolution: "Corrigir a sintaxe JSON do arquivo de requisitos",
				ResolutionOwner:    "product-owner",
				Status:             contract.FindingStatusOpen,
			})
		} else {
			reqData := objectOrEmpty(value)
			reqList := asJSONArray(reqData["requirements"])
			if _, present := reqData["requirements"]; !present || !jsTruthy(reqData["requirements"]) {
				reqList = asJSONArray(reqData["user_stories"])
			}
			covered = len(reqList)

			for index, rawReq := range reqList {
				req := objectOrEmpty(rawReq)
				if isEmptyLength(req["acceptance_criteria"]) {
					id := jsID(req["id"], "")
					ref := id
					descriptionID := id
					if id == "" {
						ref = "REQ-" + strconv.Itoa(index+1)
						descriptionID = strconv.Itoa(index + 1)
					}
					findings = append(findings, contract.Finding{
						ID:                 "FIND-REQ-" + strconv.Itoa(index+1),
						Severity:           contract.SeverityHigh,
						Type:               contract.FindingUnverifiableAcceptance,
						SourceRefs:         []string{ref},
						TargetRefs:         []string{},
						Description:        "Requisito " + descriptionID + " sem critérios de aceite observáveis",
						RequiredResolution: "Adicionar critérios de aceite testáveis",
						ResolutionOwner:    "product-owner",
						Status:             contract.FindingStatusOpen,
					})
				}
			}
		}
	}

	findings = append(findings, validateTraceability(loadTraceabilityMatrixRaw(workDir), "DISC-REQ", []string{"origin", "requirement_id"}, workID)...)

	return newOutput("GATE-DISC-REQ", workID, InputVersions{
		{Key: "discovery", Value: shortHash(discoveryPath)},
		{Key: "requirements", Value: shortHash(requirementsPath)},
		{Key: "traceability_matrix", Value: shortHash(filepath.Join(workDir, "traceability-matrix.json"))},
	}, covered, findings)
}

// ── Gate 2: REQ → PRD ──────────────────────────────────────────────

// EvaluateGateReqPrd avalia o GATE-REQ-PRD.
func EvaluateGateReqPrd(workID, workDir string) GateOutput {
	reqPath := filepath.Join(workDir, "requirements.json")
	prdPath := filepath.Join(workDir, "prd.json")

	findings := make([]contract.Finding, 0)
	covered := 0

	if _, err := os.Stat(prdPath); err != nil {
		findings = append(findings, contract.Finding{
			ID:                 "FIND-PRD-01",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"prd.json"},
			TargetRefs:         []string{},
			Description:        "Artefato prd.json ausente no Work",
			RequiredResolution: "Consolidar decisão de produto em prd.json",
			ResolutionOwner:    "product-owner",
			Status:             contract.FindingStatusOpen,
		})
	} else {
		value, err := decodeArtifactJSON(prdPath)
		if err != nil {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-PRD-ERR",
				Severity:           contract.SeverityCritical,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{"prd.json"},
				TargetRefs:         []string{},
				Description:        "Erro na leitura do prd.json: " + err.Error(),
				RequiredResolution: "Corrigir formato do prd.json",
				ResolutionOwner:    "product-owner",
				Status:             contract.FindingStatusOpen,
			})
		} else {
			prdData := objectOrEmpty(value)
			acceptedReqs := asJSONArray(prdData["accepted_requirements"])
			covered = len(acceptedReqs)

			if covered == 0 {
				findings = append(findings, contract.Finding{
					ID:                 "FIND-PRD-02",
					Severity:           contract.SeverityHigh,
					Type:               contract.FindingCoverageGap,
					SourceRefs:         []string{"prd.json"},
					TargetRefs:         []string{},
					Description:        "PRD não possui requisitos aceitos declarados (accepted_requirements)",
					RequiredResolution: "Vincular IDs dos requisitos aceitos ao PRD",
					ResolutionOwner:    "product-owner",
					Status:             contract.FindingStatusOpen,
				})
			}

			if requirementsValue, reqErr := decodeArtifactJSON(reqPath); reqErr == nil {
				reqData := objectOrEmpty(requirementsValue)
				reqIDs := make(map[string]bool)
				for _, rawReq := range asJSONArray(reqData["requirements"]) {
					req := objectOrEmpty(rawReq)
					reqIDs[jsScalarString(req["id"])] = true
				}
				for _, accepted := range acceptedReqs {
					acceptedID := jsScalarString(accepted)
					if reqIDs[acceptedID] {
						continue
					}
					findings = append(findings, contract.Finding{
						ID:                 "FIND-PRD-XREF-" + acceptedID,
						Severity:           contract.SeverityHigh,
						Type:               contract.FindingTraceabilityGap,
						SourceRefs:         []string{"prd.json", "requirements.json"},
						TargetRefs:         []string{acceptedID},
						Description:        "Requisito " + acceptedID + " aceito no PRD mas não encontrado em requirements.json",
						RequiredResolution: "Verificar se o requisito " + acceptedID + " existe ou remover do PRD",
						ResolutionOwner:    "product-owner",
						Status:             contract.FindingStatusOpen,
					})
				}
			}
		}
	}

	findings = append(findings, validatePRDSemantics(workDir)...)
	findings = append(findings, validateTraceability(loadTraceabilityMatrixRaw(workDir), "REQ-PRD", []string{"requirement_id", "decision_id"}, workID)...)

	return newOutput("GATE-REQ-PRD", workID, InputVersions{
		{Key: "requirements", Value: shortHash(reqPath)},
		{Key: "prd", Value: shortHash(prdPath)},
		{Key: "traceability_matrix", Value: shortHash(filepath.Join(workDir, "traceability-matrix.json"))},
	}, covered, findings)
}

// ── Gate 3: PRD → SPEC ─────────────────────────────────────────────

// EvaluateGatePrdSpec avalia o GATE-PRD-SPEC.
func EvaluateGatePrdSpec(workID, workDir string) GateOutput {
	prdPath := filepath.Join(workDir, "prd.json")
	specPath := filepath.Join(workDir, "spec.json")

	findings := make([]contract.Finding, 0)
	covered := 0

	if _, err := os.Stat(specPath); err != nil {
		findings = append(findings, contract.Finding{
			ID:                 "FIND-SPEC-01",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"spec.json"},
			TargetRefs:         []string{},
			Description:        "Especificação técnica spec.json ausente no Work",
			RequiredResolution: "Traduzir PRD aprovado em especificação técnica formal",
			ResolutionOwner:    "architect",
			Status:             contract.FindingStatusOpen,
		})
	} else {
		value, err := decodeArtifactJSON(specPath)
		if err != nil {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-SPEC-ERR",
				Severity:           contract.SeverityCritical,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{"spec.json"},
				TargetRefs:         []string{},
				Description:        "Erro ao ler spec.json: " + err.Error(),
				RequiredResolution: "Corrigir formato do spec.json",
				ResolutionOwner:    "architect",
				Status:             contract.FindingStatusOpen,
			})
		} else {
			specData := objectOrEmpty(value)
			capabilities := asJSONArray(specData["capabilities"])
			covered = len(capabilities)

			for index, rawCapability := range capabilities {
				capability := objectOrEmpty(rawCapability)
				if isEmptyLength(capability["rules"]) {
					id := jsID(capability["id"], "CAP-"+strconv.Itoa(index+1))
					findings = append(findings, contract.Finding{
						ID:                 "FIND-SPEC-CAP-" + strconv.Itoa(index+1),
						Severity:           contract.SeverityMedium,
						Type:               contract.FindingCoverageGap,
						SourceRefs:         []string{id},
						TargetRefs:         []string{},
						Description:        "Capacidade " + id + " não vincula nenhuma regra de negócio (rules)",
						RequiredResolution: "Adicionar regras de negócio à capacidade",
						ResolutionOwner:    "architect",
						Status:             contract.FindingStatusOpen,
					})
				}
			}

			if _, statErr := os.Stat(filepath.Join(workDir, "traceability-matrix.json")); statErr == nil {
				if matrix := loadTraceabilityMatrixRaw(workDir); matrix != nil {
					entries, ok := jsonArrayForMap(matrix["matrix"])
					sections := make(map[string]bool)
					for _, rawEntry := range entries {
						entry := objectOrEmpty(rawEntry)
						sections[jsScalarString(entry["spec_section"])] = true
					}
					if ok {
						for _, rawCapability := range capabilities {
							capability := objectOrEmpty(rawCapability)
							id := asJSONString(capability["id"])
							if id == "" || sections[id] {
								continue
							}
							findings = append(findings, contract.Finding{
								ID:                 "FIND-SPEC-TRACE-" + id,
								Severity:           contract.SeverityMedium,
								Type:               contract.FindingTraceabilityGap,
								SourceRefs:         []string{"spec.json", "traceability-matrix.json"},
								TargetRefs:         []string{id},
								Description:        "Capacidade " + id + " não está vinculada na matriz de rastreabilidade",
								RequiredResolution: "Adicionar " + id + " ao traceability-matrix.json",
								ResolutionOwner:    "architect",
								Status:             contract.FindingStatusOpen,
							})
						}
					}
				}
			}
			findings = append(findings, requirementCoverageFindings(workDir)...)
		}
	}

	return newOutput("GATE-PRD-SPEC", workID, InputVersions{
		{Key: "prd", Value: shortHash(prdPath)},
		{Key: "technical_decisions", Value: shortHash(filepath.Join(workDir, "technical-decisions.json"))},
		{Key: "spec", Value: shortHash(specPath)},
		{Key: "traceability_matrix", Value: shortHash(filepath.Join(workDir, "traceability-matrix.json"))},
	}, covered, findings)
}

// ── Gate 4: SPEC → PLAN ────────────────────────────────────────────

// EvaluateGateSpecPlan avalia o GATE-SPEC-PLAN.
func EvaluateGateSpecPlan(workID, workDir string) GateOutput {
	specPath := filepath.Join(workDir, "spec.json")
	planPath := filepath.Join(workDir, "plan.json")

	findings := make([]contract.Finding, 0)
	covered := 0

	if _, err := os.Stat(planPath); err != nil {
		findings = append(findings, contract.Finding{
			ID:                 "FIND-PLAN-01",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"plan.json"},
			TargetRefs:         []string{},
			Description:        "Artefato plan.json ausente no Work",
			RequiredResolution: "Decompor a spec técnica em plano executável de tarefas",
			ResolutionOwner:    "planner",
			Status:             contract.FindingStatusOpen,
		})
	} else {
		value, err := decodeArtifactJSON(planPath)
		if err != nil {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-PLAN-ERR",
				Severity:           contract.SeverityCritical,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         []string{},
				Description:        "Erro ao ler plan.json: " + err.Error(),
				RequiredResolution: "Corrigir formato do plan.json",
				ResolutionOwner:    "planner",
				Status:             contract.FindingStatusOpen,
			})
		} else {
			planData := objectOrEmpty(value)
			tasks := asJSONArray(planData["tasks"])
			covered = len(tasks)

			if covered == 0 {
				findings = append(findings, contract.Finding{
					ID:                 "FIND-PLAN-02",
					Severity:           contract.SeverityHigh,
					Type:               contract.FindingCoverageGap,
					SourceRefs:         []string{"plan.json"},
					TargetRefs:         []string{},
					Description:        "Plano não contém tarefas atomizadas declaradas",
					RequiredResolution: "Adicionar tarefas ao plan.json",
					ResolutionOwner:    "planner",
					Status:             contract.FindingStatusOpen,
				})
			}

			if specValue, specErr := decodeArtifactJSON(specPath); specErr == nil {
				specData := objectOrEmpty(specValue)
				capabilities, iterable := jsonArrayForMap(specData["capabilities"])
				if iterable {
					capIDs := make(map[string]bool)
					for _, rawCapability := range capabilities {
						capability := objectOrEmpty(rawCapability)
						capIDs[jsScalarString(capability["id"])] = true
					}
					for index, rawTask := range tasks {
						task := objectOrEmpty(rawTask)
						specReference := asJSONString(task["spec_reference"])
						if specReference == "" || capIDs[specReference] {
							continue
						}
						taskID := jsID(task["id"], strconv.Itoa(index+1))
						findings = append(findings, contract.Finding{
							ID:                 "FIND-PLAN-XREF-" + strconv.Itoa(index+1),
							Severity:           contract.SeverityMedium,
							Type:               contract.FindingTraceabilityGap,
							SourceRefs:         []string{"plan.json", "spec.json"},
							TargetRefs:         []string{specReference},
							Description:        "Task " + taskID + " referencia spec \"" + specReference + "\" que não existe na spec.json",
							RequiredResolution: "Corrigir spec_reference na task " + taskID,
							ResolutionOwner:    "planner",
							Status:             contract.FindingStatusOpen,
						})
					}
				}
			}
		}
	}

	findings = append(findings, ValidatePlanAcceptance(workDir)...)
	findings = append(findings, ValidateTaskAtomicity(workDir)...)

	return newOutput("GATE-SPEC-PLAN", workID, InputVersions{
		{Key: "spec", Value: shortHash(specPath)},
		{Key: "work_governance", Value: shortHash(filepath.Join(workDir, "work-governance.json"))},
		{Key: "plan", Value: shortHash(planPath)},
	}, covered, findings)
}

// ── Gate 5: PLAN → CONTRACT ────────────────────────────────────────

// EvaluateGatePlanContract avalia o GATE-PLAN-CONTRACT.
func EvaluateGatePlanContract(workID, workDir string) GateOutput {
	planPath := filepath.Join(workDir, "plan.json")

	findings := make([]contract.Finding, 0)
	covered := 0

	if _, err := os.Stat(planPath); err != nil {
		findings = append(findings, contract.Finding{
			ID:                 "FIND-CTR-01",
			Severity:           contract.SeverityCritical,
			Type:               contract.FindingCoverageGap,
			SourceRefs:         []string{"plan.json"},
			TargetRefs:         []string{},
			Description:        "Plano ausente para congelar contratos de tarefas",
			RequiredResolution: "Criar plan.json antes de gerar contratos",
			ResolutionOwner:    "planner",
			Status:             contract.FindingStatusOpen,
		})
	} else {
		value, err := decodeArtifactJSON(planPath)
		if err != nil {
			findings = append(findings, contract.Finding{
				ID:                 "FIND-CTR-ERR",
				Severity:           contract.SeverityCritical,
				Type:               contract.FindingAmbiguity,
				SourceRefs:         []string{"plan.json"},
				TargetRefs:         []string{},
				Description:        "Erro ao ler plan.json: " + err.Error(),
				RequiredResolution: "Corrigir plan.json",
				ResolutionOwner:    "planner",
				Status:             contract.FindingStatusOpen,
			})
		} else {
			planData := objectOrEmpty(value)
			tasks := asJSONArray(planData["tasks"])
			covered = len(tasks)

			for _, rawTask := range tasks {
				task := objectOrEmpty(rawTask)
				if jsTruthy(task["contract_id"]) {
					continue
				}
				taskID := jsScalarString(task["id"])
				findings = append(findings, contract.Finding{
					ID:                 "FIND-CTR-TASK-" + taskID,
					Severity:           contract.SeverityHigh,
					Type:               contract.FindingCoverageGap,
					SourceRefs:         []string{taskID},
					TargetRefs:         []string{},
					Description:        "Task " + taskID + " não vincula contract_id congelado",
					RequiredResolution: "Atribuir contract_id à task",
					ResolutionOwner:    "architect",
					Status:             contract.FindingStatusOpen,
				})
			}
		}
	}

	findings = append(findings, validateContractSemantics(workDir)...)
	findings = append(findings, validateTraceability(loadTraceabilityMatrixRaw(workDir), "PLAN-CONTRACT", []string{"task_id", "contract_id"}, workID)...)

	return newOutput("GATE-PLAN-CONTRACT", workID, InputVersions{
		{Key: "plan", Value: shortHash(planPath)},
		{Key: "task_contracts", Value: shortHash(filepath.Join(workDir, "traceability-matrix.json"))},
		{Key: "contracts", Value: contractsHash(workDir)},
	}, covered, findings)
}

// EvaluateAllGates roda os 5 gates na ordem canônica e devolve todos os
// outputs, sem parar no primeiro bloqueado.
func EvaluateAllGates(workID, workDir string) []GateOutput {
	return []GateOutput{
		EvaluateGateDiscReq(workID, workDir),
		EvaluateGateReqPrd(workID, workDir),
		EvaluateGatePrdSpec(workID, workDir),
		EvaluateGateSpecPlan(workID, workDir),
		EvaluateGatePlanContract(workID, workDir),
	}
}

// planGateCommands devolve os comandos de gate do plan.json (colunas de
// garantia dos componentes e gates globais). Nenhum deles é critério de aceite
// de task.
func planGateCommands(planData map[string]any, components []string) []string {
	wanted := make(map[string]bool, len(components))
	for _, component := range components {
		wanted[component] = true
	}
	commands := make([]string, 0)
	for _, rawComponent := range asJSONArray(planData["components"]) {
		component := objectOrEmpty(rawComponent)
		if len(wanted) > 0 && !wanted[jsScalarString(component["name"])] {
			continue
		}
		for _, key := range assuranceKeys {
			command := asJSONString(component[key])
			if command != "" && command != "N/A" {
				commands = append(commands, command)
			}
		}
	}
	for _, rawGate := range asJSONArray(planData["global_gates"]) {
		if command, ok := plan.FirstInlineCommand(asJSONString(rawGate)); ok {
			commands = append(commands, command)
		}
	}
	return commands
}

var assuranceKeys = []string{"regression", "lint", "build", "security"}

// stringList converte um array de valores para []string como String(valor) do
// JavaScript.
func stringList(value any) []string {
	items := asJSONArray(value)
	list := make([]string, len(items))
	for index, item := range items {
		list[index] = jsScalarString(item)
	}
	return list
}
