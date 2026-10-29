package gates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
)

// MutationCase declara uma mutação que um gate precisa detectar.
type MutationCase struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Gate          string `json:"gate"`
	ExpectBlocked bool   `json:"expect_blocked"`
}

// MutationResult é o resultado de uma mutação sobre uma cópia da baseline.
type MutationResult struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Gate        string `json:"gate"`
	Detected    bool   `json:"detected"`
	Detail      string `json:"detail"`
}

// gateEvaluator é a assinatura de um gate avaliável.
type gateEvaluator func(workID, workDir string) GateOutput

// gateEvaluators é o mapa canônico gate → avaliador real.
var gateEvaluators = map[string]gateEvaluator{
	"GATE-DISC-REQ":      EvaluateGateDiscReq,
	"GATE-REQ-PRD":       EvaluateGateReqPrd,
	"GATE-PRD-SPEC":      EvaluateGatePrdSpec,
	"GATE-SPEC-PLAN":     EvaluateGateSpecPlan,
	"GATE-PLAN-CONTRACT": EvaluateGatePlanContract,
}

// requiredArtifacts são os artefatos que um Work precisa ter para servir de
// baseline das mutações.
var requiredArtifacts = []string{
	"discovery.json",
	"requirements.json",
	"prd.json",
	"spec.json",
	"plan.json",
	"traceability-matrix.json",
}

// canonicalArtifacts é um Work mínimo porém válido: todos os gates passam antes
// de qualquer mutação.
func canonicalArtifacts(workID string) map[string]any {
	taskContract, err := contract.CreateDefaultContractV4("1.1", workID, "Task de referência", contract.RiskL2, nil)
	if err != nil {
		panic("gates: contrato canônico inválido: " + err.Error())
	}
	return map[string]any{
		"discovery.json": map[string]any{
			"work_id":     workID,
			"problem":     "Problema de referência da baseline canônica de mutation testing",
			"actors":      []any{"ACT-001"},
			"objectives":  []any{"Objetivo de referência"},
			"constraints": []any{"Restrição de referência"},
		},
		"requirements.json": map[string]any{
			"work_id": workID,
			"requirements": []any{
				map[string]any{
					"id":                  "FR-001",
					"title":               "Requisito de referência",
					"user_story":          "Como operador, quero X para obter Y",
					"acceptance_criteria": []any{"Critério observável de referência"},
				},
			},
		},
		"prd.json": map[string]any{
			"$schema":               "../../schemas/prd.schema.json",
			"id":                    "PRD-" + workID,
			"title":                 "PRD de referência do Work " + workID,
			"status":                "draft",
			"accepted_requirements": []any{"FR-001"},
			"requirements": []any{
				map[string]any{
					"id":        "FR-001",
					"statement": "O Work mantém a cadeia de rastreabilidade entre os artefatos.",
				},
			},
		},
		"spec.json": map[string]any{
			"work_id": workID,
			"capabilities": []any{
				map[string]any{
					"id":          "CAP-001",
					"description": "Capacidade de referência que atende FR-001",
					"rules":       []any{"RULE-001: a rastreabilidade deve ser preservada"},
				},
			},
		},
		"plan.json": map[string]any{
			"work_id":    workID,
			"title":      "Plano de referência",
			"components": []any{map[string]any{"name": "core", "purpose": "Componente de referência"}},
			"global_gates": []any{
				"`bun test` — a suíte completa passa",
			},
			"tasks": []any{
				map[string]any{
					"id":                   "1.1",
					"title":                "Task de referência",
					"requirement_id":       "FR-001",
					"spec_reference":       "CAP-001",
					"contract_id":          "CTR-001",
					"components":           []any{"core"},
					"files":                []any{"src/feature.ts", "tests/feature.test.ts"},
					"implementation_files": []any{"src/feature.ts"},
					"test_files":           []any{"tests/feature.test.ts"},
					"red": map[string]any{
						"command":     "bun test tests/feature.test.ts",
						"description": "a asserção FEATURE-REF falha antes da implementação",
					},
					"implementation_steps": []any{"Implementar o comportamento de referência"},
					"acceptance_criteria": []any{
						map[string]any{
							"command":     "bun test tests/feature.test.ts",
							"description": "o comportamento de referência é observado",
						},
					},
				},
			},
		},
		"CTR-001.json": taskContract,
		"traceability-matrix.json": map[string]any{
			"work_id": workID,
			"matrix": []any{
				map[string]any{
					"origin":         "DISC-001",
					"requirement_id": "FR-001",
					"decision_id":    "TD-001",
					"spec_section":   "CAP-001",
					"task_id":        "1.1",
					"contract_id":    "CTR-001",
					"evidence_id":    "EVD-001",
					"status":         "planned",
				},
			},
		},
	}
}

// resolveWorkDir devolve `<root>/.pwn/work/<id>` ou o próprio root quando ele já
// é o Work.
func resolveWorkDir(workID, rootDir string) (string, bool) {
	nested := filepath.Join(rootDir, ".pwn", "work", workID)
	if info, err := os.Stat(nested); err == nil && info.IsDir() {
		return nested, true
	}
	for _, name := range []string{"discovery.json", "requirements.json", "prd.json", "spec.json"} {
		if _, err := os.Stat(filepath.Join(rootDir, name)); err == nil {
			return rootDir, true
		}
	}
	return "", false
}

// missingArtifacts lista os artefatos obrigatórios ausentes num Work.
func missingArtifacts(workDir string) []string {
	missing := make([]string, 0)
	for _, name := range requiredArtifacts {
		if _, err := os.Stat(filepath.Join(workDir, name)); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

// DescribeBaseline descreve a baseline que RunMutations vai usar.
func DescribeBaseline(options RunMutationsOptions) string {
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	absolute, err := filepath.Abs(rootDir)
	if err != nil {
		absolute = rootDir
	}
	source, found := resolveWorkDir(options.WorkID, absolute)
	if !found {
		return "baseline canônica (Work " + options.WorkID + " não encontrado em " + absolute + ")"
	}
	missing := missingArtifacts(source)
	if len(missing) > 0 {
		return "baseline canônica (Work " + options.WorkID + " incompleto: falta " + strings.Join(missing, ", ") + ")"
	}
	return "Work " + options.WorkID + " (" + source + ")"
}

// MutationCases devolve a lista canônica das mutações que o harness garante
// detectar.
func MutationCases() []MutationCase {
	return []MutationCase{
		{
			ID:            "mut-missing-ac",
			Description:   "Remove acceptance_criteria de todas as tasks do plan.json",
			Gate:          "GATE-SPEC-PLAN",
			ExpectBlocked: true,
		},
		{
			ID:            "mut-missing-contract",
			Description:   "Aponta contract_id de uma task para um contrato inexistente",
			Gate:          "GATE-PLAN-CONTRACT",
			ExpectBlocked: true,
		},
		{
			ID:            "mut-broken-traceability",
			Description:   "Esvazia a matriz de rastreabilidade (traceability-matrix.json)",
			Gate:          "GATE-DISC-REQ",
			ExpectBlocked: true,
		},
		{
			ID:            "mut-prd-missing-accepted",
			Description:   "Remove accepted_requirements do prd.json",
			Gate:          "GATE-REQ-PRD",
			ExpectBlocked: true,
		},
		{
			ID:            "mut-spec-no-rules",
			Description:   "Remove rules de todas as capabilities do spec.json",
			Gate:          "GATE-PRD-SPEC",
			ExpectBlocked: false,
		},
	}
}

// RunMutationsOptions identifica o Work e a raiz do projeto.
type RunMutationsOptions struct {
	WorkID  string
	RootDir string
}

// RunMutations executa as mutações num Work temporário (cópia de um Work
// válido) e verifica que cada gate correspondente passa de pass para blocked.
//
// O Work real nunca é escrito: cada caso roda sobre uma cópia em MkdirTemp.
// Quando o Work pedido não existe ou está incompleto, a baseline é a Work
// canônica embutida neste módulo.
func RunMutations(options RunMutationsOptions) []MutationResult {
	cases := MutationCases()
	rootDir := options.RootDir
	if rootDir == "" {
		rootDir = "."
	}
	absolute, err := filepath.Abs(rootDir)
	if err != nil {
		absolute = rootDir
	}
	source, found := resolveWorkDir(options.WorkID, absolute)
	missing := requiredArtifacts
	if found {
		missing = missingArtifacts(source)
	}
	useCanonical := len(missing) > 0

	tempRoot, err := os.MkdirTemp("", "pwn-mut-")
	if err != nil {
		return nil
	}
	baselineDir := filepath.Join(tempRoot, "baseline")
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		_ = os.RemoveAll(tempRoot)
		return nil
	}

	defer func() { _ = os.RemoveAll(tempRoot) }()

	if useCanonical {
		for name, value := range canonicalArtifacts(options.WorkID) {
			if err := writeJSONFile(filepath.Join(baselineDir, name), value); err != nil {
				return nil
			}
		}
	} else if err := copyDirectory(source, baselineDir); err != nil {
		return nil
	}

	results := make([]MutationResult, 0, len(cases))
	for _, mutationCase := range cases {
		results = append(results, runSingleMutation(mutationCase, baselineDir, tempRoot, options.WorkID, useCanonical))
	}
	return results
}

// runSingleMutation roda um único caso sobre uma cópia limpa da baseline.
func runSingleMutation(mutationCase MutationCase, baselineDir, tempRoot, workID string, canonical bool) MutationResult {
	base := MutationResult{
		ID:          mutationCase.ID,
		Description: mutationCase.Description,
		Gate:        mutationCase.Gate,
	}
	origin := ""
	if canonical {
		origin = " [baseline canônica]"
	}

	evaluator, ok := gateEvaluators[mutationCase.Gate]
	if !ok {
		base.Detail = "gate desconhecido: " + mutationCase.Gate
		return base
	}

	caseDir := filepath.Join(tempRoot, "case-"+mutationCase.ID)
	defer func() { _ = os.RemoveAll(caseDir) }()

	if err := copyDirectory(baselineDir, caseDir); err != nil {
		base.Detail = "erro ao executar a mutação: " + err.Error()
		return base
	}

	before := evaluator(workID, caseDir)
	note, err := applyMutation(mutationCase.ID, caseDir)
	if err != nil {
		base.Detail = "erro ao executar a mutação: " + err.Error()
		return base
	}
	if note == "" {
		base.Detail = "mutação não aplicável neste baseline (estrutura alvo ausente)" + origin
		return base
	}

	after := evaluator(workID, caseDir)
	detected := before.Result != ResultBlocked && after.Result == ResultBlocked

	detail := note + "; antes='" + string(before.Result) + "', depois='" + string(after.Result) + "'" + origin
	switch {
	case before.Result == ResultBlocked:
		detail += "; gate já bloqueava antes da mutação (baseline inválida para este caso)"
	case !detected:
		detail += "; " + describeFindings(after)
	default:
		detail += "; gate passou a bloquear com " + strconv.Itoa(len(after.Findings)) + " finding(s)"
		if !mutationCase.ExpectBlocked {
			detail += "; gate endureceu desde a lista canônica (caso declarado advisory)"
		}
	}
	base.Detected = detected
	base.Detail = detail
	return base
}

// describeFindings resume os achados que sobraram depois da mutação.
func describeFindings(gate GateOutput) string {
	if len(gate.Findings) == 0 {
		return "gate não bloqueia: nenhum finding gerado para esta mutação"
	}
	severities := make([]string, 0)
	types := make([]string, 0)
	seenSeverity := make(map[string]bool)
	seenType := make(map[string]bool)
	for _, finding := range gate.Findings {
		severity := string(finding.Severity)
		if !seenSeverity[severity] {
			seenSeverity[severity] = true
			severities = append(severities, severity)
		}
		findingType := string(finding.Type)
		if !seenType[findingType] {
			seenType[findingType] = true
			types = append(types, findingType)
		}
	}
	return "gate não bloqueia: finding advisory (severidade '" + strings.Join(severities, ", ") +
		"', tipo '" + strings.Join(types, ", ") + "') — result='" + string(gate.Result) + "'"
}

// applyMutation aplica a mutação e devolve a nota do que mudou. Nota vazia
// significa que a mutação não era aplicável.
func applyMutation(id, workDir string) (string, error) {
	switch id {
	case "mut-missing-ac":
		return mutateMissingAC(workDir)
	case "mut-missing-contract":
		return mutateMissingContract(workDir)
	case "mut-broken-traceability":
		return mutateBrokenTraceability(workDir)
	case "mut-prd-missing-accepted":
		return mutatePRDMissingAccepted(workDir)
	case "mut-spec-no-rules":
		return mutateSpecNoRules(workDir)
	default:
		return "", nil
	}
}

func mutateMissingAC(workDir string) (string, error) {
	planPath := filepath.Join(workDir, "plan.json")
	plan, err := readJSONObject(planPath)
	if plan == nil {
		return "", err
	}
	tasks := asJSONArray(plan["tasks"])
	touched := 0
	for _, rawTask := range tasks {
		task, ok := rawTask.(map[string]any)
		if !ok {
			continue
		}
		if _, present := task["acceptance_criteria"]; present {
			delete(task, "acceptance_criteria")
			touched++
		}
	}
	if touched == 0 {
		return "", nil
	}
	if err := writeJSONFile(planPath, plan); err != nil {
		return "", err
	}
	return "acceptance_criteria removidos de " + strconv.Itoa(touched) + " task(s) do plan.json", nil
}

func mutateMissingContract(workDir string) (string, error) {
	planPath := filepath.Join(workDir, "plan.json")
	plan, err := readJSONObject(planPath)
	if plan == nil {
		return "", err
	}
	var target map[string]any
	for _, rawTask := range asJSONArray(plan["tasks"]) {
		task, ok := rawTask.(map[string]any)
		if ok && jsTruthy(task["contract_id"]) {
			target = task
			break
		}
	}
	if target == nil {
		return "", nil
	}
	target["contract_id"] = "CTR-INEXISTENTE-9999"
	if err := writeJSONFile(planPath, plan); err != nil {
		return "", err
	}
	return "contract_id da task " + jsID(target["id"], "?") + " apontado para CTR-INEXISTENTE-9999", nil
}

func mutateBrokenTraceability(workDir string) (string, error) {
	matrixPath := filepath.Join(workDir, "traceability-matrix.json")
	matrix, err := readJSONObject(matrixPath)
	if matrix == nil {
		return "", err
	}
	size := len(asJSONArray(matrix["matrix"]))
	if size == 0 {
		return "", nil
	}
	matrix["matrix"] = []any{}
	if err := writeJSONFile(matrixPath, matrix); err != nil {
		return "", err
	}
	return "matriz de rastreabilidade esvaziada (" + strconv.Itoa(size) + " entrada(s) removida(s))", nil
}

func mutatePRDMissingAccepted(workDir string) (string, error) {
	prdPath := filepath.Join(workDir, "prd.json")
	prd, err := readJSONObject(prdPath)
	if prd == nil {
		return "", err
	}
	if _, present := prd["accepted_requirements"]; !present {
		return "", nil
	}
	size := len(asJSONArray(prd["accepted_requirements"]))
	delete(prd, "accepted_requirements")
	if err := writeJSONFile(prdPath, prd); err != nil {
		return "", err
	}
	return "accepted_requirements removido do prd.json (" + strconv.Itoa(size) + " requisito(s) aceito(s))", nil
}

func mutateSpecNoRules(workDir string) (string, error) {
	specPath := filepath.Join(workDir, "spec.json")
	spec, err := readJSONObject(specPath)
	if spec == nil {
		return "", err
	}
	touched := 0
	for _, rawCapability := range asJSONArray(spec["capabilities"]) {
		capability, ok := rawCapability.(map[string]any)
		if !ok {
			continue
		}
		rules, present := capability["rules"]
		if !present {
			continue
		}
		if len(asJSONArray(rules)) > 0 {
			capability["rules"] = []any{}
			touched++
		}
	}
	if touched == 0 {
		return "", nil
	}
	if err := writeJSONFile(specPath, spec); err != nil {
		return "", err
	}
	return "rules removidas de " + strconv.Itoa(touched) + " capability(ies) do spec.json", nil
}

// readJSONObject lê um objeto JSON. Devolve nil, sem erro, quando o arquivo
// está ausente; devolve erro quando o conteúdo não é um objeto legível.
func readJSONObject(filePath string) (map[string]any, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return objectOrEmpty(value), nil
}

// writeJSONFile grava o JSON com dois espaços de indentação e uma quebra de
// linha final, como o JSON.stringify(value, null, 2) seguido de "\n".
func writeJSONFile(filePath string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, append(data, '\n'), 0o644)
}

// copyDirectory copia src para dst recursivamente.
func copyDirectory(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		source := filepath.Join(src, entry.Name())
		target := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDirectory(source, target); err != nil {
				return err
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}
