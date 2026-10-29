package decider

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
)

// `verify approve`: os testes congelados verificam o comportamento da task? O
// modelo julga o texto; a política decide. Os números são o ponto de partida do
// desenho e só mudam no código, nunca por flag.

// Limiares da aprovação de uma task.
const (
	approveCoversMin          = 0.8
	approvePassesWithoutMax   = 0.15
	approveSpecificityMin     = 2.0
	approveScopeConfidenceMin = 0.7
	approveRejectCoversBelow  = 0.2
	approveRejectPassesAbove  = 0.85
)

// ApproveThresholds são os limiares serializados no registro da decisão.
var ApproveThresholds = map[string]any{
	"covers_min":                  approveCoversMin,
	"passes_without_max":          approvePassesWithoutMax,
	"specificity_min":             approveSpecificityMin,
	"scope_confidence_min":        approveScopeConfidenceMin,
	"reject_covers_below":         approveRejectCoversBelow,
	"reject_passes_without_above": approveRejectPassesAbove,
}

var specificityLevels = []string{
	"Só checa existência, que não lança erro ou que algo foi chamado",
	"Checa forma ou tipo do resultado, sem o valor",
	"Checa o valor exato do caminho principal",
	"Checa o valor exato do caminho principal e casos de borda ou de erro",
}

// TaskApprovalRequest monta o estado da aprovação de uma task: requisito,
// comportamento, ACs, testes congelados e escopo.
func TaskApprovalRequest(rootDir, workID, taskID string) (Request, error) {
	workPlan := plan.LoadPlan(workID, rootDir)
	var task *plan.PlanTask
	if workPlan != nil {
		for index := range workPlan.Tasks {
			if workPlan.Tasks[index].ID == taskID {
				task = &workPlan.Tasks[index]
				break
			}
		}
	}
	if task == nil {
		return Request{}, fmt.Errorf("task %s não encontrada no plan.json do Work %s", taskID, workID)
	}
	taskContract, err := plan.LoadTaskContract(workID, taskID, rootDir)
	if err != nil {
		return Request{}, err
	}
	frozen := taskContract.AcceptanceContract.FrozenTests
	if len(frozen) == 0 {
		return Request{}, fmt.Errorf("a task %s não tem testes de aceitação congelados; congele-os antes de aprovar", taskID)
	}
	frozenTests := make([]map[string]any, 0, len(frozen))
	for _, entry := range frozen {
		absolute := entry.Path
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(rootDir, entry.Path)
		}
		if _, err := os.Stat(absolute); err != nil {
			return Request{}, fmt.Errorf("teste de aceitação aprovado ausente no repositório: %s", entry.Path)
		}
		content, err := os.ReadFile(absolute)
		if err != nil {
			return Request{}, fmt.Errorf("teste de aceitação aprovado ausente no repositório: %s", entry.Path)
		}
		frozenTests = append(frozenTests, map[string]any{"path": entry.Path, "content": string(content)})
	}
	return Request{
		State: map[string]any{
			"requirement_id": task.RequirementID,
			"task": map[string]any{
				"id":       task.ID,
				"title":    task.Title,
				"behavior": task.Behavior,
			},
			"acceptance_criteria":  task.AcceptanceCriteria,
			"frozen_tests":         frozenTests,
			"implementation_files": task.ImplementationFiles,
			"write_allow":          taskContract.ScopeContract.WriteAllow,
			"write_deny":           taskContract.ScopeContract.WriteDeny,
		},
		Questions: map[string]Question{
			"covers_behavior": {
				Type:         QuestionNoul,
				Instructions: "Os testes em `frozen_tests` verificam o resultado observável descrito em `task.behavior`?",
				Criteria: NoulCriteria{
					True:  "Os testes falham se o comportamento descrito não acontecer",
					False: "Os testes não exercitam o comportamento descrito",
				},
			},
			"passes_without_requirement": {
				Type:         QuestionNoul,
				Instructions: "Os testes em `frozen_tests` passariam com uma implementação que ignora o requisito (stub, valor fixo, retorno vazio)?",
				Criteria: NoulCriteria{
					True:  "Uma implementação vazia ou falsa passaria",
					False: "Só uma implementação real do comportamento passa",
				},
			},
			"specificity": {
				Type:         QuestionScore,
				Instructions: "Quão específicas são as asserções de `frozen_tests` em relação a `task.behavior`?",
				Criteria:     specificityLevels,
			},
			"scope": {
				Type:         QuestionChoice,
				Instructions: "O escopo de escrita `write_allow` é adequado para implementar `task.behavior` nos `implementation_files`?",
				Criteria: ChoiceCriteria{
					"adequate":   "Cobre os arquivos necessários e nada além do razoável",
					"too_broad":  "Permite escrever bem além do necessário (diretórios inteiros, manifestos, configuração)",
					"too_narrow": "Não permite escrever arquivos necessários para a implementação",
				},
			},
		},
	}, nil
}

// TaskApprovalPolicy decide a aprovação de uma task.
var TaskApprovalPolicy = Policy{
	Point:      PointApprove,
	Thresholds: ApproveThresholds,
	Judge:      judgeTaskApproval,
}

func judgeTaskApproval(answers map[string]Answer) Judgment {
	covers := noulValue(answers, "covers_behavior")
	passesWithout := noulValue(answers, "passes_without_requirement")
	specificity := scoreValue(answers, "specificity")
	scope := answers["scope"]
	facts := fmt.Sprintf("cobre=%.2f, passa_sem=%.2f, especificidade=%.2f, escopo=%s (%.2f)",
		covers, passesWithout, specificity, scope.Choice, confidenceValue(scope))

	rejections := make([]string, 0, 2)
	if covers < approveRejectCoversBelow {
		rejections = append(rejections, fmt.Sprintf("os testes congelados não verificam o comportamento da task (cobre=%.2f)", covers))
	}
	if passesWithout > approveRejectPassesAbove {
		rejections = append(rejections, fmt.Sprintf("os testes congelados passariam com uma implementação que ignora o requisito (passa_sem=%.2f)", passesWithout))
	}
	if len(rejections) > 0 {
		return Judgment{Outcome: OutcomeReject, Reasons: rejections}
	}

	gaps := make([]string, 0, 4)
	if covers <= approveCoversMin {
		gaps = append(gaps, fmt.Sprintf("cobertura do comportamento %.2f ≤ %v", covers, approveCoversMin))
	}
	if passesWithout >= approvePassesWithoutMax {
		gaps = append(gaps, fmt.Sprintf("chance de passar sem o requisito %.2f ≥ %v", passesWithout, approvePassesWithoutMax))
	}
	if specificity < approveSpecificityMin {
		gaps = append(gaps, fmt.Sprintf("especificidade %.2f < %v", specificity, approveSpecificityMin))
	}
	if scope.Choice != "adequate" || confidenceValue(scope) < approveScopeConfidenceMin {
		gaps = append(gaps, fmt.Sprintf("escopo %s com confiança %.2f", scope.Choice, confidenceValue(scope)))
	}
	if len(gaps) > 0 {
		return Judgment{Outcome: OutcomeEscalate, Reasons: append(gaps, facts)}
	}
	return Judgment{Outcome: OutcomeApprove, Reasons: []string{facts}}
}

// Limiares da aprovação de um gate global.
const (
	globalVerifiesMin = 0.85
	globalRejectBelow = 0.2
)

// GlobalThresholds são os limiares serializados na decisão de um gate global.
var GlobalThresholds = map[string]any{"verifies_min": globalVerifiesMin, "reject_below": globalRejectBelow}

// GlobalApprovalRequest monta o estado da aprovação de um gate global: o texto
// do gate e o comando que o verifica.
func GlobalApprovalRequest(rootDir, workID, gateName string) (Request, error) {
	planPath := plan.TasksMarkdownPath(workID, rootDir)
	data, err := os.ReadFile(planPath)
	if err != nil {
		return Request{}, fmt.Errorf("plano não encontrado: %s", planPath)
	}
	gates, found := plan.ParseGlobalGates(string(data))
	index, err := strconv.Atoi(strings.TrimPrefix(gateName, "G-"))
	if !found || err != nil || index < 1 || index > len(gates) || gates[index-1].Command == "" {
		return Request{}, fmt.Errorf("%s não existe ou não declara comando em ## Global gates", gateName)
	}
	gate := gates[index-1]
	return Request{
		State: map[string]any{
			"gate": map[string]any{"id": gateName, "text": gate.Text, "command": gate.Command},
		},
		Questions: map[string]Question{
			"verifies_gate": {
				Type:         QuestionNoul,
				Instructions: "Executar `gate.command` verifica de fato o que `gate.text` declara?",
				Criteria: NoulCriteria{
					True:  "O comando falha quando a condição declarada não vale",
					False: "O comando não verifica a condição declarada",
				},
			},
		},
	}, nil
}

// GlobalApprovalPolicy decide a aprovação de um gate global.
var GlobalApprovalPolicy = Policy{
	Point:      PointApprove,
	Thresholds: GlobalThresholds,
	Judge:      judgeGlobalApproval,
}

func judgeGlobalApproval(answers map[string]Answer) Judgment {
	verifies := noulValue(answers, "verifies_gate")
	fact := fmt.Sprintf("verifica_gate=%.2f", verifies)
	if verifies < globalRejectBelow {
		return Judgment{Outcome: OutcomeReject, Reasons: []string{"o comando não verifica o gate declarado (" + fact + ")"}}
	}
	if verifies > globalVerifiesMin {
		return Judgment{Outcome: OutcomeApprove, Reasons: []string{fact}}
	}
	return Judgment{Outcome: OutcomeEscalate, Reasons: []string{fmt.Sprintf("incerto se o comando verifica o gate (%s ≤ %v)", fact, globalVerifiesMin)}}
}

func noulValue(answers map[string]Answer, id string) float64 {
	answer, ok := answers[id]
	if !ok || answer.Noul == nil {
		return 0
	}
	return *answer.Noul
}

func scoreValue(answers map[string]Answer, id string) float64 {
	answer, ok := answers[id]
	if !ok || answer.Score == nil {
		return 0
	}
	return *answer.Score
}

func confidenceValue(answer Answer) float64 {
	if answer.Confidence == nil {
		return 0
	}
	return *answer.Confidence
}
